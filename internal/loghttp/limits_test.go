package loghttp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// counting is a body that never ends and counts the bytes read from it.
type counting struct{ n atomic.Int64 }

func (c *counting) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	c.n.Add(int64(len(p)))
	return len(p), nil
}

// blocking is a body that reports its first Read on started and then
// waits until free is closed; it ends without a byte.
type blocking struct {
	once    sync.Once
	started chan<- struct{}
	free    <-chan struct{}
}

func (b *blocking) Read([]byte) (int, error) {
	b.once.Do(func() { b.started <- struct{}{} })
	<-b.free
	return 0, io.EOF
}

// serve sends a request with body to the handler directly.
func serve(s *Server, method, target, ctype string, body io.Reader, length int64) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, body)
	r.ContentLength = length
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// TestCosignTypeBeforeBody: POST /cosign with a wrong content type, or a
// declared length above the limit, is refused before a byte of the body
// is read, and the connection is closed after the answer.
func TestCosignTypeBeforeBody(t *testing.T) {
	e := newEnv(t, 1, 1)
	for _, ct := range []string{"", "text/html", "text/plain", "text/plain; charset=latin1", "application/octet-stream",
		"text/plain; charset=utf-8; x=1", "garbage;;"} {
		for _, length := range []int64{-1, 100, translog.MaxHeadNote + 1, 1 << 40} {
			c := &counting{}
			r := serve(e.srv, http.MethodPost, witness.PathCosign, ct, c, length)
			if r.Code != http.StatusBadRequest || r.Body.String() != "content type\n" || r.Header().Get("Connection") != "close" {
				t.Fatalf("type %q, length %d: %d %q", ct, length, r.Code, r.Body.String())
			}
			if c.n.Load() != 0 {
				t.Fatalf("type %q, length %d: %d bytes read", ct, length, c.n.Load())
			}
		}
	}
	// The right type with a declared length above the limit: 413 unread.
	c := &counting{}
	if r := serve(e.srv, http.MethodPost, witness.PathCosign, witness.ContentType, c, translog.MaxHeadNote+1); r.Code != http.StatusRequestEntityTooLarge || c.n.Load() != 0 {
		t.Fatalf("declared too large: %d, %d bytes read", r.Code, c.n.Load())
	}
	// The right type without a length is read up to the limit only.
	c = &counting{}
	if r := serve(e.srv, http.MethodPost, witness.PathCosign, witness.ContentType, c, -1); r.Code != http.StatusRequestEntityTooLarge || c.n.Load() == 0 || c.n.Load() > 2*translog.MaxHeadNote {
		t.Fatalf("unknown length: %d, %d bytes read", r.Code, c.n.Load())
	}
}

// occupy takes all MaxVerifying slots directly, as MaxVerifying
// requests in their verification would, and shortens the wait for a
// slot to wait; the returned function frees them.
func occupy(t *testing.T, s *Server, wait time.Duration) func() {
	t.Helper()
	s.wait = wait
	for i := 0; i < MaxVerifying; i++ {
		s.slots <- struct{}{}
	}
	var once sync.Once
	free := func() {
		once.Do(func() {
			for i := 0; i < MaxVerifying; i++ {
				<-s.slots
			}
		})
	}
	t.Cleanup(free)
	return free
}

// TestVerifyingLimit: with all MaxVerifying slots taken, POST /cosign
// reads its body in full and then, after waiting SlotWait for a slot,
// gets 503; GET /head and /consistency get 503 when they would have to
// open the published head; GET /head of a candidate is served. The
// checks before the body still answer at once.
func TestVerifyingLimit(t *testing.T) {
	if MaxVerifying < witness.MaxWitnesses {
		t.Fatalf("MaxVerifying %d below the number of witnesses %d", MaxVerifying, witness.MaxWitnesses)
	}
	// SlotWait (its comment): positive and at most the 5 s measured there,
	// since every second more keeps a waiting request with its connection
	// and body that much longer (up to ReadTimeout + SlotWait). A witness
	// sends its body at once, so a request of it that waits the full
	// SlotWait has to write its answer (the slot's or 503) before the
	// write deadline, which net/http sets to WriteTimeout once the headers
	// are read, and the witness has to receive it within its own
	// RequestTimeout for the whole request: both need SlotWait below the
	// timeout. How far below is the time of the verification and of the
	// transfer, which the code does not fix.
	if SlotWait <= 0 || SlotWait > 5*time.Second || SlotWait >= WriteTimeout || SlotWait >= witness.RequestTimeout {
		t.Fatalf("SlotWait %v, WriteTimeout %v, witness.RequestTimeout %v", SlotWait, WriteTimeout, witness.RequestTimeout)
	}
	e := newEnv(t, 1, 1)
	e.grow(2)
	if e.srv.wait != SlotWait {
		t.Fatalf("wait %v", e.srv.wait)
	}
	const wait = 100 * time.Millisecond
	free := occupy(t, e.srv, wait)
	for _, length := range []int64{-1, 100} {
		body := strings.NewReader(strings.Repeat("x", 100))
		start := time.Now()
		r := serve(e.srv, http.MethodPost, witness.PathCosign, witness.ContentType, body, length)
		if r.Code != http.StatusServiceUnavailable || r.Body.String() != "busy\n" || r.Header().Get("Connection") != "close" ||
			r.Header().Get("Content-Type") != witness.ContentType {
			t.Fatalf("over the limit: %d %q", r.Code, r.Body.String())
		}
		if body.Len() != 0 {
			t.Fatalf("over the limit: %d bytes of the body unread", body.Len())
		}
		if d := time.Since(start); d < wait {
			t.Fatalf("over the limit: 503 after %v, before the wait", d)
		}
	}
	// No candidate: GET opens the published head and needs a slot.
	for _, target := range []string{witness.PathHead, witness.PathConsistency + "?from=1&to=1"} {
		if r := e.do(http.MethodGet, target, "", nil); r.Code != http.StatusServiceUnavailable || r.Body.String() != "busy\n" {
			t.Fatalf("%s over the limit: %d %q", target, r.Code, r.Body.String())
		}
	}
	// The checks before the body still answer, without a wait.
	e.srv.wait = time.Minute
	start := time.Now()
	c := &counting{}
	if r := serve(e.srv, http.MethodPost, witness.PathCosign, "text/html", c, 100); r.Code != http.StatusBadRequest || c.n.Load() != 0 {
		t.Fatalf("content type over the limit: %d, %d bytes read", r.Code, c.n.Load())
	}
	if r := serve(e.srv, http.MethodPost, witness.PathCosign, witness.ContentType, c, translog.MaxHeadNote+1); r.Code != http.StatusRequestEntityTooLarge || c.n.Load() != 0 {
		t.Fatalf("declared length over the limit: %d, %d bytes read", r.Code, c.n.Load())
	}
	if r := e.do(http.MethodGet, witness.PathConsistency+"?from=0&to=1", "", nil); r.Code != http.StatusBadRequest {
		t.Fatalf("malformed query over the limit: %d", r.Code)
	}
	if d := time.Since(start); d >= 30*time.Second {
		t.Fatalf("checks before the body waited %v", d)
	}
	// A candidate is served without a slot.
	e.srv.Tick()
	if r := e.do(http.MethodGet, witness.PathHead, "", nil); r.Code != http.StatusOK {
		t.Fatalf("candidate over the limit: %d", r.Code)
	}
	free()
	if r := e.do(http.MethodPost, witness.PathCosign, witness.ContentType, []byte("garbage")); r.Code != http.StatusBadRequest {
		t.Fatalf("after the limit: %d", r.Code)
	}
	if n := len(e.srv.slots); n != 0 {
		t.Fatalf("%d slots taken after the answers", n)
	}
	// Again without a candidate: the published head is opened (none yet).
	e.start()
	if r := e.do(http.MethodGet, witness.PathHead, "", nil); r.Code != http.StatusNotFound {
		t.Fatalf("head after the limit: %d", r.Code)
	}
	if n := len(e.srv.slots); n != 0 {
		t.Fatalf("%d slots taken after GET", n)
	}
}

// TestSlotWait: a request that finds every slot taken gets the first
// one that comes free within SlotWait (a short burst turns no witness
// away), and answers 503 at once when the client goes away.
func TestSlotWait(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.grow(2)
	occupy(t, e.srv, time.Minute)
	go func() {
		time.Sleep(50 * time.Millisecond)
		<-e.srv.slots
	}()
	if r := e.do(http.MethodPost, witness.PathCosign, witness.ContentType, []byte("garbage")); r.Code != http.StatusBadRequest {
		t.Fatalf("slot freed during the wait: %d %q", r.Code, r.Body.String())
	}
	if r := e.do(http.MethodGet, witness.PathHead, "", nil); r.Code != http.StatusNotFound {
		t.Fatalf("GET with a free slot: %d %q", r.Code, r.Body.String())
	}
	e.srv.slots <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	req := newRequest(http.MethodPost, witness.PathCosign, witness.ContentType, []byte("garbage")).WithContext(ctx)
	w := newRecorder()
	e.srv.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || time.Since(start) > 10*time.Second {
		t.Fatalf("client gone: %d after %v", w.Code, time.Since(start))
	}
}

// TestVerifyingLimitWitness: over HTTP, a witness whose cosignature gets
// 503 fails the round with ErrProtocol (no fork) and is merged in its
// next round once a slot is free.
func TestVerifyingLimitWitness(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.grow(2)
	e.srv.Tick()
	free := occupy(t, e.srv, 50*time.Millisecond)
	if err := e.poll(0); !errors.Is(err, witness.ErrProtocol) || errors.Is(err, witness.ErrFork) {
		t.Fatalf("poll over the limit: %v", err)
	}
	if c := e.srv.Candidate(); len(c.Sigs) != 1 {
		t.Fatalf("merged over the limit: %d lines", len(c.Sigs))
	}
	free()
	if err := e.poll(0); err != nil {
		t.Fatalf("poll after the limit: %v", err)
	}
	if c := e.srv.Candidate(); len(c.Sigs) != 2 {
		t.Fatalf("not merged after the limit: %d lines", len(c.Sigs))
	}
}

// TestHeaderLimit: the server of NewHTTPServer refuses a header block
// well above MaxHeaderBytes (431) and serves one below it. The standard
// library allows 4096 bytes on top of the limit.
func TestHeaderLimit(t *testing.T) {
	e := newEnv(t, 1, 1)
	hs := NewHTTPServer(e.srv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Shutdown(context.Background()) })
	status := func(n int) int {
		t.Helper()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(c, "GET /gomail/log/other HTTP/1.1\r\nHost: x\r\nX-Pad: %s\r\nConnection: close\r\n\r\n", strings.Repeat("a", n))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := status(MaxHeaderBytes / 2); code != http.StatusNotFound {
		t.Fatalf("below the limit: %d", code)
	}
	// Just above the limit and the 4096 bytes of the standard library.
	if code := status(MaxHeaderBytes + 5<<10); code != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("above the limit: %d", code)
	}
	if hs.MaxHeaderBytes != MaxHeaderBytes || MaxHeaderBytes > 16<<10 {
		t.Fatalf("MaxHeaderBytes %d, constant %d", hs.MaxHeaderBytes, MaxHeaderBytes)
	}
}

// TestEarlyAnswerOverHTTP: over a server of NewHTTPServer, a wrong type
// and a declared length above the limit are answered before the client
// has sent a byte of the body (without Connection: close, net/http would
// wait for the body before it answers). A full server answers 503 only
// after the body has arrived and the wait for a slot has passed.
func TestEarlyAnswerOverHTTP(t *testing.T) {
	e := newEnv(t, 1, 1)
	hs := NewHTTPServer(e.srv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	dial := func(ctype string, length int64) (net.Conn, *bufio.Reader) {
		t.Helper()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", witness.PathCosign, ctype, length)
		return c, bufio.NewReader(c)
	}
	answer := func(br *bufio.Reader, what string) int {
		t.Helper()
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("%s: no answer: %v", what, err)
		}
		resp.Body.Close()
		if !resp.Close {
			t.Fatalf("%s: connection kept", what)
		}
		return resp.StatusCode
	}
	_, br := dial("text/html", 100)
	if code := answer(br, "type"); code != http.StatusBadRequest {
		t.Fatalf("type: %d", code)
	}
	_, br = dial(witness.ContentType, translog.MaxHeadNote+1)
	if code := answer(br, "length"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("length: %d", code)
	}
	const wait = 50 * time.Millisecond
	occupy(t, e.srv, wait)
	c, br := dial(witness.ContentType, 100)
	// No answer before the body: the slot is taken only after it.
	c.SetReadDeadline(time.Now().Add(10 * wait))
	if _, err := br.Peek(1); err == nil {
		t.Fatal("full: answered before the body")
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	c.Write([]byte(strings.Repeat("x", 100)))
	if code := answer(br, "full"); code != http.StatusServiceUnavailable {
		t.Fatalf("full: %d", code)
	}
	if d := time.Since(start); d < wait {
		t.Fatalf("full: 503 after %v, before the wait", d)
	}
}
