package loghttp

// Task 24 D, rework of the review: slow bodies hold no slot (finding 1),
// a replayed published head is not written again (finding 2), answers to
// requests whose body is not read close the connection (finding 3).

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// startLimited puts the server behind an HTTP server with the limits of
// NewHTTPServer but the given ReadTimeout; it returns the address and
// the number of connections that have begun a request.
func startLimited(t *testing.T, e *env, readTimeout time.Duration) (string, *atomic.Int64) {
	t.Helper()
	if e.http != nil {
		e.http.Close()
	}
	active := new(atomic.Int64)
	hs := httptest.NewUnstartedServer(e.srv)
	ref := NewHTTPServer(e.srv)
	hs.Config.ReadHeaderTimeout = ref.ReadHeaderTimeout
	hs.Config.ReadTimeout = readTimeout
	hs.Config.WriteTimeout = ref.WriteTimeout
	hs.Config.IdleTimeout = ref.IdleTimeout
	hs.Config.MaxHeaderBytes = ref.MaxHeaderBytes
	hs.Config.ErrorLog = ref.ErrorLog
	hs.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateActive {
			active.Add(1)
		}
	}
	hs.Start()
	e.http = hs
	t.Cleanup(hs.Close)
	return strings.TrimPrefix(hs.URL, "http://"), active
}

// slowBodies runs n clients; each sends the headers of POST /cosign with
// Content-Length: MaxHeadNote and never a byte of the body, waits for the
// answer and connects again at once, until the returned function is
// called. That function returns the number of answers the clients got.
func slowBodies(t *testing.T, addr string, n int) func() int64 {
	t.Helper()
	req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
		witness.PathCosign, witness.ContentType, translog.MaxHeadNote)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var answers atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c, err := net.Dial("tcp", addr)
				if err != nil {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				done := make(chan struct{})
				go func() {
					select {
					case <-stop:
					case <-done:
					}
					c.Close()
				}()
				c.Write([]byte(req))
				if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err == nil {
					resp.Body.Close()
					answers.Add(1)
				}
				close(done)
			}
		}()
	}
	var once sync.Once
	end := func() int64 {
		once.Do(func() { close(stop); wg.Wait() })
		return answers.Load()
	}
	t.Cleanup(func() { end() })
	return end
}

// attack starts 2*MaxVerifying slow clients and waits until each has
// sent its headers and the server has had time to run the handlers.
func attack(t *testing.T, addr string, active *atomic.Int64) func() int64 {
	t.Helper()
	n := 2 * MaxVerifying
	end := slowBodies(t, addr, n)
	deadline := time.Now().Add(10 * time.Second)
	for active.Load() < int64(n) {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d slow clients connected", active.Load(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	return end
}

// TestSlowBodiesWitness (finding 1): 2*MaxVerifying clients that send
// the headers of POST /cosign and never the body, and connect again when
// ReadTimeout ends their request, keep no witness out: every round of a
// real witness over HTTP is merged, through more than two ReadTimeouts.
// Before the rework (slot before the body) the first round got 503.
func TestSlowBodiesWitness(t *testing.T) {
	const readTimeout = time.Second
	e := newEnv(t, 1, 1)
	e.grow(2)
	e.srv.Tick()
	addr, active := startLimited(t, e, readTimeout)
	end := attack(t, addr, active)
	begin := time.Now()
	rounds := 0
	for time.Since(begin) < 3*readTimeout || rounds < 3 {
		rounds++
		if rounds > 1 {
			e.grow(1)
			e.clk.add(2 * time.Minute)
			e.srv.Tick()
		}
		if err := e.poll(0); err != nil {
			t.Fatalf("round %d after %v under attack: %v", rounds, time.Since(begin).Round(time.Millisecond), err)
		}
		if c := e.srv.Candidate(); len(c.Sigs) != 2 {
			t.Fatalf("round %d: candidate with %d lines", rounds, len(c.Sigs))
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The clients were answered (400 at ReadTimeout) and came back.
	if n := end(); n < int64(MaxVerifying) {
		t.Fatalf("%d answers to the slow clients: the attack did not outlast ReadTimeout", n)
	}
	t.Logf("%d witness rounds in %v under %d slow clients", rounds, time.Since(begin).Round(time.Millisecond), 2*MaxVerifying)
}

// TestSlowBodiesNoCandidate (finding 1): without a candidate (after a
// restart) a witness under the same attack fetches the published head
// (GET /head opens it in a slot) and has its cosignature merged into it.
// Before the rework GET /head got 503.
func TestSlowBodiesNoCandidate(t *testing.T) {
	e := newEnv(t, 3, 2)
	e.grow(2)
	e.srv.Tick()
	for i := 0; i < 2; i++ {
		if err := e.poll(i); err != nil {
			t.Fatal(err)
		}
	}
	size := e.srv.Candidate().Size
	e.start() // no candidate
	addr, active := startLimited(t, e, time.Second)
	end := attack(t, addr, active)
	if err := e.poll(2); err != nil {
		t.Fatalf("witness without candidate under attack: %v", err)
	}
	end()
	h, err := e.openHead(e.headFile(size))
	if err != nil || len(h.Sigs) != 4 {
		t.Fatalf("published head after the attack: %v", err)
	}
}

// countingOp counts the calls of PublishHead.
type countingOp struct {
	translog.Operator
	publish atomic.Int64
}

func (c *countingOp) PublishHead(h *translog.Head) error {
	c.publish.Add(1)
	return c.Operator.PublishHead(h)
}

// TestReplayPublishedHead (finding 2): POST /cosign with the published
// head, which anybody can fetch, calls PublishHead only when the body
// brings a cosignature the stored head lacks; replays of it, with or
// without a newer candidate, leave heads/<size>.sig as it is and are
// answered 200 as before.
func TestReplayPublishedHead(t *testing.T) {
	e := newEnv(t, 3, 2)
	e.grow(2)
	e.srv.Tick()
	for i := 0; i < 2; i++ {
		if err := e.poll(i); err != nil {
			t.Fatal(err)
		}
	}
	size := e.srv.Candidate().Size
	first := e.headFile(size) // log line, witnesses a and b
	if first == nil {
		t.Fatal("not published")
	}
	// A restart without candidate, with PublishHead counted.
	e.start()
	cnt := &countingOp{Operator: e.op}
	cfg := e.config()
	cfg.Log = cnt
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	e.http.Close()
	e.http = httptest.NewServer(srv)
	t.Cleanup(e.http.Close)
	// Witness c brings a line the stored head lacks: one write.
	if err := e.poll(2); err != nil {
		t.Fatal(err)
	}
	if n := cnt.publish.Load(); n != 1 {
		t.Fatalf("PublishHead called %d times for a new line", n)
	}
	all := e.headFile(size)
	if h, err := e.openHead(all); err != nil || len(h.Sigs) != 4 {
		t.Fatalf("stored head: %v", err)
	}
	p := e.path(translog.HeadPath(size))
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	replay := func(what string) {
		t.Helper()
		for _, body := range [][]byte{first, all} {
			for i := 0; i < 10; i++ {
				if r := e.do(http.MethodPost, witness.PathCosign, witness.ContentType, body); r.Code != http.StatusOK || r.Body.String() != "stored\n" {
					t.Fatalf("%s: %d %q", what, r.Code, r.Body.String())
				}
			}
		}
		if n := cnt.publish.Load(); n != 1 {
			t.Fatalf("%s: PublishHead called %d times", what, n)
		}
		after, err := os.Stat(p)
		if err != nil || !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
			t.Fatalf("%s: heads/%d.sig written again", what, size)
		}
	}
	replay("without candidate")
	// A newer candidate (the replay takes the published-head path).
	e.grow(1)
	e.clk.add(2 * time.Minute)
	e.srv.Tick()
	if c := e.srv.Candidate(); c == nil || c.Size != size+1 {
		t.Fatal("no newer candidate")
	}
	replay("with a newer candidate")
}

// TestUnreadBodyAnswersAtOnce (finding 3): answers to requests whose
// body the handler does not read (404, 405, a GET) come before the
// announced body and close the connection; without Connection: close
// net/http would wait for the body until ReadTimeout. A GET without a
// body keeps the connection.
func TestUnreadBodyAnswersAtOnce(t *testing.T) {
	e := newEnv(t, 1, 1)
	hs := NewHTTPServer(e.srv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	send := func(line, extra string) *http.Response {
		t.Helper()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(c, "%s HTTP/1.1\r\nHost: x\r\n%s\r\n", line, extra)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%s: no answer before the body: %v", line, err)
		}
		resp.Body.Close()
		return resp
	}
	for _, c := range []struct {
		line string
		code int
	}{
		{"PUT " + witness.PathCosign, http.StatusMethodNotAllowed},
		{"GET " + witness.PathCosign, http.StatusMethodNotAllowed},
		{"POST " + witness.PathHead, http.StatusMethodNotAllowed},
		{"POST /gomail/log/other", http.StatusNotFound},
		{"GET /gomail/log/other", http.StatusNotFound},
		{"GET " + witness.PathHead, http.StatusNotFound},
		{"GET " + witness.PathConsistency + "?from=1&to=1", http.StatusNotFound},
		{"GET " + witness.PathConsistency + "?from=0", http.StatusBadRequest},
	} {
		for _, extra := range []string{"Content-Length: 100\r\n", "Transfer-Encoding: chunked\r\n"} {
			resp := send(c.line, extra)
			if resp.StatusCode != c.code || !resp.Close {
				t.Fatalf("%s, %q: %d, close %v", c.line, extra, resp.StatusCode, resp.Close)
			}
		}
	}
	if resp := send("GET "+witness.PathHead, ""); resp.StatusCode != http.StatusNotFound || resp.Close {
		t.Fatalf("GET without body: %d, close %v", resp.StatusCode, resp.Close)
	}
}
