package smtpd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBackend records deliveries.
type fakeBackend struct {
	mu          sync.Mutex
	known       map[string]bool
	accepting   error
	beginErr    error
	commitErr   error
	writeErr    error
	panicOnRcpt atomic.Bool
	committed   [][]byte
	aborted     int
	sessions    []Session
}

func newFake(addrs ...string) *fakeBackend {
	f := &fakeBackend{known: map[string]bool{}}
	for _, a := range addrs {
		f.known[a] = true
	}
	return f
}

func (f *fakeBackend) Accepting() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accepting
}

func (f *fakeBackend) Recipient(a string) error {
	if f.panicOnRcpt.Load() {
		panic("backend bug")
	}
	if f.known[strings.ToLower(a)] {
		return nil
	}
	if a == "temp@x.example" {
		return errors.New("io")
	}
	return ErrUnknownRecipient
}

func (f *fakeBackend) Begin(s Session, from string, rcpts []string) (Delivery, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	f.sessions = append(f.sessions, s)
	return &fakeDelivery{f: f}, nil
}

type fakeDelivery struct {
	f   *fakeBackend
	buf bytes.Buffer
}

func (d *fakeDelivery) Write(p []byte) (int, error) {
	if d.f.writeErr != nil && d.buf.Len() > 0 {
		return 0, d.f.writeErr
	}
	return d.buf.Write(p)
}

func (d *fakeDelivery) Commit() error {
	d.f.mu.Lock()
	defer d.f.mu.Unlock()
	if d.f.commitErr != nil {
		return d.f.commitErr
	}
	d.f.committed = append(d.f.committed, append([]byte(nil), d.buf.Bytes()...))
	return nil
}

func (d *fakeDelivery) Abort() {
	d.f.mu.Lock()
	d.f.aborted++
	d.f.mu.Unlock()
}

func (f *fakeBackend) messages() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.committed...)
}

func startServer(t *testing.T, cfg Config, b Backend) (*Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, b)
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	return s, ln.Addr().String()
}

// client is a raw SMTP client for protocol tests.
type client struct {
	t *testing.T
	c net.Conn
	r *bufio.Reader
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	cl := &client{t: t, c: c, r: bufio.NewReader(c)}
	cl.expect(220)
	return cl
}

// reply reads one (possibly multi-line) reply and returns its code.
func (c *client) reply() (int, string) {
	c.t.Helper()
	c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var text strings.Builder
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return 0, err.Error()
		}
		text.WriteString(line)
		if len(line) >= 4 && line[3] == ' ' {
			var code int
			fmt.Sscanf(line[:3], "%d", &code)
			return code, text.String()
		}
	}
}

func (c *client) expect(code int) string {
	c.t.Helper()
	got, text := c.reply()
	if got != code {
		c.t.Fatalf("expected %d, got %d %q", code, got, text)
	}
	return text
}

func (c *client) send(s string) {
	c.t.Helper()
	if _, err := c.c.Write([]byte(s)); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) cmd(line string, code int) string {
	c.t.Helper()
	c.send(line + "\r\n")
	return c.expect(code)
}

func (c *client) begin(rcpt string) {
	c.t.Helper()
	c.cmd("EHLO client.example", 250)
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.cmd("RCPT TO:<"+rcpt+">", 250)
	c.cmd("DATA", 354)
}

func TestSendMailWithNetSMTP(t *testing.T) {
	b := newFake("info@x.example", "alias@x.example")
	_, addr := startServer(t, Config{Hostname: "mx.test"}, b)
	body := "Subject: hi\r\n\r\nline one\r\n.\r\n..two dots\r\n.dot first\r\nlast"
	if err := smtp.SendMail(addr, nil, "s@x.example", []string{"info@x.example", "alias@x.example"}, []byte(body)); err != nil {
		t.Fatal(err)
	}
	msgs := b.messages()
	if len(msgs) != 1 {
		t.Fatalf("%d messages", len(msgs))
	}
	m := string(msgs[0])
	if !strings.HasPrefix(m, "Received: from localhost ([127.0.0.1])\r\n\tby mx.test") {
		t.Fatalf("Received header missing: %q", m[:60])
	}
	_, content, _ := strings.Cut(m, "\r\n\r\n")
	_, content, _ = strings.Cut(m[strings.Index(m, "Subject"):], "\r\n\r\n")
	want := "line one\r\n.\r\n..two dots\r\n.dot first\r\nlast\r\n"
	if content != want {
		t.Fatalf("content %q, want %q", content, want)
	}
}

func TestProtocolErrors(t *testing.T) {
	b := newFake("info@x.example")
	_, addr := startServer(t, Config{}, b)
	c := dial(t, addr)
	c.cmd("MAIL FROM:<s@x.example>", 503) // before HELO
	c.cmd("RCPT TO:<info@x.example>", 503)
	c.cmd("DATA", 503)
	c.cmd("EHLO", 501)
	text := c.cmd("EHLO me.example", 250)
	if !strings.Contains(text, "SIZE 25000000") {
		t.Fatalf("EHLO does not advertise SIZE: %q", text)
	}
	c.cmd("HELO me.example", 250)
	c.cmd("DATA", 503) // DATA before RCPT TO
	c.cmd("RCPT TO:<info@x.example>", 503)
	c.cmd("MAIL FROM:s@x.example", 501)
	c.cmd("MAIL FROM:<s@x.example> SIZE=25000001", 552)
	c.cmd("MAIL FROM:<s@x.example> SIZE=x", 501)
	c.cmd("MAIL FROM:<s@x.example> FOO=1", 555)
	c.cmd("MAIL FROM:<s@x.example> BODY=BINARY", 501)
	c.cmd("MAIL FROM:<s@x.example> SIZE=100 BODY=8BITMIME", 250)
	c.cmd("MAIL FROM:<s@x.example>", 503) // nested
	c.cmd("DATA", 503)                    // still no RCPT
	c.cmd("RCPT TO:<unknown@x.example>", 550)
	c.cmd("RCPT TO:<temp@x.example>", 451)
	c.cmd("RCPT TO:<@route:info@x.example>", 501)
	c.cmd("RCPT TO:<>", 501)
	c.cmd("RCPT TO:<info@x.example> NOTIFY=NEVER", 501)
	c.cmd("RCPT TO:<info@x.example>", 250)
	c.cmd("DATA now", 501)
	c.cmd("RSET x", 501)
	c.cmd("RSET", 250)
	c.cmd("DATA", 503) // RSET dropped the transaction
	c.cmd("NOOP", 250)
	c.cmd("VRFY info", 502)
	c.cmd("STARTTLS", 502)
	c.cmd("FOO", 500)
	c.cmd("MAIL FROM:<>", 250) // null reverse path
	c.cmd("QUIT", 221)
}

func TestTooManyRecipients(t *testing.T) {
	b := newFake("info@x.example")
	_, addr := startServer(t, Config{}, b)
	c := dial(t, addr)
	c.cmd("EHLO me", 250)
	c.cmd("MAIL FROM:<s@x.example>", 250)
	for i := 0; i < 100; i++ {
		c.cmd("RCPT TO:<info@x.example>", 250)
	}
	c.cmd("RCPT TO:<info@x.example>", 452)
	c.cmd("DATA", 354)
	c.send("x\r\n.\r\n")
	c.expect(250)
}

func TestLongLinesAndCRLF(t *testing.T) {
	b := newFake("info@x.example")
	_, addr := startServer(t, Config{}, b)
	c := dial(t, addr)
	// Command lines: 1,000 octets including CRLF are fine, 1,001 are not.
	c.cmd("NOOP "+strings.Repeat("a", MaxLineLen-7), 250)
	c.cmd("NOOP "+strings.Repeat("a", MaxLineLen-6), 500)
	c.cmd("NOOP "+strings.Repeat("a", 10000), 500)
	c.send("NOOP\n")
	c.expect(500)
	c.send("NO\rOP\r\n")
	c.expect(500)
	c.cmd("NOOP", 250)

	// Data: a line over the limit rejects the message after the dot.
	c.begin("info@x.example")
	c.send("ok\r\n" + strings.Repeat("b", MaxLineLen) + "\r\nmore\r\n.\r\n")
	c.expect(554)
	// A line of exactly 1,000 octets is accepted.
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.cmd("RCPT TO:<info@x.example>", 250)
	c.cmd("DATA", 354)
	c.send(strings.Repeat("c", MaxLineLen-2) + "\r\n.\r\n")
	c.expect(250)
	// A bare LF never ends the data and rejects the message.
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.cmd("RCPT TO:<info@x.example>", 250)
	c.cmd("DATA", 354)
	c.send("a\r\n.\nsmuggled\r\nb\r\n.\r\n")
	c.expect(554)
	// A bare CR inside a line likewise.
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.cmd("RCPT TO:<info@x.example>", 250)
	c.cmd("DATA", 354)
	c.send("a\rb\r\n.\r\n")
	c.expect(554)
	c.cmd("QUIT", 221)
	msgs := b.messages()
	if len(msgs) != 1 || !bytes.HasSuffix(msgs[0], []byte(strings.Repeat("c", MaxLineLen-2)+"\r\n")) {
		t.Fatalf("delivered %d messages", len(msgs))
	}
	if b.aborted != 3 {
		t.Fatalf("aborted %d deliveries, want 3", b.aborted)
	}
}

func TestDotUnstuffing(t *testing.T) {
	b := newFake("info@x.example")
	_, addr := startServer(t, Config{}, b)
	c := dial(t, addr)
	c.begin("info@x.example")
	c.send("..\r\n...\r\n.a\r\n\r\n.\r\n")
	c.expect(250)
	m := string(b.messages()[0])
	_, body, _ := strings.Cut(m, "\r\n\t"+time.Now().UTC().Format("Mon"))
	if !strings.HasSuffix(m, "\r\n.\r\n..\r\na\r\n\r\n") {
		t.Fatalf("unstuffed content wrong: %q", body)
	}
}

func TestSizeLimitDuringData(t *testing.T) {
	b := newFake("info@x.example")
	_, addr := startServer(t, Config{MaxSize: 100}, b)
	c := dial(t, addr)
	c.begin("info@x.example")
	for i := 0; i < 10; i++ {
		c.send(strings.Repeat("x", 30) + "\r\n")
	}
	c.send(".\r\n")
	c.expect(552)
	c.cmd("NOOP", 250)
	if len(b.messages()) != 0 || b.aborted != 1 {
		t.Fatal("oversized message delivered")
	}
}

func TestDiskFullAndBackendErrors(t *testing.T) {
	b := newFake("info@x.example")
	_, addr := startServer(t, Config{}, b)
	c := dial(t, addr)
	c.cmd("EHLO me", 250)
	b.mu.Lock()
	b.accepting = ErrDiskFull
	b.mu.Unlock()
	c.cmd("MAIL FROM:<s@x.example>", 452)
	b.mu.Lock()
	b.accepting = errors.New("other")
	b.mu.Unlock()
	c.cmd("MAIL FROM:<s@x.example>", 451)
	b.mu.Lock()
	b.accepting = nil
	b.mu.Unlock()
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.cmd("RCPT TO:<info@x.example>", 250)
	// The disk fills up between RCPT and DATA.
	b.mu.Lock()
	b.accepting = ErrDiskFull
	b.mu.Unlock()
	c.cmd("DATA", 452)
	b.mu.Lock()
	b.accepting = errors.New("other")
	b.mu.Unlock()
	c.cmd("MAIL FROM:<s@x.example>", 451)
	b.mu.Lock()
	b.accepting = nil
	b.beginErr = ErrDiskFull
	b.mu.Unlock()
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.cmd("RCPT TO:<info@x.example>", 250)
	c.cmd("DATA", 452)
	b.mu.Lock()
	b.beginErr = errors.New("x")
	b.mu.Unlock()
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.cmd("RCPT TO:<info@x.example>", 250)
	c.cmd("DATA", 451)
	b.mu.Lock()
	b.beginErr = nil
	b.commitErr = ErrDiskFull
	b.mu.Unlock()
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.cmd("RCPT TO:<info@x.example>", 250)
	c.cmd("DATA", 354)
	c.send("x\r\n.\r\n")
	c.expect(452)
	b.mu.Lock()
	b.commitErr = errors.New("x")
	b.mu.Unlock()
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.cmd("RCPT TO:<info@x.example>", 250)
	c.cmd("DATA", 354)
	c.send("x\r\n.\r\n")
	c.expect(451)
	b.mu.Lock()
	b.commitErr = nil
	b.writeErr = ErrDiskFull
	b.mu.Unlock()
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.cmd("RCPT TO:<info@x.example>", 250)
	c.cmd("DATA", 354)
	c.send("x\r\ny\r\n.\r\n")
	c.expect(452)
	b.mu.Lock()
	b.writeErr = errors.New("x")
	b.mu.Unlock()
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.cmd("RCPT TO:<info@x.example>", 250)
	c.cmd("DATA", 354)
	c.send("x\r\ny\r\n.\r\n")
	c.expect(451)
	if len(b.messages()) != 0 {
		t.Fatal("message accepted despite errors")
	}
}

func TestSlowSenderIsDisconnected(t *testing.T) {
	b := newFake("info@x.example")
	// 1,000 bytes per second over a 300 ms window: 300 bytes per window.
	_, addr := startServer(t, Config{RateWindow: 300 * time.Millisecond}, b)
	c := dial(t, addr)
	c.begin("info@x.example")
	start := time.Now()
	stop := make(chan struct{})
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := c.c.Write([]byte("ab\r\n")); err != nil {
				return
			}
		}
	}()
	code, _ := c.reply()
	close(stop)
	if code != 421 {
		t.Fatalf("slow sender got %d", code)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("disconnect took %v", d)
	}
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Fatal("connection still open")
	}
	if len(b.messages()) != 0 || b.aborted != 1 {
		t.Fatal("slow message delivered")
	}
	// A stalled sender is disconnected at the end of the window.
	c2 := dial(t, addr)
	c2.begin("info@x.example")
	if code, _ := c2.reply(); code != 421 {
		t.Fatalf("stalled sender got %d", code)
	}
}

func TestFastSenderWithPauseIsKept(t *testing.T) {
	b := newFake("info@x.example")
	_, addr := startServer(t, Config{RateWindow: 200 * time.Millisecond}, b)
	c := dial(t, addr)
	c.begin("info@x.example")
	// Enough for two windows at once, then a pause shorter than a window.
	for i := 0; i < 8; i++ {
		c.send(strings.Repeat("z", 98) + "\r\n")
	}
	time.Sleep(250 * time.Millisecond)
	c.send(strings.Repeat("y", 498) + "\r\n.\r\n")
	c.expect(250)
}

func TestTimeouts(t *testing.T) {
	b := newFake("info@x.example")
	_, addr := startServer(t, Config{CommandTimeout: 150 * time.Millisecond}, b)
	c := dial(t, addr)
	if code, _ := c.reply(); code != 421 {
		t.Fatalf("command timeout: %d", code)
	}
	_, addr2 := startServer(t, Config{DataTimeout: 300 * time.Millisecond, MinRate: 1}, b)
	c2 := dial(t, addr2)
	c2.begin("info@x.example")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 40; i++ {
			time.Sleep(20 * time.Millisecond)
			if _, err := c2.c.Write([]byte("line\r\n")); err != nil {
				return
			}
		}
	}()
	if code, _ := c2.reply(); code != 421 {
		t.Fatalf("data timeout: %d", code)
	}
	<-done
}

func TestConnectionLimits(t *testing.T) {
	b := newFake("info@x.example")
	_, addr := startServer(t, Config{MaxConns: 3, MaxConnsPerIP: 2}, b)
	c1 := dial(t, addr)
	dial(t, addr)
	// Third connection from the same IP.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	line, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.HasPrefix(line, "421") {
		t.Fatalf("per-IP limit: %q", line)
	}
	// After one closes, a new connection is accepted.
	c1.cmd("QUIT", 221)
	deadline := time.Now().Add(2 * time.Second)
	for {
		c3, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		line, _ := bufio.NewReader(c3).ReadString('\n')
		c3.Close()
		if strings.HasPrefix(line, "220") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot not released")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The global limit, independent of the IP: use a server with a
	// per-IP limit above the total.
	_, addr2 := startServer(t, Config{MaxConns: 2, MaxConnsPerIP: 5}, b)
	dial(t, addr2)
	dial(t, addr2)
	c4, _ := net.Dial("tcp", addr2)
	defer c4.Close()
	line, _ = bufio.NewReader(c4).ReadString('\n')
	if !strings.HasPrefix(line, "421") {
		t.Fatalf("global limit: %q", line)
	}
}

func TestHourlyLimit(t *testing.T) {
	b := newFake("info@x.example")
	now := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s := NewServer(Config{MaxMailsPerIP: 2, Now: clock, CommandTimeout: time.Hour, DataTimeout: time.Hour, RateWindow: time.Hour, MinRate: 1}, b)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go s.Serve(ln)
	defer s.Close()
	c := dial(t, ln.Addr().String())
	c.cmd("EHLO me", 250)
	for i := 0; i < 2; i++ {
		c.cmd("MAIL FROM:<s@x.example>", 250)
		c.cmd("RCPT TO:<info@x.example>", 250)
		c.cmd("DATA", 354)
		c.send("x\r\n.\r\n")
		c.expect(250)
	}
	c.cmd("MAIL FROM:<s@x.example>", 451)
	mu.Lock()
	now = now.Add(time.Hour)
	mu.Unlock()
	c.cmd("MAIL FROM:<s@x.example>", 250)
}

func TestLimiterMemory(t *testing.T) {
	l := newLimiter(2, 2)
	now := time.Unix(0, 0)
	l.record("a", now)
	l.record("b", now)
	if l.allow("c", now) {
		t.Fatal("table full: new address must be refused")
	}
	if !l.allow("a", now) {
		t.Fatal("known address")
	}
	l.record("a", now)
	l.record("a", now) // over the limit, not stored
	if l.allow("a", now) {
		t.Fatal("limit")
	}
	if !l.allow("c", now.Add(time.Hour)) {
		t.Fatal("old entries must be forgotten")
	}
}

func TestBackendPanicIsContained(t *testing.T) {
	b := newFake("info@x.example")
	b.panicOnRcpt.Store(true)
	s, addr := startServer(t, Config{}, b)
	c := dial(t, addr)
	c.cmd("EHLO me", 250)
	c.cmd("MAIL FROM:<s@x.example>", 250)
	c.send("RCPT TO:<info@x.example>\r\n")
	if code, _ := c.reply(); code != 0 {
		t.Fatalf("expected closed connection, got %d", code)
	}
	b.panicOnRcpt.Store(false)
	c2 := dial(t, addr)
	c2.cmd("QUIT", 221)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Serve(nil); !errors.Is(err, ErrClosed) {
		t.Fatal("Serve after Close")
	}
}

func TestSanitizeHelo(t *testing.T) {
	if got := sanitizeHelo("a(b)\x01ä"); got != "a?b???" && got != "a?b????" {
		t.Fatalf("%q", got)
	}
}

func TestRefusalsAreBounded(t *testing.T) {
	b := newFake("info@x.example")
	s, addr := startServer(t, Config{MaxConns: 1, MaxConnsPerIP: 1}, b)
	dial(t, addr)
	var conns []net.Conn
	for i := 0; i < maxRefusing*3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		if line != "" && !strings.HasPrefix(line, "421") {
			t.Fatalf("refused connection got %q", line)
		}
		c.Close()
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
