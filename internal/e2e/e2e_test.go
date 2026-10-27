package e2e

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// syncBuffer is a log sink shared by goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

type server struct {
	env  *testenv.Env
	in   *ingest.Ingest
	srv  *smtpd.Server
	addr string
	logs *syncBuffer
	free *uint64
}

func startServer(t *testing.T, env *testenv.Env, mod ...func(*ingest.Config)) *server {
	t.Helper()
	return startServerWorker(t, env, true, mod...)
}

// startServerWorker starts the server; with worker false the
// preprocessing runs only on Flush.
func startServerWorker(t *testing.T, env *testenv.Env, worker bool, mod ...func(*ingest.Config)) *server {
	t.Helper()
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	free := uint64(50)
	s := &server{env: env, logs: logs, free: &free}
	cfg := ingest.Config{Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1, Now: env.Clock.Now, Logger: logger,
		DiskSpace: func(string) (uint64, uint64, error) { return free, 100, nil }}
	for _, m := range mod {
		m(&cfg)
	}
	in, err := ingest.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Recover(); err != nil {
		t.Fatal(err)
	}
	if worker {
		in.Start()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.in = in
	s.srv = smtpd.NewServer(smtpd.Config{Hostname: "mx.test", Logger: logger}, in)
	s.addr = ln.Addr().String()
	go s.srv.Serve(ln)
	t.Cleanup(func() {
		s.srv.Close()
		in.Close()
	})
	return s
}

func send(s *server, from string, to []string, msg string) error {
	return smtp.SendMail(s.addr, nil, from, to, []byte(msg))
}

func smtpCode(err error) int {
	var te *textproto.Error
	if errors.As(err, &te) {
		return te.Code
	}
	return 0
}

// stripReceived removes the Received header the server added.
func stripReceived(t *testing.T, content []byte) []byte {
	t.Helper()
	if !bytes.HasPrefix(content, []byte("Received: ")) {
		t.Fatalf("no Received header: %q", content[:min(len(content), 40)])
	}
	// The header is three lines: the folded continuation lines start with
	// a tab.
	rest := content
	for i := 0; ; i++ {
		j := bytes.Index(rest, []byte("\r\n"))
		rest = rest[j+2:]
		if len(rest) == 0 || rest[0] != '\t' {
			break
		}
	}
	return rest
}

func TestRegisterCreateSendListRead(t *testing.T) {
	env := testenv.NewLogged(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "Büro", "info@brownbear.example")
	s := startServer(t, env)
	msg := "From: Lieferant <rechnung@lieferant.example>\r\nTo: info@brownbear.example\r\nSubject: Rechnung 4711\r\n" +
		"Message-ID: <r4711@lieferant.example>\r\n\r\nSehr geehrte Damen und Herren,\r\n.\r\nanbei die Rechnung.\r\n..\r\n"
	if err := send(s, "rechnung@lieferant.example", []string{"info@brownbear.example"}, msg); err != nil {
		t.Fatal(err)
	}
	list, err := u.Client.List(mbx, store.ID{})
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", err, env.Warnings.Take())
	}
	if list[0].Meta.Subject != "Rechnung 4711" || list[0].Meta.EnvelopeFrom != "rechnung@lieferant.example" {
		t.Fatalf("metadata %+v", list[0].Meta)
	}
	_, content, err := u.Client.Read(mbx, list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := stripReceived(t, content); !bytes.Equal(got, []byte(msg)) {
		t.Fatalf("content differs:\n%q\n%q", got, msg)
	}
	if w := env.Warnings.Take(); len(w) != 0 { // no warning at all: the client runs with its log (task 14)
		t.Fatalf("unexpected warnings: %q", w)
	}
}

func TestCopies(t *testing.T) {
	env := testenv.NewLogged(t)
	a := env.NewUser("alice")
	b := env.NewUser("bob")
	mbxA := env.Mailbox(a, "A", "info@a.example", "alias@a.example")
	mbxB := env.Mailbox(b, "B", "bob@b.example")
	s := startServer(t, env)
	msg := "Subject: two addresses\r\n\r\nx\r\n"
	if err := send(s, "s@x.example", []string{"info@a.example", "alias@a.example"}, msg); err != nil {
		t.Fatal(err)
	}
	if l, _ := a.Client.List(mbxA, store.ID{}); len(l) != 1 {
		t.Fatalf("two addresses of one mailbox: %d copies", len(l))
	}
	if err := send(s, "s@x.example", []string{"info@a.example", "bob@b.example"}, "Subject: two mailboxes\r\n\r\ny\r\n"); err != nil {
		t.Fatal(err)
	}
	la, _ := a.Client.List(mbxA, store.ID{})
	lb, _ := b.Client.List(mbxB, store.ID{})
	if len(la) != 2 || len(lb) != 1 {
		t.Fatalf("copies %d %d", len(la), len(lb))
	}
	var idA store.ID
	for _, m := range la {
		if m.Meta.Subject == "two mailboxes" {
			idA = m.ID
		}
	}
	if idA == lb[0].ID {
		t.Fatal("copies share an ID")
	}
	_, ca, _ := a.Client.Read(mbxA, idA)
	_, cb, _ := b.Client.Read(mbxB, lb[0].ID)
	if !bytes.Equal(ca, cb) {
		t.Fatal("copies differ in content")
	}
	// The files are independent: different file keys and nonces.
	fa, _ := os.ReadFile(env.Store.MailFile(mbxA, la[0].Meta.Folder, idA))
	fb, _ := os.ReadFile(env.Store.MailFile(mbxB, lb[0].Meta.Folder, lb[0].ID))
	if bytes.Equal(fa[len(fa)-64:], fb[len(fb)-64:]) {
		t.Fatal("copies encrypted alike")
	}
}

func TestUnknownRecipient550(t *testing.T) {
	env := testenv.NewLogged(t)
	u := env.NewUser("alice")
	env.Mailbox(u, "A", "info@a.example")
	s := startServer(t, env)
	err := send(s, "s@x.example", []string{"nobody@a.example"}, "Subject: x\r\n\r\ny\r\n")
	if smtpCode(err) != 550 || !strings.Contains(err.Error(), "5.1.1") {
		t.Fatalf("unknown recipient: %v", err)
	}
}

func TestDiskFull452(t *testing.T) {
	env := testenv.NewLogged(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@a.example")
	s := startServer(t, env)
	*s.free = 5
	err := send(s, "s@x.example", []string{"info@a.example"}, "Subject: x\r\n\r\ny\r\n")
	if smtpCode(err) != 452 || !strings.Contains(err.Error(), "4.3.1") {
		t.Fatalf("full disk: %v", err)
	}
	if l, _ := u.Client.List(mbx, store.ID{}); len(l) != 0 {
		t.Fatal("mail accepted on a full disk")
	}
}

// rawSession speaks SMTP by hand so that the clock can move in the
// middle of DATA.
type rawSession struct {
	t *testing.T
	c net.Conn
	r *bufio.Reader
}

func dial(t *testing.T, addr string) *rawSession {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s := &rawSession{t: t, c: c, r: bufio.NewReader(c)}
	s.expect("220")
	return s
}

func (s *rawSession) expect(code string) {
	s.t.Helper()
	for {
		line, err := s.r.ReadString('\n')
		if err != nil {
			s.t.Fatal(err)
		}
		if !strings.HasPrefix(line, code) {
			s.t.Fatalf("expected %s, got %q", code, line)
		}
		if line[3] == ' ' {
			return
		}
	}
}

func (s *rawSession) cmd(line, code string) {
	s.t.Helper()
	fmt.Fprintf(s.c, "%s\r\n", line)
	s.expect(code)
}

func TestEpochChangeDuringReceipt(t *testing.T) {
	env := testenv.NewLogged(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@a.example")
	s := startServer(t, env)
	env.Clock.Set(time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC))
	r := dial(t, s.addr)
	r.cmd("EHLO c.example", "250")
	r.cmd("MAIL FROM:<s@x.example>", "250")
	r.cmd("RCPT TO:<info@a.example>", "250")
	r.cmd("DATA", "354")
	fmt.Fprint(r.c, "Subject: during\r\n\r\nfirst half\r\n")
	time.Sleep(50 * time.Millisecond)
	// Midnight passes while the mail is being received: epoch 2 begins.
	env.Clock.Set(time.Date(2026, 11, 1, 0, 0, 1, 0, time.UTC))
	fmt.Fprint(r.c, "second half\r\n.\r\n")
	r.expect("250")
	if err := send(s, "s@x.example", []string{"info@a.example"}, "Subject: after\r\n\r\nx\r\n"); err != nil {
		t.Fatal(err)
	}
	list, err := u.Client.List(mbx, store.ID{})
	if err != nil || len(list) != 2 {
		t.Fatalf("%v %v", err, env.Warnings.Take())
	}
	epochs := map[string]uint32{}
	for _, m := range list {
		epochs[m.Meta.Subject] = m.Epoch
		if _, _, err := u.Client.Read(mbx, m.ID); err != nil {
			t.Fatal(err)
		}
	}
	if epochs["during"] != 1 || epochs["after"] != 2 {
		t.Fatalf("epochs %v", epochs)
	}
}

func TestSupplyEmptyAtMonthChange(t *testing.T) {
	env := testenv.NewLogged(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@a.example")
	s := startServer(t, env)
	// Nobody logs in for five months: the supply ends with January.
	env.Clock.Set(time.Date(2027, 3, 1, 8, 0, 0, 0, time.UTC))
	if err := send(s, "s@x.example", []string{"info@a.example"}, "Subject: march\r\n\r\nx\r\n"); err != nil {
		t.Fatal(err)
	}
	note, _ := env.Store.ReadNote(mbx)
	if note == nil || note.Epoch != 4 || note.Count != 1 {
		t.Fatalf("server must note the fallback: %+v", note)
	}
	if !bytes.Contains(s.logs.Bytes(), []byte("ingest used the last epoch past its month")) {
		t.Fatal("fallback not logged")
	}
	list, err := u.Client.List(mbx, store.ID{})
	if err != nil || len(list) != 1 || list[0].Epoch != 4 {
		t.Fatalf("fallback mail: %v %v", err, env.Warnings.Take())
	}
	if err := u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	if n, _ := env.Store.ReadNote(mbx); n != nil {
		t.Fatal("note not cleared")
	}
}

// TestNoPlaintext sends a mail with a unique marker in header and body
// and searches the data directory (including spool/ and work/), the
// client directory and every log line for it. The preprocessing queue is
// forced to spill to work/ first.
func TestNoPlaintext(t *testing.T) {
	env := testenv.NewLogged(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@a.example")
	s := startServerWorker(t, env, false, func(c *ingest.Config) { c.QueueMemory = 1; c.BatchAge = time.Hour })
	marker := "XQZMARKER-8c1f7e2a"
	msg := "From: " + marker + " <" + strings.ToLower(marker) + "@sender.example>\r\nTo: info@a.example\r\nSubject: " + marker +
		"\r\nX-Marker: " + marker + "\r\nMessage-ID: <" + marker + "@sender.example>\r\n\r\nbody " + marker + "\r\n"
	search := func(stage string) {
		t.Helper()
		needles := [][]byte{[]byte(marker), []byte(strings.ToLower(marker))}
		check := func(where string, data []byte) {
			for _, n := range needles {
				if bytes.Contains(data, n) {
					t.Fatalf("%s: marker found in %s", stage, where)
				}
			}
		}
		for _, root := range []string{env.Base} {
			filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
				if err == nil && fi.Mode().IsRegular() {
					b, _ := os.ReadFile(p)
					check(p, b)
				}
				return nil
			})
		}
		check("server log", s.logs.Bytes())
		for _, w := range env.Warnings.Take() {
			check("client warning", []byte(w))
		}
	}
	if err := send(s, "Sender@sender.example", []string{"info@a.example"}, msg); err != nil {
		t.Fatal(err)
	}
	// The header waits encrypted in work/.
	if e, _ := os.ReadDir(env.Store.WorkDir()); len(e) != 1 {
		t.Fatalf("work/ holds %d entries", len(e))
	}
	search("after receipt")
	if err := s.in.Flush(); err != nil {
		t.Fatal(err)
	}
	search("after preprocessing")
	// The client reads it (in memory only) and the state file stays clean.
	list, _ := u.Client.List(mbx, store.ID{})
	_, content, err := u.Client.Read(mbx, list[0].ID)
	if err != nil || !bytes.Contains(content, []byte(marker)) {
		t.Fatal("mail not readable")
	}
	ids, _ := env.Store.ListPending(mbx, 1)
	p, _ := u.Client.OpenPending(mbx, 1, ids[0])
	if !strings.Contains(strings.Join(p.Entries[0].Terms, " "), strings.ToLower(marker)) {
		t.Fatal("the term list must contain the sender (encrypted)")
	}
	search("after reading")
	// Aborted receipt (size limit) leaves no trace either.
	big := msg + strings.Repeat(marker+"\r\n", 1000)
	// The same backend behind a second SMTP server with a small size
	// limit: a second backend cannot start while s holds the server lock
	// (9.1).
	srv := smtpd.NewServer(smtpd.Config{MaxSize: 2000, Logger: slog.New(slog.NewTextHandler(s.logs, nil))}, s.in)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(ln)
	defer srv.Close()
	if err := smtp.SendMail(ln.Addr().String(), nil, "s@x.example", []string{"info@a.example"}, []byte(big)); smtpCode(err) != 552 {
		t.Fatalf("oversized: %v", err)
	}
	search("after an aborted receipt")
}
