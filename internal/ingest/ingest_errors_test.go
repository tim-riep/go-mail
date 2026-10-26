package ingest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

func TestServerChecksEpochs(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	in := newIngest(t, env)
	// Before epoch 1 began: no epoch.
	env.Clock.Set(testenv.Start.Add(-time.Hour))
	if _, err := in.Begin(smtpd.Session{}, "s", []string{"a@example.org"}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatal("mail before the first epoch")
	}
	env.Clock.Set(testenv.Start)
	// A forged epoch.rec (signature broken) is not used.
	path := env.Store.EpochFile(mbx, 1)
	orig, _ := os.ReadFile(path)
	bad := append([]byte(nil), orig...)
	bad[len(bad)-1] ^= 1
	os.WriteFile(path, bad, 0o600)
	if _, err := in.Begin(smtpd.Session{}, "s", []string{"a@example.org"}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatal("forged epoch used")
	}
	// An epoch signed by an unknown generation.
	e, _, _ := env.Store.ReadEpoch(mbx, 2)
	e.Number, e.PrevHash, e.Reason, e.SignerGen = 1, [32]byte{}, store.ReasonInitial, 7
	e.Begin = testenv.Start.Add(-time.Minute).UnixMilli()
	enc, _ := e.Encode()
	os.WriteFile(path, enc, 0o600)
	if _, err := in.Begin(smtpd.Session{}, "s", []string{"a@example.org"}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatal("epoch of an unknown generation used")
	}
	// An epoch whose signer has no user.rec.
	e.SignerID = store.ID{9}
	enc, _ = e.Encode()
	os.WriteFile(path, enc, 0o600)
	if _, err := in.Begin(smtpd.Session{}, "s", []string{"a@example.org"}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatal("epoch of an unknown user used")
	}
	// A missing epoch.
	os.Remove(path)
	if _, err := in.Begin(smtpd.Session{}, "s", []string{"a@example.org"}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatal("missing epoch")
	}
	os.WriteFile(path, orig, 0o600)
	if err := deliver(t, in, "s", []string{"a@example.org"}, message("ok", "x")); err != nil {
		t.Fatal(err)
	}
}

func TestMoveFailureIsUndone(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	in := newIngest(t, env)
	m, _ := env.Store.ReadMailbox(mbx)
	// mail/<inbox> is a file: the marker moves, the metadata cannot.
	store.MkdirAll(filepath.Join(env.Store.MailboxDir(mbx), "mail"))
	os.WriteFile(env.Store.MailDir(mbx, m.Inbox), []byte("x"), 0o600)
	if err := deliver(t, in, "s", []string{"a@example.org"}, message("x", "y")); err == nil {
		t.Fatal("delivery must fail")
	}
	_, _, pending := mailFiles(t, env, mbx)
	if len(pending) != 0 {
		t.Fatalf("marker not undone: %v", pending)
	}
	if f := files(t, env.Store.SpoolDir()); len(f) != 0 {
		t.Fatalf("spool: %v", f)
	}
	// pending/ is a file: the first move fails.
	os.Remove(env.Store.MailDir(mbx, m.Inbox))
	os.RemoveAll(filepath.Join(env.Store.MailboxDir(mbx), "pending"))
	os.WriteFile(filepath.Join(env.Store.MailboxDir(mbx), "pending"), []byte("x"), 0o600)
	if err := deliver(t, in, "s", []string{"a@example.org"}, message("x", "y")); err == nil {
		t.Fatal("delivery must fail")
	}
	mails, metas, _ := mailFiles(t, env, mbx)
	if len(mails)+len(metas) != 0 {
		t.Fatal("partial delivery")
	}
}

func TestSpillDamage(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	in := newIngest(t, env, func(c *Config) { c.QueueMemory = 1 })
	deliver(t, in, "s", []string{"a@example.org"}, message("x", "y"))
	deliver(t, in, "s", []string{"a@example.org"}, message("x", "y"))
	w := files(t, env.Store.WorkDir())
	if len(w) != 2 {
		t.Fatal(w)
	}
	// One spilled entry is damaged, one truncated to less than a nonce.
	p0 := filepath.Join(env.Store.WorkDir(), w[0])
	b, _ := os.ReadFile(p0)
	b[len(b)-1] ^= 1
	os.WriteFile(p0, b, 0o600)
	os.WriteFile(filepath.Join(env.Store.WorkDir(), w[1]), []byte("x"), 0o600)
	in.Flush()
	ids, _ := env.Store.ListPending(mbx, 1)
	if len(ids) != 2 {
		t.Fatal("both mails must keep their markers")
	}
	// Enqueue after close is ignored; start after close does nothing.
	in.Close()
	in.Close()
	in.queue.enqueue(job{header: []byte("x")})
	in.Start()
	if len(in.queue.jobs) != 0 {
		t.Fatal("enqueue after close")
	}
}

func TestRecoverCleansEverything(t *testing.T) {
	env := testenv.New(t)
	in := newIngest(t, env)
	os.WriteFile(filepath.Join(env.Store.SpoolDir(), "stray"), []byte("x"), 0o600)
	store.MkdirAll(filepath.Join(env.Store.SpoolDir(), "txn", "m"))
	os.WriteFile(filepath.Join(env.Store.SpoolDir(), "txn", "m", "mail.gml"), []byte("x"), 0o600)
	store.MkdirAll(filepath.Join(env.Store.WorkDir(), "d"))
	os.WriteFile(filepath.Join(env.Store.WorkDir(), "w.bin"), []byte("x"), 0o600)
	if err := in.Recover(); err != nil {
		t.Fatal(err)
	}
	if f := files(t, env.Store.SpoolDir()); len(f) != 0 {
		t.Fatal(f)
	}
	if e, _ := os.ReadDir(env.Store.WorkDir()); len(e) != 0 {
		t.Fatal("work not emptied")
	}
	os.RemoveAll(env.Store.SpoolDir())
	if err := in.Recover(); err == nil {
		t.Fatal("missing spool directory")
	}
}

func TestTerms(t *testing.T) {
	now := time.Date(2026, 10, 25, 23, 30, 0, 0, time.FixedZone("x", 2*3600))
	h := "From: =?UTF-8?Q?M=C3=BCller?= <Rechnung@Lieferant.DE>\r\nTo: undisclosed-recipients:;\r\nSubject: =?UTF-8?B?R3LDvMOfZQ==?=\r\nIn-Reply-To: <Parent@X>\r\nContent-Type: text/plain\r\n\r\n"
	terms, ok := Terms([]byte(h), now)
	if !ok {
		t.Fatal("not parsed")
	}
	got := strings.Join(terms, " ")
	want := "from:rechnung@lieferant.de fromdomain:lieferant.de day:2026-10-25 month:2026-10 thread:<parent@x>"
	if got != want {
		t.Fatalf("terms %q, want %q", got, want)
	}
	f, _ := parseHeader([]byte(h))
	if f.subject != "Grüße" || f.from != "Müller <Rechnung@Lieferant.DE>" {
		t.Fatalf("decoded fields %+v", f)
	}
	// Unknown charset: the raw value is kept.
	if d := decodeText("=?x-unknown?Q?abc?="); d != "=?x-unknown?Q?abc?=" {
		t.Fatal(d)
	}
	if firstMsgID("<abc") != "" || firstMsgID("none") != "" || firstMsgID("x <a@b> <c@d>") != "<a@b>" {
		t.Fatal("firstMsgID")
	}
	if _, ok := Terms(nil, now); ok {
		t.Fatal("empty header")
	}
	if _, ok := Terms([]byte("no colon line\r\n\r\n"), now); ok {
		t.Fatal("malformed header")
	}
	// Many recipients: the other terms are kept.
	var to []string
	for i := 0; i < 400; i++ {
		to = append(to, "u"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+"@d"+strings.Repeat("y", i/26)+".de")
	}
	terms, _ = Terms([]byte("From: a@b.c\r\nTo: "+strings.Join(to, ", ")+"\r\nMessage-Id: <m@x>\r\n\r\n"), now)
	if len(terms) != store.MaxTerms || !strings.Contains(strings.Join(terms, " "), "thread:<m@x>") {
		t.Fatalf("%d terms", len(terms))
	}
}
