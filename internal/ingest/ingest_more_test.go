package ingest

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// files lists every regular file below dir, relative, sorted.
func files(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			r, _ := filepath.Rel(dir, p)
			out = append(out, r)
		}
		return nil
	})
	return out
}

func mailFiles(t *testing.T, env *testenv.Env, mbx store.ID) (mails, metas, pending []string) {
	t.Helper()
	for _, f := range files(t, env.Store.MailboxDir(mbx)) {
		switch {
		case strings.HasPrefix(f, "mail/") && strings.HasSuffix(f, ".meta.gml"):
			metas = append(metas, f)
		case strings.HasPrefix(f, "mail/") && strings.HasSuffix(f, ".gml"):
			mails = append(mails, f)
		case strings.HasPrefix(f, "pending/"):
			pending = append(pending, f)
		}
	}
	return
}

func TestRecipientsAndCopies(t *testing.T) {
	env := testenv.New(t)
	a := env.NewUser("alice")
	b := env.NewUser("bob")
	mbxA := env.Mailbox(a, "A", "info@example.org", "alias@example.org")
	mbxB := env.Mailbox(b, "B", "bob@example.org")
	in := newIngest(t, env)
	if err := in.Recipient("nobody@example.org"); !errors.Is(err, smtpd.ErrUnknownRecipient) {
		t.Fatal("unknown recipient accepted")
	}
	if err := in.Recipient("not an address"); !errors.Is(err, smtpd.ErrUnknownRecipient) {
		t.Fatal("malformed recipient accepted")
	}
	if err := in.Recipient("INFO@Example.ORG"); err != nil {
		t.Fatal("address lookup must be case-insensitive")
	}
	// Two addresses of one mailbox: one copy.
	if err := deliver(t, in, "s@x.example", []string{"info@example.org", "alias@example.org", "INFO@example.org"}, message("one", "x")); err != nil {
		t.Fatal(err)
	}
	mails, metas, pend := mailFiles(t, env, mbxA)
	if len(mails) != 1 || len(metas) != 1 || len(pend) != 1 {
		t.Fatalf("one mailbox, two addresses: %v %v %v", mails, metas, pend)
	}
	list, _ := a.Client.List(mbxA, store.ID{})
	if len(list) != 1 || len(list[0].Meta.Recipients) != 2 {
		t.Fatalf("recipients in metadata: %+v", list[0].Meta.Recipients)
	}
	// Two mailboxes: two independent copies with their own IDs and keys.
	if err := deliver(t, in, "s@x.example", []string{"info@example.org", "bob@example.org"}, message("two", "y")); err != nil {
		t.Fatal(err)
	}
	mailsA, _, _ := mailFiles(t, env, mbxA)
	mailsB, _, _ := mailFiles(t, env, mbxB)
	if len(mailsA) != 2 || len(mailsB) != 1 {
		t.Fatalf("copies: %v %v", mailsA, mailsB)
	}
	la, _ := a.Client.List(mbxA, store.ID{})
	lb, _ := b.Client.List(mbxB, store.ID{})
	if len(la) != 2 || len(lb) != 1 {
		t.Fatal("copies")
	}
	two := la[0]
	if two.Meta.Subject != "two" {
		two = la[1]
	}
	if two.ID == lb[0].ID {
		t.Fatal("copies must have different mail IDs")
	}
	_, ca, err := a.Client.Read(mbxA, two.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, cb, err := b.Client.Read(mbxB, lb[0].ID)
	if err != nil || !bytes.Equal(ca, cb) {
		t.Fatalf("both copies must hold the same content: %v\n%q\n%q", err, ca, cb)
	}
	da, _ := env.Store.ReadMail(mbxA, two.Meta.Folder, two.ID)
	db, _ := env.Store.ReadMail(mbxB, lb[0].Meta.Folder, lb[0].ID)
	if bytes.Equal(da[:200], db[:200]) {
		t.Fatal("copies must be encrypted independently")
	}
	// Alice cannot read Bob's mailbox.
	if _, _, err := a.Client.Read(mbxB, lb[0].ID); err == nil {
		t.Fatal("foreign mailbox readable")
	}
}

func TestEpochChoiceAndChange(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	in := newIngest(t, env)
	// Epoch 1 now; the supply holds epochs 2-4 for the next months.
	m, _ := env.Store.ReadMailbox(mbx)
	if m.Epoch != 4 {
		t.Fatalf("head %d, want 4 (epoch 1 and three months of supply)", m.Epoch)
	}
	deliver(t, in, "s@x", []string{"info@example.org"}, message("oct", "1"))
	// Next month: epoch 2.
	env.Clock.Set(time.Date(2026, 11, 1, 0, 0, 1, 0, time.UTC))
	deliver(t, in, "s@x", []string{"info@example.org"}, message("nov", "2"))
	// The epoch changes while a mail is being received: it stays in the
	// epoch chosen at DATA and is valid.
	env.Clock.Set(time.Date(2026, 11, 30, 23, 59, 59, 0, time.UTC))
	d, err := in.Begin(smtpd.Session{ID: "x"}, "s@x", []string{"info@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	d.Write([]byte(message("during change", "3")))
	env.Clock.Set(time.Date(2026, 12, 1, 0, 0, 5, 0, time.UTC))
	d.Write([]byte("more\r\n"))
	if err := d.Commit(); err != nil {
		t.Fatal(err)
	}
	deliver(t, in, "s@x", []string{"info@example.org"}, message("dec", "4"))
	list, err := u.Client.List(mbx, store.ID{})
	if err != nil || len(list) != 4 {
		t.Fatalf("%d mails, %v %v", len(list), err, env.Warnings.Take())
	}
	want := map[string]uint32{"oct": 1, "nov": 2, "during change": 2, "dec": 3}
	for _, m := range list {
		if want[m.Meta.Subject] != m.Epoch {
			t.Fatalf("%q in epoch %d, want %d", m.Meta.Subject, m.Epoch, want[m.Meta.Subject])
		}
		if _, _, err := u.Client.Read(mbx, m.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSupplyEmptyFallback(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	in := newIngest(t, env)
	// Five months later nobody logged in: the supply (epoch 4, January)
	// ran out; the server keeps using epoch 4 and notes it.
	env.Clock.Set(time.Date(2027, 3, 15, 12, 0, 0, 0, time.UTC))
	if err := deliver(t, in, "s@x", []string{"info@example.org"}, message("late", "1")); err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(time.Minute)
	deliver(t, in, "s@x", []string{"info@example.org"}, message("late2", "2"))
	note, err := env.Store.ReadNote(mbx)
	if err != nil || note == nil || note.Epoch != 4 || note.Count != 2 {
		t.Fatalf("note %+v %v", note, err)
	}
	list, _ := u.Client.List(mbx, store.ID{})
	if len(list) != 2 || list[0].Epoch != 4 {
		t.Fatalf("fallback mails must be valid: %d %v", len(list), env.Warnings.Take())
	}
	// The next client creates an epoch with immediate begin and the supply.
	c := env.Reopen(u)
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if n, _ := env.Store.ReadNote(mbx); n != nil {
		t.Fatal("note must be removed after the new epoch")
	}
	e5, _, err := env.Store.ReadEpoch(mbx, 5)
	if err != nil || e5.Reason != store.ReasonRegular || e5.Begin != env.Clock.Now().Add(client.ImmediateDelay).UnixMilli() {
		t.Fatalf("immediate epoch %+v %v", e5, err)
	}
	m, _ := env.Store.ReadMailbox(mbx)
	if m.Epoch != 8 {
		t.Fatalf("head %d, want 8", m.Epoch)
	}
	// Within the delay the server still uses epoch 4; afterwards 5.
	deliver(t, in, "s@x", []string{"info@example.org"}, message("before", "3"))
	env.Clock.Advance(client.ImmediateDelay)
	deliver(t, in, "s@x", []string{"info@example.org"}, message("after", "4"))
	list, err = c.List(mbx, store.ID{})
	if err != nil || len(list) != 4 {
		t.Fatalf("%d mails %v %v", len(list), err, env.Warnings.Take())
	}
	if list[2].Epoch != 4 || list[3].Epoch != 5 {
		t.Fatalf("epochs %d %d", list[2].Epoch, list[3].Epoch)
	}
	// A second Sync in the same month changes nothing.
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if m, _ := env.Store.ReadMailbox(mbx); m.Epoch != 8 {
		t.Fatal("second sync must not add epochs")
	}
}

func TestPreprocessingAndSpill(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	in := newIngest(t, env, func(c *Config) { c.QueueMemory = 1 })
	marker := "UNIQUEMARKER7731"
	msg := "From: " + marker + " <rechnung@lieferant.de>\r\nTo: info@example.org, b@c.de\r\nCc: x@y.de\r\nSubject: " + marker +
		"\r\nMessage-ID: <root@x>\r\nReferences: <first@x> <second@x>\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\nbody\r\n"
	if err := deliver(t, in, "s@x", []string{"info@example.org"}, msg); err != nil {
		t.Fatal(err)
	}
	// The header was spilled to work/, encrypted with the ephemeral key.
	work := files(t, env.Store.WorkDir())
	if len(work) != 1 {
		t.Fatalf("work: %v", work)
	}
	wb, _ := os.ReadFile(filepath.Join(env.Store.WorkDir(), work[0]))
	if bytes.Contains(wb, []byte(marker)) || bytes.Contains(wb, []byte("lieferant")) {
		t.Fatal("plaintext in work/")
	}
	if err := in.Flush(); err != nil {
		t.Fatal(err)
	}
	if w := files(t, env.Store.WorkDir()); len(w) != 0 {
		t.Fatalf("work not emptied: %v", w)
	}
	ids, _ := env.Store.ListPending(mbx, 1)
	if len(ids) != 1 {
		t.Fatalf("pending: %v", ids)
	}
	list, _ := u.Client.List(mbx, store.ID{})
	if ids[0] == list[0].ID {
		t.Fatal("the marker must be replaced by the term list")
	}
	p, err := u.Client.OpenPending(mbx, 1, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 1 || p.Entries[0].MailID != list[0].ID || p.Entries[0].Unprocessed {
		t.Fatalf("term list %+v", p)
	}
	got := strings.Join(p.Entries[0].Terms, " ")
	for _, want := range []string{"from:rechnung@lieferant.de", "fromdomain:lieferant.de", "to:info@example.org", "to:b@c.de", "to:x@y.de", "day:2026-10-26", "month:2026-10", "has:attachment", "thread:<first@x>"} {
		if !strings.Contains(got, want) {
			t.Fatalf("term %q missing in %q", want, got)
		}
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkLimitKeepsMarker(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	in := newIngest(t, env, func(c *Config) { c.QueueMemory = 1; c.WorkLimit = 1 })
	deliver(t, in, "s@x", []string{"info@example.org"}, message("x", "y"))
	in.Flush()
	ids, _ := env.Store.ListPending(mbx, 1)
	list, _ := u.Client.List(mbx, store.ID{})
	if len(ids) != 1 || ids[0] != list[0].ID {
		t.Fatal("without room the mail must keep its unprocessed marker")
	}
	p, err := u.Client.OpenPending(mbx, 1, ids[0])
	if err != nil || !p.Entries[0].Unprocessed {
		t.Fatal("marker")
	}
}

func TestBatching(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	in := newIngest(t, env, func(c *Config) { c.BatchSize = 3; c.BatchAge = time.Hour })
	in.Start()
	defer in.Close()
	for i := 0; i < 7; i++ {
		deliver(t, in, "s@x", []string{"info@example.org"}, message("m", "x"))
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ids, _ := env.Store.ListPending(mbx, 1)
		// Two full batches of three; one mail still has its marker.
		if len(ids) == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending: %d files", len(ids))
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Wait until the worker took every job, then pass the batch age: the
	// rest is written too.
	for {
		in.queue.mu.Lock()
		n := len(in.queue.jobs)
		in.queue.mu.Unlock()
		in.queue.procMu.Lock()
		in.queue.procMu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	env.Clock.Advance(2 * time.Hour)
	deadline = time.Now().Add(5 * time.Second)
	for {
		ids, _ := env.Store.ListPending(mbx, 1)
		total := 0
		markers := 0
		for _, id := range ids {
			p, err := u.Client.OpenPending(mbx, 1, id)
			if errors.Is(err, store.ErrNotFound) {
				continue // a marker removed by the worker meanwhile
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range p.Entries {
				if e.Unprocessed {
					markers++
				} else {
					total++
				}
			}
		}
		if total == 7 && markers == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("processed %d, markers %d", total, markers)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestUnparsableHeaderStaysUnprocessed(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	in := newIngest(t, env)
	many := strings.Repeat("X-A: b\r\n", MaxHeaderFields+1) + "\r\nbody\r\n"
	big := "Subject: " + strings.Repeat("a", MaxHeaderBytes) + "\r\n\r\nbody\r\n"
	noSep := "Subject: no body"
	for _, m := range []string{many, big, noSep + "\r\n"} {
		if err := deliver(t, in, "s@x", []string{"info@example.org"}, m); err != nil {
			t.Fatal(err)
		}
	}
	in.Flush()
	list, _ := u.Client.List(mbx, store.ID{})
	if len(list) != 3 {
		t.Fatalf("%d mails", len(list))
	}
	for _, m := range list {
		if m.Meta.HeadersParsed || m.Meta.Subject != "" {
			t.Fatalf("unparsable header evaluated: %+v", m.Meta)
		}
		_, content, err := u.Client.Read(mbx, m.ID)
		if err != nil || len(content) == 0 {
			t.Fatal("mail must still be stored")
		}
	}
	ids, _ := env.Store.ListPending(mbx, 1)
	if len(ids) != 3 {
		t.Fatalf("markers: %d", len(ids))
	}
}

func TestDiskSpaceAndErrors(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	env.Mailbox(u, "A", "info@example.org")
	free := uint64(50)
	in := newIngest(t, env, func(c *Config) {
		c.DiskSpace = func(string) (uint64, uint64, error) { return free, 100, nil }
	})
	if err := in.Accepting(); err != nil {
		t.Fatal(err)
	}
	free = 9
	if err := in.Accepting(); !errors.Is(err, smtpd.ErrDiskFull) {
		t.Fatal("below 10 % free must refuse")
	}
	free = 10
	if err := in.Accepting(); err != nil {
		t.Fatal("exactly 10 % is enough")
	}
	// A second server needs the server lock (9.1) of the first.
	in.releaseLock()
	in2 := newIngest(t, env, func(c *Config) {
		c.DiskSpace = func(string) (uint64, uint64, error) { return 0, 0, errors.New("x") }
	})
	if err := in2.Accepting(); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatal("unknown space")
	}
	if !errors.Is(diskErr(syscall.ENOSPC), smtpd.ErrDiskFull) || !errors.Is(diskErr(errors.New("x")), smtpd.ErrTemporary) {
		t.Fatal("diskErr")
	}
	// The real file system statistics work.
	if f, total, err := diskSpace(env.Store.Root); err != nil || total == 0 || f > total {
		t.Fatal("statfs")
	}
	// Abort leaves nothing in spool/.
	d, err := in.Begin(smtpd.Session{}, "s@x", []string{"info@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	d.Write([]byte("x\r\n"))
	d.Abort()
	d.Abort()
	if _, err := d.Write([]byte("y")); err == nil {
		t.Fatal("write after abort")
	}
	if err := d.Commit(); err == nil {
		t.Fatal("commit after abort")
	}
	if f := files(t, env.Store.SpoolDir()); len(f) != 0 {
		t.Fatalf("spool after abort: %v", f)
	}
	// Unknown recipient at Begin.
	if _, err := in.Begin(smtpd.Session{}, "s@x", []string{"nobody@example.org"}); !errors.Is(err, smtpd.ErrUnknownRecipient) {
		t.Fatal("unknown recipient at Begin")
	}
}

func TestNewChecksKey(t *testing.T) {
	env := testenv.New(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	for name, cfg := range map[string]Config{
		"no store":  {Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1},
		"no key":    {Store: env.Store, Log: env.Log, IngestGen: 1},
		"wrong key": {Store: env.Store, Log: env.Log, IngestKey: other, IngestGen: 1},
		"no cert":   {Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 2},
	} {
		if _, err := New(cfg); !errors.Is(err, ErrConfig) {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestMailboxWithoutEpochOrRecord(t *testing.T) {
	env := testenv.New(t)
	in := newIngest(t, env)
	// An address pointing to a mailbox that does not exist yet.
	env.Store.AddAddress("ghost@example.org", store.ID{1})
	if _, err := in.Begin(smtpd.Session{}, "s@x", []string{"ghost@example.org"}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatal("missing mailbox must be a temporary error")
	}
	if f := files(t, env.Store.SpoolDir()); len(f) != 0 {
		t.Fatal("spool after failed Begin")
	}
	// A damaged addresses.json is a temporary error.
	os.WriteFile(env.Store.AddressesFile(), []byte("{"), 0o600)
	if err := in.Recipient("ghost@example.org"); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatal("damaged address table")
	}
}
