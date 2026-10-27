package ingest

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// syncBuffer collects log output from several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) take() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.b.String()
	s.b.Reset()
	return out
}

func at(hh, mm int) time.Time { return time.Date(2026, 10, 26, hh, mm, 0, 0, time.UTC) }

type epochEnv struct {
	env *testenv.Env
	u   *testenv.User
	mbx store.ID
	in  *Ingest
	log *syncBuffer
}

// newEpochEnv: epochs 1 (10:00), 2 (1.11.), 3 (1.12.), 4 (1.1.) created
// by the client; withFive adds 5 member-removed beginning at 12:00 that
// discards 2, 3 and 4, signed by the member.
func newEpochEnv(t *testing.T, withFive bool) *epochEnv {
	t.Helper()
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	buf := &syncBuffer{}
	in := newIngest(t, env, func(c *Config) { c.Logger = slog.New(slog.NewTextHandler(buf, nil)) })
	t.Cleanup(func() { in.Close() })
	if withFive {
		if e5 := env.ImmediateEpoch(u, mbx, at(12, 0), store.ReasonMemberRemoved, "A"); len(e5.Discards) != 3 {
			t.Fatalf("discards %v", e5.Discards)
		}
	}
	return &epochEnv{env: env, u: u, mbx: mbx, in: in, log: buf}
}

// deliverAt delivers one mail at t and returns the epoch the client sees
// for it (0 if the client rejects it).
func (x *epochEnv) deliverAt(t *testing.T, when time.Time, subject string) uint32 {
	t.Helper()
	x.env.Clock.Set(when)
	if err := deliver(t, x.in, "s@x", []string{"info@example.org"}, message(subject, "x")); err != nil {
		t.Fatalf("%s: %v", subject, err)
	}
	list, _ := x.u.Client.List(x.mbx, store.ID{})
	for _, m := range list {
		if m.Meta.Subject == subject {
			return m.Epoch
		}
	}
	return 0
}

func TestChooseImmediateEpoch(t *testing.T) {
	x := newEpochEnv(t, true)
	// Within the lead time of the immediate epoch 5: 5.
	if n := x.deliverAt(t, at(11, 56), "a"); n != 5 {
		t.Fatalf("11:56: epoch %d, want 5", n)
	}
	// Before the lead time: epoch 1, and the log says why 5 was not used.
	x.log.take()
	if n := x.deliverAt(t, at(11, 54), "b"); n != 1 {
		t.Fatalf("11:54: epoch %d, want 1", n)
	}
	if l := x.log.take(); !strings.Contains(l, "did not use an immediate epoch") || !strings.Contains(l, "epoch=5") {
		t.Fatalf("log %q", l)
	}
	// The discarded epochs are never used, also after their begin.
	if n := x.deliverAt(t, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), "c"); n != 5 {
		t.Fatalf("2.11.: epoch %d, want 5", n)
	}
	if n := x.deliverAt(t, time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC), "d"); n != 5 {
		t.Fatalf("2.1.: epoch %d, want 5", n)
	}
	// An immediate epoch further than the lead time in the future is
	// not used yet.
	x.env.ImmediateEpoch(x.u, x.mbx, time.Date(2027, 1, 2, 1, 0, 0, 0, time.UTC), store.ReasonGenerationRevoked, "A")
	if n := x.deliverAt(t, time.Date(2027, 1, 2, 0, 30, 0, 0, time.UTC), "e"); n != 5 {
		t.Fatalf("epoch %d, want 5", n)
	}
	if n := x.deliverAt(t, time.Date(2027, 1, 2, 0, 56, 0, 0, time.UTC), "f"); n != 6 {
		t.Fatalf("epoch %d, want 6", n)
	}
}

func TestChooseEpochPlanned(t *testing.T) {
	x := newEpochEnv(t, false)
	// Planned epochs only from their begin on, no lead time.
	nov := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if n := x.deliverAt(t, nov.Add(-time.Minute), "a"); n != 1 {
		t.Fatalf("epoch %d, want 1", n)
	}
	if n := x.deliverAt(t, nov, "b"); n != 2 {
		t.Fatalf("epoch %d, want 2", n)
	}
	if l := x.log.take(); strings.Contains(l, "did not use") {
		t.Fatalf("log %q", l)
	}
}

// mailbox.rec reset to 4 while epoch 5 lies in the directory: the server
// uses the chain up to the head as before and notes the epoch beyond it;
// the client warns about the reset and rejects what is stale.
func TestChooseEpochHeadReset(t *testing.T) {
	x := newEpochEnv(t, true)
	if _, err := x.u.Client.List(x.mbx, store.ID{}); err != nil {
		t.Fatal(err) // the client has seen 5
	}
	m, _ := x.env.Store.ReadMailbox(x.mbx)
	m.Epoch = 4
	x.env.Store.WriteMailbox(m)
	x.log.take()
	if n := x.deliverAt(t, at(11, 56), "a"); n != 1 {
		t.Fatalf("11:56 with head 4: epoch %d, want 1", n)
	}
	if l := x.log.take(); !strings.Contains(l, "beyond the head of mailbox.rec") || !strings.Contains(l, "epoch=5") {
		t.Fatalf("log %q", l)
	}
	if n := x.deliverAt(t, at(12, 30), "b"); n != 0 {
		t.Fatalf("12:30 with head 4: the client accepted epoch %d", n)
	}
	ws := strings.Join(x.env.Warnings.Take(), "\n")
	if !strings.Contains(ws, "zeigt auf Epoche 4") || !strings.Contains(ws, "nicht zustellbar") {
		t.Fatalf("warnings %q", ws)
	}
}

// deliveredFiles lists everything below the mailbox directories that a
// delivery leaves: mails, metadata and pending files.
func deliveredFiles(t *testing.T, env *testenv.Env, mbx store.ID) []string {
	t.Helper()
	var out []string
	for _, dir := range []string{"mail", "pending"} {
		filepath.WalkDir(filepath.Join(env.Store.MailboxDir(mbx), dir), func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				out = append(out, p)
			}
			return nil
		})
	}
	return out
}

// K8: an epoch created while DATA runs makes the commit fail with 451,
// and nothing is left in the mailbox or the spool.
func TestEpochChangesDuringData(t *testing.T) {
	for _, tc := range []struct {
		name  string
		begin time.Time
	}{
		// 5 overtakes epoch 1: its begin minus the lead time is before
		// the receipt.
		{"overtaken", at(11, 52)},
		// 5 begins later; the head of mailbox.rec moved all the same.
		{"head moved", at(14, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newEpochEnv(t, false)
			x.env.Clock.Set(at(11, 50))
			before := len(deliveredFiles(t, x.env, x.mbx))
			fired := false
			crashHook = func(p string) bool {
				if p == "data" && !fired {
					fired = true
					x.env.ImmediateEpoch(x.u, x.mbx, tc.begin, store.ReasonMemberRemoved, "A")
				}
				return false
			}
			t.Cleanup(func() { crashHook = nil })
			err := deliver(t, x.in, "s@x", []string{"info@example.org"}, message("k8", "x"))
			crashHook = nil
			if !fired || !errors.Is(err, smtpd.ErrTemporary) {
				t.Fatalf("delivery: %v", err)
			}
			if got := deliveredFiles(t, x.env, x.mbx); len(got) != before {
				t.Fatalf("files left in the mailbox: %v", got)
			}
			if spool, _ := os.ReadDir(x.env.Store.SpoolDir()); len(spool) != 0 {
				t.Fatalf("spool not empty: %d", len(spool))
			}
			if !strings.Contains(x.log.take(), "the epochs changed during the delivery") {
				t.Fatal("not logged")
			}
			// The sender retries: now the new chain is used.
			want := uint32(5)
			if tc.name == "head moved" {
				want = 1
			}
			if n := x.deliverAt(t, at(11, 51), "retry"); n != want {
				t.Fatalf("retry: epoch %d, want %d (%v)", n, want, x.env.Warnings.Take())
			}
		})
	}
}

// Under the lock, a chain that no longer verifies at commit time also
// refuses the delivery.
func TestEpochChainBrokenDuringData(t *testing.T) {
	x := newEpochEnv(t, false)
	fired := false
	crashHook = func(p string) bool {
		if p == "data" && !fired {
			fired = true
			os.WriteFile(x.env.Store.EpochFile(x.mbx, 2), []byte("junk"), 0o660)
		}
		return false
	}
	t.Cleanup(func() { crashHook = nil })
	if err := deliver(t, x.in, "s@x", []string{"info@example.org"}, message("k8", "x")); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("delivery: %v", err)
	}
	crashHook = nil
	if got := deliveredFiles(t, x.env, x.mbx); len(got) != 0 {
		t.Fatalf("files left: %v", got)
	}
}

// The head epoch.rec replaced by another validly signed one with the same
// number while DATA runs: the head moved as well (K8).
func TestHeadEpochReplacedDuringData(t *testing.T) {
	x := newEpochEnv(t, false)
	fired := false
	crashHook = func(p string) bool {
		if p == "data" && !fired {
			fired = true
			e4, _, err := x.env.Store.ReadEpoch(x.mbx, 4)
			if err != nil {
				t.Fatal(err)
			}
			ks, err := keys.OpenKeystore(mustRead(t, filepath.Join(x.u.Dir, "keystore")), testenv.Passphrase)
			if err != nil {
				t.Fatal(err)
			}
			e4.ContentPub = ks.Unwrap.PublicKey()
			if err := e4.Sign(ks.Identity); err != nil {
				t.Fatal(err)
			}
			ks.Zero()
			data, _ := e4.Encode()
			os.WriteFile(x.env.Store.EpochFile(x.mbx, 4), data, 0o660)
		}
		return false
	}
	t.Cleanup(func() { crashHook = nil })
	if err := deliver(t, x.in, "s@x", []string{"info@example.org"}, message("k8", "x")); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("delivery: %v", err)
	}
	crashHook = nil
	if got := deliveredFiles(t, x.env, x.mbx); len(got) != 0 {
		t.Fatalf("files left: %v", got)
	}
}

// stillValid on its own: a chosen epoch that is discarded or overtaken by
// an immediate epoch usable at the receipt is refused.
func TestStillValid(t *testing.T) {
	x := newEpochEnv(t, true)
	m, err := x.env.Store.ReadMailbox(x.mbx)
	if err != nil {
		t.Fatal(err)
	}
	_, head, err := x.in.verifyChain(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		epoch    uint32
		received time.Time
		ok       bool
	}{
		{1, at(11, 54), true},
		{1, at(11, 56), false}, // overtaken by 5 within its lead time
		{2, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), false}, // discarded
		{5, at(11, 56), true},
		{6, at(11, 56), false}, // not in the chain
	} {
		e, _, _ := x.env.Store.ReadEpoch(x.mbx, tc.epoch)
		if e == nil {
			e = &store.Epoch{Number: tc.epoch}
		}
		d := &delivery{in: x.in, session: "t", received: tc.received}
		err := d.stillValid(&target{mbx: m, epoch: e, headHash: head})
		if tc.ok != (err == nil) || err != nil && !errors.Is(err, smtpd.ErrTemporary) {
			t.Fatalf("epoch %d at %v: %v", tc.epoch, tc.received, err)
		}
	}
	// Another head hash, or mailbox.rec gone.
	d := &delivery{in: x.in, session: "t", received: at(11, 56)}
	e5, _, _ := x.env.Store.ReadEpoch(x.mbx, 5)
	if err := d.stillValid(&target{mbx: m, epoch: e5, headHash: [32]byte{1}}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatal("other head accepted")
	}
	os.Remove(x.env.Store.MailboxFile(x.mbx))
	if err := d.stillValid(&target{mbx: m, epoch: e5, headHash: head}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatal("missing mailbox.rec accepted")
	}
}

// The created time of a pending file is the receipt of the mail (marker)
// or the earliest receipt of its mails (term list), not the time the file
// is written: a file written after an immediate epoch began stays valid
// for the mails received before (sealPending).
func TestPendingCreatedIsReceipt(t *testing.T) {
	x := newEpochEnv(t, true) // 5 begins at 12:00, usable from 11:55
	// Two parsable mails for the term list, held in the queue.
	if n := x.deliverAt(t, at(11, 50), "a"); n != 1 {
		t.Fatalf("epoch %d, want 1", n)
	}
	if n := x.deliverAt(t, at(11, 52), "b"); n != 1 {
		t.Fatalf("epoch %d, want 1", n)
	}
	// A mail with an unparsable header keeps its marker. The clock passes
	// the begin of 5 while DATA runs, before the marker is written.
	x.env.Clock.Set(at(11, 53))
	crashHook = func(p string) bool {
		if p == "data" {
			x.env.Clock.Set(at(12, 30))
		}
		return false
	}
	t.Cleanup(func() { crashHook = nil })
	err := deliver(t, x.in, "s@x", []string{"info@example.org"}, "Subject: no body\r\n")
	crashHook = nil
	if err != nil {
		t.Fatal(err)
	}
	if now := x.env.Clock.Now(); !now.Equal(at(12, 30)) {
		t.Fatalf("clock %v", now)
	}
	// The term list is written at 12:30, after the begin of 5.
	if err := x.in.Flush(); err != nil {
		t.Fatal(err)
	}
	ids, err := x.env.Store.ListPending(x.mbx, 1)
	if err != nil || len(ids) != 2 {
		t.Fatalf("pending files %d: %v", len(ids), err)
	}
	x.env.Warnings.Take()
	var marker, list bool
	for _, id := range ids {
		data, err := x.env.Store.ReadPending(x.mbx, 1, id)
		if err != nil {
			t.Fatal(err)
		}
		f, err := envelope.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		p, err := x.u.Client.OpenPending(x.mbx, 1, id)
		if err != nil {
			t.Fatalf("pending %s created %v: %v", id, time.UnixMilli(f.Header.Created).UTC(), err)
		}
		switch {
		case len(p.Entries) == 1 && p.Entries[0].Unprocessed && p.Entries[0].MailID == id:
			marker = true
			if f.Header.Created != at(11, 53).UnixMilli() {
				t.Fatalf("marker created %v, want the receipt 11:53", time.UnixMilli(f.Header.Created).UTC())
			}
		case len(p.Entries) == 2 && !p.Entries[0].Unprocessed && !p.Entries[1].Unprocessed:
			list = true
			if f.Header.Created != at(11, 50).UnixMilli() {
				t.Fatalf("term list created %v, want the earliest receipt 11:50", time.UnixMilli(f.Header.Created).UTC())
			}
		default:
			t.Fatalf("pending %s: %+v", id, p.Entries)
		}
	}
	if !marker || !list {
		t.Fatalf("marker %v, term list %v", marker, list)
	}
	if ws := strings.Join(x.env.Warnings.Take(), "\n"); strings.Contains(ws, "Begriffsliste") {
		t.Fatalf("warnings %q", ws)
	}
}
