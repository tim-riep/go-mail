package ingest

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/translog/translogtest"
)

// Tests of the log checks of task 15 (translog doc.go "Tasks" point 15)
// with the operator log of the data directory (testenv.NewLogged).

// newLoggedEpochEnv is newEpochEnv with the log: epochs 1 to 4 created
// by the client and 5 (member-removed at 12:00, discarding 2 to 4), all
// logged.
func newLoggedEpochEnv(t *testing.T) *epochEnv {
	t.Helper()
	env := testenv.NewLogged(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	buf := &syncBuffer{}
	in := newIngest(t, env, func(c *Config) { c.Logger = slog.New(slog.NewTextHandler(buf, nil)) })
	if e5 := env.ImmediateEpoch(u, mbx, at(12, 0), store.ReasonMemberRemoved, "A"); len(e5.Discards) != 3 {
		t.Fatalf("discards %v", e5.Discards)
	}
	return &epochEnv{env: env, u: u, mbx: mbx, in: in, log: buf}
}

// restart ends the server x.in as a crash would and starts a new one on
// the same data directory with a fresh operator log (no memory of the
// chain), as gomail-server after a restart.
func (x *epochEnv) restart(t *testing.T) {
	t.Helper()
	kill(x.in)
	x.in = newIngest(t, x.env, func(c *Config) {
		c.Log = x.env.OpenOperator()
		c.Logger = slog.New(slog.NewTextHandler(x.log, nil))
	})
}

// TestLoggedDelivery: with the log every check passes for what the
// clients logged, and the mail is encrypted for the logged epoch.
func TestLoggedDelivery(t *testing.T) {
	x := newLoggedEpochEnv(t)
	if n := x.deliverAt(t, at(12, 1), "a"); n != 5 {
		t.Fatalf("epoch %d, want 5", n)
	}
	x.restart(t)
	if n := x.deliverAt(t, at(12, 2), "b"); n != 5 {
		t.Fatalf("after the restart: epoch %d, want 5", n)
	}
	for _, n := range []uint32{1, 5} {
		_, data, err := x.env.Store.ReadEpoch(x.mbx, n)
		if err != nil {
			t.Fatal(err)
		}
		if err := x.env.Log.CheckEpoch(x.mbx, n, data); err != nil {
			t.Fatalf("epoch %d not logged: %v", n, err)
		}
	}
}

// TestRollbackDetected (D71): the server resets mailbox.rec, and with it
// epoch.rec, to the epoch before the member was removed. Without the log
// a server without memory encrypts for the old epoch 1 again (the
// residual risk of D71); with the log the newest logged epoch 5 lies
// beyond the head, and the server refuses (451), also after a restart.
func TestRollbackDetected(t *testing.T) {
	rollback := func(x *epochEnv) {
		t.Helper()
		m, err := x.env.Store.ReadMailbox(x.mbx)
		if err != nil {
			t.Fatal(err)
		}
		m.Epoch = 4
		if err := x.env.Store.WriteMailbox(m); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(x.env.Store.EpochDir(x.mbx, 5)); err != nil {
			t.Fatal(err)
		}
	}
	// Without the log: epoch 1, nothing noticed (the residual risk).
	plain := newEpochEnv(t, true)
	rollback(plain)
	kill(plain.in)
	plain.in = newIngest(t, plain.env)
	plain.env.Clock.Set(at(12, 30))
	if err := deliver(t, plain.in, "s@x", []string{"info@example.org"}, message("old", "x")); err != nil {
		t.Fatalf("without the log: %v", err)
	}

	x := newLoggedEpochEnv(t)
	if n := x.deliverAt(t, at(12, 1), "before"); n != 5 {
		t.Fatalf("epoch %d, want 5", n)
	}
	rollback(x)
	x.restart(t)
	x.env.Clock.Set(at(12, 30))
	before := deliveredFiles(t, x.env, x.mbx)
	x.log.take()
	err := deliver(t, x.in, "s@x", []string{"info@example.org"}, message("after", "x"))
	if !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("after the rollback: %v", err)
	}
	if l := x.log.take(); !strings.Contains(l, "rollback") || !strings.Contains(l, "logged=5") || !strings.Contains(l, "head=4") ||
		strings.Contains(l, "info@") {
		t.Fatalf("log %q", l)
	}
	if after := deliveredFiles(t, x.env, x.mbx); len(after) != len(before) {
		t.Fatal("a mail was delivered after the rollback")
	}
	// mailbox.rec alone reset, epoch.rec 5 still there: refused as well.
	y := newLoggedEpochEnv(t)
	m, _ := y.env.Store.ReadMailbox(y.mbx)
	m.Epoch = 4
	if err := y.env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	y.env.Clock.Set(at(12, 30))
	if err := deliver(t, y.in, "s@x", []string{"info@example.org"}, message("c", "x")); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("mailbox.rec reset: %v", err)
	}
	if err := y.in.checkLogHead(m); !errors.Is(err, ErrRollback) {
		t.Fatalf("checkLogHead: %v", err)
	}
}

// TestEpochNotLogged: an epoch.rec the log does not hold (written past
// the log) is never used; the delivery fails with 451.
func TestEpochNotLogged(t *testing.T) {
	env := testenv.NewLogged(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	// Epoch 5 created like a client, but logged only in a placeholder.
	logged := env.Log
	env.Log, _ = translogtest.NewUnverified(true)
	env.ImmediateEpoch(u, mbx, env.Clock.Now(), store.ReasonMemberRemoved, "A")
	env.Log = logged
	buf := &syncBuffer{}
	in := newIngest(t, env, func(c *Config) { c.Logger = slog.New(slog.NewTextHandler(buf, nil)) })
	if err := deliver(t, in, "s@x", []string{"info@example.org"}, message("x", "x")); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("unlogged epoch: %v", err)
	}
	// The same epoch beyond the head of mailbox.rec: not used (D71), noted
	// with IDs only; the chain up to the head is logged and used.
	m, err := env.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	m.Epoch--
	if err := env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	buf.take()
	if err := deliver(t, in, "s@x", []string{"info@example.org"}, message("y", "x")); err != nil {
		t.Fatalf("unlogged epoch beyond the head: %v", err)
	}
	if l := buf.take(); !strings.Contains(l, "beyond the head of mailbox.rec") || strings.Contains(l, "example.org") {
		t.Fatalf("log %q", l)
	}
}

// TestAddressNotLogged: addresses.json alone assigns nothing; an address
// without a log entry, or whose log entry names another mailbox, is
// refused like an unknown address (550), and the log line names the
// mailbox only.
func TestAddressNotLogged(t *testing.T) {
	env := testenv.NewLogged(t)
	u := env.NewUser("alice")
	mbxA := env.Mailbox(u, "A", "info@example.org")
	mbxB := env.Mailbox(u, "B")
	// Only in addresses.json.
	if _, err := env.Store.AddAddress("json-only@example.org", mbxA); err != nil {
		t.Fatal(err)
	}
	// Logged for B, but addresses.json says A.
	env.AssignAddress("other@example.org", mbxB)
	if _, err := env.Store.AddAddress("other@example.org", mbxA); err != nil {
		t.Fatal(err)
	}
	// Logged with a valid_from after the receipt.
	env.Clock.Advance(time.Hour)
	env.AssignAddress("later@example.org", mbxA)
	if _, err := env.Store.AddAddress("later@example.org", mbxA); err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(-time.Hour)
	buf := &syncBuffer{}
	in := newIngest(t, env, func(c *Config) { c.Logger = slog.New(slog.NewTextHandler(buf, nil)) })
	for _, a := range []string{"json-only@example.org", "other@example.org", "later@example.org"} {
		if err := in.Recipient(a); !errors.Is(err, smtpd.ErrUnknownRecipient) {
			t.Fatalf("%s: %v", a, err)
		}
		if err := deliver(t, in, "s@x", []string{a}, message("x", "x")); !errors.Is(err, smtpd.ErrUnknownRecipient) {
			t.Fatalf("%s: %v", a, err)
		}
	}
	l := buf.take()
	if !strings.Contains(l, "assignment not in the log") || strings.Contains(l, "example.org") {
		t.Fatalf("log %q", l)
	}
	// The logged assignment works; "later" from its valid_from on.
	if err := deliver(t, in, "s@x", []string{"info@example.org"}, message("x", "x")); err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(time.Hour)
	if err := deliver(t, in, "s@x", []string{"later@example.org"}, message("y", "x")); err != nil {
		t.Fatal(err)
	}
}

// fakeLog is the placeholder with a chosen answer for the platform
// checks.
type fakeLog struct {
	translogtest.Unverified
	platformErr error
	next        []translog.Entry // Lookup(KindPlatform, ingest-2.cert)
}

func (f *fakeLog) CheckPlatform(string, []byte) error { return f.platformErr }

func (f *fakeLog) Lookup(kind translog.Kind, subject []byte) ([]translog.Entry, error) {
	if kind == translog.KindPlatform && string(subject) == "ingest-2.cert" {
		return f.next, nil
	}
	return nil, nil
}

// TestOwnCertificate: New requires the own ingest certificate in the log
// (CheckPlatform) and refuses a generation that ingest-<g+1>.cert in the
// log supersedes; a running server refuses deliveries from that
// valid_from on (451).
func TestOwnCertificate(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	env.Mailbox(u, "A", "info@example.org")
	cfg := func(l translog.Log) Config {
		return Config{Store: env.Store, Log: l, IngestKey: env.IngestKey, IngestGen: 1, Now: env.Clock.Now,
			DiskSpace: func(string) (uint64, uint64, error) { return 50, 100, nil }}
	}
	if _, err := New(cfg(&fakeLog{platformErr: translog.ErrNotInLog})); !errors.Is(err, ErrConfig) || !errors.Is(err, translog.ErrNotInLog) {
		t.Fatalf("certificate not in the log: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	pub, _, _ := ed25519.GenerateKey(nil)
	switchAt := env.Clock.Now().Add(time.Hour)
	c, err := keys.NewPlatformCert(priv, 1, keys.RoleIngest, 2, pub, switchAt.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	cd, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	fl := &fakeLog{next: []translog.Entry{{Content: cd}}}
	in, err := New(cfg(fl))
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Recover(); err != nil {
		t.Fatal(err)
	}
	if err := deliver(t, in, "s@x", []string{"info@example.org"}, message("before", "x")); err != nil {
		t.Fatalf("before the switch: %v", err)
	}
	env.Clock.Set(switchAt)
	if err := deliver(t, in, "s@x", []string{"info@example.org"}, message("after", "x")); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("after the switch: %v", err)
	}
	in.Close()
	if _, err := New(cfg(fl)); !errors.Is(err, ErrConfig) || !errors.Is(err, ErrSuperseded) {
		t.Fatalf("superseded at the start: %v", err)
	}
}

// TestBatchSizeLimit: a term list holds at most store.MaxBatch entries;
// New refuses a larger Config.BatchSize (and a negative one) with
// ErrConfig, and the message names 0 (the default) or 1 to MaxBatch.
func TestBatchSizeLimit(t *testing.T) {
	env := testenv.New(t)
	for _, n := range []int{store.MaxBatch + 1, -1, 1 << 20} {
		_, err := New(Config{Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1, BatchSize: n})
		if !errors.Is(err, ErrConfig) {
			t.Fatalf("batch size %d: %v", n, err)
		}
		// Task 15c finding 6: the text names both allowed forms.
		if want := fmt.Sprintf("0 (default %d) or 1 to %d", DefaultBatchSize, store.MaxBatch); !strings.Contains(err.Error(), want) {
			t.Fatalf("batch size %d: %q does not name %q", n, err, want)
		}
	}
	in := newIngest(t, env, func(c *Config) { c.BatchSize = store.MaxBatch })
	in.Close()
}
