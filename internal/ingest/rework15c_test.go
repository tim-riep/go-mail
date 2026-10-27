package ingest

import (
	"crypto/ed25519"
	"errors"
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
)

// Tests of task 15c (findings 1, 2 and 4 of the verification of task
// 15).

// spoolEmpty fails unless spool/ is empty.
func spoolEmpty(t *testing.T, env *testenv.Env) {
	t.Helper()
	ents, err := os.ReadDir(env.Store.SpoolDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("spool/ holds %d entries", len(ents))
	}
}

// TestGenerationRecheckedAtCommit (finding 1): ingest-2.cert is logged
// while the data arrive, valid from the receipt time on. Begin checked
// generation 1 before; the commit checks it again under the mailbox
// locks and refuses (451): nothing signed with generation 1 for a
// receipt at or after valid_from reaches the mailbox.
func TestGenerationRecheckedAtCommit(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	fl := &fakeLog{}
	buf := &syncBuffer{}
	in := newIngest(t, env, func(c *Config) { c.Log = fl; c.Logger = slog.New(slog.NewTextHandler(buf, nil)) })
	before := deliveredFiles(t, env, mbx)
	d, err := in.Begin(smtpd.Session{ID: "window"}, "s@x", []string{"info@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	received := env.Clock.Now()
	_, priv, _ := ed25519.GenerateKey(nil)
	pub, _, _ := ed25519.GenerateKey(nil)
	c, err := keys.NewPlatformCert(priv, 1, keys.RoleIngest, 2, pub, received.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	cd, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	fl.next = []translog.Entry{{Content: cd}}
	if _, err := d.Write([]byte(message("window", "x"))); err != nil {
		t.Fatal(err)
	}
	if err := d.Commit(); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("commit after the generation was superseded during DATA: %v", err)
	}
	if after := deliveredFiles(t, env, mbx); len(after) != len(before) {
		t.Fatal("delivered with a superseded generation")
	}
	spoolEmpty(t, env)
	if l := buf.take(); !strings.Contains(l, "generation is superseded") || !strings.Contains(l, "status=451") || strings.Contains(l, "example.org") {
		t.Fatalf("log %q", l)
	}
	if _, err := in.Begin(smtpd.Session{ID: "after"}, "s@x", []string{"info@example.org"}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("Begin after the switch: %v", err)
	}
	// valid_from after the receipt: the commit passes.
	fl.next = nil
	d, err = in.Begin(smtpd.Session{ID: "later"}, "s@x", []string{"info@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	c, _ = keys.NewPlatformCert(priv, 1, keys.RoleIngest, 2, pub, env.Clock.Now().Add(time.Millisecond).UnixMilli())
	cd, _ = c.Encode()
	fl.next = []translog.Entry{{Content: cd}}
	if _, err := d.Write([]byte(message("later", "x"))); err != nil {
		t.Fatal(err)
	}
	if err := d.Commit(); err != nil {
		t.Fatalf("commit before valid_from: %v", err)
	}
}

// pinIdentities returns the identity list of the pin of env for the
// operator log.
func pinIdentities(env *testenv.Env) []translog.Identity {
	var ids []translog.Identity
	for _, id := range env.Pin.Identities {
		ids = append(ids, translog.Identity{Gen: id.Gen, Pub: id.Pub})
	}
	return ids
}

// TestTreeRolledBackWhileRunning (finding 2, test of the verification):
// tree.rec is reset while the server runs to the state before the entry
// of epoch 5 (the entry file stays, no head covers it), mailbox.rec to
// epoch 4 and epoch.rec 5 removed. The operator log of the running
// server saw the larger tree: it fails closed (ErrConsistency) instead
// of rebuilding the smaller tree, and the server refuses (451) instead of
// encrypting for epoch 4; nothing is delivered.
func TestTreeRolledBackWhileRunning(t *testing.T) {
	env := testenv.NewLogged(t)
	u := env.NewUser("bob")
	mbx := env.Mailbox(u, "B", "bob@example.org")
	tree := env.Store.Path("log", "tree.rec")
	saved, err := os.ReadFile(tree)
	if err != nil {
		t.Fatal(err)
	}
	in := newIngest(t, env)
	if err := deliver(t, in, "s@x", []string{"bob@example.org"}, message("a", "x")); err != nil {
		t.Fatal(err)
	}
	e5 := env.ImmediateEpoch(u, mbx, env.Clock.Now(), store.ReasonMemberRemoved, "B")
	env.Clock.Advance(time.Minute)
	if err := deliver(t, in, "s@x", []string{"bob@example.org"}, message("b", "x")); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(tree, saved); err != nil {
		t.Fatal(err)
	}
	m, err := env.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	m.Epoch = e5.Number - 1
	if err := env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(env.Store.EpochDir(mbx, e5.Number)); err != nil {
		t.Fatal(err)
	}
	before := deliveredFiles(t, env, mbx)
	if _, err := env.Log.Lookup(translog.KindEpoch, mbx[:]); !errors.Is(err, translog.ErrConsistency) {
		t.Fatalf("Lookup on the rolled back tree: %v", err)
	}
	if err := in.Recipient("bob@example.org"); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("RCPT after the rollback: %v", err)
	}
	if err := deliver(t, in, "s@x", []string{"bob@example.org"}, message("c", "x")); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("running server after the rollback of tree.rec and mailbox.rec: %v", err)
	}
	if after := deliveredFiles(t, env, mbx); len(after) != len(before) {
		t.Fatal("a mail was delivered after the rollback")
	}
	spoolEmpty(t, env)
}

// TestRepairTreeAfterRestart (finding 2): tree.rec rolled back below
// existing entries while the server runs. The running server refuses
// (451), a restarted one does not start (its own certificate cannot be
// checked: ErrConsistency); after RepairTree ("gomail-server log
// repair") the restarted server delivers again, for the newest epoch.
func TestRepairTreeAfterRestart(t *testing.T) {
	x := newLoggedEpochEnv(t)
	env := x.env
	tree := env.Store.Path("log", "tree.rec")
	saved, err := os.ReadFile(tree)
	if err != nil {
		t.Fatal(err)
	}
	if n := x.deliverAt(t, at(12, 1), "before"); n != 5 {
		t.Fatalf("epoch %d, want 5", n)
	}
	// Two more entries, so that the entry beyond the next index shows
	// the rollback to a new process as well.
	mbxB := env.Mailbox(x.u, "B")
	env.AssignAddress("b1@example.org", mbxB)
	env.AssignAddress("b2@example.org", mbxB)
	if err := store.WriteFileAtomic(tree, saved); err != nil {
		t.Fatal(err)
	}
	env.Clock.Set(at(12, 30))
	before := deliveredFiles(t, env, x.mbx)
	if err := deliver(t, x.in, "s@x", []string{"info@example.org"}, message("rolled back", "x")); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("running server: %v", err)
	}
	kill(x.in)
	cfg := Config{Store: env.Store, Log: env.OpenOperator(), IngestKey: env.IngestKey, IngestGen: 1, Now: env.Clock.Now,
		DiskSpace: func(string) (uint64, uint64, error) { return 50, 100, nil }}
	if in, err := New(cfg); !errors.Is(err, ErrConfig) || !errors.Is(err, translog.ErrConsistency) {
		if in != nil {
			in.Close()
		}
		t.Fatalf("restart before the repair: %v", err)
	}
	if after := deliveredFiles(t, env, x.mbx); len(after) != len(before) {
		t.Fatal("a mail was delivered on the rolled back tree")
	}
	if err := translog.RepairTree(translog.Options{Store: env.Store, Identities: pinIdentities(env), Origin: env.Pin.Origin}); err != nil {
		t.Fatal(err)
	}
	x.in = newIngest(t, env, func(c *Config) { c.Log = env.OpenOperator() })
	if n := x.deliverAt(t, at(12, 31), "repaired"); n != 5 {
		t.Fatalf("after the repair: epoch %d, want 5", n)
	}
}

// TestAddressRecheckInCommit (finding 4, test of the verification): while
// the data arrive, a backdated assignment of the address to another
// mailbox is logged (valid_from before the receipt, after the first
// assignment). The commit checks the assignment at the receipt time
// again under the locks (stillValid) and refuses (451).
func TestAddressRecheckInCommit(t *testing.T) {
	env := testenv.NewLogged(t)
	u := env.NewUser("alice")
	mbxA := env.Mailbox(u, "A", "info@example.org")
	mbxB := env.Mailbox(u, "B")
	env.Clock.Advance(time.Hour)
	in := newIngest(t, env)
	d, err := in.Begin(smtpd.Session{ID: "recheck"}, "s@x", []string{"info@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Write([]byte(message("recheck", "x"))); err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(-time.Second)
	env.AssignAddress("info@example.org", mbxB)
	env.Clock.Advance(time.Second)
	before := deliveredFiles(t, env, mbxA)
	if err := d.Commit(); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("commit despite the reassigned address: %v", err)
	}
	if after := deliveredFiles(t, env, mbxA); len(after) != len(before) {
		t.Fatal("delivered despite the reassigned address")
	}
	spoolEmpty(t, env)
}
