package client_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 24 package B, backlog 52 (test part): the behavior of
// today for the open points S88 and S89 of SPEC-ISSUES (residual risks of
// D88). They pin what the code does, not what the specification will
// decide.

// TestLogFreeCheckpointLocksMailbox (S88): bob, a valid user member of
// alice's mailbox, signs a checkpoint that no signed head of the log
// ever named (the size of alice's head with a root he made up). Alice's
// client takes it for a split view: every operation on the mailbox
// fails with ErrLog (translog.ErrConsistency), on the same client again
// (the checkpoint is not remembered as seen), after a reopen, for a
// reader and for a change, and still after the log has grown. The lock
// lasts as long as the file lies there; alice's client neither removes
// nor changes it, and the change writes nothing.
func TestLogFreeCheckpointLocksMailbox(t *testing.T) {
	f := newFixture(t)
	m := f.deliver(t, "before", "body")
	bob := f.env.NewUser("bob")
	carol := f.env.NewUser("carol")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	if _, err := bob.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	f.env.Reopen(bob)
	f.env.AutoHeads = false
	f.env.Clock.Advance(time.Minute)
	h := f.env.MustPublishHead()
	c := f.env.Reopen(f.u)
	if _, err := c.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	bks := f.env.Keystore(bob)
	defer bks.Zero()
	dev := deviceOf(t, bob.Dir)
	var root [32]byte
	if _, err := rand.Read(root[:]); err != nil {
		t.Fatal(err)
	}
	forgeCheckpoint(t, f.env, f.mbx, bob, dev, 1, bks.Identity, h, func(cp *store.Checkpoint) { copy(cp.RootHash[:], root[:]) })
	cpFile := f.env.Store.CheckpointFile(f.mbx, bob.ID, dev)
	cpData := mustRead(t, cpFile)
	locked := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, client.ErrLog) || !errors.Is(err, translog.ErrConsistency) {
			t.Fatalf("%s: %v", name, err)
		}
		warningWith(t, f.env.Warnings.Take(), bob.ID.String(), f.mbx.String())
	}
	ops := func(c *client.Client) {
		t.Helper()
		for run := 0; run < 2; run++ {
			f.env.Warnings.Take()
			_, err := c.List(f.mbx, store.ID{})
			locked("list", err)
			_, _, err = c.Read(f.mbx, m.ID)
			locked("read", err)
			tree := treeOf(t, f.env.Store.MailboxDir(f.mbx))
			_, err = c.Share(f.mbx, carol.ID, client.ShareOptions{})
			locked("share", err)
			sameTree(t, "share", f.env.Store.MailboxDir(f.mbx), tree)
		}
	}
	ops(c)
	ops(f.env.Reopen(f.u))
	// The log grows: a new head, signed after bob's checkpoint.
	f.env.Clock.Advance(time.Minute)
	f.env.AssignAddress("grow24@example.org", f.mbx)
	f.env.Clock.Advance(time.Minute)
	if h2 := f.env.MustPublishHead(); h2.Size <= h.Size {
		t.Fatalf("log did not grow: %d, was %d", h2.Size, h.Size)
	}
	f.env.Clock.Advance(24 * time.Hour)
	ops(f.env.Reopen(f.u))
	if !bytes.Equal(mustRead(t, cpFile), cpData) {
		t.Fatal("bob's checkpoint was changed")
	}
}

// sameTree fails unless the result of treeOf for dir is want, naming
// what differs.
func sameTree(t *testing.T, name, dir string, want map[string]string) {
	t.Helper()
	got := treeOf(t, dir)
	if maps.Equal(got, want) {
		return
	}
	for p, v := range got {
		if want[p] != v {
			t.Errorf("%s: %s: %s, was %q", name, p, v, want[p])
		}
	}
	for p := range want {
		if _, ok := got[p]; !ok {
			t.Errorf("%s: %s removed", name, p)
		}
	}
	t.FailNow()
}

// TestLogUnloggableEpochOneNotHealed (S89): a mailbox whose epoch.rec 1
// can never be logged. Alice prepares a mailbox (the copy of the first
// step in her client directory, CreateMailbox stopped before the log
// entry), the copy is taken away, and her generation 1, which signed
// epoch 1, is revoked (DeviceLost): Append now refuses the epoch with
// ErrOrder. Somebody with write access to the data directory puts the
// files of the copy there. A change by alice, a user member of epoch 1,
// ends with store.ErrChain before the repair (healHead) runs, as there
// is no epoch n-1 to take the members from; a reader fails as well.
// Nothing is written: the mailbox directory is unchanged, epoch 1 is
// still not in the log, and no copy is left in the client directory;
// the same again after a reopen. The text of the warning is not fixed
// here.
func TestLogUnloggableEpochOneNotHealed(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	client.SetCrashHook(t, func(p string) bool { return p == "mailbox-copy" })
	if _, err := f.u.Client.CreateMailbox("U"); !errors.Is(err, client.ErrCrashed) {
		t.Fatal(err)
	}
	client.SetCrashHook(t, nil)
	copies := newMailboxCopies(t, f.u.Dir)
	if len(copies) != 1 {
		t.Fatalf("copies %v", copies)
	}
	id := copies[0]
	stolen := filepath.Join(f.env.Base, "stolen24")
	if err := os.Rename(filepath.Join(f.u.Dir, "new-mailboxes", id.String()), stolen); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	epoch1 := mustRead(t, filepath.Join(stolen, "epoch.rec"))
	for _, w := range []struct{ path, name string }{
		{f.env.Store.WrapFile(id, 1, f.u.ID), "wrap"},
		{f.env.Store.FoldersFile(id, 1), "folders.gml"},
		{f.env.Store.EpochFile(id, 1), "epoch.rec"},
		{f.env.Store.MailboxFile(id), "mailbox.rec"},
	} {
		if err := store.MkdirAll(filepath.Dir(w.path)); err != nil {
			t.Fatal(err)
		}
		if err := store.WriteFileAtomic(w.path, mustRead(t, filepath.Join(stolen, w.name))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.env.LogOperator().Append(translog.KindEpoch, epoch1); !errors.Is(err, translog.ErrOrder) {
		t.Fatalf("epoch 1 signed by the revoked generation: %v", err)
	}
	// The empty lock file of the mailbox (9.1) comes with the first
	// lock; it is not a write of the change.
	unlock, err := f.env.Store.LockMailbox(id)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	tree := treeOf(t, f.env.Store.MailboxDir(id))
	files := map[string][]byte{}
	for _, p := range []string{f.env.Store.EpochFile(id, 1), f.env.Store.MailboxFile(id)} {
		files[p] = mustRead(t, p)
	}
	unchanged := func(name string) {
		t.Helper()
		sameTree(t, name, f.env.Store.MailboxDir(id), tree)
		for p, data := range files {
			if !bytes.Equal(mustRead(t, p), data) {
				t.Fatalf("%s: %s changed", name, p)
			}
		}
		if err := f.env.LogOperator().CheckEpoch(id, 1, epoch1); !errors.Is(err, translog.ErrNotInLog) {
			t.Fatalf("%s: epoch 1 in the log: %v", name, err)
		}
		if len(newMailboxCopies(t, f.u.Dir)) != 0 {
			t.Fatalf("%s: a copy in the client directory", name)
		}
	}
	c := f.env.Reopen(f.u)
	for run := 0; run < 2; run++ {
		// The guard of mutate before healHead (S89: "no epochs").
		if _, err := c.Share(id, bob.ID, client.ShareOptions{}); !errors.Is(err, store.ErrChain) || !strings.Contains(err.Error(), "no epochs") {
			t.Fatalf("share: %v", err)
		}
		unchanged("share")
		// A reader finds no verified epoch with access (today
		// client.ErrWrap after the warning that the chain breaks).
		if _, err := c.List(id, store.ID{}); !errors.Is(err, store.ErrChain) && !errors.Is(err, client.ErrWrap) {
			t.Fatalf("list: %v", err)
		}
		unchanged("list")
		c = f.env.Reopen(f.u)
	}
}
