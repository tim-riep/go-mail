package translog

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// Tests of task 15d: refuse in SignHead (point 1) and the orphaned
// entries RepairTree reports (point 2).

// TestSignHeadRefuseEntryBeyond (point 1): tree.rec rolled back below
// existing entries, entries/<n+1>.rec still there, no head above n. A
// new process, which never saw the larger tree (no seen), refuses
// SignHead with ErrConsistency through refuse alone: the entries up to n
// give the root of tree.rec, so every later check of SignHead would
// pass. Nothing is deleted and no head is written.
func TestSignHeadRefuseEntryBeyond(t *testing.T) {
	x := newShrinkFixture(t)
	e := x.e
	n := e.tree().Size
	e.addresses(2)
	x.rollBack(t, n)
	fresh := e.openServer()
	if h, err := fresh.SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) || h != nil {
		t.Fatalf("SignHead of a new process on the rolled back tree: %v", err)
	}
	if fresh.signed != nil {
		t.Fatal("a head was taken as signed")
	}
	for _, i := range []int64{n, n + 1} {
		if _, err := os.Stat(e.path(EntryPath(i))); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	if size, err := fresh.f.newestHeadSize(); err != nil || size != 0 {
		t.Fatalf("head written: %d %v", size, err)
	}
	if e.tree().Size != n {
		t.Fatal("tree.rec changed")
	}
}

// TestRepairTreeOrphans (point 2, doc.go "What write access to log/
// gives an attacker"): tree.rec rolled back by four entries and
// entries/<n+1>.rec removed, no head above n. Only the running process
// notices (seen). A new process does not: its first Append removes
// entry n as a leftover and appends at n; its second Append fails on
// entries/<n+2>.rec (refuse). RepairTree reports the orphans n+2 and n+3
// beyond m = n+1 as an OrphanEntriesError, removes nothing and writes
// nothing; the log keeps refusing. Once the operator has removed the
// orphans, RepairTree succeeds and a new process works again.
func TestRepairTreeOrphans(t *testing.T) {
	x := newShrinkFixture(t)
	e := x.e
	n := e.tree().Size
	e.addresses(4)
	x.rollBack(t, n)
	if err := os.Remove(e.path(EntryPath(n + 1))); err != nil {
		t.Fatal(err)
	}
	x.allFail(t, "running", e.op)
	fresh := e.openOp()
	if _, err := fresh.Lookup(KindEpoch, x.mbx[:]); err != nil {
		t.Fatalf("new process, Lookup: %v", err)
	}
	if i, err := fresh.Append(KindUser, newUser(t).rec(t, 1)); err != nil || i != n {
		t.Fatalf("first append of the new process: %d %v", i, err)
	}
	if _, err := fresh.Append(KindUser, newUser(t).rec(t, 1)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("second append: %v", err)
	}
	tree, err := os.ReadFile(e.path(TreeFile))
	if err != nil {
		t.Fatal(err)
	}
	var oe *OrphanEntriesError
	err = RepairTree(e.serverOptions())
	if !errors.As(err, &oe) || !errors.Is(err, ErrConsistency) {
		t.Fatalf("repair with orphans: %v", err)
	}
	if oe.Size != n+1 || oe.Count != 2 || oe.First != n+2 || oe.Last != n+3 {
		t.Fatalf("reported %+v, want size %d, 2 orphans %d to %d", *oe, n+1, n+2, n+3)
	}
	for _, i := range []int64{n + 2, n + 3} {
		if _, err := os.Stat(e.path(EntryPath(i))); err != nil {
			t.Fatalf("orphan %d removed: %v", i, err)
		}
	}
	if now, err := os.ReadFile(e.path(TreeFile)); err != nil || !bytes.Equal(now, tree) {
		t.Fatal("tree.rec written despite the orphans")
	}
	x.allFail(t, "after the refused repair, new process", e.openOp())
	// The operator removes the orphans on purpose and repairs again.
	for _, i := range []int64{n + 2, n + 3} {
		if err := os.Remove(e.path(EntryPath(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := RepairTree(e.serverOptions()); err != nil {
		t.Fatalf("repair after removing the orphans: %v", err)
	}
	if e.tree().Size != n+1 {
		t.Fatalf("repaired size %d, want %d", e.tree().Size, n+1)
	}
	restarted := e.openServer()
	x.allPass(t, "after the repair, new process", restarted)
	if _, err := restarted.SignHead(e.signer, e.now); err != nil {
		t.Fatalf("SignHead after the repair: %v", err)
	}
}

// TestOrphanEntriesErrorText: the message names count, size and range
// and wraps ErrConsistency.
func TestOrphanEntriesErrorText(t *testing.T) {
	for _, tc := range []struct {
		e    OrphanEntriesError
		want string
	}{
		{OrphanEntriesError{Size: 5, Count: 1, First: 5, Last: 5}, "translog: log is inconsistent: 1 orphaned entries beyond the 5 entries that exist and decode (entries/5.rec); nothing removed"},
		{OrphanEntriesError{Size: 5, Count: 2, First: 7, Last: 9}, "translog: log is inconsistent: 2 orphaned entries beyond the 5 entries that exist and decode (entries/7.rec to entries/9.rec); nothing removed"},
	} {
		if got := tc.e.Error(); got != tc.want {
			t.Errorf("%q, want %q", got, tc.want)
		}
		if !errors.Is(&tc.e, ErrConsistency) {
			t.Error("does not wrap ErrConsistency")
		}
	}
}
