package translog

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of task 15c finding 2: an operator log fails closed on a
// committed tree that shrank or was replaced while the process runs; a
// client log keeps rebuilding silently from its verified reference
// (TestOwnErrCleared, rework2_test.go).

// shrinkFixture is an operator log with one record of every kind and
// the records to check.
type shrinkFixture struct {
	e        *tenv
	u        *tuser
	mbx      store.ID
	ep1, adr []byte
	cert     []byte
}

func newShrinkFixture(t *testing.T) *shrinkFixture {
	t.Helper()
	e := newEnv(t, 1, 1)
	e.op = e.openServer() // with the origin, for SignHead
	x := &shrinkFixture{e: e, u: newUser(t), mbx: newMbx(t)}
	e.mustAppend(KindUser, x.u.rec(t, 1))
	x.ep1 = mkEpoch(t, x.mbx, 1, nil, x.u, 1, []store.Member{member(x.u, 1)}, t0)
	e.mustAppend(KindEpoch, x.ep1)
	x.adr = e.addr(t, "shrink@example.org", x.mbx, t0, 1)
	e.mustAppend(KindAddress, x.adr)
	var err error
	if x.cert, err = e.st.ReadPlatformFile("ingest-1.cert"); err != nil {
		t.Fatal(err)
	}
	return x
}

// checks runs Lookup, every Check method and Append on l and returns
// the error of each.
func (x *shrinkFixture) checks(t *testing.T, l Log) map[string]error {
	t.Helper()
	_, lerr := l.Lookup(KindEpoch, x.mbx[:])
	_, aerr := l.Append(KindUser, newUser(t).rec(t, 1))
	return map[string]error{
		"Lookup":                lerr,
		"CheckUser":             l.CheckUser(x.u.id, x.u.rec(t, 1)),
		"CheckGeneration":       l.CheckGeneration(x.u.id, 1),
		"CheckRevokedSignature": l.CheckRevokedSignature(x.u.id, 1, x.ep1),
		"CheckEpoch":            l.CheckEpoch(x.mbx, 1, x.ep1),
		"CheckAddress":          l.CheckAddress("shrink@example.org", x.mbx, t0),
		"CheckPlatform":         l.CheckPlatform("ingest-1.cert", x.cert),
		"Append":                aerr,
	}
}

func (x *shrinkFixture) allFail(t *testing.T, name string, l Log) {
	t.Helper()
	for m, err := range x.checks(t, l) {
		if !errors.Is(err, ErrConsistency) {
			t.Errorf("%s: %s: %v, want ErrConsistency", name, m, err)
		}
	}
}

func (x *shrinkFixture) allPass(t *testing.T, name string, l Log) {
	t.Helper()
	for m, err := range x.checks(t, l) {
		if err != nil {
			t.Errorf("%s: %s: %v", name, m, err)
		}
	}
}

// rollBack writes tree.rec with the first n entries of the committed
// tree.
func (x *shrinkFixture) rollBack(t *testing.T, n int64) {
	t.Helper()
	h, err := tlog.TreeHash(n, x.e.hashReader())
	if err != nil {
		t.Fatal(err)
	}
	if err := (&files{root: x.e.st.Root}).writeTree(treeState{Size: n, Hash: h}); err != nil {
		t.Fatal(err)
	}
}

// TestOperatorShrunkTree: tree.rec rolled back while the operator log
// runs, the entries beyond it removed and no head published, so that
// nothing in the files shows the rollback: the running process remembers
// the larger tree and refuses Lookup, every Check and Append with
// ErrConsistency instead of rebuilding its state from the smaller tree.
// A new process accepts the smaller tree (nothing in log/ contradicts
// it), as after a restart.
func TestOperatorShrunkTree(t *testing.T) {
	x := newShrinkFixture(t)
	e := x.e
	n := e.tree().Size
	x.allPass(t, "before", e.op)
	e.addresses(2)
	big := e.tree().Size
	x.rollBack(t, n)
	for i := n; i < big; i++ {
		if err := os.Remove(e.path(EntryPath(i))); err != nil {
			t.Fatal(err)
		}
	}
	x.allFail(t, "shrunk", e.op)
	// Twice: no rebuild on the second call either.
	x.allFail(t, "shrunk, again", e.op)
	if _, err := e.op.(*operatorLog).SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("SignHead: %v", err)
	}
	x.allPass(t, "new process", e.openOp())
}

// TestOperatorReplacedTree (replaces TestGetCurRebuild of task 11,
// addendum point 2): tree.rec rolled back by one and another entry
// appended at the same index by another process. The tree has the size
// this process saw but another root: the operator log of this process
// refuses (no silent rebuild); a new process accepts it.
func TestOperatorReplacedTree(t *testing.T) {
	x := newShrinkFixture(t)
	e := x.e
	e.addresses(1)
	n := e.tree().Size
	x.rollBack(t, n-1)
	other := e.openOp()
	if _, err := other.Append(KindUser, newUser(t).rec(t, 1)); err != nil {
		t.Fatal(err)
	}
	if e.tree().Size != n {
		t.Fatal("setup")
	}
	x.allFail(t, "replaced", e.op)
	// The state dropped for another reason (as after errIndex) is
	// rebuilt only into a tree that extends what the process saw.
	other.(*operatorLog).addresses(t, e, 1)
	l := e.op.(*operatorLog)
	l.cur = nil
	x.allFail(t, "grown after the replacement", e.op)
	x.allPass(t, "new process", e.openOp())
}

// TestOperatorForkedGrownTree: tree.rec rolled back by one and two other
// entries appended by another process, so that the tree is larger than
// the one this process saw but does not extend it. The cached state of
// the running process does not match (sync), and nothing is rebuilt from
// entry 0: the first call already fails.
func TestOperatorForkedGrownTree(t *testing.T) {
	x := newShrinkFixture(t)
	e := x.e
	e.addresses(1)
	x.allPass(t, "before", e.op) // appends one entry
	n := e.tree().Size
	x.rollBack(t, n-1)
	other := e.openOp()
	other.(*operatorLog).addresses(t, e, 2)
	if e.tree().Size != n+1 {
		t.Fatal("setup")
	}
	if e.op.(*operatorLog).cur == nil {
		t.Fatal("setup: no cached state")
	}
	x.allFail(t, "forked and grown", e.op)
	x.allPass(t, "new process", e.openOp())
}

// addresses appends n address assignments through o.
func (o *operatorLog) addresses(t *testing.T, e *tenv, n int) {
	t.Helper()
	mbx := newMbx(t)
	for i := 0; i < n; i++ {
		e.vf++
		if _, err := o.Append(KindAddress, e.addr(t, "grow@example.org", mbx, t0+e.vf, 1)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestOperatorRefuseInView: tree.rec rolled back below existing entries
// and below a published head, found by a process that never saw the
// larger tree (a restart): Lookup and every Check fail like Append
// (refuse in view); the published head is still served (Head). Only
// RepairTree heals, and the operator log of a new process then works;
// the process that saw the rollback keeps working once the tree is back.
func TestOperatorRefuseInView(t *testing.T) {
	for _, tc := range []struct {
		name string
		head bool
	}{{"entry beyond the next index", false}, {"published head beyond the size", true}} {
		t.Run(tc.name, func(t *testing.T) {
			x := newShrinkFixture(t)
			e := x.e
			n := e.tree().Size
			e.addresses(2)
			if tc.head {
				e.head()
			}
			big := e.tree().Size
			x.rollBack(t, n)
			if !tc.head {
				// Only the entry beyond the next index shows the
				// rollback.
				if _, err := os.Stat(e.path(EntryPath(n + 1))); err != nil {
					t.Fatal(err)
				}
			}
			restarted := e.openOp()
			x.allFail(t, "restarted", restarted)
			if tc.head {
				if h, err := e.op.Head(); err != nil || h.Size != big {
					t.Fatalf("Head of the running process: %v", err)
				}
			}
			x.allFail(t, "running", e.op)
			if err := RepairTree(Options{Store: e.st, Identities: e.p.ids(t, e.idGen)}); err != nil {
				t.Fatal(err)
			}
			if tr := e.tree(); tr.Size != big {
				t.Fatalf("repaired size %d, want %d", tr.Size, big)
			}
			x.allPass(t, "after the repair, new process", e.openOp())
			x.allPass(t, "after the repair, running process", e.op)
		})
	}
}
