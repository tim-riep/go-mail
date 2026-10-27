package translog

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of task 07b (docs/tasks/07b-translog-rework.md).

// TestBoundedSync (finding 1 of task 07b, finding 1 of task 07c): a
// tree.rec naming MaxTreeSize is refused before anything of that size
// is allocated, by the operator (Open and Append from an empty state),
// by a client (first Append without a head) and by every other reader
// of the committed tree; the process lives on.
// The leaf hashes are read at most one tile per call (maxLeavesPerRead),
// checked against a tree with real tiles.
func TestBoundedSync(t *testing.T) {
	if os.Getenv(boundedChildEnv) != "" {
		// Child process of runBounded: only the forged top tile, with the
		// address space bounded.
		if err := limitMemory(1 << 30); err != nil {
			t.Fatalf("limit memory: %v", err)
		}
		topTileOnly(t)
		return
	}
	t.Run("tiles missing", func(t *testing.T) {
		huge := func(e *tenv) {
			t.Helper()
			if err := (&files{root: e.st.Root}).writeTree(treeState{Size: MaxTreeSize, Hash: tlog.Hash{1}}); err != nil {
				t.Fatal(err)
			}
		}
		e := newEnv(t, 1, 1)
		huge(e)
		for i := 0; i < 2; i++ {
			if _, err := e.op.Append(KindUser, newUser(t).rec(t, 1)); !errors.Is(err, ErrConsistency) {
				t.Fatalf("operator append %d: %v", i+1, err)
			}
		}
		e2 := newEnv(t, 1, 1)
		c, _ := e2.client()
		huge(e2)
		if _, err := c.Append(KindUser, newUser(t).rec(t, 1)); !errors.Is(err, ErrConsistency) {
			t.Fatalf("client append without a head: %v", err)
		}
	})
	t.Run("every reader", func(t *testing.T) {
		// tree.rec forged after Open, with a hash of nothing and with the
		// root of the real tree: every reader of the committed tree
		// fails closed, and a client keeps its reference head.
		e := newEnv(t, 1, 1)
		e.head()
		c, _ := e.client()
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatal(err)
		}
		want := func(what string, err, want error) {
			t.Helper()
			if !errors.Is(err, want) || errors.Is(err, ErrIO) {
				t.Fatalf("%s: want %v, got %v", what, want, err)
			}
		}
		f := &files{root: e.st.Root}
		for _, hash := range []tlog.Hash{{1}, e.tree().Hash} {
			if err := f.writeTree(treeState{Size: MaxTreeSize, Hash: hash}); err != nil {
				t.Fatal(err)
			}
			_, err := e.op.Append(KindUser, newUser(t).rec(t, 1))
			want("operator append", err, ErrConsistency)
			_, err = c.Append(KindUser, newUser(t).rec(t, 1))
			want("client append", err, ErrConsistency)
			_, err = c.Entry(5)
			want("client entry beyond the head", err, ErrPending)
			_, err = e.op.Entry(5)
			want("operator entry", err, ErrConsistency)
			_, err = e.op.InclusionProof(0, MaxTreeSize)
			want("operator inclusion proof", err, ErrConsistency)
			_, err = e.op.ConsistencyProof(1, MaxTreeSize)
			want("operator consistency proof", err, ErrConsistency)
			want("operator check", e.op.CheckGeneration(newUser(t).id, 1), ErrConsistency)
			_, err = Open(Options{Store: e.st, Identities: e.p.ids(t, 1)})
			want("operator open", err, ErrConsistency)
			e.publish(&Head{Origin: testOrigin, Size: MaxTreeSize, Hash: hash, Time: e.now.UnixMilli()}, e.all()...)
			_, err = c.Refresh(e.now)
			want("client refresh with a head of the forged size", err, ErrConsistency)
			if c.v.Last.Size == MaxTreeSize {
				t.Fatal("forged head taken over")
			}
		}
	})
	t.Run("leaves per read", func(t *testing.T) {
		// A tree of 300 records with every tile in place: leaves reads
		// up to maxLeavesPerRead records, across a tile boundary as well,
		// and refuses one more although the tiles would deliver it.
		f := &files{root: t.TempDir()}
		tree, want := syntheticTree(t, f, 300)
		for _, r := range [][2]int64{{0, maxLeavesPerRead}, {44, 300}, {299, 300}, {7, 7}} {
			got, err := f.leaves(tree, r[0], r[1])
			if err != nil || len(got) != int(r[1]-r[0]) || len(got) > 0 && !reflect.DeepEqual(got, want[r[0]:r[1]]) {
				t.Fatalf("leaves %d to %d: %v", r[0], r[1], err)
			}
		}
		for _, r := range [][2]int64{{0, maxLeavesPerRead + 1}, {0, 300}, {-1, 5}, {5, 4}, {290, 301}} {
			if _, err := f.leaves(tree, r[0], r[1]); !errors.Is(err, ErrConsistency) {
				t.Fatalf("leaves %d to %d: %v", r[0], r[1], err)
			}
		}
	})
	t.Run("top tile only", func(t *testing.T) { runBounded(t, topTileOnly) })

	// A client that brings its state across a tile boundary, one tile
	// per read: TestManyEntries.
}

// boundedChildEnv marks the child process of runBounded.
const boundedChildEnv = "TRANSLOG_TEST_BOUNDED_CHILD"

// runBounded runs fn in a child process (this test binary, running only
// TestBoundedSync) whose address space is limited like "ulimit -v"
// (limitMemory), so that an allocation of the size of a forged tree
// kills the child with "out of memory" and fails this test instead of
// the machine. Under the race detector, which needs a large address
// space, and where the limit is not supported, fn runs in this process.
func runBounded(t *testing.T, fn func(*testing.T)) {
	if raceEnabled || !memLimitSupported {
		fn(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestBoundedSync$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), boundedChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("--- PASS: TestBoundedSync")) {
		if len(out) > 4096 {
			out = out[:4096] // a fatal error comes first, the stacks after it
		}
		t.Fatalf("bounded child: %v\n%s", err, out)
	}
}

// topTileOnly (task 07c finding 1): tree.rec names MaxTreeSize with a
// root hash H, and the only tile is the top tile tile/8/5/000.p/1 with
// the content H. tlog.TreeHash reads exactly that hash, so the tile
// check of Open and sync passes; then only the bound per read keeps the
// leaf read from an allocation of the size of the tree.
func topTileOnly(t *testing.T) {
	e := newEnv(t, 1, 1)
	c, _ := e.client()
	f := &files{root: e.st.Root}
	root := tlog.Hash{7}
	if err := f.writeTree(treeState{Size: MaxTreeSize, Hash: root}); err != nil {
		t.Fatal(err)
	}
	top := tlog.Tile{H: TileHeight, L: 5, N: 0, W: 1}
	if err := f.createOrSame(TilePath(top), root[:], maxTileFile); err != nil {
		t.Fatal(err)
	}
	if h, err := tlog.TreeHash(MaxTreeSize, f.reader(treeState{Size: MaxTreeSize, Hash: root})); err != nil || h != root {
		t.Fatalf("the top tile does not prove the forged tree: %v", err)
	}
	if _, err := Open(Options{Store: e.st, Identities: e.p.ids(t, 1)}); !errors.Is(err, ErrConsistency) {
		t.Fatalf("operator open: %v", err)
	}
	// The first Append starts from the operator's state, the second from
	// an empty one (the first one discarded it).
	for i := 0; i < 2; i++ {
		if _, err := e.op.Append(KindUser, newUser(t).rec(t, 1)); !errors.Is(err, ErrConsistency) {
			t.Fatalf("operator append %d: %v", i+1, err)
		}
	}
	if _, err := c.Append(KindUser, newUser(t).rec(t, 1)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("client append without a head: %v", err)
	}
}

// syntheticTree writes the tiles of a tree of n records (record i is
// the two bytes of i) under f and returns the tree and its leaf hashes.
func syntheticTree(t *testing.T, f *files, n int64) (treeState, []tlog.Hash) {
	t.Helper()
	var stored, leaves []tlog.Hash
	rd := tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(idx))
		for i, x := range idx {
			out[i] = stored[x]
		}
		return out, nil
	})
	for i := int64(0); i < n; i++ {
		data := []byte{byte(i), byte(i >> 8)}
		leaves = append(leaves, tlog.RecordHash(data))
		hs, err := tlog.StoredHashes(i, data, rd)
		if err != nil {
			t.Fatal(err)
		}
		stored = append(stored, hs...)
	}
	for _, tile := range tlog.NewTiles(TileHeight, 0, n) {
		data, err := tlog.ReadTileData(tile, rd)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.createOrSame(TilePath(tile), data, maxTileFile); err != nil {
			t.Fatal(err)
		}
	}
	h, err := tlog.TreeHash(n, rd)
	if err != nil {
		t.Fatal(err)
	}
	return treeState{Size: n, Hash: h}, leaves
}

// refreshState is what a failed Refresh must leave unchanged.
type refreshState struct {
	last    *Head
	ref     *state
	pending []Pending
	keys    []LogKey
	index   []byte
}

func takeRefreshState(t *testing.T, c *fileLog, v *Verifier) refreshState {
	t.Helper()
	idx, err := os.ReadFile(c.opts.IndexFile)
	if err != nil {
		t.Fatal(err)
	}
	return refreshState{last: v.Last, ref: c.ref, pending: append([]Pending(nil), v.Pending...),
		keys: append([]LogKey(nil), v.LogKeys...), index: idx}
}

func (a refreshState) same(t *testing.T, b refreshState) {
	t.Helper()
	switch {
	case a.last != b.last:
		t.Fatal("Verifier.Last changed")
	case a.ref != b.ref:
		t.Fatal("reference index changed")
	case !reflect.DeepEqual(a.pending, b.pending):
		t.Fatal("Verifier.Pending changed")
	case len(a.keys) != len(b.keys):
		t.Fatal("Verifier.LogKeys changed")
	case !bytes.Equal(a.index, b.index):
		t.Fatal("index file changed")
	}
}

// TestRefreshCommit (finding 2): Refresh takes nothing over before the
// audit, the check of every covered Pending entry, CheckHead and the
// index file have succeeded; an own entry found replaced keeps
// CheckFresh failing.
func TestRefreshCommit(t *testing.T) {
	t.Run("pending leaf", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		e.head()
		c, v := e.client()
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Append(KindUser, newUser(t).rec(t, 1)); err != nil {
			t.Fatal(err)
		}
		v.Pending[0].Leaf[0] ^= 1
		before := takeRefreshState(t, c, v)
		e.now = e.now.Add(time.Minute)
		h := e.head()
		for i := 0; i < 2; i++ {
			if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
				t.Fatalf("refresh %d: %v", i+1, err)
			}
			before.same(t, takeRefreshState(t, c, v))
			if err := c.CheckFresh(e.now); !errors.Is(err, ErrConsistency) {
				t.Fatalf("CheckFresh after a replaced own entry: %v", err)
			}
		}
		// With the leaf the entry was appended with, the same head is
		// taken over.
		v.Pending[0].Leaf[0] ^= 1
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatal(err)
		}
		if v.Last.Size != h.Size || len(v.Pending) != 0 || c.ref.Size != h.Size {
			t.Fatal("head not taken over")
		}
		if err := c.CheckFresh(e.now); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("rollback by one", func(t *testing.T) {
		// The real case: tree.rec rolled back by one before a head
		// covered the own entry, and another writer's Append took the
		// index (the own entry was removed as a leftover).
		e := newEnv(t, 1, 1)
		e.head()
		c, v := e.client()
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatal(err)
		}
		u := newUser(t)
		i, err := c.Append(KindUser, u.rec(t, 1))
		if err != nil {
			t.Fatal(err)
		}
		h, err := tlog.TreeHash(i, e.hashReader())
		if err != nil {
			t.Fatal(err)
		}
		if err := (&files{root: e.st.Root}).writeTree(treeState{Size: i, Hash: h}); err != nil {
			t.Fatal(err)
		}
		if j, err := e.openOp().Append(KindUser, newUser(t).rec(t, 1)); err != nil || j != i {
			t.Fatalf("foreign append: %d %v", j, err)
		}
		before := takeRefreshState(t, c, v)
		e.now = e.now.Add(time.Minute)
		e.head()
		if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("refresh: %v", err)
		}
		before.same(t, takeRefreshState(t, c, v))
		if err := c.CheckFresh(e.now); err == nil {
			t.Fatal("CheckFresh nil after the own entry was replaced")
		}
		if err := c.CheckUser(u.id, u.rec(t, 1)); err == nil {
			t.Fatal("replaced own entry checks")
		}
	})
	t.Run("index file", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		e.head()
		dir := filepath.Join(t.TempDir(), "client")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		v := e.verifier()
		l, err := Open(Options{Store: e.st, Verifier: v, IndexFile: filepath.Join(dir, "index.json")})
		if err != nil {
			t.Fatal(err)
		}
		c := l.(*fileLog)
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatal(err)
		}
		u := newUser(t)
		e.mustAppend(KindUser, u.rec(t, 1))
		e.now = e.now.Add(time.Minute)
		h := e.head()
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		last, ref := v.Last, c.ref
		if _, err := c.Refresh(e.now); !errors.Is(err, ErrIO) || errors.Is(err, ErrConsistency) {
			t.Fatalf("refresh without the index directory: %v", err)
		}
		if v.Last != last || c.ref != ref {
			t.Fatal("head taken over without the index")
		}
		if err := c.CheckUser(u.id, u.rec(t, 1)); !errors.Is(err, ErrNotInLog) {
			t.Fatalf("entry beyond the reference head: %v", err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatalf("refresh after the repair: %v", err)
		}
		if v.Last.Size != h.Size {
			t.Fatal("head not taken over")
		}
		if err := c.CheckUser(u.id, u.rec(t, 1)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("covered pending", func(t *testing.T) {
		// Fresh does not skip a Pending entry that Last covers; Refresh
		// checks and drops it, with or without a published head.
		e := newEnv(t, 1, 1)
		e.head()
		c, v := e.client()
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatal(err)
		}
		i, err := c.Append(KindUser, newUser(t).rec(t, 1))
		if err != nil {
			t.Fatal(err)
		}
		e.now = e.now.Add(time.Minute)
		e.head()
		if _, err := c.Refresh(e.now); err != nil || len(v.Pending) != 0 {
			t.Fatalf("refresh: %v", err)
		}
		data, err := os.ReadFile(e.path(EntryPath(i)))
		if err != nil {
			t.Fatal(err)
		}
		covered := []Pending{{Index: i, Leaf: LeafHash(data), At: e.now.UnixMilli()}}
		for _, heads := range []bool{true, false} {
			if !heads {
				if err := os.RemoveAll(e.path(HeadsDir)); err != nil {
					t.Fatal(err)
				}
			}
			v.Pending = append([]Pending(nil), covered...)
			if err := c.CheckFresh(e.now); !errors.Is(err, ErrConsistency) {
				t.Fatalf("covered Pending entry skipped: %v", err)
			}
			if _, err := c.Refresh(e.now); err != nil || len(v.Pending) != 0 {
				t.Fatalf("heads %v: %v %v", heads, err, v.Pending)
			}
			if err := c.CheckFresh(e.now); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// TestFileErrors (finding 3): every error of the file system leaves the
// package wrapping exactly one documented error: ErrConsistency under
// log/, ErrIO for the audit index.
func TestFileErrors(t *testing.T) {
	consistency := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, ErrConsistency) || errors.Is(err, ErrIO) {
			t.Fatalf("want ErrConsistency: %v", err)
		}
	}
	t.Cleanup(func() { crashHook = nil })
	for _, d := range []string{HeadsDir, KeysDir} {
		t.Run(d+" is a file at open", func(t *testing.T) {
			st, err := store.Init(filepath.Join(t.TempDir(), "data"))
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(st.Root, filepath.FromSlash(d))
			if err := store.MkdirAll(filepath.Dir(p)); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err = Open(Options{Store: st, Identities: newPlat(t).ids(t, 1)})
			consistency(t, err)
		})
		t.Run(d+" is a file", func(t *testing.T) {
			e := newEnv(t, 1, 1)
			e.head()
			c, _ := e.client()
			if err := os.RemoveAll(e.path(d)); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(e.path(d), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := e.op.Append(KindUser, newUser(t).rec(t, 1))
			consistency(t, err)
			if d == HeadsDir {
				_, err = c.Refresh(e.now)
				consistency(t, err)
				_, err = e.op.Head()
				consistency(t, err)
			}
		})
	}
	t.Run("directory at the key file", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		u := newUser(t)
		p := e.path(KeyPath(Key{Kind: KindUser, Subject: u.id[:], Seq: 1}))
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := e.op.Append(KindUser, u.rec(t, 1))
		consistency(t, err)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if _, err := e.op.Append(KindUser, u.rec(t, 1)); err != nil {
			t.Fatalf("append after the repair: %v", err)
		}
	})
	t.Run("entries is a file", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		if err := os.RemoveAll(e.path(EntriesDir)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(e.path(EntriesDir), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := e.op.Append(KindUser, newUser(t).rec(t, 1))
		consistency(t, err)
	})
	leftover := func(t *testing.T, rel func(n int64) string) {
		e := newEnv(t, 1, 1)
		p := e.path(rel(e.tree().Size))
		if err := os.MkdirAll(filepath.Join(p, "x"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := e.op.Append(KindUser, newUser(t).rec(t, 1))
		consistency(t, err)
	}
	t.Run("leftover entry", func(t *testing.T) { leftover(t, EntryPath) })
	t.Run("leftover tile", func(t *testing.T) {
		leftover(t, func(n int64) string { return TilePath(tlog.NewTiles(TileHeight, n, n+1)[0]) })
	})
	t.Run("tile directory is a file", func(t *testing.T) {
		// A fresh log: the tile of entry 0 has no directory yet.
		st, err := store.Init(filepath.Join(t.TempDir(), "data"))
		if err != nil {
			t.Fatal(err)
		}
		p := newPlat(t)
		l, err := Open(Options{Store: st, Identities: p.ids(t, 1)})
		if err != nil {
			t.Fatal(err)
		}
		tile := filepath.Join(st.Root, filepath.FromSlash(TilePath(tlog.NewTiles(TileHeight, 0, 1)[0])))
		crashHook = func(step string) error {
			if step == "entry" {
				if err := store.MkdirAll(filepath.Dir(filepath.Dir(tile))); err != nil {
					return err
				}
				return os.WriteFile(filepath.Dir(tile), nil, 0o644)
			}
			return nil
		}
		_, err = l.Append(KindPlatform, p.cert(t, keys.RoleAdmin, 1, 1, t0))
		crashHook = nil
		consistency(t, err)
	})
	t.Run("tree.rec is a directory at the commit", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		crashHook = func(step string) error {
			if step == "key" {
				if err := os.Remove(e.path(TreeFile)); err != nil {
					return err
				}
				return os.MkdirAll(e.path(TreeFile+"/x"), 0o755)
			}
			return nil
		}
		_, err := e.op.Append(KindUser, newUser(t).rec(t, 1))
		crashHook = nil
		consistency(t, err)
	})
	t.Run("index file at open", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		_, err := Open(Options{Store: e.st, Verifier: e.verifier(), IndexFile: filepath.Join(t.TempDir(), "missing", "index.json")})
		if !errors.Is(err, ErrIO) || errors.Is(err, ErrConsistency) {
			t.Fatalf("want ErrIO: %v", err)
		}
	})
	if errors.Is(ErrIO, ErrConsistency) || errors.Is(ErrConsistency, ErrIO) {
		t.Fatal("ErrIO and ErrConsistency must stay apart")
	}
}

// TestOptionsNow (finding 4): Options.Now is the clock of a client log
// and of its Verifier.
func TestOptionsNow(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.head()
	clock := func() time.Time { return e.now }
	for _, vnow := range []func() time.Time{nil, func() time.Time { return time.UnixMilli(t0 - 10*day) }} {
		v := e.verifier()
		v.Now = vnow
		l, err := Open(Options{Store: e.st, Verifier: v, IndexFile: filepath.Join(t.TempDir(), "i"), Now: clock})
		if err != nil {
			t.Fatal(err)
		}
		if v.Now == nil || !v.Now().Equal(e.now) {
			t.Fatal("Options.Now not copied into the Verifier")
		}
		if _, err := l.Refresh(e.now); err != nil {
			t.Fatalf("refresh with Options.Now: %v", err)
		}
	}
}

// TestEntryMissing (finding 6): an entry file missing below the
// reference size or the committed size is ErrConsistency.
func TestEntryMissing(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.mustAppend(KindUser, newUser(t).rec(t, 1))
	e.head()
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.path(EntryPath(2))); err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]Log{"client": c, "operator": e.op} {
		if _, err := l.Entry(2); !errors.Is(err, ErrConsistency) || errors.Is(err, ErrNotInLog) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := l.Entry(3); !errors.Is(err, ErrNotInLog) {
			t.Fatalf("%s beyond the tree: %v", name, err)
		}
	}
}

// TestNewestHeadSize (finding 7 of task 07b, task 07d): the scan of
// heads/ grows linearly with the number of heads. 4,000 and 40,000
// heads are each scanned five times, interleaved so that load on the
// machine hits both sizes alike, and the best runs are compared: ten
// times the heads may take at most 40 times as long (linear: about 10;
// the insertion sort of task 07, quadratic: about 100, half a second
// for 40,000 heads). The absolute bound of 2 s (5 s with the race
// detector) only catches a hang; it does not measure the machine.
func TestNewestHeadSize(t *testing.T) {
	const small, large = 4000, 40000
	mk := func(n int) *files {
		f := &files{root: t.TempDir()}
		if err := os.MkdirAll(f.path(HeadsDir), 0o755); err != nil {
			t.Fatal(err)
		}
		for i := n; i >= 1; i-- {
			if err := os.WriteFile(filepath.Join(f.path(HeadsDir), fmt.Sprintf("%d.sig", i)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return f
	}
	fSmall, fLarge := mk(small), mk(large)
	scan := func(f *files, n int64) time.Duration {
		start := time.Now()
		size, err := f.newestHeadSize()
		d := time.Since(start)
		if err != nil || size != n {
			t.Fatalf("newest head %d %v, want %d", size, err, n)
		}
		return d
	}
	bestS, bestL := time.Hour, time.Hour
	for i := 0; i < 5; i++ {
		bestS = min(bestS, scan(fSmall, small))
		bestL = min(bestL, scan(fLarge, large))
	}
	limit := 2 * time.Second
	if raceEnabled {
		limit = 5 * time.Second
	}
	ratio := float64(bestL) / float64(max(bestS, time.Nanosecond))
	t.Logf("best of five: %d heads %v, %d heads %v, ratio %.1f (limit 40, absolute limit %v)", small, bestS, large, bestL, ratio, limit)
	if ratio > 40 {
		t.Fatalf("%d heads took %.1f times as long as %d heads (%v against %v): not linear", large, ratio, small, bestL, bestS)
	}
	if bestL >= limit {
		t.Fatalf("%d heads took %v (limit %v)", large, bestL, limit)
	}
}

// TestWitnessKeyOnce (finding 8): one witness key under two names does
// not satisfy MinWitnesses = 2; a witness verifier whose key is unknown
// is refused.
func TestWitnessKeyOnce(t *testing.T) {
	e := newEnv(t, 1, 1)
	w := e.ws[0]
	other, err := NewWitnessVerifier("other-name", w.pub)
	if err != nil {
		t.Fatal(err)
	}
	v := e.verifier()
	v.Witnesses = append(v.Witnesses, other)
	v.MinWitnesses = 2
	if _, err := Open(Options{Store: e.st, Verifier: v, IndexFile: filepath.Join(t.TempDir(), "i")}); !errors.Is(err, ErrWitness) {
		t.Fatalf("one key under two names: %v", err)
	}
	h := e.headOf(e.now.UnixMilli())
	h.Note = sign(t, h, e.signer, w.signer, &edSigner{name: "other-name", hash: other.KeyHash(), priv: w.signer.(*edSigner).priv})
	if err := v.CheckHead(h, nil); !errors.Is(err, ErrWitness) {
		t.Fatalf("CheckHead: %v", err)
	}
	vkey, err := note.NewEd25519VerifierKey(w.name, w.pub)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	v = e.verifier()
	v.Witnesses = []note.Verifier{plain}
	if _, err := Open(Options{Store: e.st, Verifier: v, IndexFile: filepath.Join(t.TempDir(), "i")}); !errors.Is(err, ErrWitness) {
		t.Fatalf("witness verifier without its key: %v", err)
	}
}
