package translog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
)

// fullEnv returns a log with a user (2 generations), a mailbox with two
// epochs, an address and a succession, covered by a head the returned
// client accepted.
func fullEnv(t testing.TB) (*tenv, *fileLog, *Verifier) {
	t.Helper()
	e := newEnv(t, 1, 1)
	u := newUser(t)
	mbx := newMbx(t)
	e.mustAppend(KindUser, u.rec(t, 1))
	ep1 := mkEpoch(t, mbx, 1, nil, u, 1, []store.Member{member(u, 1)}, t0)
	e.mustAppend(KindEpoch, ep1)
	e.mustAppend(KindEpoch, mkEpoch(t, mbx, 2, ep1, u, 1, []store.Member{member(u, 1)}, t0+1))
	e.mustAppend(KindUser, u.rec(t, 2))
	e.mustAppend(KindAddress, e.addr(t, "a@example.org", mbx, t0, 1))
	e.mustAppend(KindPlatform, e.p.succ(t, 2, t0))
	e.head()
	c, v := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	return e, c, v
}

// reopen opens a client log with a copy of v and the index file idx.
func reopen(e *tenv, v *Verifier, idx string) (*fileLog, error) {
	nv := *v
	nv.Pending = nil
	l, err := Open(Options{Store: e.st, Verifier: &nv, IndexFile: idx})
	if err != nil {
		return nil, err
	}
	return l.(*fileLog), nil
}

// TestAuditIndex: the index is reused when it matches, rebuilt when it
// is damaged or built for another head, and never trusted beyond its
// structure checks.
func TestAuditIndex(t *testing.T) {
	e, c, v := fullEnv(t)
	idx := c.opts.IndexFile
	data, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "a@example.org") {
		t.Fatal("address in clear in the audit index")
	}
	// Reused: entry 0 is unreadable, but nothing is audited again.
	e0 := e.path(EntryPath(0))
	orig, _ := os.ReadFile(e0)
	if err := os.Remove(e0); err != nil {
		t.Fatal(err)
	}
	if _, err := reopen(e, v, idx); err != nil {
		t.Fatalf("index not reused: %v", err)
	}
	// Built for another head: rebuilt (and fails on the missing entry).
	other := *v.Last
	other.Size--
	other.Hash, _ = tlog.TreeHash(other.Size, e.hashReader())
	nv := *v
	nv.Last = &other
	if _, err := reopen(e, &nv, idx); !errors.Is(err, ErrConsistency) {
		t.Fatalf("index for another head: %v", err)
	}
	if err := os.WriteFile(e0, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	// Without Last the index is empty.
	nv.Last = nil
	l, err := reopen(e, &nv, filepath.Join(t.TempDir(), "i"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.CheckGeneration(store.ID{1}, 1); !errors.Is(err, ErrNotInLog) {
		t.Fatal(err)
	}
	// Every structural violation makes the index rebuilt.
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(m map[string]any)) []byte {
		var c map[string]any
		_ = json.Unmarshal(data, &c)
		f(c)
		b, _ := json.Marshal(c)
		return b
	}
	first := func(x any) map[string]any {
		for _, v := range x.(map[string]any) {
			return v.(map[string]any)
		}
		return nil
	}
	cases := map[string][]byte{
		"not json": []byte("{"),
		"version":  mutate(func(m map[string]any) { m["version"] = 2 }),
		"size":     mutate(func(m map[string]any) { m["size"] = -1 }),
		"size 0":   mutate(func(m map[string]any) { m["size"] = 0 }),
		"key":      mutate(func(m map[string]any) { m["valid"].(map[string]any)["user/xx/1"] = map[string]any{"i": 0} }),
		"key kind": mutate(func(m map[string]any) {
			m["valid"].(map[string]any)["x/"+strings.Repeat("0", 64)+"/1"] = map[string]any{"i": 0, "seq": 1}
		}),
		"key index":  mutate(func(m map[string]any) { first(m["valid"])["i"] = 99 }),
		"user id":    mutate(func(m map[string]any) { m["users"].(map[string]any)["x"] = first(m["users"]) }),
		"user keys":  mutate(func(m map[string]any) { first(m["users"])["idents"] = []any{} }),
		"user key":   mutate(func(m map[string]any) { first(m["users"])["idents"].([]any)[0] = "AA==" }),
		"user root":  mutate(func(m map[string]any) { first(m["users"])["root"] = "AA==" }),
		"epochs":     mutate(func(m map[string]any) { m["epochs"].(map[string]any)["x"] = 1 }),
		"epoch 0":    mutate(func(m map[string]any) { m["epochs"].(map[string]any)[store.ID{1}.String()] = 0 }),
		"address":    mutate(func(m map[string]any) { m["addresses"].(map[string]any)["x"] = []any{} }),
		"addr entry": mutate(func(m map[string]any) { setFirstList(m["addresses"], "mbx", "x") }),
		"cert":       mutate(func(m map[string]any) { first(m["certs"])["gen"] = 7 }),
		"cert role":  mutate(func(m map[string]any) { first(m["certs"])["role"] = 9 }),
		"succ":       mutate(func(m map[string]any) { first(m["succs"])["pub"] = "AA==" }),
		"invalid":    mutate(func(m map[string]any) { m["invalid"] = []any{map[string]any{"i": 99, "err": "x"}} }),
	}
	for name, b := range cases {
		if _, err := unmarshalState(b, nil, nil); !errors.Is(err, ErrConsistency) {
			t.Fatalf("%s: %v", name, err)
		}
		if err := os.WriteFile(idx, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := reopen(e, v, idx); err != nil {
			t.Fatalf("%s: not rebuilt: %v", name, err)
		}
	}
	if _, err := unmarshalState(make([]byte, MaxIndexFile+1), nil, nil); !errors.Is(err, ErrConsistency) {
		t.Fatal("index too large")
	}
	t.Run("keys", testIndexKeys)
}

// testIndexKeys (task 07b finding 5): an audit index whose keys do not
// match its entries is discarded and rebuilt, at Open (structure) and
// when an answer meets the contradiction (find, chain).
func testIndexKeys(t *testing.T) {
	e := newEnv(t, 1, 1)
	u := newUser(t)
	mbx, fresh := newMbx(t), newMbx(t)
	e.mustAppend(KindUser, u.rec(t, 1))
	ep1 := mkEpoch(t, mbx, 1, nil, u, 1, []store.Member{member(u, 1)}, t0)
	e.mustAppend(KindEpoch, ep1)
	e.head()
	c, v := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	idx := c.opts.IndexFile
	data, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	k1 := keyID(Key{Kind: KindUser, Subject: u.id[:], Seq: 1})
	k2 := keyID(Key{Kind: KindUser, Subject: u.id[:], Seq: 2})
	write := func(f func(m map[string]any)) {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		b, _ := json.Marshal(m)
		if err := os.WriteFile(idx, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := unmarshalState(b, nil, nil); !errors.Is(err, ErrConsistency) {
			t.Fatalf("index with contradicting keys accepted: %v", err)
		}
	}

	// The entry of (u, 1) copied under (u, 2): rebuilt at Open.
	write(func(m map[string]any) {
		r := m["valid"].(map[string]any)[k1].(map[string]any)
		m["valid"].(map[string]any)[k2] = map[string]any{"i": r["i"], "leaf": r["leaf"], "seq": 2}
	})
	l, err := reopen(e, v, idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.CheckGeneration(u.id, 2); !errors.Is(err, ErrNotInLog) {
		t.Fatalf("copied key: %v", err)
	}
	if err := l.CheckGeneration(u.id, 1); err != nil {
		t.Fatal(err)
	}
	// An epoch count without its entries: rebuilt at Open, the epochs of
	// the mailbox stay appendable.
	write(func(m map[string]any) {
		m["epochs"].(map[string]any)[mbx.String()] = 3
		m["epochs"].(map[string]any)[fresh.String()] = 3
	})
	if l, err = reopen(e, v, idx); err != nil {
		t.Fatal(err)
	}
	ep2 := mkEpoch(t, mbx, 2, ep1, u, 1, []store.Member{member(u, 1)}, t0+1)
	if _, err := l.Append(KindEpoch, ep2); err != nil {
		t.Fatalf("epoch 2 after a count without entries: %v", err)
	}
	if _, err := l.Append(KindEpoch, mkEpoch(t, fresh, 1, nil, u, 1, []store.Member{member(u, 1)}, t0)); err != nil {
		t.Fatalf("epoch 1 of a mailbox with a count without entries: %v", err)
	}

	// A wrong leaf passes the structure checks; the answer meets it.
	data, err = os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	write2 := func(f func(s *state)) *fileLog {
		t.Helper()
		st, err := unmarshalState(data, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		f(st)
		b, err := st.marshal()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(idx, b, 0o600); err != nil {
			t.Fatal(err)
		}
		l, err := reopen(e, v, idx)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	l = write2(func(s *state) {
		r := s.Valid[k1]
		r.Leaf[0] ^= 1
		s.Valid[k1] = r
	})
	if err := l.CheckGeneration(u.id, 1); err != nil {
		t.Fatalf("wrong leaf: %v", err)
	}
	// The leaf and index of another valid entry: the key does not match.
	l = write2(func(s *state) {
		r := s.Valid[keyID(Key{Kind: KindEpoch, Subject: mbx[:], Seq: 1})]
		r.Seq = 1
		s.Valid[k1] = r
	})
	if err := l.CheckUser(u.id, u.rec(t, 1)); err != nil {
		t.Fatalf("key of another entry: %v", err)
	}

	// The same contradictions in the index in memory (past the
	// structure checks), met by an answer: the index is rebuilt and the
	// answer comes from the log.
	l, err = reopen(e, v, idx)
	if err != nil {
		t.Fatal(err)
	}
	r := l.ref.Valid[k1]
	r.Seq = 2
	l.ref.Valid[k2] = r
	if err := l.CheckGeneration(u.id, 2); !errors.Is(err, ErrNotInLog) {
		t.Fatalf("copied key in memory: %v", err)
	}
	if _, ok := l.ref.Valid[k2]; ok {
		t.Fatal("index not rebuilt")
	}
	e.now = e.now.Add(time.Minute)
	e.head()
	if _, err := l.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	l.ref.Epochs[mbx.String()] = 3
	l.cur = nil
	ep3 := mkEpoch(t, mbx, 3, ep2, u, 1, []store.Member{member(u, 1)}, t0+2)
	if _, err := l.Append(KindEpoch, ep3); err != nil {
		t.Fatalf("epoch 3 after a count without entries in memory: %v", err)
	}
	if err := l.CheckEpoch(mbx, 2, ep2); err != nil {
		t.Fatal(err)
	}
	ep4 := mkEpoch(t, mbx, 4, ep3, u, 1, []store.Member{member(u, 1)}, t0+3)
	// The operator rebuilds its state from the committed tree.
	op := e.openOp().(*operatorLog)
	op.cur.Epochs[mbx.String()] = 4
	if err := op.CheckEpoch(mbx, 3, ep3); err != nil {
		t.Fatal(err)
	}
	if _, err := op.Append(KindEpoch, ep4); err != nil {
		t.Fatalf("operator with a count without entries: %v", err)
	}
	// A log changed below the reference head is not repaired by a
	// rebuild: ErrConsistency, and no second rebuild for the same head.
	if err := os.WriteFile(e.path(EntryPath(2)), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := l.CheckGeneration(u.id, 1); !errors.Is(err, ErrConsistency) {
			t.Fatalf("changed entry: %v", err)
		}
	}
	// A changed epoch entry is met by the chain, which cannot tell the
	// index from the files: one rebuild, which fails on the proof, and
	// none for the next call.
	if err := os.WriteFile(e.path(EntryPath(3)), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ep5 := mkEpoch(t, mbx, 5, ep4, u, 1, []store.Member{member(u, 1)}, t0+4)
	l.cur = nil // the cached chain holds epoch 3 already
	for i := 0; i < 2; i++ {
		ref := l.ref
		if _, err := l.Append(KindEpoch, ep5); !errors.Is(err, ErrConsistency) {
			t.Fatalf("changed epoch entry: %v", err)
		}
		if l.ref != ref || l.rebuilt != ref {
			t.Fatal("index replaced by a failed rebuild, or rebuilt twice")
		}
	}
}

func setFirstList(x any, key string, val any) {
	for _, v := range x.(map[string]any) {
		v.([]any)[0].(map[string]any)[key] = val
		return
	}
}

// TestClientAppend: a client appends against the committed tree (beyond
// its reference head), with a chain built from the entries.
func TestClientAppend(t *testing.T) {
	e := newEnv(t, 1, 1)
	u := newUser(t)
	mbx := newMbx(t)
	e.mustAppend(KindUser, u.rec(t, 1))
	ep1 := mkEpoch(t, mbx, 1, nil, u, 1, []store.Member{member(u, 1)}, t0)
	e.mustAppend(KindEpoch, ep1)
	e.head()
	c, v := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	ep2 := mkEpoch(t, mbx, 2, ep1, u, 1, []store.Member{member(u, 1)}, t0+1)
	e.mustAppend(KindEpoch, ep2) // by another process
	ep3 := mkEpoch(t, mbx, 3, ep2, u, 1, []store.Member{member(u, 1)}, t0+2)
	i, err := c.Append(KindEpoch, ep3)
	if err != nil || i != 5 {
		t.Fatalf("client append: %d %v", i, err)
	}
	if err := c.CheckEpoch(mbx, 3, ep3); !errors.Is(err, ErrPending) {
		t.Fatalf("own entry before a head: %v", err)
	}
	if err := c.CheckEpoch(mbx, 2, ep2); !errors.Is(err, ErrPending) {
		t.Fatalf("other entry before a head: %v", err)
	}
	if _, err := c.Entry(4); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	e.head()
	if _, err := c.Refresh(e.now); err != nil || len(v.Pending) != 0 {
		t.Fatal(err)
	}
	if err := c.CheckEpoch(mbx, 3, ep3); err != nil {
		t.Fatal(err)
	}
	// An entry below the client's head changed: its next append fails.
	ep4 := mkEpoch(t, mbx, 4, ep3, u, 1, []store.Member{member(u, 1)}, t0+3)
	e.mustAppend(KindUser, newUser(t).rec(t, 1))
	if err := os.WriteFile(e.path(EntryPath(6)), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(KindEpoch, ep4); !errors.Is(err, ErrConsistency) {
		t.Fatalf("committed entry changed: %v", err)
	}
	if err := os.Remove(e.path(EntryPath(6))); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(KindEpoch, ep4); !errors.Is(err, ErrConsistency) {
		t.Fatalf("committed entry missing: %v", err)
	}
	// tree.rec names the reference size with another hash.
	f := &files{root: e.st.Root}
	if err := f.writeTree(treeState{Size: v.Last.Size, Hash: tlog.Hash{1}}); err != nil {
		t.Fatal(err)
	}
	c.cur = nil
	if err := os.Remove(e.path(EntryPath(7))); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if _, err := c.Append(KindEpoch, ep4); !errors.Is(err, ErrConsistency) {
		t.Fatalf("tree.rec with another hash: %v", err)
	}
}

// TestInvalidClasses: entries written past Append are classified.
func TestInvalidClasses(t *testing.T) {
	e := newEnv(t, 1, 1)
	alice, mallory := newUser(t), newUser(t)
	mbx := newMbx(t)
	e.mustAppend(KindUser, alice.rec(t, 1))
	e.mustAppend(KindUser, mallory.rec(t, 1))
	ep1 := mkEpoch(t, mbx, 1, nil, alice, 1, []store.Member{member(alice, 1)}, t0)
	e.mustAppend(KindEpoch, ep1)
	other := newPlat(t)
	s3, _ := keys.NewPlatformSuccession(e.p.identity(t, 1), 2, other.identity(t, 2).Public().(ed25519PublicKey), t0)
	b3, _ := s3.Encode()
	f := &files{root: e.st.Root}
	raw := func(kind Kind, content []byte) {
		t.Helper()
		en, err := NewEntry(kind, content)
		if err != nil {
			t.Fatal(err)
		}
		enc, err := en.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (&fileLog{f: f}).write(e.tree(), en.Key, enc); err != nil {
			t.Fatal(err)
		}
	}
	raw(KindEpoch, mkEpoch(t, mbx, 2, ep1, mallory, 1, []store.Member{member(mallory, 1), member(alice, 1)}, t0+1))
	raw(KindAddress, e.addr(t, "a@example.org", mbx, t0, 5))
	raw(KindPlatform, b3)
	e.head()
	e.idGen = 2
	_ = e.st.WritePlatformFile("identity-2.succ", e.p.succ(t, 2, t0))
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range c.Invalid() {
		got = append(got, x.Class)
	}
	if strings.Join(got, ",") != "order,prerequisite,mismatch" {
		t.Fatalf("classes %v", got)
	}
	if errClass(ErrConsistency) != "consistency" {
		t.Fatal("errClass")
	}
}

// TestFiles covers the helpers of files.go.
func TestFiles(t *testing.T) {
	e := newEnv(t, 1, 1)
	f := &files{root: e.st.Root}
	if _, err := encodeTree(treeState{Size: -1}); !errors.Is(err, ErrConsistency) {
		t.Fatal("encodeTree")
	}
	if err := f.writeTree(treeState{Size: MaxTreeSize + 1}); !errors.Is(err, ErrConsistency) {
		t.Fatal("writeTree")
	}
	for _, b := range [][]byte{
		[]byte("x"),
		mustEnc(t, treeState{Size: 0, Hash: tlog.Hash{1}}),
	} {
		if _, err := decodeTree(b); !errors.Is(err, ErrConsistency) {
			t.Fatal("decodeTree")
		}
	}
	if _, err := f.readEntry(-1); !errors.Is(err, ErrNotInLog) {
		t.Fatal("readEntry")
	}
	if err := os.WriteFile(e.path(EntryPath(9)), make([]byte, MaxEntryFile+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.readEntry(9); !errors.Is(err, ErrConsistency) {
		t.Fatal("readEntry too large")
	}
	if _, _, _, err := f.readEntryLeaf(8, tlog.Hash{}); !errors.Is(err, ErrConsistency) {
		t.Fatal("readEntryLeaf of a missing entry")
	}
	if err := os.WriteFile(e.path(EntryPath(8)), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := f.readEntryLeaf(8, LeafHash([]byte("x"))); !errors.Is(err, ErrConsistency) {
		t.Fatal("readEntryLeaf of garbage")
	}
	if err := f.createOrSame("log/x", []byte("a"), 10); err != nil {
		t.Fatal(err)
	}
	if err := f.createOrSame("log/x", []byte("a"), 10); err != nil {
		t.Fatal(err)
	}
	if err := f.createOrSame("log/x", []byte("b"), 10); !errors.Is(err, ErrConsistency) {
		t.Fatal("createOrSame with other content")
	}
	for _, n := range []string{"x.sig", "01.sig", "0.sig", "3.txt"} {
		if err := os.WriteFile(e.path(HeadsDir+"/"+n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []int64{5, 2, 9} {
		if err := os.WriteFile(e.path(HeadPath(n)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := f.newestHeadSize(); err != nil || n != 9 {
		t.Fatalf("newestHeadSize %v %v", n, err)
	}
	k := Key{Kind: KindUser, Subject: []byte("s"), Seq: 1}
	if f.readKeyFile(k) != -1 {
		t.Fatal("missing key file")
	}
	if err := f.writeKeyFile(k, 3); err != nil {
		t.Fatal(err)
	}
	if err := f.writeKeyFile(k, 3); err != nil || f.readKeyFile(k) != 3 {
		t.Fatal("key file")
	}
	if err := f.writeKeyFile(k, 4); err != nil || f.readKeyFile(k) != 4 {
		t.Fatal("key file replaced")
	}
	if err := os.WriteFile(e.path(KeyPath(k)), []byte("x"), 0o644); err != nil || f.readKeyFile(k) != -1 {
		t.Fatal("garbage key file")
	}
	tr := e.tree()
	if _, err := f.leaves(tr, 1, 0); !errors.Is(err, ErrConsistency) {
		t.Fatal("leaves out of range")
	}
	if l, err := f.leaves(tr, 1, 1); err != nil || l != nil {
		t.Fatal("no leaves")
	}
	rd := &tileFiles{f: f}
	if _, err := rd.ReadTiles([]tlog.Tile{{H: 4}}); !errors.Is(err, ErrConsistency) {
		t.Fatal("tile of another height")
	}
	if _, err := rd.ReadTiles([]tlog.Tile{{H: TileHeight, W: 5}}); !errors.Is(err, ErrConsistency) {
		t.Fatal("missing tile")
	}
	if err := os.WriteFile(e.path(TilePath(tlog.Tile{H: TileHeight, W: 7})), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := rd.ReadTiles([]tlog.Tile{{H: TileHeight, W: 7}}); !errors.Is(err, ErrConsistency) {
		t.Fatal("short tile")
	}
	if _, err := (&files{root: e.st.Root}).reader(treeState{}).ReadHashes([]int64{0}); !errors.Is(err, ErrConsistency) {
		t.Fatal("hash of the empty tree")
	}
	for _, c := range []struct {
		name string
		ok   bool
	}{{"ingest-1.cert", true}, {"ingest-0.cert", false}, {"ingest-01.cert", false}, {"admin-1.cert", false},
		{"ingest-1.pub", false}, {"ingest-4294967296.cert", false}} {
		if _, ok := parseGenName(c.name, "ingest-", ".cert"); ok != c.ok {
			t.Fatalf("parseGenName %s", c.name)
		}
	}
}

func mustEnc(t *testing.T, s treeState) []byte {
	t.Helper()
	b, err := rec.New(TreeSchema).SetI64(1, s.Size).SetBytes(2, s.Hash[:]).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHeadAccess: Head and operator Refresh without heads, a head file
// of another size.
func TestHeadAccess(t *testing.T) {
	e := newEnv(t, 1, 1)
	if _, err := e.op.Head(); !errors.Is(err, ErrStale) {
		t.Fatal("Head without heads")
	}
	h := e.head()
	if err := os.Rename(e.path(HeadPath(h.Size)), e.path(HeadPath(h.Size+1))); err != nil {
		t.Fatal(err)
	}
	if _, err := e.op.Head(); !errors.Is(err, ErrHead) {
		t.Fatal("head under another size")
	}
	c, _ := e.client()
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatal("client: head under another size")
	}
	if err := os.WriteFile(e.path(HeadPath(h.Size+1)), make([]byte, MaxHeadNote+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.op.Head(); !errors.Is(err, ErrHead) {
		t.Fatal("head too large")
	}
	// The operator's checks with a head beyond its tree refuse appends.
	if _, err := e.op.Append(KindUser, newUser(t).rec(t, 1)); !errors.Is(err, ErrConsistency) {
		t.Fatal("head beyond tree.rec")
	}
	// CheckFresh of a client before any head; Verifier.Fresh errors.
	v := e.verifier()
	v.Last = &Head{Size: 1, Time: e.now.Add(time.Hour).UnixMilli()}
	if err := v.Fresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatal("Last in the future")
	}
	v.Last = &Head{Size: 0}
	if err := v.Fresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatal("Last of size 0")
	}
}
