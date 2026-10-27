package translog

import (
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

// hugeSizes are the sizes for which tlog.CheckTree and tlog.CheckRecord
// never return (finding A5 of task 03b).
var hugeSizes = []int64{1<<62 + 1, math.MaxInt64}

// noHang runs f and fails the test if it does not return within a few
// seconds; f must return an error wrapping want.
func noHang(t *testing.T, name string, want error, f func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("%s: got %v, want %v", name, err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: did not return (tlog called with an unbounded size)", name)
	}
}

// memTree is a small tlog tree in memory for proofs.
type memTree struct{ hashes []tlog.Hash }

func (m *memTree) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	for i, x := range idx {
		out[i] = m.hashes[x]
	}
	return out, nil
}

func (m *memTree) add(t *testing.T, data []byte) tlog.Hash {
	t.Helper()
	hs, err := tlog.StoredHashes(m.size(), data, m)
	if err != nil {
		t.Fatal(err)
	}
	m.hashes = append(m.hashes, hs...)
	return LeafHash(data)
}

func (m *memTree) size() int64 {
	// Count records: the smallest n with StoredHashCount(n) == len.
	var n int64
	for tlog.StoredHashCount(n) < int64(len(m.hashes)) {
		n++
	}
	return n
}

func TestSizeLimits(t *testing.T) {
	if MaxTreeSize != 1<<40 {
		t.Fatal("MaxTreeSize")
	}
	// Heads.
	h := testHead()
	h.Size = MaxTreeSize
	text, err := h.Text()
	if err != nil {
		t.Fatal(err)
	}
	if p, err := ParseHeadText(text); err != nil || p.Size != MaxTreeSize {
		t.Fatal("largest size refused", err)
	}
	hash := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	for _, size := range append([]int64{MaxTreeSize + 1}, hugeSizes...) {
		if _, err := ParseHeadText([]byte("o\n" + strconv.FormatInt(size, 10) + "\n" + hash + "\ntime 1\n")); !errors.Is(err, ErrHead) {
			t.Fatalf("head of size %d accepted", size)
		}
		h.Size = size
		if _, err := h.Text(); !errors.Is(err, ErrHead) {
			t.Fatalf("head of size %d formatted", size)
		}
	}
	// Entry indices.
	r := makeRecords(t)
	e, _ := NewEntry(KindEpoch, r.epoch)
	enc, _ := e.Encode()
	if _, err := DecodeEntry(enc, MaxTreeSize-1); err != nil {
		t.Fatal("largest index refused", err)
	}
	for _, idx := range append([]int64{-1, MaxTreeSize}, hugeSizes...) {
		if _, err := DecodeEntry(enc, idx); !errors.Is(err, ErrEntry) {
			t.Fatalf("index %d accepted", idx)
		}
	}
	// Proofs: an error, never a hang.
	var zero tlog.Hash
	for _, size := range hugeSizes {
		size := size
		noHang(t, "CheckTreeProof", ErrConsistency, func() error {
			return CheckTreeProof(tlog.TreeProof{zero}, size, zero, 1, zero)
		})
		noHang(t, "CheckTreeProof old", ErrConsistency, func() error {
			return CheckTreeProof(tlog.TreeProof{zero}, size, zero, size-1, zero)
		})
		noHang(t, "CheckRecordProof", ErrConsistency, func() error {
			return CheckRecordProof(tlog.RecordProof{zero}, size, zero, 0, zero)
		})
		noHang(t, "CheckRecordProof index", ErrConsistency, func() error {
			return CheckRecordProof(tlog.RecordProof{zero}, size, zero, size-1, zero)
		})
	}
	for _, c := range []struct{ n, m int64 }{{1, 0}, {1, 2}, {0, 0}, {MaxTreeSize + 1, 1}} {
		if err := CheckTreeProof(nil, c.n, zero, c.m, zero); !errors.Is(err, ErrConsistency) {
			t.Fatalf("tree sizes %d %d accepted", c.n, c.m)
		}
	}
	for _, c := range []struct{ t, n int64 }{{1, 1}, {1, -1}, {0, 0}, {MaxTreeSize + 1, 0}} {
		if err := CheckRecordProof(nil, c.t, zero, c.n, zero); !errors.Is(err, ErrConsistency) {
			t.Fatalf("record %d of %d accepted", c.n, c.t)
		}
	}
}

func TestProofs(t *testing.T) {
	var m memTree
	var leaves []tlog.Hash
	for i := 0; i < 9; i++ {
		leaves = append(leaves, m.add(t, []byte{byte(i), 'x'}))
	}
	th4, err := tlog.TreeHash(4, &m)
	if err != nil {
		t.Fatal(err)
	}
	th9, err := tlog.TreeHash(9, &m)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := tlog.ProveTree(9, 4, &m)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckTreeProof(tp, 9, th9, 4, th4); err != nil {
		t.Fatal(err)
	}
	if err := CheckTreeProof(tp, 9, th9, 4, th9); !errors.Is(err, ErrConsistency) {
		t.Fatal("wrong old hash accepted")
	}
	rp, err := tlog.ProveRecord(9, 6, &m)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckRecordProof(rp, 9, th9, 6, leaves[6]); err != nil {
		t.Fatal(err)
	}
	if err := CheckRecordProof(rp, 9, th9, 6, leaves[5]); !errors.Is(err, ErrConsistency) {
		t.Fatal("wrong leaf accepted")
	}
}

func TestQuorum(t *testing.T) {
	for _, c := range []struct {
		min, n int
		ok     bool
	}{
		{1, 1, true}, {2, 3, true}, {3, 3, true}, {3, 4, true}, {2, 2, true}, {3, 5, true},
		{1, 2, false}, {2, 4, false}, {1, 3, false}, {0, 1, false}, {2, 1, false}, {0, 0, false}, {1, 0, false},
	} {
		err := CheckQuorum(c.min, c.n)
		if (err == nil) != c.ok {
			t.Fatalf("%d of %d: %v", c.min, c.n, err)
		}
		if err != nil && !errors.Is(err, ErrWitness) {
			t.Fatal("quorum error must be ErrWitness")
		}
	}
}

func TestErrorTaxonomy(t *testing.T) {
	if !errors.Is(ErrWithheld, ErrStale) {
		t.Fatal("ErrWithheld must be an ErrStale")
	}
	if errors.Is(ErrPrerequisite, ErrOrder) || errors.Is(ErrOrder, ErrPrerequisite) || errors.Is(ErrPrerequisite, ErrNotInLog) {
		t.Fatal("ErrPrerequisite (transient) and ErrOrder (permanent) must stay apart")
	}
}
