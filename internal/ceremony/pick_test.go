package ceremony

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/tim-riep/go-mail/internal/witness"
)

// TestPickFixed: a fixed random source gives a known selection (task 10b
// finding 2). rand.Int(r, m) reads one byte for m <= 8 and keeps the low
// bits of 2^ceil(log2 m) - 1; with the bytes 4, 3, 2 the partial shuffle
// of [1 2 3 4 5] swaps positions 0/4, 1/4 and 2/4.
func TestPickFixed(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		k, n int
		want string
	}{
		{[]byte{4, 3, 2}, 3, 5, "[5 1 2]"},
		{[]byte{0, 0, 0}, 3, 5, "[1 2 3]"},
		{[]byte{2, 2, 2}, 3, 5, "[3 4 5]"},
		{[]byte{7, 4, 7, 3, 3, 2}, 3, 5, "[5 1 2]"}, // 7 (> 4) and 3 (> 2) are redrawn
		{[]byte{1, 0}, 2, 3, "[2 1]"},
	} {
		got, err := pick(bytes.NewReader(c.in), c.k, c.n)
		if err != nil || fmt.Sprint(got) != c.want {
			t.Fatalf("pick(%v, %d, %d) = %v, %v; want %s", c.in, c.k, c.n, got, err, c.want)
		}
	}
	if _, err := pick(bytes.NewReader([]byte{4}), 3, 5); err == nil {
		t.Fatal("short random source accepted")
	}
}

// TestPickRandom: with crypto/rand the selection varies, and every
// selection holds k distinct indices of 1..n.
func TestPickRandom(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		got, err := pick(rand.Reader, 3, 5)
		if err != nil {
			t.Fatal(err)
		}
		dup := map[int]bool{}
		for _, i := range got {
			if i < 1 || i > 5 || dup[i] {
				t.Fatalf("selection %v", got)
			}
			dup[i] = true
		}
		seen[fmt.Sprint(got)] = true
	}
	// 60 ordered selections are possible; 200 draws see far more than 2.
	if len(seen) < 2 {
		t.Fatalf("always the same selection: %v", seen)
	}
}

// TestInitProbeVaries: Init asks the probe shares chosen at random, not
// a fixed set.
func TestInitProbeVaries(t *testing.T) {
	f := &fixture{base: t.TempDir(), w: []witness.Key{witnessKey(t, "w")}}
	seen := map[string]bool{}
	for i := range 16 {
		p := &prompter{scr: &screen{}}
		o := f.opts(filepath.Join(f.base, fmt.Sprint("out", i)), filepath.Join(f.base, fmt.Sprint("keys", i)), p)
		o.MinWitnesses = 1
		o.Rand = nil
		if _, err := Init(o); err != nil {
			t.Fatal(err)
		}
		seen[fmt.Sprint(p.asked)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("the probe always asked %v", seen)
	}
}
