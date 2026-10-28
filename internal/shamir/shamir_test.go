package shamir

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"testing"
)

func testSecret() []byte {
	s := sha256.Sum256([]byte("gomail shamir test secret"))
	return s[:]
}

func TestSplitInvalid(t *testing.T) {
	secret := testSecret()
	cases := []struct {
		name   string
		secret []byte
		k, n   int
		err    error
	}{
		{"threshold above count", secret, 4, 3, ErrParams},
		{"threshold 1", secret, 1, 3, ErrParams},
		{"threshold 0", secret, 0, 3, ErrParams},
		{"count 0", secret, 0, 0, ErrParams},
		{"count 256", secret, 2, 256, ErrParams},
		{"threshold 256", secret, 256, 256, ErrParams},
		{"negative", secret, -1, 3, ErrParams},
		{"secret too short", secret[:31], 2, 3, ErrSecretSize},
		{"secret too long", append(secret, 0), 2, 3, ErrSecretSize},
		{"nil secret", nil, 2, 3, ErrSecretSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shares, err := Split(tc.secret, tc.k, tc.n, nil)
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if shares != nil {
				t.Fatal("no shares on error")
			}
		})
	}
	// Exhausted random source.
	if _, err := Split(secret, 2, 3, bytes.NewReader([]byte{1, 2})); err == nil {
		t.Fatal("short random source must fail")
	}
	if _, err := Split(secret, 2, 3, iotest{}); err == nil {
		t.Fatal("failing random source must fail")
	}
}

type iotest struct{}

func (iotest) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestSplitCombine(t *testing.T) {
	secret := testSecret()
	shares, err := Split(secret, 3, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares", len(shares))
	}
	for i, s := range shares {
		if s.Index != uint8(i+1) || s.Threshold != 3 || s.ID != shares[0].ID {
			t.Fatalf("share %d has unexpected metadata %+v", i, s)
		}
		if bytes.Equal(s.Y[:], secret) {
			t.Fatal("a share must not equal the secret")
		}
	}
	got, err := Combine(shares)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("all shares: wrong secret")
	}
	got, err = Combine(shares[2:])
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("three shares: %v", err)
	}
	// Two splits of the same secret differ (fresh randomness and ID).
	again, _ := Split(secret, 3, 5, nil)
	if again[0].ID == shares[0].ID && again[0].Y == shares[0].Y {
		t.Fatal("split is not randomized")
	}
}

func combos(n, k int) [][]int {
	var out [][]int
	var rec func(start int, cur []int)
	rec = func(start int, cur []int) {
		if len(cur) == k {
			out = append(out, append([]int(nil), cur...))
			return
		}
		for i := start; i < n; i++ {
			rec(i+1, append(cur, i))
		}
	}
	rec(0, nil)
	return out
}

func pick(shares []*Share, idx []int) []*Share {
	out := make([]*Share, len(idx))
	for i, j := range idx {
		out[i] = shares[j]
	}
	return out
}

// TestThresholdProperty: every combination of k out of n shares yields
// the secret; every combination of k-1 shares never does.
func TestThresholdProperty(t *testing.T) {
	secret := testSecret()
	for _, kn := range [][2]int{{2, 2}, {2, 3}, {3, 5}, {5, 5}, {3, 7}, {4, 6}} {
		k, n := kn[0], kn[1]
		shares, err := Split(secret, k, n, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range combos(n, k) {
			got, err := Combine(pick(shares, c))
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("%d of %d: combination %v failed: %v", k, n, c, err)
			}
		}
		for _, c := range combos(n, k-1) {
			sel := pick(shares, c)
			if got, err := Combine(sel); !errors.Is(err, ErrInsufficient) || got != nil {
				t.Fatalf("%d of %d: %d shares must be insufficient, got %v", k, n, k-1, err)
			}
			// Even the raw interpolation of k-1 shares yields something
			// else; the secret is information-theoretically hidden.
			if bytes.Equal(interpolateShares(sel), secret) {
				t.Fatalf("%d of %d: %d shares revealed the secret", k, n, k-1)
			}
		}
	}
}

func TestCombineInvalid(t *testing.T) {
	secret := testSecret()
	a, _ := Split(secret, 2, 3, nil)
	b, _ := Split(secret, 2, 3, nil)
	c, _ := Split(secret, 3, 4, nil)
	dupIndex := *a[0]
	dupIndex.Y[0] ^= 1
	zeroIndex := *a[1]
	zeroIndex.Index = 0
	badThreshold := *a[1]
	badThreshold.Threshold = 1
	cases := []struct {
		name   string
		shares []*Share
		err    error
	}{
		{"none", nil, ErrInsufficient},
		{"one", a[:1], ErrInsufficient},
		{"nil share", []*Share{a[0], nil}, ErrShare},
		{"duplicate share", []*Share{a[0], a[0]}, ErrDuplicate},
		{"duplicate index different y", []*Share{a[0], &dupIndex}, ErrDuplicate},
		{"index zero", []*Share{a[0], &zeroIndex}, ErrShare},
		{"threshold below 2", []*Share{a[0], &badThreshold}, ErrShare},
		{"mixed sets", []*Share{a[0], b[1]}, ErrMismatch},
		{"mixed thresholds", []*Share{c[0], c[1], a[2]}, ErrMismatch},
		{"insufficient for threshold 3", c[:2], ErrInsufficient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Combine(tc.shares)
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if got != nil {
				t.Fatal("no secret on error")
			}
		})
	}
}

func TestCombineWithTamperedShareGivesOtherSecret(t *testing.T) {
	// There is no integrity check on the secret itself: a tampered share
	// yields a different value without error. Callers must verify the
	// reconstructed secret by other means (specification: trial
	// reconstruction in the ceremony).
	secret := testSecret()
	shares, _ := Split(secret, 2, 3, nil)
	x := *shares[1]
	x.Y[5] ^= 0x10
	got, err := Combine([]*Share{shares[0], &x})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, secret) {
		t.Fatal("tampered share reproduced the secret")
	}
}

func TestShareBytesAndWords(t *testing.T) {
	secret := testSecret()
	shares, _ := Split(secret, 3, 5, nil)
	for _, s := range shares {
		b := s.Bytes()
		if len(b) != ShareSize || b[0] != shareVersion {
			t.Fatalf("unexpected share bytes %x", b)
		}
		back, err := ShareFromBytes(b)
		if err != nil {
			t.Fatal(err)
		}
		if *back != *s {
			t.Fatal("bytes round trip differs")
		}
		words := s.Words()
		if len(words) != ShareWords {
			t.Fatalf("%d words", len(words))
		}
		for _, w := range words {
			if w == "" || strings.ToLower(w) != w {
				t.Fatalf("bad word %q", w)
			}
		}
		back, err = ShareFromWords(words)
		if err != nil {
			t.Fatal(err)
		}
		if *back != *s {
			t.Fatal("words round trip differs")
		}
		if !bytes.Equal(back.Bytes(), b) {
			t.Fatal("re-encoding differs")
		}
	}
	// Shares reconstructed from words combine.
	var fromWords []*Share
	for _, s := range shares[:3] {
		w, _ := ShareFromWords(s.Words())
		fromWords = append(fromWords, w)
	}
	got, err := Combine(fromWords)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatal("combination from words failed")
	}
}

func TestShareFromWordsRejects(t *testing.T) {
	secret := testSecret()
	shares, _ := Split(secret, 2, 3, nil)
	good := shares[0].Words()
	mut := func(f func(w []string)) []string {
		w := append([]string(nil), good...)
		f(w)
		return w
	}
	// Two different words to swap (task 20a point 6): the split is
	// random, and two equal words, swapped, give the same share (about
	// one run in 2048 for words 0 and 1).
	other := 1
	for other < len(good) && good[other] == good[0] {
		other++
	}
	if other == len(good) {
		t.Fatal("all words of the share equal")
	}
	cases := []struct {
		name  string
		words []string
		err   error
	}{
		{"nil", nil, ErrWordCount},
		{"29 words", good[:29], ErrWordCount},
		{"31 words", append(append([]string(nil), good...), "zoo"), ErrWordCount},
		{"24 words", good[:24], ErrWordCount},
		{"unknown word", mut(func(w []string) { w[3] = "notaword" }), ErrUnknownWord},
		{"uppercase", mut(func(w []string) { w[3] = strings.ToUpper(w[3]) }), ErrUnknownWord},
		{"swapped words", mut(func(w []string) { w[0], w[other] = w[other], w[0] }), ErrChecksum},
		{"changed word", mut(func(w []string) {
			if w[10] == "zoo" {
				w[10] = "abandon"
			} else {
				w[10] = "zoo"
			}
		}), ErrChecksum},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ShareFromWords(tc.words)
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if s != nil {
				t.Fatal("no share on error")
			}
		})
	}
	// A swapped pair that happens to keep the checksum is astronomically
	// unlikely; the padding bits are checked too.
	for i := range good {
		for _, alt := range []string{"abandon", "zoo", "ability"} {
			if alt == good[i] {
				continue
			}
			w := mut(func(w []string) { w[i] = alt })
			if _, err := ShareFromWords(w); err == nil {
				t.Fatalf("single word change at %d accepted", i)
			}
		}
	}
}

func TestShareFromBytesRejects(t *testing.T) {
	secret := testSecret()
	shares, _ := Split(secret, 2, 3, nil)
	good := shares[0].Bytes()
	mut := func(f func(b []byte)) []byte {
		b := append([]byte(nil), good...)
		f(b)
		return b
	}
	cases := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"short", good[:ShareSize-1]},
		{"long", append(append([]byte(nil), good...), 0)},
		{"version 0", mut(func(b []byte) { b[0] = 0 })},
		{"version 2", mut(func(b []byte) { b[0] = 2 })},
		{"threshold 0", mut(func(b []byte) { b[3] = 0 })},
		{"threshold 1", mut(func(b []byte) { b[3] = 1 })},
		{"index 0", mut(func(b []byte) { b[4] = 0 })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if s, err := ShareFromBytes(tc.data); !errors.Is(err, ErrShare) || s != nil {
				t.Fatalf("expected ErrShare, got %v %v", s, err)
			}
		})
	}
}

func TestZero(t *testing.T) {
	shares, _ := Split(testSecret(), 2, 2, nil)
	shares[0].Zero()
	if shares[0].Y != [SecretSize]byte{} || shares[0].ID != 0 || shares[0].Index != 0 {
		t.Fatal("Zero must clear the share")
	}
	var nilShare *Share
	nilShare.Zero()
	if nilShare.Bytes() != nil || nilShare.Words() != nil {
		t.Fatal("nil share must be inert")
	}
}

func TestSplitDeterministicWithInjectedRandom(t *testing.T) {
	secret := testSecret()
	fixed := make([]byte, 2+32*4)
	for i := range fixed {
		fixed[i] = byte(i * 7)
	}
	a, err := Split(secret, 5, 6, bytes.NewReader(fixed))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Split(secret, 5, 6, bytes.NewReader(fixed))
	for i := range a {
		if *a[i] != *b[i] {
			t.Fatal("split with the same randomness must be reproducible")
		}
	}
	if a[0].ID != uint16(fixed[0])<<8|uint16(fixed[1]) {
		t.Fatal("ID must be the first two random bytes")
	}
}

var _ = rand.Reader
