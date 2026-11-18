package ceremony

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/tim-riep/go-mail/internal/shamir"
)

// swapWords returns a copy of the words of a share with word i swapped
// with the first later word for which shamir.ShareFromWords reports
// shamir.ErrChecksum. Two equal words, swapped, give the same share
// (task 30A).
func swapWords(t testing.TB, words []string, i int) []string {
	t.Helper()
	for j := i + 1; j < len(words); j++ {
		ws := append([]string(nil), words...)
		ws[i], ws[j] = ws[j], ws[i]
		if _, err := shamir.ShareFromWords(ws); errors.Is(err, shamir.ErrChecksum) {
			return ws
		}
	}
	t.Fatalf("no swap with word %d breaks the checksum", i+1)
	return nil
}

// TestSwapWords: swapWords breaks the checksum of a share whose words 1
// and 2 are equal, where swapping them changes nothing, and of random
// shares.
func TestSwapWords(t *testing.T) {
	secret := sha256.Sum256([]byte("task 30A share"))
	shares, err := shamir.Split(secret[:], 2, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Word 1 is the version and the first 3 bits of the identifier, word
	// 2 the next 11 bits of the identifier: copy word 1 to word 2.
	b := shares[0].Bytes()
	for k := 0; k < 11; k++ {
		from, to := k, 11+k
		b[to/8] &^= 1 << (7 - to%8)
		b[to/8] |= (b[from/8] >> (7 - from%8) & 1) << (7 - to%8)
	}
	s, err := shamir.ShareFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	words := s.Words()
	if words[0] != words[1] {
		t.Fatalf("words 1 and 2 differ: %q %q", words[0], words[1])
	}
	if _, err := shamir.ShareFromWords(words); err != nil {
		t.Fatal(err)
	}
	for _, ws := range [][]string{words, shares[1].Words(), shares[2].Words()} {
		got := swapWords(t, ws, 0)
		if _, err := shamir.ShareFromWords(got); !errors.Is(err, shamir.ErrChecksum) {
			t.Fatal(err)
		}
		n := 0
		for j := range ws {
			if got[j] != ws[j] {
				n++
			}
		}
		if n != 2 || got[0] == ws[0] {
			t.Fatalf("%d words changed", n)
		}
	}
}
