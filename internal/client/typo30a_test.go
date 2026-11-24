package client_test

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"sort"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/shamir"
)

// Typing errors with a checksum mismatch (task 30A). The checksum of a
// seed has 8 bits: a fixed wrong word keeps it for about one seed in 256,
// and a test expecting keys.ErrChecksum then gets a seed of nobody. A
// copied neighbour changes nothing when both words are equal (about one
// share in 2048). The helpers pick a word for which the checksum is shown
// to fail.

// seedTypo returns a copy of words with word i replaced by the first word
// of the list, other than words[i], for which keys.SeedFromWords reports
// keys.ErrChecksum.
func seedTypo(t testing.TB, words []string, i int) []string {
	t.Helper()
	typo := append([]string(nil), words...)
	for _, w := range keys.Wordlist() {
		if w == words[i] {
			continue
		}
		typo[i] = w
		if _, err := keys.SeedFromWords(typo); errors.Is(err, keys.ErrChecksum) {
			return typo
		}
	}
	t.Fatalf("no word breaks the checksum at word %d", i+1)
	return nil
}

// shareTypo is seedTypo for the words of a share: shamir.ShareFromWords
// reports shamir.ErrChecksum for the result.
func shareTypo(t testing.TB, words []string, i int) []string {
	t.Helper()
	typo := append([]string(nil), words...)
	for _, w := range keys.Wordlist() {
		if w == words[i] {
			continue
		}
		typo[i] = w
		if _, err := shamir.ShareFromWords(typo); errors.Is(err, shamir.ErrChecksum) {
			return typo
		}
	}
	t.Fatalf("no word breaks the checksum at word %d", i+1)
	return nil
}

// onlyAt fails unless got differs from want exactly at position i.
func onlyAt(t *testing.T, got, want []string, i int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d words, want %d", len(got), len(want))
	}
	for j := range want {
		if (got[j] != want[j]) != (j == i) {
			t.Fatalf("word %d: %q, was %q", j+1, got[j], want[j])
		}
	}
}

// TestSeedTypo: seedTypo breaks the checksum for many seeds, among them
// seeds for which word 6 in place of word 5 (the old choice of
// TestDeviceLostWrongSeed) keeps it, and seeds for which the first word
// of the list ("abandon", index 0) in place of word 5 keeps it, which a
// helper taking the first other word unchecked would choose; and, for
// every word of the list, seeds for which that word keeps it
// (seedTypoEveryWord).
func TestSeedTypo(t *testing.T) {
	// Fixed seeds; the words are only built for the first ones and for
	// those where one of the two choices keeps the checksum, found on the
	// bytes: word 5 is bits 44 to 54 of the seed, word 6 bits 55 to 65,
	// and the checksum is the first byte of SHA-256 over the seed.
	const seeds, first = 4096, 32
	var keptSeeds, keptFirst, checked int
	for n := uint32(0); n < seeds; n++ {
		var s keys.Seed
		h := sha256.Sum256(binary.BigEndian.AppendUint32([]byte("task 30A seed "), n))
		copy(s[:], h[:])
		sum := sha256.Sum256(s[:])
		moved, zero := s, s
		for k := 0; k < 11; k++ {
			from, to := 55+k, 44+k
			moved[to/8] &^= 1 << (7 - to%8)
			moved[to/8] |= (s[from/8] >> (7 - from%8) & 1) << (7 - to%8)
			zero[to/8] &^= 1 << (7 - to%8)
		}
		keeps := sha256.Sum256(moved[:])[0] == sum[0]
		if zero != s && sha256.Sum256(zero[:])[0] == sum[0] {
			keptFirst++
		} else if n >= first && !keeps {
			continue
		}
		checked++
		words, err := s.Words()
		if err != nil {
			t.Fatal(err)
		}
		old := append([]string(nil), words...)
		old[4] = words[5]
		if _, err := keys.SeedFromWords(old); (err == nil) != keeps {
			t.Fatalf("seed %d: old choice %v, keeps %v", n, err, keeps)
		}
		if keeps && words[4] != words[5] {
			keptSeeds++
		}
		typo := seedTypo(t, words, 4)
		onlyAt(t, typo, words, 4)
		if _, err := keys.SeedFromWords(typo); !errors.Is(err, keys.ErrChecksum) {
			t.Fatalf("seed %d: %v", n, err)
		}
	}
	// The seeds are fixed: this count does not vary between runs. Without
	// such seeds the loop would not tell the helper from the old choice
	// or from an unchecked one.
	if keptSeeds == 0 || keptFirst == 0 {
		t.Fatalf("of %d seeds, word 6 keeps the checksum of %d, the first word of the list of %d", seeds, keptSeeds, keptFirst)
	}
	t.Logf("%d of %d seeds checked; the checksum is kept by word 6 in %d, by the first word of the list in %d", checked, seeds, keptSeeds, keptFirst)

	seedTypoEveryWord(t)
}

// seedTypoEveryWord: for every word of the list, seedTypo breaks the
// checksum of a seed for which that word in place of word 5 keeps it, so
// a helper taking any fixed word unchecked ("zoo" as well as "abandon")
// fails here (task 33C). The seeds are bases with word 5 set to a value
// v. For one base, the values whose seeds have the same first byte of
// SHA-256 (a class) keep the checksum of each other: a seed with word 5
// from a class shows every other word of the class. Classes of 32 bases
// are chosen greedily, larger gains first, and word 5 is taken from a
// word already shown where the class has one; about 270 seeds show all
// 2048 words. The bases are fixed, so the choice does not vary between
// runs.
func seedTypoEveryWord(t *testing.T) {
	type class struct {
		base   keys.Seed
		values []int
	}
	list := keys.Wordlist()
	var classes []class
	for n := uint32(0); n < 32; n++ {
		var base keys.Seed
		h := sha256.Sum256(binary.BigEndian.AppendUint32([]byte("task 33C seed "), n))
		copy(base[:], h[:])
		var byFirst [256][]int
		for v := range list {
			s := base
			setSeedWord(&s, 4, v)
			first := sha256.Sum256(s[:])[0]
			byFirst[first] = append(byFirst[first], v)
		}
		for _, vs := range byFirst {
			if len(vs) >= 2 {
				classes = append(classes, class{base, vs})
			}
		}
	}
	sort.SliceStable(classes, func(a, b int) bool { return len(classes[a].values) > len(classes[b].values) })
	shown := make([]bool, len(list))
	left, checked := len(list), 0
	for least := len(classes[0].values) - 1; least >= 1 && left > 0; least-- {
		for _, c := range classes {
			at := c.values[0]
			for _, v := range c.values {
				if shown[v] {
					at = v
					break
				}
			}
			var gain []int
			for _, v := range c.values {
				if v != at && !shown[v] {
					gain = append(gain, v)
				}
			}
			if len(gain) < least {
				continue
			}
			s := c.base
			setSeedWord(&s, 4, at)
			words := seedWords(list, s)
			if checked == 0 {
				if ws, err := s.Words(); err != nil || !slices.Equal(ws, words) {
					t.Fatalf("words of the seed: %v, differ from Seed.Words", err)
				}
			}
			// What the bytes say, with keys.SeedFromWords: a word of the
			// class in place of word 5 keeps the checksum.
			kept := append([]string(nil), words...)
			kept[4] = list[gain[0]]
			if _, err := keys.SeedFromWords(kept); err != nil {
				t.Fatalf("base %x, word %q in place of %q: %v", c.base[:4], kept[4], words[4], err)
			}
			typo := seedTypo(t, words, 4)
			onlyAt(t, typo, words, 4)
			if _, err := keys.SeedFromWords(typo); !errors.Is(err, keys.ErrChecksum) {
				t.Fatalf("base %x, %q in place of %q: %v", c.base[:4], typo[4], words[4], err)
			}
			for _, v := range gain {
				shown[v] = true
			}
			left -= len(gain)
			checked++
		}
	}
	if left != 0 {
		t.Fatalf("%d words of the list keep the checksum of no seed checked", left)
	}
	t.Logf("%d seeds checked; each word of the list in place of word 5 keeps the checksum of one of them", checked)
}

// setSeedWord sets the 11 bits of word k+1 of s to v (k below 23; word 24
// holds the checksum).
func setSeedWord(s *keys.Seed, k, v int) {
	for b := 0; b < 11; b++ {
		bit := k*11 + b
		s[bit/8] &^= 1 << (7 - bit%8)
		s[bit/8] |= byte(v>>(10-b)&1) << (7 - bit%8)
	}
}

// seedWords is Seed.Words without the lookup in constant time: the words
// of s and of the first byte of SHA-256 of s, 11 bits each.
func seedWords(list []string, s keys.Seed) []string {
	sum := sha256.Sum256(s[:])
	bits := append(s[:], sum[0])
	words := make([]string, keys.SeedWords)
	for i := range words {
		v := 0
		for b := 0; b < 11; b++ {
			bit := i*11 + b
			v = v<<1 | int(bits[bit/8]>>(7-bit%8)&1)
		}
		words[i] = list[v]
	}
	return words
}

// TestShareTypo: shareTypo breaks the checksum of a share whose words 8
// and 9 are equal, where copying word 9 to word 8 (the old choice of
// TestKeygenSharesAndRestore) changes nothing.
func TestShareTypo(t *testing.T) {
	secret := sha256.Sum256([]byte("task 30A share"))
	shares, err := shamir.Split(secret[:], 2, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := shares[0].Bytes()
	// Words 8 and 9 are bits 77 to 98, all in y: copy word 8 to word 9.
	for k := 0; k < 11; k++ {
		from, to := 77+k, 88+k
		b[to/8] &^= 1 << (7 - to%8)
		b[to/8] |= (b[from/8] >> (7 - from%8) & 1) << (7 - to%8)
	}
	s, err := shamir.ShareFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	words := s.Words()
	if words[7] != words[8] {
		t.Fatalf("words 8 and 9 differ: %q %q", words[7], words[8])
	}
	old := append([]string(nil), words...)
	old[7] = old[8]
	if _, err := shamir.ShareFromWords(old); err != nil {
		t.Fatalf("old choice: %v", err)
	}
	typo := shareTypo(t, words, 7)
	onlyAt(t, typo, words, 7)
	if _, err := shamir.ShareFromWords(typo); !errors.Is(err, shamir.ErrChecksum) {
		t.Fatal(err)
	}
	// And on random shares.
	for range 64 {
		shares, err := shamir.Split(secret[:], 2, 3, nil)
		if err != nil {
			t.Fatal(err)
		}
		words := shares[1].Words()
		typo := shareTypo(t, words, 7)
		onlyAt(t, typo, words, 7)
		if _, err := shamir.ShareFromWords(typo); !errors.Is(err, shamir.ErrChecksum) {
			t.Fatal(err)
		}
	}
}
