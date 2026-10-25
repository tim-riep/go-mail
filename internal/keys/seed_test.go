package keys

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestWordlistEmbedded(t *testing.T) {
	if sum := sha256.Sum256(wordlistData); hex.EncodeToString(sum[:]) != WordlistSHA256 {
		t.Fatalf("embedded wordlist hash %x", sum)
	}
	w := Wordlist()
	if len(w) != 2048 || w[0] != "abandon" || w[2047] != "zoo" {
		t.Fatalf("unexpected wordlist: %d words", len(w))
	}
	w[0] = "changed"
	if Wordlist()[0] != "abandon" {
		t.Fatal("Wordlist must return a copy")
	}
}

func TestParseWordlistRejects(t *testing.T) {
	good := string(wordlistData)
	lines := strings.Split(strings.TrimRight(good, "\n"), "\n")
	join := func(l []string) []byte { return []byte(strings.Join(l, "\n") + "\n") }
	swapped := append([]string(nil), lines...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	dup := append([]string(nil), lines...)
	dup[1] = dup[0]
	upper := append([]string(nil), lines...)
	upper[5] = "Absent"
	empty := append([]string(nil), lines...)
	empty[7] = ""
	long := append([]string(nil), lines...)
	long[7] = "abcdefghi"
	digit := append([]string(nil), lines...)
	digit[7] = "abc1"
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"too few", join(lines[:2047])},
		{"too many", join(append(append([]string(nil), lines...), "zzzz"))},
		{"unsorted", join(swapped)},
		{"duplicate", join(dup)},
		{"uppercase", join(upper)},
		{"empty line", join(empty)},
		{"word too long", join(long)},
		{"digit", join(digit)},
		{"CRLF", []byte(strings.ReplaceAll(good, "\n", "\r\n"))},
		{"no trailing newline but blank line", []byte(good + "\n")},
		{"leading blank line", []byte("\n" + good)},
		{"space in word", []byte(strings.Replace(good, "abandon", "aban don", 1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseWordlist(tc.data); !errors.Is(err, ErrWordlist) {
				t.Fatalf("expected ErrWordlist, got %v", err)
			}
		})
	}
	// Without the trailing newline the list is still valid.
	if _, err := parseWordlist([]byte(strings.TrimRight(good, "\n"))); err != nil {
		t.Fatal(err)
	}
}

func TestBIP39Vectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/bip39_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct{ Entropy, Mnemonic string }
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 8 {
		t.Fatalf("expected the 8 Trezor vectors with 256-bit entropy, got %d", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		ent, err := hex.DecodeString(v.Entropy)
		if err != nil {
			t.Fatal(err)
		}
		var seed Seed
		copy(seed[:], ent)
		words, err := seed.Words()
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(words, " "); got != v.Mnemonic {
			t.Errorf("entropy %s: got %q", v.Entropy, got)
		}
		back, err := SeedFromWords(strings.Fields(v.Mnemonic))
		if err != nil {
			t.Errorf("entropy %s: %v", v.Entropy, err)
			continue
		}
		if !bytes.Equal(back[:], ent) {
			t.Errorf("entropy %s: round trip differs", v.Entropy)
		}
	}
}

func TestSeedFromWordsRejects(t *testing.T) {
	zero := strings.Fields("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
	badChecksum := append([]string(nil), zero...)
	badChecksum[23] = "abandon"
	swapped := append([]string(nil), zero...)
	swapped[0], swapped[23] = swapped[23], swapped[0]
	unknown := append([]string(nil), zero...)
	unknown[3] = "abandonx"
	upper := append([]string(nil), zero...)
	upper[3] = "Abandon"
	space := append([]string(nil), zero...)
	space[3] = " abandon"
	cases := []struct {
		name  string
		words []string
		err   error
	}{
		{"nil", nil, ErrWordCount},
		{"12 words", zero[:12], ErrWordCount},
		{"23 words", zero[:23], ErrWordCount},
		{"25 words", append(append([]string(nil), zero...), "art"), ErrWordCount},
		{"bad checksum", badChecksum, ErrChecksum},
		{"swapped words", swapped, ErrChecksum},
		{"unknown word", unknown, ErrUnknownWord},
		{"uppercase", upper, ErrUnknownWord},
		{"leading space", space, ErrUnknownWord},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := SeedFromWords(tc.words)
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if s != nil {
				t.Fatal("no seed on error")
			}
		})
	}
}

func TestNewSeed(t *testing.T) {
	s1, err := NewSeed(nil)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewSeed(nil)
	if err != nil {
		t.Fatal(err)
	}
	if *s1 == *s2 || *s1 == (Seed{}) {
		t.Fatal("seeds must be random")
	}
	// Injected reader.
	fixed := bytes.NewReader(bytes.Repeat([]byte{7}, 32))
	s3, err := NewSeed(fixed)
	if err != nil {
		t.Fatal(err)
	}
	if s3[0] != 7 || s3[31] != 7 {
		t.Fatal("seed must come from the injected reader")
	}
	if _, err := NewSeed(bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("short reader must fail")
	}
	words, err := s3.Words()
	if err != nil || len(words) != 24 {
		t.Fatal("24 words expected")
	}
	s3.Zero()
	if *s3 != (Seed{}) {
		t.Fatal("Zero must clear the seed")
	}
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3}
	Wipe(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Fatal("Wipe must zero the slice")
	}
	Wipe(nil)
}
