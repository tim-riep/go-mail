// Package keys implements the key material of go-mail: the user and
// platform seeds with their BIP-39 word encoding, the HKDF derivation of
// the sub-keys of sections 2.2 and 2.3 of the specification, generation
// certificates, platform key certificates, and the passphrase-protected
// key store of the client.
//
// Secret material is zeroed where Go allows it. See the notes on Zero and
// Wipe for what is not guaranteed.
package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Exported errors. Every error of this package wraps one of them.
var (
	ErrWordlist    = errors.New("keys: malformed word list")
	ErrWordCount   = errors.New("keys: a seed has exactly 24 words")
	ErrUnknownWord = errors.New("keys: word is not in the BIP-39 list")
	ErrChecksum    = errors.New("keys: seed checksum mismatch")
	ErrGeneration  = errors.New("keys: invalid generation")
	ErrZeroed      = errors.New("keys: key material has been zeroed")
	ErrDomain      = errors.New("keys: invalid signature domain")
	ErrSignature   = errors.New("keys: signature verification failed")
	ErrCert        = errors.New("keys: invalid certificate")
	ErrKeystore    = errors.New("keys: malformed key store")
	ErrPassphrase  = errors.New("keys: key store authentication failed (wrong passphrase or damaged file)")
	ErrKDFParams   = errors.New("keys: key derivation parameters out of range")
)

// SeedSize is the size of a seed in bytes: 256 bits of entropy.
const SeedSize = 32

// SeedWords is the number of BIP-39 words that encode a seed.
const SeedWords = 24

// Seed is 256 bits of entropy from which all keys of a user or of the
// platform are derived. It is never stored on a device; see 2.2.
type Seed [SeedSize]byte

// NewSeed draws a seed from r, or from crypto/rand if r is nil.
func NewSeed(r io.Reader) (*Seed, error) {
	if r == nil {
		r = rand.Reader
	}
	s := new(Seed)
	if _, err := io.ReadFull(r, s[:]); err != nil {
		return nil, fmt.Errorf("keys: reading seed entropy: %w", err)
	}
	return s, nil
}

// Zero overwrites the seed.
func (s *Seed) Zero() {
	if s != nil {
		Wipe(s[:])
	}
}

// Wipe overwrites b with zeros. Go gives no guarantee that no other copy
// of the data exists: values may have been copied by the garbage
// collector, spilled to the stack, or retained by the standard library
// (for example ecdh.PrivateKey keeps its own copy). Wipe reduces the
// lifetime of secrets in memory; it does not eliminate it.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// WordlistSHA256 is the SHA-256 of the embedded BIP-39 English word list.
//
// Source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
// (2048 words, one per line, LF line endings, trailing newline).
const WordlistSHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

//go:embed english.txt
var wordlistData []byte

// wordlist is the parsed list. Lookups in both directions go through
// Word and LookupWord, which scan the whole list with constant-time
// selects: the index of a seed word is 11 bits of the seed, so neither a
// slice index nor a map lookup may depend on it.
var wordlist []string

func init() {
	sum := sha256.Sum256(wordlistData)
	if hex.EncodeToString(sum[:]) != WordlistSHA256 {
		panic("keys: embedded BIP-39 word list does not match its recorded SHA-256")
	}
	words, err := parseWordlist(wordlistData)
	if err != nil {
		panic("keys: embedded BIP-39 word list: " + err.Error())
	}
	wordlist = words
}

// Wordlist returns a copy of the BIP-39 English word list.
func Wordlist() []string {
	return append([]string(nil), wordlist...)
}

// maxWordLen is the longest word in the BIP-39 English list.
const maxWordLen = 8

// LookupWord returns the index of w in the BIP-39 word list. It compares
// w with every word, so the running time does not depend on which word
// matches (it does depend on the length of w, which the caller's own
// handling of the string reveals anyway).
func LookupWord(w string) (int, bool) {
	if len(w) == 0 || len(w) > maxWordLen {
		return 0, false
	}
	var buf [maxWordLen]byte
	copy(buf[:], w)
	idx, found := 0, 0
	for i, cand := range wordlist {
		var cb [maxWordLen]byte
		copy(cb[:], cand)
		eq := subtle.ConstantTimeCompare(buf[:], cb[:]) & subtle.ConstantTimeEq(int32(len(cand)), int32(len(w)))
		idx = subtle.ConstantTimeSelect(eq, i, idx)
		found |= eq
	}
	return idx, found == 1
}

// Word returns the word at index i (0 to 2047) of the BIP-39 word list.
// It selects the word from the whole list in constant time with respect
// to i.
func Word(i int) (string, bool) {
	if i < 0 || i >= len(wordlist) {
		return "", false
	}
	var out [maxWordLen]byte
	n := 0
	for j, cand := range wordlist {
		eq := subtle.ConstantTimeEq(int32(j), int32(i))
		var cb [maxWordLen]byte
		copy(cb[:], cand)
		for k := range out {
			out[k] = byte(subtle.ConstantTimeSelect(eq, int(cb[k]), int(out[k])))
		}
		n = subtle.ConstantTimeSelect(eq, len(cand), n)
	}
	w := string(out[:n])
	Wipe(out[:])
	return w, true
}

// parseWordlist parses a BIP-39 word list: exactly 2048 lines of lowercase
// ASCII letters, strictly ascending, separated by LF, with at most one
// trailing LF.
func parseWordlist(data []byte) ([]string, error) {
	s := string(data)
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}
	if s == "" {
		return nil, fmt.Errorf("%w: empty", ErrWordlist)
	}
	lines := strings.Split(s, "\n")
	if len(lines) != 2048 {
		return nil, fmt.Errorf("%w: %d lines, want 2048", ErrWordlist, len(lines))
	}
	for i, w := range lines {
		if len(w) == 0 || len(w) > 8 {
			return nil, fmt.Errorf("%w: line %d has length %d", ErrWordlist, i+1, len(w))
		}
		for j := 0; j < len(w); j++ {
			if w[j] < 'a' || w[j] > 'z' {
				return nil, fmt.Errorf("%w: line %d is not lowercase ASCII", ErrWordlist, i+1)
			}
		}
		if i > 0 && lines[i-1] >= w {
			return nil, fmt.Errorf("%w: line %d is not in ascending order", ErrWordlist, i+1)
		}
	}
	if !sort.StringsAreSorted(lines) {
		return nil, fmt.Errorf("%w: not sorted", ErrWordlist)
	}
	return lines, nil
}

// Words encodes the seed as 24 BIP-39 words: the 256 entropy bits followed
// by the 8 checksum bits (the first byte of SHA-256 over the entropy),
// split into 24 groups of 11 bits. The BIP-39 passphrase derivation to a
// wallet seed is not used; the words stand only for the entropy.
func (s *Seed) Words() ([]string, error) {
	if s == nil {
		return nil, errors.New("keys: nil seed")
	}
	sum := sha256.Sum256(s[:])
	bits := make([]byte, 0, SeedSize+1)
	bits = append(bits, s[:]...)
	bits = append(bits, sum[0])
	defer Wipe(bits)
	words := make([]string, SeedWords)
	for i := range words {
		words[i], _ = Word(bitsAt(bits, i*11))
	}
	return words, nil
}

// bitsAt returns the 11 bits of b starting at bit offset off (MSB first).
func bitsAt(b []byte, off int) int {
	var v int
	for i := 0; i < 11; i++ {
		bit := off + i
		v = v<<1 | int(b[bit/8]>>(7-bit%8)&1)
	}
	return v
}

// SeedFromWords decodes 24 BIP-39 words and verifies the checksum. Words
// must be given exactly as in the list (lowercase, no surrounding space).
func SeedFromWords(words []string) (*Seed, error) {
	if len(words) != SeedWords {
		return nil, fmt.Errorf("%w: got %d", ErrWordCount, len(words))
	}
	var bits [SeedSize + 1]byte
	defer Wipe(bits[:])
	for i, w := range words {
		idx, ok := LookupWord(w)
		if !ok {
			return nil, fmt.Errorf("%w: word %d", ErrUnknownWord, i+1)
		}
		for j := 0; j < 11; j++ {
			if idx>>(10-j)&1 == 1 {
				bit := i*11 + j
				bits[bit/8] |= 1 << (7 - bit%8)
			}
		}
	}
	s := new(Seed)
	copy(s[:], bits[:SeedSize])
	sum := sha256.Sum256(s[:])
	if sum[0] != bits[SeedSize] {
		s.Zero()
		return nil, ErrChecksum
	}
	return s, nil
}
