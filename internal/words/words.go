// Package words normalizes typed seed and share words (2.2 "Eingabe von
// Wörtern", SPEC-ISSUES S11).
//
// The command line and the ceremony are lenient about how words are
// typed: the input is brought into Unicode normalization form NFKD,
// converted to lower case and split at any Unicode white space. After
// that every word must be exactly a word of the BIP-39 English list;
// abbreviations (the first four letters) are not accepted. Packages keys
// and shamir stay strict and accept only the exact form, so this package
// is used only by the command line, the client and the ceremony.
//
// Input longer than MaxInput bytes or MaxTokens words is refused before
// it is normalized (ErrTooLong): no input makes the normalization
// allocate without bound (task 15b point 5, low finding of the attack on
// task 06b; the bounds are the ones of the client of task 06b).
//
// Errors never contain the words themselves, only their positions: typed
// words are parts of a seed or a share.
package words

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/tim-riep/go-mail/internal/keys"
)

// Errors of this package. Every error wraps one of them.
var (
	// ErrNotOneWord reports an input that does not hold exactly one word.
	ErrNotOneWord = errors.New("words: exactly one word expected")
	// ErrUnknownWord reports a word that is not in the word list after
	// normalization. The message names its position only.
	ErrUnknownWord = errors.New("words: word is not in the word list")
	// ErrTooLong reports an input of more than MaxTokens words or
	// MaxInput bytes; it never names the input.
	ErrTooLong = errors.New("words: input too long")
)

// MaxTokens is the most words one input may hold (a seed has 24, a
// share 30).
const MaxTokens = 512

// MaxInput is the most bytes one input may hold, checked before any copy
// is made: MaxTokens words of at most 64 bytes each.
const MaxInput = MaxTokens * 64

var errTooLong = fmt.Errorf("%w: more than %d words or %d bytes", ErrTooLong, MaxTokens, MaxInput)

// countFields counts the words of input as strings.Fields splits them,
// without allocating, and stops after limit+1.
func countFields(input string, limit int) int {
	n, in := 0, false
	for _, r := range input {
		if unicode.IsSpace(r) {
			in = false
			continue
		}
		if !in {
			in = true
			if n++; n > limit {
				break
			}
		}
	}
	return n
}

// Normalize brings input into NFKD, converts it to lower case
// (strings.ToLower after NFKD) and splits it at any Unicode white space
// (unicode.IsSpace). Leading and trailing white space is dropped; an
// input of white space only yields no words. Invalid UTF-8 becomes
// U+FFFD, which is in no word list. Input with more than MaxInput bytes
// or MaxTokens words is refused before it is normalized (ErrTooLong),
// and so is input that NFKD splits into more words (a compatibility
// character can decompose into a space and a combining mark).
func Normalize(input string) ([]string, error) {
	if len(input) > MaxInput || countFields(input, MaxTokens) > MaxTokens {
		return nil, errTooLong
	}
	w := strings.Fields(strings.ToLower(norm.NFKD.String(input)))
	if len(w) > MaxTokens {
		return nil, errTooLong
	}
	return w, nil
}

// List normalizes words typed as a list: each element may hold one or
// several words and any white space (the elements are joined by a space
// first). The length is checked before the elements are joined.
func List(ws []string) ([]string, error) {
	if len(ws) > MaxTokens {
		return nil, errTooLong
	}
	total := 0
	for _, w := range ws {
		if total += len(w) + 1; total > MaxInput+1 {
			return nil, errTooLong
		}
	}
	return Normalize(strings.Join(ws, " "))
}

// One normalizes input and requires exactly one word (ErrNotOneWord). It
// does not check the word list; see Check.
func One(input string) (string, error) {
	w, err := Normalize(input)
	if err != nil {
		return "", err
	}
	if len(w) != 1 {
		return "", fmt.Errorf("%w: got %d", ErrNotOneWord, len(w))
	}
	return w[0], nil
}

// Check reports the first word of ws that is not exactly a word of the
// BIP-39 English list, by its position (1-based) and never by the word
// itself (ErrUnknownWord). Abbreviations are unknown words.
func Check(ws []string) error {
	for i, w := range ws {
		if _, ok := keys.LookupWord(w); !ok {
			return fmt.Errorf("%w: word %d", ErrUnknownWord, i+1)
		}
	}
	return nil
}
