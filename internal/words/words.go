// Package words normalizes typed seed and share words (2.2 "Eingabe von
// Wörtern", SPEC-ISSUES S11).
//
// The command line and the ceremony are lenient about how words are
// typed: the input is brought into Unicode normalization form NFKD,
// converted to lower case and split at any Unicode white space. After
// that every word must be exactly a word of the BIP-39 English list;
// abbreviations (the first four letters) are not accepted. Packages keys
// and shamir stay strict and accept only the exact form, so this package
// is used only by the command line and the ceremony.
//
// Errors never contain the words themselves, only their positions: typed
// words are parts of a seed or a share.
package words

import (
	"errors"
	"fmt"
	"strings"

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
)

// Normalize brings input into NFKD, converts it to lower case
// (strings.ToLower after NFKD) and splits it at any Unicode white space
// (unicode.IsSpace). Leading and trailing white space is dropped; an
// input of white space only yields no words. Invalid UTF-8 becomes
// U+FFFD, which is in no word list.
func Normalize(input string) []string {
	return strings.Fields(strings.ToLower(norm.NFKD.String(input)))
}

// One normalizes input and requires exactly one word (ErrNotOneWord). It
// does not check the word list; see Check.
func One(input string) (string, error) {
	w := Normalize(input)
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
