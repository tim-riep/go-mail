package client

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Input of seed and share words (2.2 "Eingabe von Wörtern", SPEC-ISSUES
// S11): the input is brought into NFKD, converted to lower case and split
// at any Unicode white space; after that every word must be exactly a
// word of the list (keys.SeedFromWords, shamir.ShareFromWords stay strict,
// abbreviations are not accepted). Errors name positions, never words.
//
// TODO(task-10): package words (task 10) provides exactly these two
// functions as words.Normalize and words.One; it is not merged into this
// branch yet and this task may not create it. Replace normalizeWords and
// oneWord by them when task 10 is merged.

// errNotOneWord reports an answer that does not hold exactly one word.
var errNotOneWord = errors.New("client: exactly one word expected")

// maxWordTokens is the most words one input may hold (a seed has 24, a
// share 30): longer input is rejected before it is normalized, so that
// no input makes the normalization allocate without bound.
const maxWordTokens = 512

// maxWordInput is the most bytes one input may hold, checked before any
// copy is made: 512 words of at most 64 bytes each.
const maxWordInput = maxWordTokens * 64

// errWordInput reports input with too many words or bytes; it never
// names the input.
var errWordInput = fmt.Errorf("%w: word input longer than %d words or %d bytes", ErrArgument, maxWordTokens, maxWordInput)

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

// normalizeWords brings input into NFKD, converts it to lower case and
// splits it at any Unicode white space (words.Normalize). Input with more
// than maxWordTokens words or maxWordInput bytes is rejected before it is
// normalized (errWordInput), and so is input that NFKD splits into more
// words (a compatibility character can decompose into a space).
func normalizeWords(input string) ([]string, error) {
	if len(input) > maxWordInput || countFields(input, maxWordTokens) > maxWordTokens {
		return nil, errWordInput
	}
	w := strings.Fields(strings.ToLower(norm.NFKD.String(input)))
	if len(w) > maxWordTokens {
		return nil, errWordInput
	}
	return w, nil
}

// oneWord normalizes input and requires exactly one word (words.One).
func oneWord(input string) (string, error) {
	w, err := normalizeWords(input)
	if err != nil {
		return "", err
	}
	if len(w) != 1 {
		return "", fmt.Errorf("%w: got %d", errNotOneWord, len(w))
	}
	return w[0], nil
}

// normalizeList normalizes words typed as a list: each element may hold
// one or several words and any white space (the elements are joined by a
// space first). Device lost, Restore and RecoverRead take their words
// through it. The length is checked before the elements are joined.
func normalizeList(words []string) ([]string, error) {
	if len(words) > maxWordTokens {
		return nil, errWordInput
	}
	total := 0
	for _, w := range words {
		if total += len(w) + 1; total > maxWordInput+1 {
			return nil, errWordInput
		}
	}
	return normalizeWords(strings.Join(words, " "))
}
