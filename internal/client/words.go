package client

import (
	"errors"
	"fmt"

	"github.com/tim-riep/go-mail/internal/words"
)

// Input of seed and share words (2.2 "Eingabe von Wörtern", SPEC-ISSUES
// S11): package words brings the input into NFKD, converts it to lower
// case and splits it at any Unicode white space; after that every word
// must be exactly a word of the list (keys.SeedFromWords,
// shamir.ShareFromWords stay strict, abbreviations are not accepted).
// Input longer than words.MaxTokens words or words.MaxInput bytes is
// refused before it is normalized (words.ErrTooLong, here also an
// ErrArgument). Errors name positions, never words.

// tooLong marks a refused overlong input as an ErrArgument as well.
func tooLong(err error) error {
	if errors.Is(err, words.ErrTooLong) {
		return fmt.Errorf("%w: %w", ErrArgument, err)
	}
	return err
}

// oneWord normalizes input and requires exactly one word (words.One).
func oneWord(input string) (string, error) {
	w, err := words.One(input)
	if err != nil {
		return "", tooLong(err)
	}
	return w, nil
}

// normalizeList normalizes words typed as a list: each element may hold
// one or several words and any white space (words.List). Device lost,
// Restore and RecoverRead take their words through it.
func normalizeList(ws []string) ([]string, error) {
	w, err := words.List(ws)
	if err != nil {
		return nil, tooLong(err)
	}
	return w, nil
}
