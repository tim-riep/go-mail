package main

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/words"
)

// TestWordsNFKDTooLong (merge with task 15b point 5): one typed "word"
// that NFKD splits into more than words.MaxTokens words (U+00A8 becomes
// a space and a combining mark) passes the count before the
// normalization and is refused by words.Normalize (words.ErrTooLong),
// with positions only in the error.
func TestWordsNFKDTooLong(t *testing.T) {
	in := strings.Repeat("¨", words.MaxTokens+1) + "\n"
	e := &env{stdin: bufio.NewReader(strings.NewReader(in)), stderr: io.Discard}
	ws, err := e.readWords(nil, "Seed", 24)
	if !errors.Is(err, words.ErrTooLong) || ws != nil {
		t.Fatalf("%v %v", ws, err)
	}
	if !strings.Contains(err.Error(), "nach 0 von 24 Wörtern") || strings.Contains(err.Error(), "¨") {
		t.Fatalf("error %q", err)
	}
}
