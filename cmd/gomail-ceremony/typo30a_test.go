package main

import (
	"errors"
	"testing"

	"github.com/tim-riep/go-mail/internal/shamir"
)

// swapWords returns a copy of the words of a share with word i swapped
// with the first later word for which shamir.ShareFromWords reports
// shamir.ErrChecksum. Two equal words, swapped, give the same share
// (task 30A; tested in internal/ceremony, TestSwapWords, where
// TestSwapWordsCopies keeps this copy equal to the tested one).
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
