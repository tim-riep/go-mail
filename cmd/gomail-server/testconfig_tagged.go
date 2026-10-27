//go:build gomail_test

package main

import (
	"errors"
	"os"
	"strconv"

	"github.com/tim-riep/go-mail/internal/ingest"
)

// testEnvMinFree is read only by a test build (go build -tags
// gomail_test, internal/e2e): it sets ingest.Config.MinFree, so that the
// end-to-end tests do not fail on the free space of the host (task 15c
// finding 7). A production build has neither this file nor the variable.
const testEnvMinFree = "GOMAIL_TEST_MIN_FREE"

// testConfig applies GOMAIL_TEST_MIN_FREE, a fraction above 0 and below
// 1; any other value stops the start (fail closed).
func testConfig(c *ingest.Config) error {
	v, ok := os.LookupEnv(testEnvMinFree)
	if !ok {
		return nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || !(f > 0 && f < 1) {
		return errors.New(testEnvMinFree + ": a fraction above 0 and below 1")
	}
	c.MinFree = f
	return nil
}
