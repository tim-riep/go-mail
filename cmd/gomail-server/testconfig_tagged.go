//go:build gomail_test

package main

import (
	"errors"
	"os"
	"strconv"
	"time"

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

// testEnvHeadGap is read only by a test build: the shortest time between
// two signed heads (loghttp.Config.MinGap), so that the end-to-end tests
// of the client log (task 14) do not wait a minute for every head that
// covers their entries. A production build has neither this file nor the
// variable.
const testEnvHeadGap = "GOMAIL_TEST_HEAD_GAP"

// testMinGap applies GOMAIL_TEST_HEAD_GAP, a duration of at least one
// second; an unset, malformed or smaller value leaves the default.
func testMinGap() time.Duration {
	d, err := time.ParseDuration(os.Getenv(testEnvHeadGap))
	if err != nil || d < time.Second {
		return 0
	}
	return d
}
