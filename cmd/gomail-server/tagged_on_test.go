//go:build gomail_test

package main

import (
	"testing"

	"github.com/tim-riep/go-mail/internal/ingest"
)

const testTagged = true

// TestTestConfig: the test build applies GOMAIL_TEST_MIN_FREE and stops
// the start on a value outside (0, 1).
func TestTestConfig(t *testing.T) {
	c := ingest.Config{}
	if err := testConfig(&c); err != nil || c.MinFree != 0 {
		t.Fatalf("unset: %v %v", c.MinFree, err)
	}
	t.Setenv(testEnvMinFree, "0.000001")
	if err := testConfig(&c); err != nil || c.MinFree != 0.000001 {
		t.Fatalf("set: %v %v", c.MinFree, err)
	}
	for _, v := range []string{"0", "1", "-1", "x", "NaN"} {
		t.Setenv(testEnvMinFree, v)
		if err := testConfig(&ingest.Config{}); err == nil {
			t.Fatalf("%q accepted", v)
		}
	}
}
