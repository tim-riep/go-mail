//go:build !gomail_test

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestKeygenPipeProduction: a production build has no switch around the
// terminal rule of keygen (task 13b finding 1); GOMAILCTL_TEST_KEYGEN_PIPE
// changes nothing.
func TestKeygenPipeProduction(t *testing.T) {
	c := newCLI(t)
	for _, v := range []string{"1", "yes"} {
		t.Setenv(testEnvKeygenPipeName, v)
		dir := filepath.Join(c.env.Base, "clients", "pipe")
		r := c.do(dir, "\n\n\n\n", "keygen")
		if r.code != 1 || r.out != "" || !strings.Contains(r.errOut, "nur auf einem Terminal") || exists(dir) {
			t.Fatalf("keygen with %s=%s: %+v", testEnvKeygenPipeName, v, r)
		}
	}
}
