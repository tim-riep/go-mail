//go:build !gomail_dev

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUsageNoDev: the production build has no development ceremony
// (task 15b point 4): init --dev and --data are usage errors (exit code
// 2), the usage does not name them, and nothing is written.
func TestUsageNoDev(t *testing.T) {
	dir := t.TempDir()
	data, keys := filepath.Join(dir, "data"), filepath.Join(dir, "keys")
	for _, args := range [][]string{
		{"init", "--dev", "--data", data, "--keys", keys},
		{"init", "--dev", "--keys", keys},
		{"init", "--data", data, "--keys", keys},
		{"init", "--dev", "--data", data, "--keys", keys, "--insecure-no-log"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, nil, &out, &errb); code != exitUsage {
			t.Fatalf("%v: exit %d", args, code)
		}
		if strings.Contains(errb.String(), "init --dev --data") || strings.Contains(errb.String(), "Entwicklungszeremonie ohne Shamir") {
			t.Fatalf("%v: usage names the development ceremony: %q", args, errb.String())
		}
	}
	for _, d := range []string{data, keys} {
		if _, err := os.Lstat(d); err == nil {
			t.Fatalf("%s written", d)
		}
	}
}
