//go:build !linux

package store

import "testing"

// watchOpens needs inotify (opens26d_linux_test.go). Elsewhere it
// returns nil, and the caller counts only the reads through
// platformReadHook.
func watchOpens(t *testing.T, dir string) func() (opened, closed map[string]int) {
	t.Helper()
	t.Logf("opens of %s not counted (no inotify), only reads through ReadPlatformFile", dir)
	return nil
}
