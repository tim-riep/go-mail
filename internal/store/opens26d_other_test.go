//go:build !linux

package store

import (
	"os"
	"testing"
)

// watchOpens needs inotify (opens26d_linux_test.go). Elsewhere it
// returns nil, and the caller counts only the reads through
// platformReadHook.
func watchOpens(t *testing.T, dir string) func() (opened, closed map[string]int) {
	t.Helper()
	t.Logf("opens of %s not counted (no inotify), only reads through ReadPlatformFile", dir)
	return nil
}

// heldFDs reads /proc/self/fd (opens26d_linux_test.go). Elsewhere it
// returns nil without looking, and a descriptor of the file that stays
// open after the call goes unseen.
func heldFDs(t *testing.T, files ...os.FileInfo) []string {
	t.Helper()
	return nil
}
