//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package store

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestLockFileNotRegular (task 20l point 3): an existing lock path that
// is not a regular file, a FIFO or a device (here /dev/null through a
// symbolic link named lock), is refused by LockFile, LockPath and
// probeLock with ErrNotRegular after the open, before any lock is
// taken, and the open of a FIFO returns at once. The registry entry of
// the path is released again: a regular file at the path locks after.
func TestLockFileNotRegular(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo-lock")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	dev := filepath.Join(dir, "dev-lock")
	if err := os.Symlink(os.DevNull, dev); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fifo, dev} {
		done := make(chan error, 3)
		go func() {
			_, err := LockFile(p)
			done <- err
			_, err = LockPath(p)
			done <- err
			done <- probeLock(p)
		}()
		for i := 0; i < 3; i++ {
			select {
			case err := <-done:
				if !errors.Is(err, ErrNotRegular) {
					t.Fatalf("%s, call %d: %v", filepath.Base(p), i, err)
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("%s: the lock blocks", filepath.Base(p))
			}
		}
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		unlock, err := LockFile(p)
		if err != nil {
			t.Fatalf("%s as a regular file: %v", filepath.Base(p), err)
		}
		unlock()
		if err := probeLock(p); err != nil {
			t.Fatalf("probe of the released %s: %v", filepath.Base(p), err)
		}
	}
}
