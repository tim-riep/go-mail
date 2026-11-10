//go:build unix

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

// TestFIFOCheckPlatformPin (task 24 package F, R41): a FIFO in place of
// platform/ makes checkPlatformPin fail at once (syscall.ENOTDIR) instead
// of an open that waits for a writer, so the server start ends with an
// error. checkDataDir lists the data directory only after os.Stat found
// a directory there, so a FIFO as data directory fails before the list.
func TestFIFOCheckPlatformPin(t *testing.T) {
	st, err := store.Init(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	platform := st.Path("platform")
	if err := os.RemoveAll(platform); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(platform, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { done <- checkPlatformPin(st, &store.PlatformPin{Gen: 1}) }()
	select {
	case err := <-done:
		if !errors.Is(err, syscall.ENOTDIR) {
			t.Fatalf("checkPlatformPin: %v, want %v", err, syscall.ENOTDIR)
		}
	case <-time.After(10 * time.Second):
		if w, err := os.OpenFile(platform, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		t.Fatal("checkPlatformPin hangs at the FIFO")
	}
}

// TestFIFOEmptyDir (task 24 package F, R41): emptyDir opens --data with
// store.OpenDir, so a FIFO put there after the Lstat of runInit is an
// error at once (syscall.ENOTDIR) instead of an open that waits for a
// writer. The window between Lstat and the open cannot be hit from a
// test, so emptyDir is called directly. An empty directory is empty, a
// directory with an entry is not, and a missing one is fs.ErrNotExist.
func TestFIFOEmptyDir(t *testing.T) {
	tmp := t.TempDir()
	fifo := filepath.Join(tmp, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := emptyDir(fifo); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, syscall.ENOTDIR) {
			t.Fatalf("emptyDir: %v, want %v", err, syscall.ENOTDIR)
		}
	case <-time.After(10 * time.Second):
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		t.Fatal("emptyDir hangs at the FIFO")
	}
	dir := filepath.Join(tmp, "dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if empty, err := emptyDir(dir); err != nil || !empty {
		t.Fatalf("empty directory: %v %v", empty, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if empty, err := emptyDir(dir); err != nil || empty {
		t.Fatalf("directory with an entry: %v %v", empty, err)
	}
	if _, err := emptyDir(filepath.Join(tmp, "none")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing directory: %v", err)
	}
}
