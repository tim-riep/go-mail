//go:build unix

package translog

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

// fifoNoHang runs f and fails unless it returns an error wrapping want
// within a few seconds; if it hangs at fifo, a writer opened on fifo
// lets it return before the test fails.
func fifoNoHang(t *testing.T, name, fifo string, want error, f func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("%s: %v, want %v", name, err, want)
		}
	case <-time.After(10 * time.Second):
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		t.Fatalf("%s: hangs at the FIFO", name)
	}
}

// mkfifo creates a FIFO at p (and its parent), or skips the test.
func mkfifo(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
}

// TestFIFOInLogDirectory (task 20b point 5, R41): a FIFO in place of a
// file synced by SignHead (syncFile), of a directory synced (fsyncDir,
// store.SyncDir), of heads/ (eachHead) or of entries/ (orphans) is an
// error at once instead of an open that waits for a writer.
func TestFIFOInLogDirectory(t *testing.T) {
	root := t.TempDir()
	f := &files{root: root}
	entry := f.path(EntryPath(0))
	mkfifo(t, entry)
	fifoNoHang(t, "syncFile", entry, store.ErrNotRegular, func() error { return syncFile(entry) })

	dir := filepath.Join(t.TempDir(), "dir")
	mkfifo(t, dir)
	fifoNoHang(t, "fsyncDir", dir, syscall.ENOTDIR, func() error { return fsyncDir(dir) })

	heads := f.path(HeadsDir)
	mkfifo(t, heads)
	l := &fileLog{f: f}
	fifoNoHang(t, "eachHead", heads, ErrConsistency, func() error {
		return l.eachHead(func(int64) error { return nil })
	})

	root2 := t.TempDir()
	f2 := &files{root: root2}
	entries := f2.path(EntriesDir)
	mkfifo(t, entries)
	fifoNoHang(t, "orphans", entries, ErrConsistency, func() error { return f2.orphans(0) })

	// A regular file and a directory are synced as before.
	reg := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(reg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syncFile(reg); err != nil {
		t.Fatal(err)
	}
	if err := fsyncDir(filepath.Dir(reg)); err != nil {
		t.Fatal(err)
	}
}
