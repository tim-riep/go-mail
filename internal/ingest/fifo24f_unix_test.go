//go:build unix

package ingest

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

// TestFIFORecover (task 24 package F, R41): a FIFO in place of spool/ or
// work/ makes Recover fail at once (syscall.ENOTDIR) instead of an open
// that waits for a writer; a missing spool/ is still fs.ErrNotExist.
// Recover needs only the store and the logger of Ingest, so the test
// runs without the development ceremony.
func TestFIFORecover(t *testing.T) {
	st, err := store.Init(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	in := &Ingest{st: st, log: slog.New(slog.DiscardHandler)}
	if err := in.Recover(); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{st.SpoolDir(), st.WorkDir()} {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(dir, 0o600); err != nil {
			t.Skip(err)
		}
		done := make(chan error, 1)
		go func() { done <- in.Recover() }()
		select {
		case err := <-done:
			if !errors.Is(err, syscall.ENOTDIR) {
				t.Fatalf("Recover with FIFO %s: %v, want %v", dir, err, syscall.ENOTDIR)
			}
		case <-time.After(10 * time.Second):
			if w, err := os.OpenFile(dir, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
			t.Fatalf("Recover hangs at the FIFO %s", dir)
		}
		if err := os.Remove(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := in.Recover(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(st.SpoolDir()); err != nil {
		t.Fatal(err)
	}
	if err := in.Recover(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing spool/: %v", err)
	}
}
