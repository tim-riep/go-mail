//go:build unix

package ceremony

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestFIFOExportDir (task 20b point 5, R41): a FIFO as <from>/platform
// makes readExport (publish) fail with ErrOutDir at once, and a FIFO as
// the output directory makes checkEmpty fail, instead of an open that
// waits for a writer. checkEmpty opens the directory with
// store.OpenDir, so a FIFO put there after its Lstat fails at the open
// as well.
func TestFIFOExportDir(t *testing.T) {
	from := t.TempDir()
	platform := filepath.Join(from, "platform")
	if err := syscall.Mkfifo(platform, 0o600); err != nil {
		t.Skip(err)
	}
	for _, c := range []struct {
		name string
		f    func() error
	}{
		{"readExport", func() error { _, _, err := readExport(from); return err }},
		{"checkEmpty", func() error { return checkEmpty(platform) }},
	} {
		done := make(chan error, 1)
		go func() { done <- c.f() }()
		select {
		case err := <-done:
			if !errors.Is(err, ErrOutDir) {
				t.Fatalf("%s: %v", c.name, err)
			}
		case <-time.After(10 * time.Second):
			if w, err := os.OpenFile(platform, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
			t.Fatalf("%s: hangs at the FIFO", c.name)
		}
	}
	if err := os.Remove(platform); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(platform, 0o700); err != nil {
		t.Fatal(err)
	}
	if files, _, err := readExport(from); err != nil || len(files) != 0 {
		t.Fatalf("empty platform directory: %v %v", files, err)
	}
	if err := checkEmpty(platform); err != nil {
		t.Fatalf("empty directory: %v", err)
	}
}
