//go:build unix

package store

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestReadFileLimitedFIFO (task 20a point 2): a FIFO in place of a file
// that is read (a record of the data directory, a pin) is refused as
// not regular at once, without a writer; so is a device. Without
// O_NONBLOCK the open waited for a writer and the reader hung.
func TestReadFileLimitedFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "user.rec")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	for name, read := range map[string]func() error{
		"fifo":        func() error { _, err := ReadFileLimited(fifo, MaxRecordFile); return err },
		"fifo as pin": func() error { _, err := ReadPlatformPin(fifo); return err },
		"device":      func() error { _, err := ReadFileLimited(os.DevNull, MaxRecordFile); return err },
	} {
		done := make(chan error, 1)
		go func() { done <- read() }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "is not a regular file") {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(20 * time.Second):
			// Unblock the open so that the test ends.
			if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				f.Close()
			}
			t.Fatalf("%s: the read waits", name)
		}
	}
	// A regular file is read as before.
	reg := filepath.Join(dir, "regular")
	if err := os.WriteFile(reg, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadFileLimited(reg, 4); err != nil || string(data) != "data" {
		t.Fatalf("regular file: %q %v", data, err)
	}
}
