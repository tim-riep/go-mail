//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestPinFIFO (task 20a point 2): a FIFO as --pin is refused as not a
// regular file at once (store.ReadFileLimited opens with O_NONBLOCK),
// without a writer; before, the open waited for one and the ceremony
// hung. publish needs no terminal, so the read of the pin is its first
// step; reshare, ingest-rotate and succeed read the pin the same way.
func TestPinFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "identity-1.pin")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan int, 1)
	var errb bytes.Buffer
	go func() {
		var out bytes.Buffer
		done <- run([]string{"publish", "--from", filepath.Join(dir, "export"), "--data", filepath.Join(dir, "data"), "--pin", fifo},
			strings.NewReader(""), &out, &errb)
	}()
	select {
	case code := <-done:
		if code == 0 || !strings.Contains(errb.String(), "is not a regular file") {
			t.Fatalf("exit code %d: %s", code, errb.String())
		}
	case <-time.After(20 * time.Second):
		// Unblock the open so that the test ends.
		if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
		t.Fatal("publish waits at a FIFO as --pin")
	}
}
