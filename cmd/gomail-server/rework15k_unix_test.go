//go:build unix

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestInitFIFO (finding 3): a FIFO or a device as --pin or --witnesses
// is refused as not a regular file (exit status 1) at once, without a
// writer on the FIFO; nothing is created. readPin (serve, address add,
// log repair) reads its pin through readPinFile as well.
func TestInitFIFO(t *testing.T) {
	dir := t.TempDir()
	_, pin := testPin(t, dir, "identity-1.pin", false, 1, 1)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	data := filepath.Join(dir, "data")
	cases := map[string][]string{
		"fifo as --pin":         {"init", "--data", data, "--pin", fifo},
		"fifo as --witnesses":   {"init", "--data", data, "--pin", pin, "--witnesses", fifo},
		"device as --pin":       {"init", "--data", data, "--pin", os.DevNull},
		"device as --witnesses": {"init", "--data", data, "--pin", pin, "--witnesses", os.DevNull},
	}
	for name, args := range cases {
		done := make(chan struct{})
		var code int
		var errb bytes.Buffer
		go func() {
			var out bytes.Buffer
			code = run(context.Background(), args, &out, &errb, nil)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			// Unblock the open so that the test ends.
			if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				f.Close()
			}
			t.Fatalf("%s: init waits", name)
		}
		if code != 1 || !strings.Contains(errb.String(), "keine reguläre Datei") {
			t.Fatalf("%s: %d %s", name, code, errb.String())
		}
		if _, err := os.Lstat(data); err == nil {
			t.Fatalf("%s: data directory created", name)
		}
	}
	if _, err := readPinFile(fifo); err == nil || !strings.Contains(err.Error(), "keine reguläre Datei") {
		t.Fatalf("readPinFile on a FIFO: %v", err)
	}
}
