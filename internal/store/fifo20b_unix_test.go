//go:build unix

package store

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestOpenDirOpenRegularFIFO (task 20b point 5, R41): OpenDir and
// SyncDir refuse a FIFO, or a regular file, in place of a directory at
// once (syscall.ENOTDIR); OpenRegular and ReadFileLimited refuse a FIFO
// in place of a file as ErrNotRegular. A directory, a symbolic link to
// one and a regular file open as before.
func TestOpenDirOpenRegularFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	reg := filepath.Join(dir, "regular")
	if err := os.WriteFile(reg, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	// index/<n>/ of a mailbox as a FIFO (ListIndexSegments, task 20b
	// point 4).
	s, err := Init(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	mbx := ID{9}
	idx := s.IndexDir(mbx, 1)
	if err := MkdirAll(filepath.Dir(idx)); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(idx, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		want error
		f    func() error
	}{
		{"OpenDir fifo", syscall.ENOTDIR, func() error { _, err := OpenDir(fifo); return err }},
		{"SyncDir fifo", syscall.ENOTDIR, func() error { return SyncDir(fifo) }},
		{"OpenDir regular", syscall.ENOTDIR, func() error { _, err := OpenDir(reg); return err }},
		{"OpenRegular fifo", ErrNotRegular, func() error { _, _, err := OpenRegular(fifo); return err }},
		{"ReadFileLimited fifo", ErrNotRegular, func() error { _, err := ReadFileLimited(fifo, MaxRecordFile); return err }},
		{"OpenRegular directory", ErrNotRegular, func() error { _, _, err := OpenRegular(dir); return err }},
		{"OpenRegular missing", ErrNotFound, func() error { _, _, err := OpenRegular(filepath.Join(dir, "none")); return err }},
		{"ListIndexSegments fifo", syscall.ENOTDIR, func() error { _, err := s.ListIndexSegments(mbx, 1); return err }},
	} {
		done := make(chan error, 1)
		go func() { done <- c.f() }()
		select {
		case err := <-done:
			if !errors.Is(err, c.want) {
				t.Fatalf("%s: %v, want %v", c.name, err, c.want)
			}
		case <-time.After(10 * time.Second):
			for _, p := range []string{fifo, idx} {
				if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					w.Close()
				}
			}
			t.Fatalf("%s: hangs at the FIFO", c.name)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{dir, link} {
		f, err := OpenDir(d)
		if err != nil {
			t.Fatalf("OpenDir %s: %v", d, err)
		}
		f.Close()
		if err := SyncDir(d); err != nil {
			t.Fatalf("SyncDir %s: %v", d, err)
		}
	}
	f, fi, err := OpenRegular(reg)
	if err != nil || fi.Size() != 4 {
		t.Fatalf("OpenRegular regular: %v", err)
	}
	f.Close()
}
