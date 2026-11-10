//go:build unix

package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRemoveTempReport (review of task 25 A, L2): RemoveTempReport
// reports the name of every temporary file it removed, and nothing
// else: not a ".tmp-" directory, symbolic link or FIFO, not the bare
// prefix, not a data file.
func TestRemoveTempReport(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	for _, n := range []string{".tmp-b", ".tmp-a", ".tmp-", "data", "x.tmp-1"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(outside, []byte("o"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".tmp-dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".tmp-link")); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := RemoveTempReport(dir, func(n string) { got = append(got, n) }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != ".tmp-a .tmp-b" {
		t.Fatalf("reported %q", got)
	}
	for _, n := range []string{".tmp-", "data", "x.tmp-1", ".tmp-dir", ".tmp-link"} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("%s removed: %v", n, err)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := RemoveTempReport(dir, func(n string) { got = append(got, n) }); err != nil || got != nil {
		t.Fatalf("second run: %q %v", got, err)
	}
}

// TestRemoveNameKeepsDirectory (review of task 25 A, H2): the name of a
// temporary file is removed with unlink, so an empty directory that
// another process put under it after the listing is not removed; the
// error names the path.
func TestRemoveNameKeepsDirectory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".tmp-raced")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	err := removeName(p)
	var pe *fs.PathError
	if err == nil || !errors.As(err, &pe) || pe.Path != p {
		t.Fatalf("empty directory: %v", err)
	}
	if fi, err := os.Lstat(p); err != nil || !fi.IsDir() {
		t.Fatalf("directory removed: %v", err)
	}
	f := filepath.Join(dir, ".tmp-file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeName(f); err != nil {
		t.Fatal(err)
	}
	if err := removeName(f); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing name: %v", err)
	}
}
