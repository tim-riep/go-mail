package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

// TestReadDir (task 24 package F, R41): ReadDir returns the entries of a
// directory sorted by name with their types, like os.ReadDir; a missing
// directory is fs.ErrNotExist (as for os.ReadDir, so callers that treat
// it as empty keep doing so), a regular file in place of the directory
// is syscall.ENOTDIR, and an empty directory has no entries.
func TestReadDir(t *testing.T) {
	dir := t.TempDir()
	// Created in ascending order and with names whose byte order differs
	// from their numeric order: no file system lists 40 of them sorted by
	// chance, so an unsorted result is noticed.
	var want []string
	for i := range 40 {
		name := fmt.Sprintf("%d", i)
		if i%3 == 0 {
			name += ".gml"
		}
		p := filepath.Join(dir, name)
		if i%2 == 0 {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		want = append(want, name)
	}
	slices.Sort(want)
	got, err := ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || len(ref) != len(want) {
		t.Fatalf("%d entries, os.ReadDir %d, want %d", len(got), len(ref), len(want))
	}
	for i, e := range got {
		if e.Name() != want[i] || e.Name() != ref[i].Name() || e.IsDir() != ref[i].IsDir() || e.Type() != ref[i].Type() {
			t.Fatalf("entry %d: %q dir=%v, want %q (os.ReadDir %q dir=%v)", i, e.Name(), e.IsDir(), want[i], ref[i].Name(), ref[i].IsDir())
		}
	}

	empty := filepath.Join(dir, "2")
	if got, err := ReadDir(empty); err != nil || len(got) != 0 {
		t.Fatalf("empty directory: %v %v", got, err)
	}

	missing := filepath.Join(dir, "none")
	got, err = ReadDir(missing)
	_, ref2 := os.ReadDir(missing)
	if got != nil || !errors.Is(err, fs.ErrNotExist) || !errors.Is(ref2, fs.ErrNotExist) || errors.Is(err, ErrNotFound) {
		t.Fatalf("missing directory: %v %v (os.ReadDir: %v)", got, err, ref2)
	}

	file := filepath.Join(dir, "1")
	got, err = ReadDir(file)
	_, ref2 = os.ReadDir(file)
	if got != nil || !errors.Is(err, syscall.ENOTDIR) || !errors.Is(ref2, syscall.ENOTDIR) {
		t.Fatalf("file: %v %v (os.ReadDir: %v)", got, err, ref2)
	}
}
