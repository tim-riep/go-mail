//go:build unix

package store

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests of task 26 package 26B (backlog 72): the functions of fsroot.go
// work in the directory an os.Root holds, wherever its path leads by
// now.

// movedRoot opens a new directory with the files files as an os.Root,
// then moves the directory away and puts a symbolic link to a decoy
// directory with the same files in its place. It returns the root, the
// moved directory and the decoy.
func movedRoot(t *testing.T, files ...string) (*os.Root, string, string) {
	t.Helper()
	base := t.TempDir()
	dir, moved, decoy := filepath.Join(base, "dir"), filepath.Join(base, "moved"), filepath.Join(base, "decoy")
	for _, d := range []string{dir, decoy} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, n := range files {
			if err := os.WriteFile(filepath.Join(d, n), []byte(n), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, dir); err != nil {
		t.Fatal(err)
	}
	return root, moved, decoy
}

// names lists dir.
func names(t *testing.T, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, e := range ents {
		s = append(s, e.Name())
	}
	return strings.Join(s, " ")
}

// TestRemoveTempReportIn: the temporary files of the directory the root
// holds are removed and reported, a ".tmp-" directory (empty) and a
// ".tmp-" symbolic link stay, and nothing changes in the directory the
// old path leads to now.
func TestRemoveTempReportIn(t *testing.T) {
	root, moved, decoy := movedRoot(t, ".tmp-b", ".tmp-a", "data")
	if err := os.Mkdir(filepath.Join(moved, ".tmp-dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("data", filepath.Join(moved, ".tmp-link")); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := RemoveTempReportIn(root, func(n string) { got = append(got, n) }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != ".tmp-a .tmp-b" {
		t.Fatalf("reported %q", got)
	}
	if n := names(t, moved); n != ".tmp-dir .tmp-link data" {
		t.Fatalf("left %q", n)
	}
	if n := names(t, decoy); n != ".tmp-a .tmp-b data" {
		t.Fatalf("decoy changed: %q", n)
	}
}

// TestRemoveNameInKeepsDirectory: removeNameIn removes with unlink, so
// an empty directory under the name stays; the error names its path.
func TestRemoveNameInKeepsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".tmp-raced"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	err = removeNameIn(root, ".tmp-raced")
	var pe *fs.PathError
	if err == nil || !errors.As(err, &pe) || pe.Op != "unlink" || pe.Path != filepath.Join(dir, ".tmp-raced") {
		t.Fatalf("empty directory: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(dir, ".tmp-raced")); err != nil || !fi.IsDir() {
		t.Fatalf("directory removed: %v", err)
	}
	for _, n := range []string{"", ".", "..", "a/b"} {
		if err := removeNameIn(root, n); !errors.Is(err, errNameInRoot) {
			t.Fatalf("%q: %v", n, err)
		}
	}
}

// TestWriteFilesIn: CreateFileAtomicIn, WriteFileAtomicIn and
// OpenRegularIn work in the directory the root holds: a new file lands
// there with mode FilePerm and no temporary file left, a taken name (a
// dangling symbolic link as well) is ErrExists, WriteFileAtomicIn
// replaces a symbolic link itself, never its target, and nothing goes
// to the directory the old path leads to now.
func TestWriteFilesIn(t *testing.T) {
	root, moved, decoy := movedRoot(t, "old")
	if err := CreateFileAtomicIn(root, "new", []byte("n")); err != nil {
		t.Fatal(err)
	}
	if err := CreateFileAtomicIn(root, "old", []byte("x")); !errors.Is(err, ErrExists) || err.Error() != "store: file exists: old" {
		t.Fatalf("taken name: %v", err)
	}
	if err := os.Symlink("none", filepath.Join(moved, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := CreateFileAtomicIn(root, "dangling", []byte("x")); !errors.Is(err, ErrExists) {
		t.Fatalf("dangling link: %v", err)
	}
	if err := os.Symlink("old", filepath.Join(moved, "link")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomicIn(root, "link", []byte("l")); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]string{"new": "n", "old": "old", "link": "l"} {
		fi, err := os.Lstat(filepath.Join(moved, n))
		if err != nil || !fi.Mode().IsRegular() || n != "old" && fi.Mode()&modeBits != FilePerm&modeBits {
			t.Fatalf("%s: %v %v", n, fi, err)
		}
		f, ofi, err := OpenRegularIn(root, n)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		b.ReadFrom(f)
		f.Close()
		if b.String() != want || !os.SameFile(fi, ofi) {
			t.Fatalf("%s holds %q", n, b.String())
		}
	}
	if n := names(t, moved); n != "dangling link new old" {
		t.Fatalf("left %q", n)
	}
	if n := names(t, decoy); n != "old" {
		t.Fatalf("decoy changed: %q", n)
	}
	if _, _, err := OpenRegularIn(root, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := os.Mkdir(filepath.Join(moved, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenRegularIn(root, "sub"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directory: %v", err)
	}
}

// TestRemoveTempFilesKeepsDirectory (backlog 73): RemoveTempFiles
// removes the names of temporary files with unlink. A ".tmp-" directory
// stays (its temporary files inside are removed), and so does an empty
// directory that another process puts under the name of a temporary
// file after the listing (tempFilesHook); neither is an error, so the
// server start does not stop at it.
func TestRemoveTempFilesKeepsDirectory(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := s.Path("mailboxes", "x")
	for _, d := range []string{dir, filepath.Join(dir, ".tmp-dir"), filepath.Join(dir, ".tmp-empty")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{".tmp-raced", ".tmp-file", filepath.Join(".tmp-dir", ".tmp-inner"), "keep"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raced := filepath.Join(dir, ".tmp-raced")
	var seen []string
	tempFilesHook = func(p string) {
		seen = append(seen, p)
		if p == raced {
			if err := os.Remove(p); err != nil {
				t.Error(err)
			}
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Error(err)
			}
		}
	}
	defer func() { tempFilesHook = nil }()
	if err := s.RemoveTempFiles(); err != nil {
		t.Fatal(err)
	}
	if n := names(t, dir); n != ".tmp-dir .tmp-empty .tmp-raced keep" {
		t.Fatalf("left %q (hook saw %q)", n, seen)
	}
	if fi, err := os.Lstat(raced); err != nil || !fi.IsDir() {
		t.Fatalf("directory under the name removed: %v", err)
	}
	if n := names(t, filepath.Join(dir, ".tmp-dir")); n != "" {
		t.Fatalf("left in .tmp-dir: %q", n)
	}
}
