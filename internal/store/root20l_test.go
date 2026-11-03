package store

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestWritePrivateFileAtomicIn (task 20l point 1): the file is written
// through the root into the directory it holds, with mode
// PrivateFilePerm, also after the directory was renamed and another one
// put at its old name; no temporary file is left, on success or when
// the rename fails.
func TestWritePrivateFileAtomicIn(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := WritePrivateFileAtomicIn(root, "a", []byte("one")); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFileAtomicIn(root, "a", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFileAtomicIn(root, "b", []byte("three")); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"a": "two", "b": "three"} {
		p := filepath.Join(moved, name)
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, []byte(want)) {
			t.Fatalf("%s: %q %v", name, got, err)
		}
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != PrivateFilePerm {
			t.Fatalf("%s: mode %v %v", name, fi, err)
		}
	}
	if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
		t.Fatalf("directory at the old name: %v %v", ents, err)
	}
	// A directory as target: the rename fails and the temporary file is
	// removed.
	if err := os.Mkdir(filepath.Join(moved, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moved, "sub", "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFileAtomicIn(root, "sub", []byte("four")); err == nil {
		t.Fatal("write over a directory")
	}
	ents, err := os.ReadDir(moved)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 3 {
		t.Fatalf("entries after the failed write: %v", ents)
	}
	if err := SyncRoot(root); err != nil {
		t.Fatal(err)
	}
	// A name outside the root is refused.
	if err := WritePrivateFileAtomicIn(root, "../escape", []byte("x")); err == nil {
		t.Fatal("write outside the root")
	}
	if _, err := os.Lstat(filepath.Join(base, "escape")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("file outside the root: %v", err)
	}
}
