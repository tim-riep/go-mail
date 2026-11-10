//go:build unix

package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Tests of the rework 26B2 of task 26 package B: the errors of the
// functions of fsroot.go name paths as the functions on a path do
// (review N2), and RemoveTempFiles stops at a temporary file it cannot
// remove (review of the specification, N2).

// tmpName matches the random part of a temporary file's name.
var tmpName = regexp.MustCompile(`\.tmp-[0-9a-f]{16}`)

// openDotRoot opens dir as gomail-ceremony publish opens platform/:
// os.OpenRoot of "<dir>/.", so that the root is named "<dir>/." and a
// file opened through it "<dir>/./<name>".
func openDotRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir + string(filepath.Separator) + ".")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// TestFilesInErrorsNamePaths: each function of fsroot.go fails in a
// case that the function on a path fails in as well, and the two
// messages are the same (up to the random name of a temporary file),
// or, where the function on a path has no such case, the message is
// the one given:
// the path of the name in the directory and the operation of the os
// function on a path ("open", "rename", "link"), never the name alone
// ("openat ingest-1.cert"), the operation of os.Root ("renameat",
// "linkat") or the name of the descriptor ("<dir>/./.").
func TestFilesInErrorsNamePaths(t *testing.T) {
	long := strings.Repeat("n", 300)
	for _, c := range []struct {
		name string
		// prep makes the case in dir (which exists and is empty) and
		// returns whether dir is to be removed after the root is open.
		prep   func(t *testing.T, dir string) bool
		path   func(dir string) error
		in     func(root *os.Root) error
		prefix string
	}{
		{"open long name", func(*testing.T, string) bool { return false },
			func(dir string) error { _, _, err := OpenRegular(filepath.Join(dir, long)); return err },
			func(root *os.Root) error { _, _, err := OpenRegularIn(root, long); return err },
			"open DIR/" + long + ": "},
		{"rename over a directory", func(t *testing.T, dir string) bool {
			if err := os.MkdirAll(filepath.Join(dir, "witnesses.rec", "k"), 0o755); err != nil {
				t.Fatal(err)
			}
			return false
		},
			func(dir string) error { return WriteFileAtomic(filepath.Join(dir, "witnesses.rec"), []byte("w")) },
			func(root *os.Root) error { return ReplaceFileIn(root, "witnesses.rec", []byte("w")) },
			"rename DIR/.tmp-X DIR/witnesses.rec: "},
		{"link long name", func(*testing.T, string) bool { return false },
			func(dir string) error { return CreateFileAtomic(filepath.Join(dir, long), []byte("c")) },
			func(root *os.Root) error { return CreateFileAtomicIn(root, long, []byte("c")) },
			"link DIR/.tmp-X DIR/" + long + ": "},
		{"temporary file in a removed directory", func(*testing.T, string) bool { return true },
			func(dir string) error { return WriteFileAtomic(filepath.Join(dir, "ingest-1.cert"), []byte("c")) },
			func(root *os.Root) error { return WriteFileAtomicIn(root, "ingest-1.cert", []byte("c")) },
			"open DIR/.tmp-X: "},
		{"create in a removed directory", func(*testing.T, string) bool { return true },
			func(dir string) error { return CreateFileAtomic(filepath.Join(dir, "ingest-1.cert"), []byte("c")) },
			func(root *os.Root) error { return CreateFileAtomicIn(root, "ingest-1.cert", []byte("c")) },
			"open DIR/.tmp-X: "},
		// The descriptor of a removed directory still opens as ".", and
		// its listing fails: ReadDir fails the same way while the
		// directory is listed (review of task 26 package B, H1: it named
		// "DIR/./." before).
		{"list a removed directory", func(*testing.T, string) bool { return true },
			nil,
			func(root *os.Root) error { _, err := ReadDirIn(root); return err },
			"readdirent DIR: no such file or directory"},
		// A closed root stands for a descriptor that cannot be opened.
		{"sync through a closed root", func(*testing.T, string) bool { return false },
			nil,
			func(root *os.Root) error { root.Close(); return SyncDirIn(root) },
			"open DIR: file already closed"},
		{"list through a closed root", func(*testing.T, string) bool { return false },
			nil,
			func(root *os.Root) error { root.Close(); _, err := ReadDirIn(root); return err },
			"open DIR: file already closed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "list a removed directory" && runtime.GOOS != "linux" {
				t.Skip("getdents(2) of a removed directory fails with ENOENT on Linux")
			}
			norm := func(err error, dir string) string {
				if err == nil {
					return "<nil>"
				}
				return tmpName.ReplaceAllString(strings.ReplaceAll(err.Error(), dir, "DIR"), ".tmp-X")
			}
			pdir := filepath.Join(t.TempDir(), "platform")
			if err := os.Mkdir(pdir, 0o755); err != nil {
				t.Fatal(err)
			}
			if c.prep(t, pdir) {
				if err := os.Remove(pdir); err != nil {
					t.Fatal(err)
				}
			}
			want := c.prefix
			if c.path != nil {
				want = norm(c.path(pdir), pdir)
			}

			rdir := filepath.Join(t.TempDir(), "platform")
			if err := os.Mkdir(rdir, 0o755); err != nil {
				t.Fatal(err)
			}
			gone := c.prep(t, rdir)
			root := openDotRoot(t, rdir)
			if gone {
				if err := os.Remove(rdir); err != nil {
					t.Fatal(err)
				}
			}
			got := norm(c.in(root), rdir)
			if got != want || !strings.HasPrefix(got, c.prefix) || strings.Contains(got, "/./") {
				t.Fatalf("message:\n got %s\nwant %s (prefix %q)", got, want, c.prefix)
			}
		})
	}
}

// TestRemoveTempFilesDenied (review of the specification of task 26
// package B, proposal): a temporary file that cannot be removed (its
// directory is not writable) stops RemoveTempFiles with that error;
// only a directory under the name, or a name gone meanwhile, is skipped.
// Without CAP_DAC_OVERRIDE only.
func TestRemoveTempFilesDenied(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := s.Path("mailboxes", "x")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".tmp-f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if err := os.WriteFile(filepath.Join(dir, "probe"), nil, 0o600); err == nil {
		t.Skip("privileged: the directory is writable all the same")
	}
	err = s.RemoveTempFiles()
	if !errors.Is(err, fs.ErrPermission) || err.Error() != "unlink "+filepath.Join(dir, ".tmp-f")+": permission denied" {
		t.Fatalf("denied: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, ".tmp-f")); err != nil {
		t.Fatalf("temporary file: %v", err)
	}
}
