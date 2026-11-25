package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Tests of task 34 package A (review of task 33 A, H1; reviews of task
// 34 A, N1 and N3): ReplaceFileIn, WriteFileAtomicIn and
// CreateFileAtomicIn look at the name again after the rename or link
// and refuse anything but the file they wrote (ErrReplacedMeanwhile),
// and they never remove an entry of another process, neither under the
// name nor under the temporary name. tempInHook stands for the other
// process.

// foreignKinds are the entries another process puts under the
// temporary name in these tests: make makes one at p in the directory
// dir (which holds the file "other"). A make that returns errSkipKind
// is skipped (a device without CAP_MKNOD).
var foreignKinds = []struct {
	name string
	make func(dir, p string) error
}{
	{"dir", func(_, p string) error { return os.Mkdir(p, 0o755) }},
	{"dir-full", func(_, p string) error {
		if err := os.Mkdir(p, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(p, "x"), nil, 0o644)
	}},
	{"fifo", func(_, p string) error { return syscall.Mkfifo(p, 0o644) }},
	{"socket", func(_, p string) error { return syscall.Mknod(p, syscall.S_IFSOCK|0o644, 0) }},
	{"link-out", func(_, p string) error { return os.Symlink("/etc/passwd", p) }},
	{"link-loop", func(_, p string) error { return os.Symlink(filepath.Base(p), p) }},
	{"link-in", func(dir, p string) error { return os.Symlink("other", p) }},
	// A symbolic link to the file written itself (moved to "away"):
	// only Root.Lstat, never Root.Stat, sees that the name is no
	// regular file.
	{"link-own", func(dir, p string) error { return os.Symlink("away", p) }},
	{"hardlink", func(dir, p string) error { return os.Link(filepath.Join(dir, "other"), p) }},
	{"file", func(_, p string) error { return os.WriteFile(p, []byte("data"), 0o660) }},
	{"device", func(_, p string) error {
		err := syscall.Mknod(p, syscall.S_IFCHR|0o600, int(1<<8|3))
		if errors.Is(err, syscall.EPERM) {
			return errSkipKind
		}
		return err
	}},
}

var errSkipKind = errors.New("kind not possible here")

// tempNameRE is a name of newTempName.
var tempNameRE = regexp.MustCompile(`^\.tmp-[0-9a-f]{16}$`)

// entryID is the identity of an entry for the test: device and inode
// of its Lstat, and its type.
type entryID struct {
	dev, ino uint64
	mode     fs.FileMode
}

func lstatID(t *testing.T, p string) (entryID, bool) {
	t.Helper()
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return entryID{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	s := fi.Sys().(*syscall.Stat_t)
	return entryID{uint64(s.Dev), uint64(s.Ino), fi.Mode().Type()}, true
}

// fdCount counts the descriptors of the process (/proc/self/fd).
func fdCount(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// withTempInHook sets tempInHook to h for the test.
func withTempInHook(t *testing.T, h func(root *os.Root, tmp, point string)) {
	t.Helper()
	old := tempInHook
	tempInHook = h
	t.Cleanup(func() { tempInHook = old })
}

// callWithin runs f and fails the test if it does not return within a
// minute (an open of a FIFO under the name would wait for a writer).
func callWithin(t *testing.T, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Minute):
		t.Fatal("the call hangs")
		return nil
	}
}

// swapCase is one run: before is what is under name before the call
// ("" for nothing, "file", "emptydir"), point the point of tempInHook
// at which the temporary name is swapped, kind the foreign entry.
type swapCase struct {
	fn     string
	before string
	point  string
	kind   int
}

// runSwap runs one swapCase: at point, the temporary file is moved
// away (to "away", so its inode stays) and the foreign entry is put
// under the temporary name. The call must fail with
// ErrReplacedMeanwhile, the foreign entry must still be there (under
// the temporary name or under name, the same inode), no temporary
// file of the call may be left that is the file written, and no
// descriptor may be left.
func runSwap(t *testing.T, c swapCase) {
	k := foreignKinds[c.kind]
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "other"), []byte("other"), 0o660); err != nil {
		t.Fatal(err)
	}
	name := "witnesses.rec"
	p := filepath.Join(dir, name)
	switch c.before {
	case "file":
		if err := os.WriteFile(p, []byte("old"), 0o660); err != nil {
			t.Fatal(err)
		}
	case "emptydir":
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	root := openDotRoot(t, dir)
	var tmpPath string
	var foreign entryID
	swapped, skip := false, false
	withTempInHook(t, func(_ *os.Root, tmp, point string) {
		if point != c.point || swapped {
			return
		}
		swapped = true
		tmpPath = filepath.Join(dir, tmp)
		if err := os.Rename(tmpPath, filepath.Join(dir, "away")); err != nil {
			t.Error(err)
			return
		}
		if err := k.make(dir, tmpPath); err != nil {
			if err == errSkipKind {
				skip = true
				return
			}
			t.Error(err)
			return
		}
		foreign, _ = lstatID(t, tmpPath)
	})
	fds := fdCount(t)
	err := callWithin(t, func() error {
		switch c.fn {
		case "replace":
			return ReplaceFileIn(root, name, []byte("new"))
		case "write":
			return WriteFileAtomicIn(root, name, []byte("new"))
		}
		return CreateFileAtomicIn(root, name, []byte("new"))
	})
	tempInHook = nil
	if skip {
		t.Skip("no device without CAP_MKNOD")
	}
	if t.Failed() || !swapped {
		t.Fatalf("swapped %v, err %v", swapped, err)
	}
	if n := fdCount(t); n != fds {
		t.Errorf("descriptors %d before, %d after", fds, n)
	}
	if c.fn == "create" && c.before != "" {
		// The name is taken: ErrExists, and ErrReplacedMeanwhile for
		// the foreign entry under the temporary name.
		if !errors.Is(err, ErrExists) {
			t.Errorf("not ErrExists: %v", err)
		}
	}
	if !errors.Is(err, ErrReplacedMeanwhile) {
		t.Fatalf("not ErrReplacedMeanwhile: %v", err)
	}
	if strings.Contains(err.Error(), "new") {
		t.Fatalf("content in the message: %v", err)
	}
	// The foreign entry is still there: under name after a rename that
	// happened, or under the name that the temporary name was moved to
	// (dropTemp; the message names it), never removed.
	at := findID(t, dir, foreign)
	if len(at) == 0 {
		t.Fatalf("the foreign entry %s is gone: %v", k.name, err)
	}
	for _, n := range at {
		if n != name && n != "other" && !strings.Contains(err.Error(), "moved to "+filepath.Join(dir, n)+", is ") {
			t.Fatalf("the foreign entry %s is under %s, which the message does not name: %v", k.name, n, err)
		}
	}
	if n, ok := tempWritten(t, dir); ok {
		t.Fatalf("the temporary name %s, the file written, is left", n)
	}
}

// findID returns the names in dir whose entry is id.
func findID(t *testing.T, dir string, id entryID) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var at []string
	for _, e := range ents {
		if got, ok := lstatID(t, filepath.Join(dir, e.Name())); ok && got == id {
			at = append(at, e.Name())
		}
	}
	return at
}

// tempWritten returns a temporary name in dir that is a regular file
// with the content "new", the content the tests write.
func tempWritten(t *testing.T, dir string) (string, bool) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), tmpPrefix) || !e.Type().IsRegular() {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil && string(b) == "new" {
			return e.Name(), true
		}
	}
	return "", false
}

// TestFilesInTempSwapped (task 34 package A points 1 and 3, review of
// task 34 A, N1 and N3): every kind of foreign entry under the
// temporary name, put there before the close of the temporary file
// ("written") or before the rename or link, for every function and
// every state of the name before (missing, a file, an empty
// directory: renameat(2) puts a directory over a missing name or an
// empty directory, review of task 33 A, H1). Each call fails with
// ErrReplacedMeanwhile, leaves the foreign entry where it is, does
// not hang (no open of a FIFO or a device) and leaves no descriptor.
func TestFilesInTempSwapped(t *testing.T) {
	for _, fn := range []string{"replace", "write", "create"} {
		points := []string{"written", "rename"}
		if fn == "create" {
			points = []string{"written", "link"}
		}
		for _, before := range []string{"", "file", "emptydir"} {
			for _, point := range points {
				for i, k := range foreignKinds {
					c := swapCase{fn, before, point, i}
					t.Run(fn+"/"+before+"/"+point+"/"+k.name, func(t *testing.T) { runSwap(t, c) })
				}
			}
		}
	}
}

// TestFilesInTempRemoved: the temporary file removed by another
// process before the rename or link (nothing put there): the rename or
// link fails with ENOENT, nothing is removed, and the error is
// ErrReplacedMeanwhile and the *os.LinkError.
func TestFilesInTempRemoved(t *testing.T) {
	for _, fn := range []string{"replace", "create"} {
		t.Run(fn, func(t *testing.T) {
			dir := t.TempDir()
			root := openDotRoot(t, dir)
			point := map[string]string{"replace": "rename", "create": "link"}[fn]
			withTempInHook(t, func(_ *os.Root, tmp, pt string) {
				if pt == point {
					if err := os.Remove(filepath.Join(dir, tmp)); err != nil {
						t.Error(err)
					}
				}
			})
			var err error
			if fn == "replace" {
				err = ReplaceFileIn(root, "w", []byte("new"))
			} else {
				err = CreateFileAtomicIn(root, "w", []byte("new"))
			}
			var le *os.LinkError
			if !errors.Is(err, ErrReplacedMeanwhile) || !errors.As(err, &le) || !errors.Is(err, syscall.ENOENT) {
				t.Fatalf("err %v", err)
			}
			if !strings.HasSuffix(err.Error(), " is missing: "+ErrReplacedMeanwhile.Error()) {
				t.Fatalf("message %v", err)
			}
		})
	}
}

// TestCreateFileAtomicInTempGoneAfterLink: the temporary name removed
// or replaced by another process after the link, before it is looked
// at again: name is the file written and stays, but the call fails with
// ErrReplacedMeanwhile. A FIFO put under the temporary name is moved to
// a name of the call's own (dropTemp, task 36 package A point 1) and
// stays there; the message names both names.
func TestCreateFileAtomicInTempGoneAfterLink(t *testing.T) {
	for _, name := range []string{"removed", "fifo"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			root := openDotRoot(t, dir)
			var tmpPath string
			withTempInHook(t, func(_ *os.Root, tmp, pt string) {
				if pt == "linked" {
					tmpPath = filepath.Join(dir, tmp)
					if err := os.Remove(tmpPath); err != nil {
						t.Error(err)
					}
					if name == "fifo" {
						if err := syscall.Mkfifo(tmpPath, 0o644); err != nil {
							t.Error(err)
						}
					}
				}
			})
			err := callWithin(t, func() error { return CreateFileAtomicIn(root, "w", []byte("new")) })
			tempInHook = nil
			want := "store: " + tmpPath + " is missing: " + ErrReplacedMeanwhile.Error()
			if name == "fifo" {
				fifo := ""
				ents, _ := os.ReadDir(dir)
				for _, e := range ents {
					if e.Type() == fs.ModeNamedPipe {
						fifo = filepath.Join(dir, e.Name())
					}
				}
				if fifo == "" || fifo == tmpPath {
					t.Fatalf("the FIFO is gone or not moved: %q", fifo)
				}
				want = "store: " + tmpPath + ", moved to " + fifo + ", is not a regular file, not the file written, and stays there: " + ErrReplacedMeanwhile.Error()
			}
			if err == nil || err.Error() != want {
				t.Fatalf("err %v, want %s", err, want)
			}
			if b, err := os.ReadFile(filepath.Join(dir, "w")); err != nil || string(b) != "new" {
				t.Fatalf("name: %q %v", b, err)
			}
		})
	}
}

// TestFilesInTempChangedAtUnlink (task 36 package A points 2 and 3):
// the temporary name, moved to a name of its own and found to be the
// file written there, is removed or replaced by a directory before the
// unlink (the point "unlink"). The unlink finds the name missing
// (ENOENT) or a directory (EISDIR): both are ErrReplacedMeanwhile, with
// fixed messages, and the directory stays. For CreateFileAtomicIn the
// link succeeded and name is the file written; for ReplaceFileIn the
// rename failed (a full directory under name), and the error is its
// *os.LinkError and ErrReplacedMeanwhile (review of task 34 A, H2 of
// the second reviewer: removeTemp reports it).
func TestFilesInTempChangedAtUnlink(t *testing.T) {
	for _, fn := range []string{"create", "replace"} {
		for _, change := range []string{"removed", "dir"} {
			t.Run(fn+"/"+change, func(t *testing.T) {
				dir := t.TempDir()
				if fn == "replace" {
					if err := os.MkdirAll(filepath.Join(dir, "w", "x"), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				root := openDotRoot(t, dir)
				var tmpPath, aside string
				withTempInHook(t, func(_ *os.Root, tmp, pt string) {
					switch pt {
					case "opened":
						tmpPath = filepath.Join(dir, tmp)
					case "unlink":
						aside = filepath.Join(dir, tmp)
						if err := os.Rename(aside, filepath.Join(dir, "away")); err != nil {
							t.Error(err)
						}
						if change == "dir" {
							if err := os.Mkdir(aside, 0o755); err != nil {
								t.Error(err)
							}
						}
					}
				})
				fds := fdCount(t)
				var err error
				if fn == "create" {
					err = CreateFileAtomicIn(root, "w", []byte("new"))
				} else {
					err = ReplaceFileIn(root, "w", []byte("new"))
				}
				tempInHook = nil
				if n := fdCount(t); n != fds {
					t.Errorf("descriptors %d before, %d after", fds, n)
				}
				// A new temporary name of its own: random, like the
				// temporary name, not one derived from it that another
				// process could put an entry under before the rename.
				if aside == "" || aside == tmpPath || !tempNameRE.MatchString(filepath.Base(aside)) || strings.Contains(aside, filepath.Base(tmpPath)) {
					t.Fatalf("no unlink of a new name of its own: %q %q %v", tmpPath, aside, err)
				}
				what := "is missing"
				if change == "dir" {
					what = "is not a regular file, not the file written, and stays there"
				}
				want := "store: " + tmpPath + ", moved to " + aside + ", " + what + ": " + ErrReplacedMeanwhile.Error()
				var le *os.LinkError
				if fn == "create" {
					if err == nil || err.Error() != want {
						t.Fatalf("err %v, want %s", err, want)
					}
					if b, err := os.ReadFile(filepath.Join(dir, "w")); err != nil || string(b) != "new" {
						t.Fatalf("name: %q %v", b, err)
					}
				} else if !errors.Is(err, ErrReplacedMeanwhile) || !errors.As(err, &le) || !strings.HasSuffix(err.Error(), "; "+want) {
					t.Fatalf("err %v, want ...; %s", err, want)
				}
				if change == "dir" {
					if fi, err := os.Lstat(aside); err != nil || !fi.IsDir() {
						t.Fatalf("the directory: %v %v", fi, err)
					}
				}
				if _, err := os.Lstat(tmpPath); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("the temporary name is back: %v", err)
				}
			})
		}
	}
}

// TestFilesInNameChangedAfter: the name changed by another process
// after the rename or link, before it is looked at again ("renamed",
// "linked"): removed, replaced by a directory, by a FIFO or by another
// file. ErrReplacedMeanwhile without an *os.LinkError or an
// *fs.PathError (the rename happened: gomail-ceremony publish says "is
// not the file publish wrote"), the entry stays, and the message says
// what is there. For CreateFileAtomicIn the temporary name, still the
// file written, is removed.
func TestFilesInNameChangedAfter(t *testing.T) {
	for _, fn := range []string{"replace", "write", "create"} {
		for _, c := range []struct {
			name, what string
			change     func(p string) error
		}{
			{"removed", "is missing", os.Remove},
			{"dir", "is not a regular file, not the file written", func(p string) error {
				if err := os.Remove(p); err != nil {
					return err
				}
				return os.Mkdir(p, 0o755)
			}},
			{"fifo", "is not a regular file, not the file written", func(p string) error {
				if err := os.Remove(p); err != nil {
					return err
				}
				return syscall.Mkfifo(p, 0o644)
			}},
			{"file", "is another file, not the file written", func(p string) error {
				return os.Rename(filepath.Join(filepath.Dir(p), "other"), p)
			}},
		} {
			t.Run(fn+"/"+c.name, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "other"), []byte("other"), 0o660); err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(dir, "w")
				root := openDotRoot(t, dir)
				point, step := "renamed", "rename"
				if fn == "create" {
					point, step = "linked", "link"
				}
				var tmpPath string
				withTempInHook(t, func(_ *os.Root, tmp, pt string) {
					if pt == point {
						tmpPath = filepath.Join(dir, tmp)
						if err := c.change(p); err != nil {
							t.Error(err)
						}
					}
				})
				before, _ := lstatID(t, filepath.Join(dir, "other"))
				fds := fdCount(t)
				err := callWithin(t, func() error {
					switch fn {
					case "replace":
						return ReplaceFileIn(root, "w", []byte("new"))
					case "write":
						return WriteFileAtomicIn(root, "w", []byte("new"))
					}
					return CreateFileAtomicIn(root, "w", []byte("new"))
				})
				tempInHook = nil
				if n := fdCount(t); n != fds {
					t.Errorf("descriptors %d before, %d after", fds, n)
				}
				var le *os.LinkError
				var pe *fs.PathError
				if !errors.Is(err, ErrReplacedMeanwhile) || errors.As(err, &le) || errors.As(err, &pe) {
					t.Fatalf("err %v", err)
				}
				if want := "store: after the " + step + ", " + filepath.Join(dir, ".", "w") + " " + c.what + ": " + ErrReplacedMeanwhile.Error(); err.Error() != want {
					t.Fatalf("message\n%q, want\n%q", err.Error(), want)
				}
				switch c.name {
				case "removed":
					if _, ok := lstatID(t, p); ok {
						t.Fatal("name is back")
					}
				case "file":
					if id, _ := lstatID(t, p); id != before {
						t.Fatal("the other file is not under the name")
					}
				default:
					if id, ok := lstatID(t, p); !ok || id.mode.IsRegular() {
						t.Fatal("the entry under the name is gone")
					}
				}
				if fn == "create" {
					if _, ok := lstatID(t, tmpPath); ok {
						t.Fatal("the temporary name, the file written, is left")
					}
				}
			})
		}
	}
}

// TestFilesInInodeReused (review of task 34 A, M4): the temporary file
// removed before the rename and a new file of the same content created
// under its name. On ext4 the new file may get the inode number just
// freed; held keeps the inode of the file written in use, so the
// numbers differ and the rename of the new file is refused. Without
// held (a mutant) the check can take the new file for the file
// written, so the test repeats the case.
func TestFilesInInodeReused(t *testing.T) {
	for i := 0; i < 50; i++ {
		dir := t.TempDir()
		root := openDotRoot(t, dir)
		withTempInHook(t, func(_ *os.Root, tmp, pt string) {
			if pt == "rename" {
				p := filepath.Join(dir, tmp)
				if err := os.Remove(p); err != nil {
					t.Error(err)
				}
				if err := os.WriteFile(p, []byte("new"), 0o660); err != nil {
					t.Error(err)
				}
			}
		})
		err := ReplaceFileIn(root, "w", []byte("new"))
		tempInHook = nil
		if !errors.Is(err, ErrReplacedMeanwhile) || !strings.Contains(err.Error(), "is another file") {
			t.Fatalf("run %d: err %v", i, err)
		}
	}
}

// TestFilesInTempGoneOnError: on an error of the temporary file or the
// rename, the temporary name is removed only while it is the file
// written. A rename that fails for a directory under the name removes
// the temporary file (still the file written), and the error is the
// *os.LinkError alone, not ErrReplacedMeanwhile.
func TestFilesInTempGoneOnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "w"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "w", "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	root := openDotRoot(t, dir)
	err := ReplaceFileIn(root, "w", []byte("new"))
	var le *os.LinkError
	if !errors.As(err, &le) || errors.Is(err, ErrReplacedMeanwhile) {
		t.Fatalf("err %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("entries %v", ents)
	}
}
