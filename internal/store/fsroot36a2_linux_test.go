package store

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Tests of task 36 package A2 (review of task 36 A, N1 and N2 of both
// reviewers): written.dropTemp falls back to the temporary name itself
// when its rename to aside fails, and aside is new in every call.

// tempEntries lists the entries of dir whose names start with ".tmp-".
func tempEntries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			names = append(names, e.Name())
		}
	}
	return names
}

// TestDropTempAppendOnly (task 36 package A2 points 1 and 3): in a
// directory with chattr +a a link and a create succeed, a rename and an
// unlink fail with EPERM. The rename to aside fails, and dropTemp falls
// back to the temporary name: CreateFileAtomicIn reports the unlink of
// the temporary name as before task 36 package A, never a rename to a
// name that does not exist; ReplaceFileIn reports its failing rename to
// name only. The temporary file stays under its own name, and
// RemoveTempReportIn removes it once chattr -a is back. Skipped where
// chattr +a is not possible (not root, or a file system without it).
func TestDropTempAppendOnly(t *testing.T) {
	chattr, err := exec.LookPath("chattr")
	if err != nil {
		t.Skip("no chattr")
	}
	for _, fn := range []string{"create", "replace"} {
		t.Run(fn, func(t *testing.T) {
			dir := t.TempDir()
			if fn == "replace" {
				// A full directory under name: the rename to it fails.
				if err := os.MkdirAll(filepath.Join(dir, "w", "x"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if out, err := exec.Command(chattr, "+a", dir).CombinedOutput(); err != nil {
				t.Skipf("chattr +a not possible here: %v %s", err, bytes.TrimSpace(out))
			}
			appendOnly := true
			unset := func() {
				if appendOnly {
					if out, err := exec.Command(chattr, "-a", dir).CombinedOutput(); err != nil {
						t.Errorf("chattr -a: %v %s", err, out)
					}
					appendOnly = false
				}
			}
			t.Cleanup(unset)
			root := openDotRoot(t, dir)
			var tmpPath string
			withTempInHook(t, func(_ *os.Root, tmp, pt string) {
				if pt == "opened" {
					tmpPath = filepath.Join(dir, tmp)
				}
			})
			fds := fdCount(t)
			if fn == "create" {
				err = CreateFileAtomicIn(root, "w", []byte("new"))
			} else {
				err = ReplaceFileIn(root, "w", []byte("new"))
			}
			tempInHook = nil
			if n := fdCount(t); n != fds {
				t.Errorf("descriptors %d before, %d after", fds, n)
			}
			if errors.Is(err, ErrReplacedMeanwhile) {
				t.Fatalf("err %v is ErrReplacedMeanwhile", err)
			}
			if fn == "create" {
				want := "unlink " + tmpPath + ": " + syscall.EPERM.Error()
				var pe *fs.PathError
				if err == nil || err.Error() != want || !errors.As(err, &pe) || !errors.Is(err, syscall.EPERM) {
					t.Fatalf("err %v, want %s", err, want)
				}
				if b, err := os.ReadFile(filepath.Join(dir, "w")); err != nil || string(b) != "new" {
					t.Fatalf("name: %q %v", b, err)
				}
			} else {
				var le *os.LinkError
				if !errors.As(err, &le) || le.Op != "rename" || le.Old != tmpPath || le.New != filepath.Join(dir, "w") {
					t.Fatalf("err %v, want the *os.LinkError of the rename of %s", err, tmpPath)
				}
			}
			if got := tempEntries(t, dir); len(got) != 1 || got[0] != filepath.Base(tmpPath) {
				t.Fatalf("temporary entries %q, want %s under its own name", got, filepath.Base(tmpPath))
			}
			unset()
			var removed []string
			if err := RemoveTempReportIn(root, func(n string) { removed = append(removed, n) }); err != nil || len(removed) != 1 {
				t.Fatalf("RemoveTempReportIn: %q %v", removed, err)
			}
		})
	}
}

// mountSmallExt4 mounts a new ext4 file system of 8 MiB (blocks of 1 KiB,
// no reserved blocks) from an image in a new directory of the test and
// returns its root; the test unmounts it when it ends. Skipped where
// that is not possible: not root, no mkfs.ext4 or mount, no loop device.
func mountSmallExt4(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("a full file system of its own needs a loop mount, as root only")
	}
	var tools [3]string
	for i, name := range []string{"mkfs.ext4", "mount", "umount"} {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("no %s", name)
		}
		tools[i] = p
	}
	base := t.TempDir()
	img, mnt := filepath.Join(base, "img"), filepath.Join(base, "mnt")
	if err := os.Mkdir(mnt, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 8<<20); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(tools[0], "-q", "-F", "-m", "0", "-b", "1024", "-N", "2048", img).CombinedOutput(); err != nil {
		t.Skipf("mkfs.ext4: %v %s", err, bytes.TrimSpace(out))
	}
	if out, err := exec.Command(tools[1], "-o", "loop", img, mnt).CombinedOutput(); err != nil {
		t.Skipf("loop mount not possible here: %v %s", err, bytes.TrimSpace(out))
	}
	t.Cleanup(func() {
		if out, err := exec.Command(tools[2], mnt).CombinedOutput(); err != nil {
			t.Errorf("umount: %v %s", err, out)
		}
	})
	return mnt
}

// fillExt4 fills the file system of mnt: one big file until ENOSPC,
// then empty files with names as long as a temporary name in sub until
// its directory has no room for another entry; then it removes free of
// them, which leaves room for free entries in sub and none for a new
// block of the directory.
func fillExt4(t *testing.T, mnt, sub string, free int) {
	t.Helper()
	f, err := os.Create(filepath.Join(mnt, "big"))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1<<16)
	for _, n := range []int{len(buf), 512} {
		for {
			if _, err := f.Write(buf[:n]); err != nil {
				break
			}
		}
	}
	if err := f.Close(); err != nil && !errors.Is(err, syscall.ENOSPC) {
		t.Fatal(err)
	}
	name := func(i int) string { return filepath.Join(sub, fmt.Sprintf("f%020d", i)) }
	i := 0
	for ; ; i++ {
		g, err := os.OpenFile(name(i), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("fill: %v", err)
			}
			break
		}
		g.Close()
	}
	if i < 2*free+10 {
		t.Fatalf("fill: only %d entries", i)
	}
	for j := 0; j < free; j++ {
		if err := os.Remove(name(2 + 2*j)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestDropTempNoSpace (task 36 package A2 points 1 and 3; review of
// task 36 A, N1 and N2 of the second reviewer, F1 of the review of
// task 36 g): a full file system whose directory has room for the
// entries a call makes but not for aside. The rename to aside fails
// with ENOSPC and dropTemp falls back to the temporary name:
//   - "link": CreateFileAtomicIn with empty data succeeds, as before
//     task 36 package A (no new refusal on its way to success), and
//     leaves no temporary file;
//   - "link-fifo": the same, but another process put a FIFO under the
//     temporary name after the link: ErrReplacedMeanwhile, and the FIFO
//     stays (the fallback looks at the name before its unlink);
//   - "write-create", "write-replace": the write fails with ENOSPC, and
//     the temporary file is removed (it stayed in 558ce2b).
func TestDropTempNoSpace(t *testing.T) {
	// A name as long as a temporary name: its entry takes a slot as
	// large as that of aside.
	const name = "w00000000000000000000"
	for _, c := range []string{"link", "link-fifo", "write-create", "write-replace"} {
		t.Run(c, func(t *testing.T) {
			mnt := mountSmallExt4(t)
			sub := filepath.Join(mnt, "d")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			data := []byte{}
			free := 2
			if strings.HasPrefix(c, "write-") {
				if err := os.WriteFile(filepath.Join(sub, name), []byte("old"), 0o600); err != nil {
					t.Fatal(err)
				}
				data = make([]byte, 1<<16)
				free = 1
			}
			fillExt4(t, mnt, sub, free)
			root := openDotRoot(t, sub)
			var tmpPath, unlinked string
			withTempInHook(t, func(_ *os.Root, tmp, pt string) {
				switch pt {
				case "opened":
					tmpPath = filepath.Join(sub, tmp)
				case "unlink":
					unlinked = tmp
				case "linked":
					if c == "link-fifo" {
						if err := os.Remove(tmpPath); err != nil {
							t.Error(err)
						}
						if err := syscall.Mkfifo(tmpPath, 0o644); err != nil {
							t.Error(err)
						}
					}
				}
			})
			fds := fdCount(t)
			var err error
			if c == "write-replace" {
				err = callWithin(t, func() error { return ReplaceFileIn(root, name, data) })
			} else {
				err = callWithin(t, func() error { return CreateFileAtomicIn(root, name, data) })
			}
			tempInHook = nil
			if n := fdCount(t); n != fds {
				t.Errorf("descriptors %d before, %d after", fds, n)
			}
			wantName := ""
			switch c {
			case "link":
				if err != nil {
					t.Fatalf("err %v, want nil", err)
				}
			case "link-fifo":
				want := "store: " + tmpPath + " is not a regular file, not the file written, and stays: " + ErrReplacedMeanwhile.Error()
				if err == nil || err.Error() != want {
					t.Fatalf("err %v, want %s", err, want)
				}
				if fi, err := os.Lstat(tmpPath); err != nil || fi.Mode().Type() != fs.ModeNamedPipe {
					t.Fatalf("the FIFO: %v %v", fi, err)
				}
			default:
				wantName = "old"
				var pe *fs.PathError
				if !errors.As(err, &pe) || pe.Op != "write" || pe.Path != tmpPath || !errors.Is(err, syscall.ENOSPC) || errors.Is(err, ErrReplacedMeanwhile) {
					t.Fatalf("err %v, want the ENOSPC of the write to %s", err, tmpPath)
				}
			}
			if c != "link-fifo" && unlinked != filepath.Base(tmpPath) {
				// The rename to aside must have failed (the fallback
				// unlinks the temporary name itself).
				t.Fatalf("unlink of %q, want the fallback to %s", unlinked, tmpPath)
			}
			if b, err := os.ReadFile(filepath.Join(sub, name)); err != nil || string(b) != wantName {
				t.Fatalf("name: %q %v, want %q", b, err, wantName)
			}
			got := tempEntries(t, sub)
			if c == "link-fifo" {
				if len(got) != 1 || got[0] != filepath.Base(tmpPath) {
					t.Fatalf("temporary entries %q, want the FIFO only", got)
				}
			} else if len(got) != 0 {
				t.Fatalf("temporary entries %q left", got)
			}
		})
	}
}

// TestDropTempAsideNew (task 36 package A2 point 3; review of task
// 36 A, N2 of the first reviewer): two calls move their temporary names
// to two different names aside, each a name of newTempName and none of
// them a temporary name of either call.
func TestDropTempAsideNew(t *testing.T) {
	dir := t.TempDir()
	root := openDotRoot(t, dir)
	var tmps, asides []string
	withTempInHook(t, func(_ *os.Root, tmp, pt string) {
		switch pt {
		case "opened":
			tmps = append(tmps, tmp)
		case "unlink":
			asides = append(asides, tmp)
		}
	})
	for _, name := range []string{"a", "b"} {
		if err := CreateFileAtomicIn(root, name, []byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	tempInHook = nil
	if len(tmps) != 2 || len(asides) != 2 || asides[0] == asides[1] {
		t.Fatalf("temporary names %q, aside %q", tmps, asides)
	}
	for _, a := range asides {
		if !tempNameRE.MatchString(a) || a == tmps[0] || a == tmps[1] {
			t.Fatalf("aside %q: temporary names %q", asides, tmps)
		}
	}
	if got := tempEntries(t, dir); len(got) != 0 {
		t.Fatalf("temporary entries %q left", got)
	}
}
