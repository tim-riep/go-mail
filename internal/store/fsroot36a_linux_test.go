package store

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Tests of task 36 package A (reviews of task 34 A, N1 and N2 of the
// first reviewer): the error path of writeTempIn with a temporary name
// swapped by another process, and FD_CLOEXEC of held.

// fsizeChildEnv marks the child process of inFsizeChild.
const fsizeChildEnv = "GOMAIL_STORE_TEST_FSIZE_CHILD"

// inFsizeChild reports whether this process is the child of
// inFsizeChild, in which the test t runs itself. In the test process
// itself it runs t in a child process (this test binary, running only
// t) and fails t with the output of the child unless the child passed
// t, or skips t with it when the child skipped t; it returns false
// then. A test that lowers RLIMIT_FSIZE (limitFileSize) runs only in
// such a child: the limit holds for the whole process, and with the
// test cache on, go test makes the test process write each file it
// opens or stats and each variable it reads to a log file of its own
// (-test.testlogfile); under the lowered limit that write fails and
// the package fails although every test passed (task 36 A3). The child
// gets no -test.testlogfile, writes its output only to a pipe, and
// gets the environment of this process, so the variables it reads are
// those read here.
func inFsizeChild(t *testing.T) bool {
	t.Helper()
	if os.Getenv(fsizeChildEnv) == "1" {
		return true
	}
	parts := strings.Split(t.Name(), "/")
	for i, p := range parts {
		parts[i] = "^" + regexp.QuoteMeta(p) + "$"
	}
	ctx := context.Background()
	if d, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, d)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run="+strings.Join(parts, "/"), "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), fsizeChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	switch {
	case err != nil:
		t.Fatalf("child: %v\n%s", err, out)
	case bytes.Contains(out, []byte("--- SKIP: "+t.Name()+" (")):
		t.Skipf("skipped in the child:\n%s", out)
	case !bytes.Contains(out, []byte("--- PASS: "+t.Name()+" (")):
		t.Fatalf("child did not pass %s:\n%s", t.Name(), out)
	}
	return false
}

// limitFileSize sets RLIMIT_FSIZE to 0 (the hard limit stays), so that
// the next write to a regular file fails with EFBIG (the runtime
// ignores SIGXFSZ), and returns the function that puts the limit
// before back; the test puts it back as well when it ends. Only tests
// that do not run in parallel call it, and only in the child of
// inFsizeChild.
func limitFileSize(t *testing.T) (restore func()) {
	t.Helper()
	if os.Getenv(fsizeChildEnv) != "1" {
		t.Fatal("limitFileSize outside the child of inFsizeChild")
	}
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	done := false
	restore = func() {
		if done {
			return
		}
		done = true
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
			t.Errorf("RLIMIT_FSIZE not put back: %v", err)
		}
	}
	t.Cleanup(restore)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 0, Max: old.Max}); err != nil {
		t.Fatal(err)
	}
	return restore
}

// TestWriteTempInErrorSwapped (task 36 package A point 3; review of
// task 34 A, N1 of the first reviewer): the temporary file fails to be
// written (EFBIG under RLIMIT_FSIZE 0, set at the point "opened") after
// another process moved it away and put a foreign entry under its name,
// or removed it, or did nothing. The error is the *fs.PathError of the
// write; with a swap it is ErrReplacedMeanwhile as well, and the foreign
// entry is still there (at most moved to a name the message names);
// without one the temporary file is removed and nothing is left. A
// mutant that removes the temporary name on the error without looking
// at it removes the foreign entry. Each case runs in a child process
// (inFsizeChild).
func TestWriteTempInErrorSwapped(t *testing.T) {
	kinds := []string{"none", "removed"}
	for _, k := range foreignKinds {
		kinds = append(kinds, k.name)
	}
	for _, fn := range []string{"replace", "write", "create"} {
		for ki, kind := range kinds {
			t.Run(fn+"/"+kind, func(t *testing.T) {
				if !inFsizeChild(t) {
					return
				}
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "other"), []byte("other"), 0o660); err != nil {
					t.Fatal(err)
				}
				root := openDotRoot(t, dir)
				var tmpPath string
				var foreign entryID
				var restore func()
				skip := false
				withTempInHook(t, func(_ *os.Root, tmp, pt string) {
					if pt != "opened" {
						return
					}
					tmpPath = filepath.Join(dir, tmp)
					if kind != "none" {
						if err := os.Rename(tmpPath, filepath.Join(dir, "away")); err != nil {
							t.Error(err)
						}
					}
					if ki >= 2 {
						if err := foreignKinds[ki-2].make(dir, tmpPath); err != nil {
							if err == errSkipKind {
								skip = true
							} else {
								t.Error(err)
							}
						}
						foreign, _ = lstatID(t, tmpPath)
					}
					restore = limitFileSize(t)
				})
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
				if restore != nil {
					restore()
				}
				tempInHook = nil
				if skip {
					t.Skip("no device without CAP_MKNOD")
				}
				if t.Failed() || tmpPath == "" {
					t.Fatalf("hook: %q, err %v", tmpPath, err)
				}
				if n := fdCount(t); n != fds {
					t.Errorf("descriptors %d before, %d after", fds, n)
				}
				var pe *fs.PathError
				if !errors.Is(err, syscall.EFBIG) || !errors.As(err, &pe) || pe.Op != "write" || pe.Path != tmpPath {
					t.Fatalf("not the error of the write of %s: %v", tmpPath, err)
				}
				if strings.Contains(err.Error(), "new") {
					t.Fatalf("content in the message: %v", err)
				}
				if _, ok := lstatID(t, filepath.Join(dir, "w")); ok {
					t.Fatal("name written")
				}
				switch {
				case kind == "none":
					if errors.Is(err, ErrReplacedMeanwhile) {
						t.Fatalf("ErrReplacedMeanwhile without a swap: %v", err)
					}
				case kind == "removed":
					if want := "; store: " + tmpPath + " is missing: " + ErrReplacedMeanwhile.Error(); !strings.HasSuffix(err.Error(), want) {
						t.Fatalf("err %v, want ...%s", err, want)
					}
				default:
					if !errors.Is(err, ErrReplacedMeanwhile) {
						t.Fatalf("not ErrReplacedMeanwhile: %v", err)
					}
					at := findID(t, dir, foreign)
					if len(at) == 0 {
						t.Fatalf("the foreign entry %s is gone: %v", kind, err)
					}
					for _, n := range at {
						if n != "other" && !strings.Contains(err.Error(), "store: "+tmpPath+", moved to "+filepath.Join(dir, n)+", is ") {
							t.Fatalf("the foreign entry %s is under %s, which the message does not name: %v", kind, n, err)
						}
					}
				}
				// Nothing of the call is left: the entries are those of
				// the test ("other", "away") and the foreign one.
				ents, rerr := os.ReadDir(dir)
				if rerr != nil {
					t.Fatal(rerr)
				}
				want := map[string]bool{"other": true, "away": kind != "none"}
				for _, e := range ents {
					if want[e.Name()] {
						continue
					}
					if id, ok := lstatID(t, filepath.Join(dir, e.Name())); ki >= 2 && ok && id == foreign {
						continue
					}
					t.Fatalf("left in the directory: %s (%v)", e.Name(), err)
				}
			})
		}
	}
}

// fdsOn returns the descriptors of the process on path (/proc/self/fd)
// and whether each has FD_CLOEXEC.
func fdsOn(t *testing.T, path string) map[int]bool {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	fds := map[int]bool{}
	for _, e := range ents {
		l, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil || l != path {
			continue
		}
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		fl, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != 0 {
			t.Fatalf("F_GETFD %d: %v", fd, errno)
		}
		fds[fd] = fl&syscall.FD_CLOEXEC != 0
	}
	return fds
}

// TestHeldCloseOnExec (task 36 package A point 3; review of task 34 A,
// N2 of the first reviewer, after its probe): the duplicate held has
// FD_CLOEXEC, as the descriptor of the open has, so that no child
// started meanwhile inherits the temporary file. At "opened" there are
// two descriptors on the temporary file (the file and held), at
// "rename" one (held; the file is closed); each has FD_CLOEXEC.
func TestHeldCloseOnExec(t *testing.T) {
	dir := t.TempDir()
	root := openDotRoot(t, dir)
	got := map[string]int{}
	withTempInHook(t, func(_ *os.Root, tmp, pt string) {
		if pt != "opened" && pt != "rename" {
			return
		}
		for fd, cloexec := range fdsOn(t, filepath.Join(dir, tmp)) {
			if !cloexec {
				t.Errorf("at %s descriptor %d on the temporary file without FD_CLOEXEC", pt, fd)
			}
			got[pt]++
		}
	})
	if err := ReplaceFileIn(root, "w", []byte("new")); err != nil {
		t.Fatal(err)
	}
	tempInHook = nil
	if got["opened"] != 2 || got["rename"] != 1 {
		t.Fatalf("descriptors on the temporary file: %v", got)
	}
}
