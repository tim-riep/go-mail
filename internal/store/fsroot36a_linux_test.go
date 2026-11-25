package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Tests of task 36 package A (reviews of task 34 A, N1 and N2 of the
// first reviewer): the error path of writeTempIn with a temporary name
// swapped by another process, and FD_CLOEXEC of held.

// fsizeChildEnv and the flag -gomail.fsizechild mark the child process
// of inFsizeChild: the test process passes both with the same token,
// made by crypto/rand for each child (task 37 A point 6). The flag is
// only on the command line of the child; a variable fsizeChildEnv set
// from outside (with go test, the flag is empty) never makes the test
// process take itself for the child, and the child is not told apart
// by a value anyone can guess.
const fsizeChildEnv = "GOMAIL_STORE_TEST_FSIZE_CHILD"

var fsizeChildToken = flag.String("gomail.fsizechild", "", "token of the child of inFsizeChild (store tests only)")

// Limits of the child of inFsizeChild: it gets at most fsizeChildMax as
// its own -test.timeout, and fsizeChildGrace before the deadline of the
// test process (twice: one for the child to report its timeout before
// it is killed, one for the test process to report it).
const (
	fsizeChildMax   = 3 * time.Minute
	fsizeChildGrace = 10 * time.Second
)

// isFsizeChild reports whether this process is the child of
// inFsizeChild: the flag carries a token and the variable the same.
func isFsizeChild() bool {
	return *fsizeChildToken != "" && os.Getenv(fsizeChildEnv) == *fsizeChildToken
}

// fsizeMark is the line that limitFileSize logs in the child once it
// has lowered the limit; the test process requires it with the token
// of the child on a PASS, as proof that the body ran there.
func fsizeMark(token string) string {
	return "RLIMIT_FSIZE lowered in the child " + token
}

// inFsizeChild reports whether this process is the child of
// inFsizeChild, in which the test t runs itself. In the test process
// itself it runs t in a child process (this test binary, running only
// t) and fails t with the output of the child unless the child passed
// t with the mark of limitFileSize, or skips t with the SKIP line and
// the reason when the child skipped t; it returns false then. A test
// that lowers RLIMIT_FSIZE (limitFileSize) runs only in such a child:
// the limit holds for the whole process, and with the test cache on,
// go test makes the test process write each file it opens or stats and
// each variable it reads to a log file of its own (-test.testlogfile);
// under the lowered limit that write fails and the package fails
// although every test passed (task 36 A3). The child gets no
// -test.testlogfile, writes its output only to a pipe, and gets the
// environment of this process, so the variables it reads are those
// read here; it gets -test.gocoverdir of this process if set, so that
// what runs only in the child counts for -cover and -coverprofile. The
// child has a deadline fsizeChildGrace before that of t and its own
// -test.timeout another fsizeChildGrace before, and gets SIGKILL when
// the thread that started it ends (Pdeathsig; this goroutine keeps the
// thread until the child is waited for).
func inFsizeChild(t *testing.T) bool {
	t.Helper()
	if isFsizeChild() {
		return true
	}
	parts := strings.Split(t.Name(), "/")
	for i, p := range parts {
		parts[i] = "^" + regexp.QuoteMeta(p) + "$"
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(b[:])
	budget := fsizeChildMax
	if d, ok := t.Deadline(); ok {
		left := time.Until(d)
		if left-2*fsizeChildGrace <= 0 {
			t.Fatalf("%v left until the deadline, too little for the child", left)
		}
		budget = min(budget, left-2*fsizeChildGrace)
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget+fsizeChildGrace)
	defer cancel()
	args := []string{"-test.run=" + strings.Join(parts, "/"), "-test.count=1", "-test.v",
		"-test.timeout=" + budget.String(), "-gomail.fsizechild=" + token}
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String())
	}
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, fsizeChildEnv+"=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, fsizeChildEnv+"="+token)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = fsizeChildGrace
	runtime.LockOSThread()
	out, err := cmd.CombinedOutput()
	runtime.UnlockOSThread()
	if err != nil && ctx.Err() != nil {
		err = fmt.Errorf("%w (%w after %v)", err, ctx.Err(), budget+fsizeChildGrace)
	}
	skip, verr := fsizeChildVerdict(t.Name(), token, out, err)
	switch {
	case verr != nil:
		t.Fatal(verr)
	case skip != "":
		t.Skip(skip)
	}
	return false
}

// fsizeChildVerdict judges the output out and the error runErr of the
// child of inFsizeChild that ran the test name with token: an error
// with the output of the child unless it passed name, with the PASS
// line at the start of a line (after the indent) and the mark of
// limitFileSize with token as a log line; or, when it skipped name,
// the SKIP line and the log lines of the child but the mark (the
// reason), and no error.
func fsizeChildVerdict(name, token string, out []byte, runErr error) (skip string, err error) {
	if runErr != nil {
		return "", fmt.Errorf("child: %v\n%s", runErr, out)
	}
	q := regexp.QuoteMeta(name)
	logLine := regexp.MustCompile(`^[ \t]+[^ \t:]+\.go:[0-9]+: `)
	if m := regexp.MustCompile(`(?m)^[ \t]*--- SKIP: ` + q + ` \([^)\n]*\)$`).Find(out); m != nil {
		lines := []string{strings.TrimLeft(string(m), " \t")}
		for _, l := range strings.Split(string(out), "\n") {
			if logLine.MatchString(l) && !strings.HasSuffix(l, ": "+fsizeMark(token)) {
				lines = append(lines, l)
			}
		}
		return strings.Join(lines, "\n"), nil
	}
	if !regexp.MustCompile(`(?m)^[ \t]*--- PASS: ` + q + ` \([^)\n]*\)$`).Match(out) {
		return "", fmt.Errorf("child did not pass %s:\n%s", name, out)
	}
	if !regexp.MustCompile(`(?m)^[ \t]+[^ \t:]+\.go:[0-9]+: ` + regexp.QuoteMeta(fsizeMark(token)) + `$`).Match(out) {
		return "", fmt.Errorf("child passed %s without the mark of limitFileSize:\n%s", name, out)
	}
	return "", nil
}

// requireFsizeChild fails t at once unless this process is the child
// of inFsizeChild: the guard on the goroutine of the test before
// anything can call limitFileSize (task 37 A point 1).
func requireFsizeChild(t *testing.T) {
	t.Helper()
	if !isFsizeChild() {
		t.Fatal("the body of the test outside the child of inFsizeChild")
	}
}

// limitFileSize sets RLIMIT_FSIZE to 0 (the hard limit stays), so that
// the next write to a regular file fails with EFBIG (the runtime
// ignores SIGXFSZ), logs the mark of the child (fsizeMark), and returns
// the function that puts the limit before back; the test puts it back
// as well when it ends. Only tests that do not run in parallel call it,
// and only in the child of inFsizeChild, after requireFsizeChild. It
// may run on another goroutine (a hook of the call), so it fails t with
// t.Errorf only and returns a restore that does nothing when it did
// not lower the limit.
func limitFileSize(t *testing.T) (restore func()) {
	t.Helper()
	if !isFsizeChild() {
		t.Error("limitFileSize outside the child of inFsizeChild")
		return func() {}
	}
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Error(err)
		return func() {}
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
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 0, Max: old.Max}); err != nil {
		t.Error(err)
		return func() {}
	}
	t.Cleanup(restore)
	t.Log(fsizeMark(*fsizeChildToken))
	return restore
}

// TestFsizeChildVerdict (task 37 A points 3, 4 and 7): the test process
// takes a PASS of the child only from a PASS line at the start of a line
// with the mark of the token, and shows on a SKIP only the SKIP line and
// the reason.
func TestFsizeChildVerdict(t *testing.T) {
	const name, tok = "TestX/create/fifo", "0123abcd"
	run := "=== RUN   TestX\n=== RUN   TestX/create\n=== RUN   TestX/create/fifo\n"
	mark := "    fsroot36a_linux_test.go:208: " + fsizeMark(tok) + "\n"
	pass := "--- PASS: TestX (0.01s)\n    --- PASS: TestX/create (0.01s)\n        --- PASS: TestX/create/fifo (0.01s)\nPASS\n"
	for _, c := range []struct {
		what, out string
		runErr    error
		skip      string
		ok        bool
	}{
		{"pass", run + mark + pass, nil, "", true},
		{"exit error", run + mark + pass, errors.New("exit status 1"), "", false},
		{"no PASS line", run + mark + "--- PASS: TestX (0.01s)\nPASS\n", nil, "", false},
		{"PASS line in a log", run + mark + "    x_test.go:1: --- PASS: TestX/create/fifo (0.01s)\nPASS\n", nil, "", false},
		{"PASS of another test", run + mark + "        --- PASS: TestX/create/fifo2 (0.01s)\nPASS\n", nil, "", false},
		{"no mark", run + pass, nil, "", false},
		{"mark of another token", run + "    fsroot36a_linux_test.go:208: " + fsizeMark("ffff") + "\n" + pass, nil, "", false},
		{"mark not a log line", run + fsizeMark(tok) + "\n" + pass, nil, "", false},
		{"skip", run + mark + "    fsroot36a_linux_test.go:168: no device without CAP_MKNOD\n" +
			"--- PASS: TestX (0.01s)\n    --- PASS: TestX/create (0.01s)\n        --- SKIP: TestX/create/fifo (0.00s)\nPASS\n", nil,
			"--- SKIP: TestX/create/fifo (0.00s)\n    fsroot36a_linux_test.go:168: no device without CAP_MKNOD", true},
		{"SKIP line in a log", run + mark + "    x_test.go:1: --- SKIP: TestX/create/fifo (0.00s)\n" + pass, nil,
			"", true},
	} {
		skip, err := fsizeChildVerdict(name, tok, []byte(c.out), c.runErr)
		if (err == nil) != c.ok || skip != c.skip {
			t.Errorf("%s: skip %q, err %v; want skip %q, ok %v", c.what, skip, err, c.skip, c.ok)
		}
		if err != nil && !strings.Contains(err.Error(), c.out) {
			t.Errorf("%s: the output of the child is not in the error: %v", c.what, err)
		}
	}
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
// (inFsizeChild), and its body only there (requireFsizeChild).
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
				requireFsizeChild(t)
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
