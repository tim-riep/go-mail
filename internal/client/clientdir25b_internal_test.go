package client

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// Internal tests of task 25 package B (N1 of the review of task 24
// package B, follow-up B2): a client directory that cannot be checked
// against the data directory is refused with an error that names the
// cause, and errors.Is still matches it with errInsideDataDir.

// wantUnchecked fails unless err is an uncheckedDirError with the cause
// want whose message names text and none of the strings in hidden.
func wantUnchecked(t *testing.T, what string, err, want error, text string, hidden ...string) {
	t.Helper()
	var u *uncheckedDirError
	if !errors.As(err, &u) || !errors.Is(err, errInsideDataDir) || !errors.Is(err, want) {
		t.Errorf("%s: %v (%T), want an unchecked directory caused by %v", what, err, err, want)
		return
	}
	msg := err.Error()
	if !strings.Contains(msg, text) || strings.Contains(msg, errInsideDataDir.Error()) {
		t.Errorf("%s: message %q, want %q and not %q", what, msg, text, errInsideDataDir.Error())
	}
	for _, h := range hidden {
		if strings.Contains(msg, h) {
			t.Errorf("%s: message %q names %q", what, msg, h)
		}
	}
}

// TestInsideDataDirCause: insideDataDir returns nil outside the data
// directory, errInsideDataDir itself inside it, and an uncheckedDirError
// naming the errno where resolveExisting fails: a name longer than
// NAME_MAX (ENAMETOOLONG) and a cycle of links (ELOOP). An empty data
// directory and a relative path have a fixed cause; any other failure
// has a fixed cause that names no part of the path.
func TestInsideDataDirCause(t *testing.T) {
	b, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(b, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := insideDataDir(filepath.Join(b, "other", "client"), data); err != nil {
		t.Errorf("outside: %v", err)
	}
	if err := insideDataDir(filepath.Join(data, "client"), data); err != errInsideDataDir {
		t.Errorf("inside: %v, want errInsideDataDir itself", err)
	}
	if err := os.Symlink(data, filepath.Join(b, "toData")); err != nil {
		t.Fatal(err)
	}
	if err := insideDataDir(filepath.Join(b, "toData", "client"), data); err != errInsideDataDir {
		t.Errorf("inside through a link: %v, want errInsideDataDir itself", err)
	}
	wantUnchecked(t, "empty data directory", insideDataDir(filepath.Join(b, "other"), ""), errNoDataDir, "no data directory")
	long := strings.Repeat("y", 300)
	wantUnchecked(t, "<300 bytes>/client", insideDataDir(filepath.Join(b, long, "client"), data),
		syscall.ENAMETOOLONG, syscall.ENAMETOOLONG.Error(), long, b)
	wantUnchecked(t, "data directory <300 bytes>", insideDataDir(filepath.Join(b, "other"), filepath.Join(b, long)),
		syscall.ENAMETOOLONG, syscall.ENAMETOOLONG.Error(), long, b)
	// createClientDir passes the cause on (M12 of the second review of
	// task 25 package B); unlike TestInsideDataDirCauseEACCES this also
	// runs as root.
	create := func(dir string) error {
		return createClientDir(dir, data, "keygen", func(r *os.Root) error {
			return r.WriteFile("marker", []byte("x"), 0o600)
		})
	}
	wantUnchecked(t, "createClientDir <300 bytes>/client", create(filepath.Join(b, long, "client")),
		syscall.ENAMETOOLONG, syscall.ENAMETOOLONG.Error(), long, b)
	if runtime.GOOS != "windows" {
		if err := os.Symlink("cycB", filepath.Join(b, "cycA")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("cycA", filepath.Join(b, "cycB")); err != nil {
			t.Fatal(err)
		}
		wantUnchecked(t, "cycle", insideDataDir(filepath.Join(b, "cycA", "client"), data),
			syscall.ELOOP, syscall.ELOOP.Error(), "cyc", b)
		wantUnchecked(t, "createClientDir cycle", create(filepath.Join(b, "cycA", "client")),
			syscall.ELOOP, syscall.ELOOP.Error(), "cyc", b)
	}
	if got := dirNames(t, data); len(got) != 0 {
		t.Errorf("data directory: %v", got)
	}
	_, err = resolveExisting("rel-dir/client")
	wantUnchecked(t, "relative", unchecked(err), errRelativePath, "relative path", "rel-dir")
	wantUnchecked(t, "other failure", unchecked(errors.New("lstat /secret/path: odd")), errUnexaminable,
		"cannot be examined", "secret", "odd")
	wantUnchecked(t, "wrapped errno", unchecked(&fs.PathError{Op: "lstat", Path: "/secret", Err: syscall.EIO}),
		syscall.EIO, syscall.EIO.Error(), "secret", "lstat")
}

// TestInsideDataDirCauseEACCES: below a directory without search
// permission, insideDataDir and createClientDir report "permission
// denied" (EACCES, fs.ErrPermission) instead of "inside the data
// directory", errors.Is still matches errInsideDataDir, and nothing is
// created. It needs a process without CAP_DAC_OVERRIDE (task 25: a
// compiled test binary under setpriv --inh-caps=-all
// --bounding-set=-all).
func TestInsideDataDirCauseEACCES(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits")
	}
	b, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(b, "data")
	for _, d := range []string{"data", "nox/sub"} {
		if err := os.MkdirAll(filepath.Join(b, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(b, "nox"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(b, "nox"), 0o700) })
	if _, err := os.Lstat(filepath.Join(b, "nox", "sub")); err == nil {
		t.Skip("privileged: needs a process without CAP_DAC_OVERRIDE")
	}
	dir := filepath.Join(b, "nox", "sub", "client")
	wantUnchecked(t, "insideDataDir", insideDataDir(dir, data), syscall.EACCES, "permission denied", "nox")
	err = createClientDir(dir, data, "keygen", func(r *os.Root) error {
		return r.WriteFile("marker", []byte("x"), 0o600)
	})
	wantUnchecked(t, "createClientDir", err, syscall.EACCES, "permission denied", "nox")
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("createClientDir: %v, want fs.ErrPermission", err)
	}
	if got := dirNames(t, data); len(got) != 0 {
		t.Errorf("data directory: %v", got)
	}
}

// TestInsideDataDirCauseAbs: where filepath.Abs fails for the client
// directory or for the data directory, insideDataDir reports the cause
// instead of letting the directory pass. A working directory that has
// been removed makes os.Getwd fail with ENOENT on Linux (getcwd), and $PWD
// no longer names ".".
func TestInsideDataDirCauseAbs(t *testing.T) {
	b, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(b, "gone")
	if err := os.Mkdir(gone, 0o700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(b, "data")
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Skipf("cannot remove the working directory: %v", err)
	}
	if wd, err := os.Getwd(); !errors.Is(err, syscall.ENOENT) {
		t.Skipf("os.Getwd in a removed directory: %q, %v; want ENOENT", wd, err)
	}
	wantUnchecked(t, "relative client directory", insideDataDir("relname", data),
		syscall.ENOENT, syscall.ENOENT.Error(), "relname", b)
	wantUnchecked(t, "relative data directory", insideDataDir(filepath.Join(b, "other", "client"), "relname"),
		syscall.ENOENT, syscall.ENOENT.Error(), "relname", b)
}
