//go:build linux

package ceremony

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of the rework of task 28 package 28A on Linux: the second look
// after a failed open (a FIFO and the file back, an inode number reused,
// EMFILE with a failing os.Lstat), and the error of a failed replacement
// of witnesses.rec after its line.

// changedOpenMsg is the refusal of the entry p of platform/ that was
// replaced between os.Lstat and the open (backlog 93).
func changedOpenMsg(p string) string {
	return "ceremony: an entry of platform/ changed while publish read it: " + p +
		" was replaced before it was opened; another process writes platform/ during publish: stop it, look at the entry and run the same publish again"
}

// TestPublishEntryBackAfterNotRegularOpen (review of task 28 A, F1; probe
// of the specification review): ingest-1.cert is replaced by a FIFO
// right before publish opens it (hook "<at>-open ingest-1.cert"), in
// checkDataPlatform and in the comparison with the export, and the file
// is put back if a hook after the failed open is reached
// ("<at>-failed"). The open found no regular file under a name os.Lstat
// showed as one: errChanged at once, never the second look, which would
// find the file again and pass on store.ErrNotRegular of the open with
// "remove it by hand" for a regular file (mutant N1: the branch for
// store.ErrNotRegular of the open removed). Nothing written or logged.
func TestPublishEntryBackAfterNotRegularOpen(t *testing.T) {
	for _, at := range []string{"check", "publish"} {
		t.Run(at, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			p, aside := st.Path("platform", "ingest-1.cert"), filepath.Join(f.base, "aside")
			before := platformSnapshot(t, st)
			logged := len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert"))
			var serr error
			var hits []string
			crashHook = func(pt string) error {
				switch {
				case pt == at+"-open ingest-1.cert" && len(hits) == 0:
					hits = append(hits, pt)
					if serr = os.Rename(p, aside); serr == nil {
						serr = syscall.Mkfifo(p, 0o644)
					}
				case pt == at+"-failed ingest-1.cert" && len(hits) == 1:
					hits = append(hits, pt)
					if serr = os.Remove(p); serr == nil {
						serr = os.Rename(aside, p)
					}
				}
				return nil
			}
			t.Cleanup(func() { crashHook = nil })
			err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
			crashHook = nil
			if serr != nil || len(hits) == 0 {
				t.Fatalf("swap: %v %v", serr, hits)
			}
			if !errors.Is(err, errChanged) || errors.Is(err, store.ErrNotRegular) || err.Error() != changedOpenMsg(p) {
				t.Fatalf("FIFO at the open, file back afterwards (hooks %q): %v", hits, err)
			}
			if len(hits) == 1 {
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(aside, p); err != nil {
					t.Fatal(err)
				}
			}
			if platformSnapshot(t, st) != before || len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert")) != logged {
				t.Fatal("written or logged before the refusal")
			}
		})
	}
}

// TestPublishEntryInodeReused (review of task 28 A, N1; after
// TestRev28ARInodeReuse of the robustness review): ingest-1.cert is
// removed right before publish opens it (hook "check-open
// ingest-1.cert"), not put aside, and a socket or the device 0:0 (no
// driver, no CAP_MKNOD needed) is made under its name. The open fails
// with ENXIO; when the new entry got the inode number of the removed
// file, os.SameFile in the second look is true, and only its kind tells
// that the entry was replaced: errChanged, not ENXIO. The file system
// does not always give the freed number again (ext4 mostly does), so
// publish is run until it does, at most 50 times; the case is skipped
// with the count otherwise. Nothing written or logged.
func TestPublishEntryInodeReused(t *testing.T) {
	kinds := []struct {
		name string
		make func(p string) error
	}{
		{"socket", func(p string) error { return syscall.Mknod(p, syscall.S_IFSOCK|0o644, 0) }},
		{"chr-0-0", func(p string) error { return syscall.Mknod(p, syscall.S_IFCHR|0o644, 0) }},
	}
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			p := st.Path("platform", "ingest-1.cert")
			if err := k.make(filepath.Join(f.base, "probe")); err != nil {
				if errors.Is(err, syscall.EPERM) {
					t.Skipf("%s: %v", k.name, err)
				}
				t.Fatal(err)
			}
			orig := mustReadFile(t, p)
			before := platformSnapshot(t, st)
			logged := len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert"))
			t.Cleanup(func() { crashHook = nil })
			const tries = 50
			reused := false
			for i := 0; i < tries && !reused; i++ {
				var serr error
				hit := false
				crashHook = func(pt string) error {
					if pt != "check-open ingest-1.cert" || hit {
						return nil
					}
					hit = true
					fi1, err := os.Lstat(p)
					if serr = err; err != nil {
						return nil
					}
					if serr = os.Remove(p); serr != nil {
						return nil
					}
					if serr = k.make(p); serr != nil {
						return nil
					}
					fi2, err := os.Lstat(p)
					serr = err
					reused = err == nil && os.SameFile(fi1, fi2)
					return nil
				}
				err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
				crashHook = nil
				if serr != nil || !hit {
					t.Fatalf("swap: %v %v", serr, hit)
				}
				if !errors.Is(err, errChanged) || errors.Is(err, syscall.ENXIO) || err.Error() != changedOpenMsg(p) {
					t.Fatalf("try %d, %s, inode number reused %v: %v", i+1, k.name, reused, err)
				}
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, orig, 0o644); err != nil {
					t.Fatal(err)
				}
				if reused {
					t.Logf("inode number reused in try %d", i+1)
				}
			}
			if platformSnapshot(t, st) != before || len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert")) != logged {
				t.Fatal("written or logged before the refusal")
			}
			if !reused {
				t.Skipf("the file system never gave the %s the inode number of the removed file in %d tries", k.name, tries)
			}
		})
	}
}

// setNofile sets the soft RLIMIT_NOFILE of this process to cur, the hard
// one stays max. It calls prlimit64(2) itself, not syscall.Setrlimit:
// the Go runtime raises the soft limit at start and gives every child it
// starts the soft limit the process started with (while the soft limit
// is still the one it raised it to), but once the limit was set through
// package syscall (Setrlimit) it gives none, and every child started
// later inherits the limit in place (review of task 28 A2, robustness
// H1). With prlimit64 the runtime keeps the soft limit to give, and
// setNofile(old.Cur, old.Max) puts back the raised one: a child started
// after the test gets the soft limit it got before
// (TestSetNofileChildLimit). The soft limit 0 holds for the whole
// process: no other test may run meanwhile, so the tests that use
// setNofile must never call t.Parallel (crashHook, which they set, is
// global as well).
func setNofile(cur, max uint64) error {
	lim := syscall.Rlimit{Cur: cur, Max: max}
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRLIMIT64, 0, syscall.RLIMIT_NOFILE, uintptr(unsafe.Pointer(&lim)), 0, 0, 0); e != 0 {
		return e
	}
	return nil
}

// nofileChild names the child of TestSetNofileChildLimit.
const nofileChild = "GOMAIL_TEST_29C_NOFILE_CHILD"

// childSoftNofile is the soft RLIMIT_NOFILE a child that is no Go program
// (sh) gets from this process.
func childSoftNofile() (string, error) {
	out, err := exec.Command("sh", "-c", "ulimit -Sn").Output()
	return strings.TrimSpace(string(out)), err
}

// TestSetNofileChildLimit (task 29 C point 2): after setNofile lowered the
// soft RLIMIT_NOFILE to 0 and put it back, as TestPublishEMFILEAtOpen and
// TestPublishReplaceFailsAfterLine do, a child started afterwards gets
// the soft limit the process started with, as before, not the one the
// Go runtime raised it to. The test runs in a child of the test program
// that sh starts with the soft limit 512 (lower than the hard one, so
// that the runtime raises it and keeps 512 for children); that child
// prints the soft limit of a child of its own before and after
// setNofile.
func TestSetNofileChildLimit(t *testing.T) {
	if os.Getenv(nofileChild) != "" {
		var old syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &old); err != nil {
			t.Fatal(err)
		}
		before, err := childSoftNofile()
		if err != nil {
			t.Fatal(err)
		}
		serr := setNofile(0, old.Max)
		if rerr := setNofile(old.Cur, old.Max); serr == nil {
			serr = rerr
		}
		if serr != nil {
			t.Fatal(serr)
		}
		after, err := childSoftNofile()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("nofile %d %s %s\n", old.Cur, before, after)
		return
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("no sh: %v", err)
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Max <= 513 {
		t.Skipf("hard RLIMIT_NOFILE %d: the runtime would not raise a soft limit of 512", lim.Max)
	}
	cmd := exec.Command("sh", "-c", `ulimit -Sn 512 && exec "$0" -test.run='^TestSetNofileChildLimit$' -test.count=1`, os.Args[0])
	cmd.Env = append(os.Environ(), nofileChild+"=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v %q %q", err, stdout.String(), stderr.String())
	}
	var own uint64
	var before, after string
	if _, err := fmt.Sscanf(stdout.String(), "nofile %d %s %s\n", &own, &before, &after); err != nil {
		t.Fatalf("child's output %q: %v", stdout.String(), err)
	}
	t.Logf("child: soft limit %d, its child %s before setNofile, %s after", own, before, after)
	if before != "512" {
		t.Skipf("the runtime gave the child's child the soft limit %s, not 512: nothing to compare", before)
	}
	if after != before {
		t.Fatalf("a child started after setNofile gets the soft limit %s, not %s", after, before)
	}
}

// TestPublishEMFILEAtOpen (review of task 28 A, H1): the open of
// ingest-1.cert in checkDataPlatform fails with EMFILE (the soft
// RLIMIT_NOFILE set to 0 at the hook "check-open ingest-1.cert" and put
// back at "check-failed ingest-1.cert"; no root needed). The second look
// finds the same regular file: the error of the open, neither
// errChanged nor store.ErrNotRegular. With "emfile-lstat-fails" the
// hook "check-failed" stands for a failing os.Lstat of the second look
// (EIO): still the error of the open, never "is gone" (mutant M12 of
// the robustness review: every failure of that os.Lstat taken for a
// name gone). Nothing written or logged. Never t.Parallel: the soft
// limit 0 holds for the whole process (setNofile).
func TestPublishEMFILEAtOpen(t *testing.T) {
	for _, c := range []string{"emfile", "emfile-lstat-fails"} {
		t.Run(c, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			p := st.Path("platform", "ingest-1.cert")
			before := platformSnapshot(t, st)
			logged := len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert"))
			var old syscall.Rlimit
			if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &old); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { crashHook = nil; setNofile(old.Cur, old.Max) })
			lstatErr := fmt.Errorf("lstat in the test: %w", syscall.EIO)
			var serr error
			var hits []string
			crashHook = func(pt string) error {
				switch {
				case pt == "check-open ingest-1.cert" && len(hits) == 0:
					hits = append(hits, pt)
					serr = setNofile(0, old.Max)
				case pt == "check-failed ingest-1.cert" && len(hits) == 1:
					hits = append(hits, pt)
					serr = setNofile(old.Cur, old.Max)
					if c == "emfile-lstat-fails" {
						return lstatErr
					}
				}
				return nil
			}
			err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
			crashHook = nil
			if rerr := setNofile(old.Cur, old.Max); rerr != nil {
				t.Fatal(rerr)
			}
			if serr != nil || len(hits) != 2 {
				t.Fatalf("hooks: %v %q (err %v)", serr, hits, err)
			}
			if !errors.Is(err, syscall.EMFILE) || errors.Is(err, errChanged) || errors.Is(err, store.ErrNotRegular) || errors.Is(err, syscall.EIO) ||
				!strings.Contains(err.Error(), "ingest-1.cert") {
				t.Fatalf("%s: %v", c, err)
			}
			if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
				t.Fatalf("ingest-1.cert afterwards: %v %v", fi, err)
			}
			if platformSnapshot(t, st) != before || len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert")) != logged {
				t.Fatal("written or logged before the refusal")
			}
		})
	}
}

// TestPublishReplaceFailsAfterLine (review of task 28 A, F3; probe
// rev28a_announce_unix_test.go of the specification review):
// witnesses.rec is a regular working copy with other witnesses, a
// symbolic or a hard link, ReplaceWitnesses is set, and admin-1.pub is
// missing, so publish writes it first. Right after that write (hook
// "publish-file") the replacement of witnesses.rec is made to fail:
//
//   - "create": the soft RLIMIT_NOFILE is 0, the temporary file cannot
//     be made (EMFILE); witnesses.rec stays what it was;
//   - "rename": another process puts a directory under witnesses.rec, the
//     rename fails (EEXIST).
//
// WitnessesReplacing has come, WitnessesReplaced and
// WitnessesLinkReplaced do not, and the error names witnesses.rec, says
// it is unchanged ("create") or was not replaced ("rename": the
// directory of the other process stands there now; review of task 28
// A2, H4), nothing is logged, files of the export may be written
// (admin-1.pub is), and the remedy; errors.Is holds for the cause. No
// temporary file is left, nothing is logged. When witnesses.rec is
// missing ("missing", written for the first time) no line comes and the
// error of store.ReplaceFileIn is returned as it is. Never t.Parallel:
// the soft limit 0 holds for the whole process (setNofile).
func TestPublishReplaceFailsAfterLine(t *testing.T) {
	for _, c := range []struct{ kind, fail string }{
		{"regular", "create"}, {"symbolic", "create"}, {"hard", "create"}, {"missing", "create"}, {"regular", "rename"},
	} {
		t.Run(c.kind+"-"+c.fail, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			p := st.Path("platform", WitnessesFile)
			other, err := (&witness.Witnesses{List: f.w[:1], Min: 1}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(f.base, "outside-w")
			switch c.kind {
			case "regular":
				err = os.WriteFile(p, other, 0o644)
			case "missing":
				err = os.Remove(p)
			case "symbolic", "hard":
				if err = os.WriteFile(outside, other, 0o644); err == nil {
					err = os.Remove(p)
				}
				if err == nil && c.kind == "symbolic" {
					err = os.Symlink(outside, p)
				} else if err == nil {
					err = os.Link(outside, p)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			a1 := st.Path("platform", "admin-1.pub")
			if err := os.Remove(a1); err != nil {
				t.Fatal(err)
			}
			wantA1 := mustReadFile(t, filepath.Join(out, "platform", "admin-1.pub"))
			var old syscall.Rlimit
			if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &old); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { crashHook = nil; setNofile(old.Cur, old.Max) })
			logged := len(loggedPlatform(t, st, f.res.Pin, "admin-1.pub"))
			var serr error
			hit, logReached := false, false
			crashHook = func(pt string) error {
				if pt == "publish-log" {
					logReached = true
				}
				if pt != "publish-file" || hit {
					return nil
				}
				hit = true
				if c.fail == "create" {
					serr = setNofile(0, old.Max)
				} else if serr = os.Remove(p); serr == nil {
					serr = os.Mkdir(p, 0o755)
				}
				return nil
			}
			var calls []string
			err = Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, ReplaceWitnesses: true,
				WitnessesReplacing: func(before *witness.Witnesses, link string, after *witness.Witnesses) {
					calls = append(calls, replacingLine(before, link, after))
				},
				WitnessesReplaced:     func(_, _ *witness.Witnesses) { calls = append(calls, "replaced") },
				WitnessesLinkReplaced: func(string, *witness.Witnesses) { calls = append(calls, "link replaced") }})
			crashHook = nil
			if rerr := setNofile(old.Cur, old.Max); rerr != nil {
				t.Fatal(rerr)
			}
			if serr != nil || !hit {
				t.Fatalf("hook: %v %v (err %v)", serr, hit, err)
			}
			if err == nil {
				t.Fatal("publish went through")
			}
			var cause error = syscall.EMFILE
			if c.fail == "rename" {
				cause = syscall.EEXIST
			}
			if !errors.Is(err, cause) {
				t.Fatalf("not %v: %v", cause, err)
			}
			// The cause is the error of store.ReplaceFileIn as it is:
			// whatever stands between the prefix and "; <p> <state>".
			state := stateUnchanged
			if c.fail == "rename" {
				state = stateNotReplaced
			}
			msg := err.Error()
			t.Log(msg)
			if c.kind == "missing" {
				if len(calls) != 0 || strings.Contains(msg, stateUnchanged) || strings.Contains(msg, stateNotReplaced) || strings.HasPrefix(msg, "ceremony: replacing ") {
					t.Fatalf("written for the first time: calls %q, %v", calls, err)
				}
			} else {
				pre := "ceremony: replacing " + p + ": "
				i := strings.Index(msg, "; "+p+" "+state)
				if !strings.HasPrefix(msg, pre) || i < len(pre) || msg != replaceFailedMsg(p, msg[len(pre):i], state) {
					t.Fatalf("message %q", msg)
				}
				if len(calls) != 1 || !strings.HasPrefix(calls[0], "replacing ") {
					t.Fatalf("callbacks %q", calls)
				}
			}
			// witnesses.rec as before the replacement (the directory of the
			// other process for "rename").
			fi, lerr := os.Lstat(p)
			switch {
			case c.fail == "rename":
				if lerr != nil || !fi.IsDir() {
					t.Fatalf("witnesses.rec: %v %v", fi, lerr)
				}
			case c.kind == "missing":
				if !errors.Is(lerr, os.ErrNotExist) {
					t.Fatalf("witnesses.rec: %v %v", fi, lerr)
				}
			case c.kind == "symbolic":
				if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("witnesses.rec: %v %v", fi, lerr)
				}
			default:
				if lerr != nil || !fi.Mode().IsRegular() || !bytes.Equal(mustReadFile(t, p), other) || c.kind == "hard" && nlink(fi) != 2 {
					t.Fatalf("witnesses.rec: %v %v", fi, lerr)
				}
			}
			if !bytes.Equal(mustReadFile(t, a1), wantA1) {
				t.Fatal("admin-1.pub not written before witnesses.rec")
			}
			for _, n := range listDir(t, st.Path("platform")) {
				if strings.HasPrefix(n, ".tmp-") {
					t.Fatalf("temporary file left: %s", n)
				}
			}
			if logReached || len(loggedPlatform(t, st, f.res.Pin, "admin-1.pub")) != logged {
				t.Fatal("logged after the failure")
			}
		})
	}
}
