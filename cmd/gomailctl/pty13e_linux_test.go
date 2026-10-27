//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 13e: two descriptors of /dev/tty are the same terminal
// only when both are the controlling terminal of the program (point 1),
// and the tests on a pseudo terminal wait for output instead of sleeping
// (point 2).

// quiet waits until everything written to the terminal before, on the
// slave (shown) or on the master (typed, echoed), is in the transcript
// and in the input queue, without a fixed sleep (task 13e point 2): it
// types a marker line on the master and waits for its echo. The line
// discipline echoes the marker after everything typed before it, and
// the echo is shown after everything written to the slave before it. It
// returns the transcript from offset from up to the echo of the marker
// and the bytes in the input queue that complete lines before the
// marker, and discards the input queue. The echo must be on (restored).
func (p *ptyRec) quiet(t *testing.T, from int) (shown string, queued int) {
	t.Helper()
	const mark = "gomailctl-test-mark"
	if l := p.lflag(t); l&syscall.ECHO == 0 || l&syscall.ICANON == 0 {
		t.Fatalf("quiet needs echo and canonical input: lflag %#x", l)
	}
	p.typeIn(t, mark+"\n")
	end, _ := p.wait(t, from, regexp.QuoteMeta(mark)+`\r?\n`)
	s := p.out.String()[:end]
	shown = s[from:strings.LastIndex(s, mark)]
	queued = inputQueued(t, p.slave) - len(mark) - 1
	if err := flushInput(p.slave.Fd()); err != nil {
		t.Fatal(err)
	}
	return shown, queued
}

// sessionsEnv makes this test binary the first session of
// TestPtyWordsDevTTYSessions (sessionsMain) instead of running tests.
const sessionsEnv = "GOMAILCTL_TEST_SESSIONS"

func init() {
	if os.Getenv(sessionsEnv) == "1" {
		os.Exit(sessionsMain())
	}
}

// sessionsMain is session 1 with the controlling terminal A (standard
// input, made so by the test): it opens /dev/tty (A) and runs
// /bin/sh -c os.Args[1] in session 2, whose controlling terminal is B
// (descriptor 3 here); the shell gets /dev/tty (A, opened in session 1)
// as descriptor 3 and the slave of B as descriptors 0 and 4, its
// standard output and error are those of this process. "$0" is this
// binary as gomailctl, "$@" are os.Args[2:]. The exit code is that of
// the shell.
func sessionsMain() int {
	ttyA, err := os.OpenFile(devTTY, os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "session 1:", err)
		return 2
	}
	slaveB := os.NewFile(3, "slave B")
	var env []string
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, sessionsEnv+"=") {
			env = append(env, v)
		}
	}
	cmd := exec.Command("/bin/sh", append([]string{"-c", os.Args[1], os.Args[0]}, os.Args[2:]...)...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slaveB, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{ttyA, slaveB}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Run(); err != nil && cmd.ProcessState == nil {
		fmt.Fprintln(os.Stderr, "session 2:", err)
		return 2
	}
	return cmd.ProcessState.ExitCode()
}

// startSessions runs gomailctl with args in session 2 of
// sessionsMain: session 1 has the controlling terminal a, session 2 the
// controlling terminal b; inner is the shell command of session 2. Its
// options, environment and the head of the platform are those of start
// (task 14: gomailctl works with its client log from the pin).
func (c *cli) startSessions(t *testing.T, dir string, a, b *ptyRec, stderr *os.File, inner string, env []string, args ...string) *child {
	t.Helper()
	c.childHead()
	cmd := exec.Command(os.Args[0], append([]string{inner}, c.args(dir, args)...)...)
	cmd.Env = append(childEnv(env), sessionsEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.slave, stderr, stderr
	cmd.ExtraFiles = []*os.File{b.slave}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	return startChild(t, cmd)
}

// TestPtyWordsDevTTYSessions (task 13e point 1, Q21): descriptors of
// /dev/tty from two sessions. Session 1 (controlling terminal A) opens
// /dev/tty, session 2 (controlling terminal B) inherits it as
// descriptor 3. device lost with that descriptor on one side and
// /dev/tty of session 2 (B), or the slave of B, on the other ends with
// exit code 1 before the passphrase is asked or a word is read; so does
// the inherited /dev/tty (A) on both sides, A not being the controlling
// terminal of session 2. Nothing is shown on A or B, nothing is queued
// in their input, the echo stays on, the generation is unchanged.
// /dev/tty of session 2 on both sides is still accepted: the words are
// read from B with the echo off, and the generation is renewed.
func TestPtyWordsDevTTYSessions(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	c := newCLI(t)
	alice := c.user("alice")
	t.Setenv("GOMAILCTL_PASSPHRASE", "")
	gen := func() uint32 {
		t.Helper()
		u, _, err := c.env.Store.ReadUser(alice.ID)
		if err != nil {
			t.Fatal(err)
		}
		return u.Current().Gen
	}
	const closeFds = ` 3<&- 4<&-`
	for _, tc := range []struct{ name, redir string }{
		{"stdin /dev/tty of session 1 (A), stdout /dev/tty (B)", `<&3 >/dev/tty`},
		{"stdin /dev/tty (B), stdout /dev/tty of session 1 (A)", `</dev/tty >&3`},
		{"stdin and stdout /dev/tty of session 1 (A)", `<&3 >&3`},
		{"stdin slave B, stdout /dev/tty of session 1 (A)", `<&4 >&3`},
		{"stdin /dev/tty of session 1 (A), stdout slave B", `<&3 >&4`},
	} {
		a, b := newPtyRec(t), newPtyRec(t)
		stderr, errOut := stderrFile(t)
		ch := c.startSessions(t, alice.Dir, a, b, stderr, `exec "$0" "$@" `+tc.redir+closeFds, nil, "device", "lost")
		if code := ch.exit(t); code != 1 {
			t.Fatalf("%s: exit %d\n%q", tc.name, code, errOut())
		}
		if s := errOut(); !strings.Contains(s, "dasselbe Terminal") || strings.Contains(s, "Passphrase") || strings.Contains(s, "eingeben") {
			t.Fatalf("%s: stderr %q", tc.name, s)
		}
		for _, p := range []*ptyRec{a, b} {
			p.restored(t)
			if shown, queued := p.quiet(t, 0); shown != "" || queued != 0 {
				t.Fatalf("%s: terminal shows %q, %d bytes queued", tc.name, shown, queued)
			}
		}
		if g := gen(); g != 1 {
			t.Fatalf("%s: generation %d", tc.name, g)
		}
	}

	// /dev/tty of session 2 on both sides: the controlling terminal B.
	a, b := newPtyRec(t), newPtyRec(t)
	stderr, errOut := stderrFile(t)
	ch := c.startSessions(t, alice.Dir, a, b, stderr, `exec "$0" "$@" </dev/tty >/dev/tty`+closeFds,
		[]string{"GOMAILCTL_PASSPHRASE=" + string(testenv.Passphrase)}, "device", "lost")
	for deadline := time.Now().Add(60 * time.Second); !strings.Contains(errOut(), "ohne Anzeige"); time.Sleep(5 * time.Millisecond) {
		ch.running(t)
		if time.Now().After(deadline) {
			t.Fatalf("no word prompt: %q", errOut())
		}
	}
	if !b.echoOff(t) {
		t.Fatal("echo of B on while the seed is typed")
	}
	from := len(b.out.String())
	b.typeIn(t, strings.Join(alice.Words, " ")+"\n")
	if code := ch.exit(t); code != 0 {
		t.Fatalf("/dev/tty of session 2: exit %d\n%q\n%q", code, errOut(), b.out.String())
	}
	b.restored(t)
	shown, _ := b.quiet(t, from)
	if !strings.HasPrefix(shown, clearScreen) || !strings.Contains(shown, "Neue Generation 2") {
		t.Fatalf("terminal B shows %q", shown)
	}
	noWordsAfter(t, "terminal B", strings.ToLower(b.out.String()), alice.Words)
	a.restored(t)
	if shown, queued := a.quiet(t, 0); shown != "" || queued != 0 {
		t.Fatalf("terminal A shows %q, %d bytes queued", shown, queued)
	}
	if g := gen(); g != 2 {
		t.Fatalf("generation %d", g)
	}
}

// TestIsControllingFd (task 13e point 1): TIOCGDEV names the terminal
// behind a descriptor, which must be tty_nr of the status file; a
// descriptor that is no terminal, or a status file without a
// controlling terminal, fails. Two descriptors of terminals that are not
// the controlling terminal of the test never pass sameControlling.
func TestIsControllingFd(t *testing.T) {
	_, slave := openPty(t)
	var st syscall.Stat_t
	if err := syscall.Fstat(int(slave.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if isDevTTYNumber(uint64(st.Rdev)) || !isDevTTYNumber(5<<8) || isDevTTY(uint64(st.Rdev)) || !isDevTTY(5<<8) {
		t.Fatal("isDevTTY")
	}
	defer func(p string) { procStat = p }(procStat)
	procStat = filepath.Join(t.TempDir(), "stat")
	writeFile(t, procStat, fmt.Sprintf("1 (gomailctl) S 1 1 1 %d 1\n", st.Rdev))
	if !isControllingFd(slave.Fd()) {
		t.Fatal("TIOCGDEV does not name the terminal")
	}
	_, other := openPty(t)
	if isControllingFd(other.Fd()) {
		t.Fatal("another terminal counts as the controlling one")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isControllingFd(r.Fd()) {
		t.Fatal("a pipe counts as the controlling terminal")
	}
	writeFile(t, procStat, "1 (gomailctl) S 1 1 1 0 1\n")
	if isControllingFd(slave.Fd()) {
		t.Fatal("controlling terminal without one")
	}
	// The slave is not the controlling terminal of the test: it does not
	// answer TIOCGPGRP, with any status file.
	writeFile(t, procStat, fmt.Sprintf("1 (gomailctl) S 1 1 1 %d 1\n", st.Rdev))
	if sameControlling(slave.Fd(), slave.Fd()) || sameControlling(r.Fd(), slave.Fd()) {
		t.Fatal("sameControlling without the controlling terminal")
	}
}
