//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Tests of task 13c on a pseudo terminal (pty_linux_test.go): a closed
// standard error while the screen is open, and /dev/tty as the same
// terminal.

// closedStderr returns the write side of a pipe for standard error and
// a function that closes its read side, so that every later write to
// standard error fails with EPIPE (and, by default, raises SIGPIPE).
func closedStderr(t *testing.T) (w *os.File, closeReader func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return w, func() { r.Close() }
}

// endedBy130 fails unless the program ended with exit code 130, not by a
// signal.
func endedBy130(t *testing.T, ch *child, p *ptyRec) {
	t.Helper()
	code := ch.exit(t)
	if ws, ok := ch.cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		t.Fatalf("ended by %v\n%q", ws.Signal(), p.out.String())
	}
	if code != 130 {
		t.Fatalf("exit %d\n%q", code, p.out.String())
	}
}

// waitEcho waits until the echo of the terminal is off.
func (p *ptyRec) waitEcho(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(60 * time.Second); !p.echoOff(t); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("echo stays on")
		}
	}
}

// TestPtyKeygenStderrClosed (task 13c finding 1, B13): keygen on a
// terminal with standard error in a pipe whose reader is gone before
// "Seed notiert?" is written. The failed prompt does not end the
// program: Enter still clears the seed, the word question fails as well
// and the program waits for the word with the echo off; Ctrl-C then
// takes the abort path (exit code 130, not SIGPIPE), the terminal is
// restored and nothing is written.
func TestPtyKeygenStderrClosed(t *testing.T) {
	c := newCLI(t)
	p := newPtyRec(t)
	dir := filepath.Join(c.env.Base, "clients", "stderr-closed")
	w, closeReader := closedStderr(t)
	closeReader()
	ch := c.start(t, dir, p.slave, p.slave, w, true, nil, "keygen")
	w.Close()
	pos, _ := p.wait(t, 0, `24\. [a-z]+ *\r\n\r\n`)
	seed := seedOf(t, p.out.String())
	// The prompt "Seed notiert?" failed with EPIPE meanwhile.
	time.Sleep(300 * time.Millisecond)
	ch.running(t)
	if s := p.out.String()[pos:]; strings.Contains(s, clearScreen) {
		t.Fatalf("seed cleared before Enter: %q", s)
	}
	p.typeIn(t, "\n")
	pos, _ = p.wait(t, pos, regexp.QuoteMeta(clearScreen))
	p.waitEcho(t)
	time.Sleep(100 * time.Millisecond)
	ch.running(t)
	p.typeIn(t, "\x03")
	endedBy130(t, ch, p)
	time.Sleep(50 * time.Millisecond)
	noWordsAfter(t, "after the seed", p.out.String()[pos:], seed)
	p.restored(t)
	if exists(dir) {
		t.Fatal("client directory")
	}
}

// TestPtyWordsStderrClosed (task 13c finding 1, B18): device lost on a
// terminal with standard error in a pipe whose reader is gone after the
// word prompt. The progress line after the first words fails without
// ending the program, the echo stays off and the input goes on; Ctrl-C
// clears the screen, turns the echo back on and ends with exit code 130;
// the generation is unchanged.
func TestPtyWordsStderrClosed(t *testing.T) {
	c := newCLI(t)
	alice := c.user("alice")
	ws := alice.Words
	p := newPtyRec(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ch := c.start(t, alice.Dir, p.slave, p.slave, w, true, nil, "device", "lost")
	w.Close()
	var got []byte
	for b := make([]byte, 4096); !strings.Contains(string(got), "ohne Anzeige"); {
		k, err := r.Read(b)
		got = append(got, b[:k]...)
		if err != nil {
			t.Fatalf("stderr: %v, %q", err, got)
		}
	}
	r.Close()
	p.waitEcho(t)
	p.typeIn(t, strings.Join(ws[:5], " ")+"\n")
	time.Sleep(300 * time.Millisecond)
	ch.running(t)
	if !p.echoOff(t) {
		t.Fatal("echo on after the failed progress line")
	}
	p.typeIn(t, strings.Join(ws[5:9], " ")+"\n")
	time.Sleep(100 * time.Millisecond)
	ch.running(t)
	p.typeIn(t, "\x03")
	endedBy130(t, ch, p)
	time.Sleep(50 * time.Millisecond)
	s := p.out.String()
	if !strings.Contains(s, clearScreen) {
		t.Fatalf("no clear: %q", s)
	}
	noWordsAfter(t, "device lost", s, ws)
	p.restored(t)
	u, _, err := c.env.Store.ReadUser(alice.ID)
	if err != nil || u.Current().Gen != 1 {
		t.Fatalf("generation changed: %v", err)
	}
}

// startShell runs gomailctl through /bin/sh with the redirection redir
// (">/dev/tty", "</dev/tty") in a session of its own whose controlling
// terminal is ctty; stdin, stdout and stderr are its descriptors 0 to 2
// before the redirection.
func (c *cli) startShell(t *testing.T, dir string, ctty, stdin, stdout, stderr *os.File, redir string, args ...string) *child {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{"-c", `exec "$0" "$@" ` + redir, os.Args[0]}, c.args(dir, args)...)...)
	cmd.Env = childEnv(nil)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.ExtraFiles = []*os.File{ctty}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3}
	return startChild(t, cmd)
}

// TestPtyWordsDevTTY (task 13c finding 2, B8 "devtty"): /dev/tty counts
// as the controlling terminal it names. device lost and restore with
// standard output (or input) redirected to /dev/tty and the other one
// on the controlling terminal read the words with the echo off, clear
// the screen afterwards and succeed; /dev/tty beside another terminal
// is refused before anything is read.
func TestPtyWordsDevTTY(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	c := newCLI(t)
	alice := c.user("alice")
	ws := alice.Words
	gen := uint32(1)
	for i, tc := range []struct {
		redir string
		args  []string
	}{
		{">/dev/tty", []string{"device", "lost"}},
		{"</dev/tty", []string{"device", "lost"}},
		{">/dev/tty", []string{"restore"}},
		// Both redirected (task 13d finding 1: still allowed).
		{"</dev/tty >/dev/tty", []string{"device", "lost"}},
	} {
		dir := alice.Dir
		if tc.args[0] == "restore" {
			dir = filepath.Join(c.env.Base, "clients", "devtty")
		}
		p := newPtyRec(t)
		ch := c.startShell(t, dir, p.slave, p.slave, p.slave, p.slave, tc.redir, tc.args...)
		pos, _ := p.wait(t, 0, `Seed eingeben \(24 Wörter, auch über mehrere Zeilen, ohne Anzeige\):\r?\n`)
		if !p.echoOff(t) {
			t.Fatalf("%d: echo on while the seed is typed", i)
		}
		p.typeIn(t, strings.Join(ws[:12], " ")+"\n")
		p.wait(t, pos, `\(12 von 24 Wörtern\)`)
		p.typeIn(t, strings.Join(ws[12:], " ")+"\n")
		if code := ch.exit(t); code != 0 {
			t.Fatalf("%d %v %s: exit %d\n%q", i, tc.args, tc.redir, code, p.out.String())
		}
		want := "wiederhergestellt"
		if tc.args[0] == "device" {
			gen++
			want = "Neue Generation " + itoa(gen)
		}
		p.wait(t, pos, want)
		s := p.out.String()
		if k := strings.Index(s[pos:], want); !strings.Contains(s[pos:pos+k], clearScreen) {
			t.Fatalf("%d: no clear after the words: %q", i, s[pos:])
		}
		noWordsAfter(t, "/dev/tty", strings.ToLower(s), ws)
		p.restored(t)
	}
	if !exists(filepath.Join(c.env.Base, "clients", "devtty", "keystore")) {
		t.Fatal("restore wrote no key store")
	}

	// /dev/tty (the controlling terminal A) as standard output, standard
	// input on another terminal B: refused, nothing read.
	a, b := newPtyRec(t), newPtyRec(t)
	ch := c.startShell(t, alice.Dir, a.slave, b.slave, a.slave, a.slave, ">/dev/tty", "device", "lost")
	b.typeIn(t, strings.Join(ws, " ")+"\n")
	if code := ch.exit(t); code != 1 {
		t.Fatalf("/dev/tty beside another terminal: exit %d\n%q", code, a.out.String())
	}
	a.wait(t, 0, `dasselbe Terminal`)
	if s := a.out.String(); strings.Contains(s, "eingeben") {
		t.Fatalf("words asked: %q", s)
	}
	u, _, err := c.env.Store.ReadUser(alice.ID)
	if err != nil || u.Current().Gen != gen {
		t.Fatalf("generation %d, want %d: %v", u.Current().Gen, gen, err)
	}
}

// TestForegroundNotControlling (task 13c finding 2): a terminal that is
// not the controlling terminal of the program does not answer TIOCGPGRP,
// and two descriptors of such a terminal, neither of them /dev/tty, are
// the same terminal only by their device.
func TestForegroundNotControlling(t *testing.T) {
	_, slave := openPty(t)
	_, other := openPty(t)
	if _, ok := foreground(slave.Fd()); ok {
		t.Fatal("TIOCGPGRP answered on a terminal that is not the controlling one")
	}
	if sameControlling(slave.Fd(), other.Fd()) || sameControlling(slave.Fd(), slave.Fd()) {
		t.Fatal("sameControlling without /dev/tty")
	}
	if tty, err := os.OpenFile(devTTY, os.O_RDWR, 0); err == nil {
		// The test runs on a terminal: /dev/tty is not a pseudo
		// terminal of the test.
		defer tty.Close()
		if sameTerminal(tty, slave) || sameTerminal(slave, tty) {
			t.Fatal("/dev/tty is the same terminal as another one")
		}
	}
}
