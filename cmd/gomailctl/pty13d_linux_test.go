//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Tests of task 13d: the master side of a pseudo terminal is never a
// terminal of the user (finding 1), and SIGPIPE is taken over for the
// whole run (finding 2).

// dupFile returns a second descriptor of f, closed with the test.
func dupFile(t *testing.T, f *os.File) *os.File {
	t.Helper()
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	d := os.NewFile(uintptr(fd), f.Name()+"-dup")
	t.Cleanup(func() { d.Close() })
	return d
}

// stderrFile returns a temporary file for the standard error of a child
// and a function that reads what the child wrote to it.
func stderrFile(t *testing.T) (*os.File, func() string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f, func() string {
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

// inputQueued returns the number of bytes in the input queue of the
// terminal f that no program has read.
func inputQueued(t *testing.T, f *os.File) int {
	t.Helper()
	var n int32
	if err := ioctl(f.Fd(), syscall.TIOCINQ, unsafe.Pointer(&n)); err != nil {
		t.Fatal(err)
	}
	return int(n)
}

// TestPtyMaster (task 13d finding 1): the master side of a pseudo
// terminal answers TIOCGPTN, its slave does not; a master is no
// terminal, has no identity and no echo switch, is not the same terminal
// as its slave, and is refused by keygen and by the word input.
func TestPtyMaster(t *testing.T) {
	master, slave := openPty(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !isPtyMaster(master.Fd()) || isPtyMaster(slave.Fd()) || isPtyMaster(r.Fd()) || isPtyMaster(f.Fd()) {
		t.Fatal("isPtyMaster")
	}
	if isTerminalFd(master.Fd()) || isTerminal(master) || !isTerminal(slave) {
		t.Fatal("a master counts as a terminal")
	}
	if _, ok := terminalID(master.Fd()); ok {
		t.Fatal("terminalID of a master")
	}
	if echoControl(master) != nil {
		t.Fatal("echo switch of a master")
	}
	if !ptyMasterOf(master) || ptyMasterOf(slave) || ptyMasterOf(&bytes.Buffer{}) || ptyMasterOf(&tty{}) {
		t.Fatal("ptyMasterOf")
	}
	if sameTerminal(master, slave) || sameTerminal(slave, master) || sameTerminal(master, master) ||
		sameControlling(master.Fd(), slave.Fd()) || sameControlling(slave.Fd(), master.Fd()) {
		t.Fatal("a master is the same terminal as its slave")
	}
	for i, e := range []*env{
		{in: slave, stdout: master},
		{in: master, stdout: slave},
		{in: r, stdout: master},
		{in: master, stdout: &bytes.Buffer{}},
	} {
		if err := e.checkWordInput(); !errors.Is(err, errPtyMaster) {
			t.Fatalf("checkWordInput %d: %v", i, err)
		}
		if err := keygenPre(e, &options{}); !errors.Is(err, errPtyMaster) {
			t.Fatalf("keygenPre %d: %v", i, err)
		}
	}
	// The slave on both sides still passes.
	if err := (&env{in: slave, stdout: slave}).checkWordInput(); err != nil {
		t.Fatal(err)
	}
	// The masters of the legacy BSD pseudo terminals by their major.
	for _, c := range []struct {
		dev, major uint64
	}{{0x0200, 2}, {0x0205, 2}, {0x8803, 136}, {0x8000, 128}, {0x500, 5}, {0x12c05, 300}, {0x100200, 2}} {
		if got := linuxMajor(c.dev); got != c.major {
			t.Fatalf("linuxMajor(%#x) = %d, want %d", c.dev, got, c.major)
		}
	}
}

// TestParseTTYNr (task 13d finding 1): tty_nr is the fifth field after
// the command name, which ends at the last ")"; 0 and malformed lines
// name no terminal. isControllingDevice compares it with a device.
func TestParseTTYNr(t *testing.T) {
	for _, c := range []struct {
		line string
		nr   uint64
		ok   bool
	}{
		{"1234 (gomailctl) S 1 1234 1234 34816 1234 4194560 0 0", 34816, true},
		{"7 (a) b (c) R 1 2 3 34817 5", 34817, true},
		{"7 (a b) S 1 2 3 0 5", 0, false},
		{"7 (x) S 1 2 3", 0, false},
		{"7 x S 1 2 3 34816", 0, false},
		{"7 (x) S 1 2 3 tty 5", 0, false},
		{"7 (x) S 1 2 3 4294967296 5", 0, false},
		{"7 (x) S 1 2 3 -2147483648 5", 0x80000000, true},
		{"", 0, false},
	} {
		nr, ok := parseTTYNr([]byte(c.line))
		if nr != c.nr || ok != c.ok {
			t.Fatalf("%q: %d %v, want %d %v", c.line, nr, ok, c.nr, c.ok)
		}
	}
	defer func(p string) { procStat = p }(procStat)
	procStat = filepath.Join(t.TempDir(), "stat")
	if isControllingDevice(34816) {
		t.Fatal("controlling device without the status file")
	}
	writeFile(t, procStat, "1 (gomailctl) S 1 1 1 34816 1 "+strings.Repeat("0 ", 600)+"\n")
	if !isControllingDevice(34816) || isControllingDevice(34817) || isControllingDevice(0) {
		t.Fatal("isControllingDevice")
	}
	writeFile(t, procStat, "1 (gomailctl) S 1 1 1 0 1\n")
	if isControllingDevice(0) {
		t.Fatal("no controlling terminal counts as one")
	}
}

// TestPtyKeygenMasterStdout (task 13d finding 1, C8): keygen with
// standard input on the slave of terminal A and standard output on its
// master ends with exit code 1 before anything is shown, read or
// written: no byte reaches the input of A (nothing echoed, nothing
// queued), no passphrase is asked, no client directory. The same with
// the sides swapped.
func TestPtyKeygenMasterStdout(t *testing.T) {
	c := newCLI(t)
	t.Setenv("GOMAILCTL_PASSPHRASE", "")
	for _, swap := range []bool{false, true} {
		p := newPtyRec(t)
		dir := filepath.Join(c.env.Base, "clients", "master")
		stderr, errOut := stderrFile(t)
		stdin, stdout := p.slave, dupFile(t, p.master)
		if swap {
			stdin, stdout = stdout, stdin
		}
		ch := c.start(t, dir, stdin, stdout, stderr, !swap, nil, "keygen")
		if code := ch.exit(t); code != 1 {
			t.Fatalf("swap %v: exit %d\n%q\n%q", swap, code, errOut(), p.out.String())
		}
		time.Sleep(100 * time.Millisecond)
		if s := errOut(); !strings.Contains(s, "Gegenseite (Master) eines Pseudoterminals") || strings.Contains(s, "Passphrase") {
			t.Fatalf("swap %v: stderr %q", swap, s)
		}
		if s := p.out.String(); s != "" {
			t.Fatalf("swap %v: written to the terminal: %q", swap, s)
		}
		if n := inputQueued(t, p.slave); n != 0 {
			t.Fatalf("swap %v: %d bytes in the input of the terminal", swap, n)
		}
		if exists(dir) {
			t.Fatalf("swap %v: client directory", swap)
		}
		p.restored(t)
	}
}

// TestPtyWordsMasterDevTTY (task 13d finding 1, C4/C8): device lost and
// restore with /dev/tty (the controlling terminal A) on one side and the
// master of A, or of another terminal B, on the other end with exit code
// 1 before the passphrase is asked or a word is read; the generation is
// unchanged and nothing reaches the input of A.
func TestPtyWordsMasterDevTTY(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	c := newCLI(t)
	alice := c.user("alice")
	t.Setenv("GOMAILCTL_PASSPHRASE", "")
	for _, tc := range []struct {
		name, redir string
		masterIn    bool // the master on standard input, else on standard output
		otherB      bool // the master of another terminal B
		args        []string
	}{
		{"</dev/tty, master A out", "</dev/tty", false, false, []string{"device", "lost"}},
		{"master A in, >/dev/tty", ">/dev/tty", true, false, []string{"device", "lost"}},
		{"</dev/tty, master B out", "</dev/tty", false, true, []string{"device", "lost"}},
		{"restore </dev/tty, master A out", "</dev/tty", false, false, []string{"restore"}},
	} {
		a := newPtyRec(t)
		m := a.master
		var b *ptyRec
		if tc.otherB {
			b = newPtyRec(t)
			m = b.master
		}
		dir := alice.Dir
		if tc.args[0] == "restore" {
			dir = filepath.Join(c.env.Base, "clients", "master-restore")
		}
		stderr, errOut := stderrFile(t)
		stdin, stdout := a.slave, dupFile(t, m)
		if tc.masterIn {
			stdin, stdout = stdout, a.slave
		}
		ch := c.startShell(t, dir, a.slave, stdin, stdout, stderr, tc.redir, tc.args...)
		a.typeIn(t, strings.Join(alice.Words, " ")+"\n")
		if code := ch.exit(t); code != 1 {
			t.Fatalf("%s: exit %d\n%q\n%q", tc.name, code, errOut(), a.out.String())
		}
		time.Sleep(100 * time.Millisecond)
		if s := errOut(); !strings.Contains(s, "Gegenseite (Master) eines Pseudoterminals") || strings.Contains(s, "Passphrase") || strings.Contains(s, "eingeben") {
			t.Fatalf("%s: stderr %q", tc.name, s)
		}
		// Only the typed words, echoed by A, and none of the program.
		if s := strings.TrimSpace(strings.ReplaceAll(a.out.String(), "\r\n", "\n")); s != strings.Join(alice.Words, " ") {
			t.Fatalf("%s: terminal A shows %q", tc.name, s)
		}
		if b != nil && b.out.String() != "" {
			t.Fatalf("%s: terminal B shows %q", tc.name, b.out.String())
		}
		u, _, err := c.env.Store.ReadUser(alice.ID)
		if err != nil || u.Current().Gen != 1 {
			t.Fatalf("%s: generation changed: %v", tc.name, err)
		}
		if exists(filepath.Join(c.env.Base, "clients", "master-restore")) {
			t.Fatalf("%s: restore wrote a client directory", tc.name)
		}
		a.restored(t)
	}
}

// TestPtyRestoreStderrClosed (task 13d finding 2, C7): restore on a
// terminal with standard error in a pipe whose reader is gone after the
// word prompt. The failed progress line and the warning of the restored
// client after the screen is closed do not end the program: it ends with
// exit code 0, not by SIGPIPE, with a complete key store that opens with
// the passphrase.
func TestPtyRestoreStderrClosed(t *testing.T) {
	c := newCLI(t)
	alice := c.user("alice")
	ws := alice.Words
	p := newPtyRec(t)
	dir := filepath.Join(c.env.Base, "clients", "restore-stderr-closed")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ch := c.start(t, dir, p.slave, p.slave, w, true, nil, "restore")
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
	p.typeIn(t, strings.Join(ws[:12], " ")+"\n")
	time.Sleep(200 * time.Millisecond)
	ch.running(t)
	p.typeIn(t, strings.Join(ws[12:], " ")+"\n")
	code := ch.exit(t)
	if st, ok := ch.cmd.ProcessState.Sys().(syscall.WaitStatus); ok && st.Signaled() {
		t.Fatalf("ended by %v\n%q", st.Signal(), p.out.String())
	}
	if code != 0 {
		t.Fatalf("exit %d\n%q", code, p.out.String())
	}
	p.wait(t, 0, "auf diesem Gerät wiederhergestellt")
	noWordsAfter(t, "restore", p.out.String(), ws)
	p.restored(t)
	for _, f := range []string{"keystore", "state.json"} {
		if !exists(filepath.Join(dir, f)) {
			t.Fatalf("no %s", f)
		}
	}
	// The key store opens with the passphrase and the client works.
	c.must(0, dir, "", "sync")
}

// TestRelayBrokenPipe (task 13d finding 2): with SIGPIPE taken over as
// main does, a write to standard error without a reader fails with
// EPIPE and the program goes on.
func TestRelayBrokenPipe(t *testing.T) {
	relayBrokenPipe()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	saved, err := syscall.Dup(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Dup3(int(w.Fd()), 2, 0); err != nil {
		syscall.Close(saved)
		t.Fatal(err)
	}
	_, werr := os.Stderr.Write([]byte("x"))
	syscall.Dup3(saved, 2, 0)
	syscall.Close(saved)
	if !errors.Is(werr, syscall.EPIPE) {
		t.Fatalf("write to standard error without a reader: %v", werr)
	}
}
