//go:build linux

package main

import (
	"bufio"
	"bytes"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// openPty opens a pseudo terminal and returns its master and slave side.
func openPty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no /dev/ptmx:", err)
	}
	t.Cleanup(func() { m.Close() })
	var n uint32
	if err := ioctl(m.Fd(), syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		t.Skip("TIOCGPTN:", err)
	}
	var unlock int32
	if err := ioctl(m.Fd(), syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		t.Skip("TIOCSPTLCK:", err)
	}
	s, err := os.OpenFile("/dev/pts/"+itoa(n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skip("pty slave:", err)
	}
	t.Cleanup(func() { s.Close() })
	// Drain the master so that writes to the slave never block.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := m.Read(buf); err != nil {
				return
			}
		}
	}()
	return m, s
}

func itoa(n uint32) string {
	var b [10]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		if n /= 10; n == 0 {
			return string(b[i:])
		}
	}
}

func iflag(t *testing.T, f *os.File) uint32 {
	t.Helper()
	var tio syscall.Termios
	if err := ioctl(f.Fd(), ioctlGetTermios, unsafe.Pointer(&tio)); err != nil {
		t.Fatal(err)
	}
	return tio.Iflag
}

// TestScreenOnPty: on a real terminal the screen switches the flow
// control off and restores it, discards input typed ahead, and a
// regular file or a pipe is no terminal.
func TestScreenOnPty(t *testing.T) {
	_, slave := openPty(t)
	if !isTerminal(slave) || isTerminal(&bytes.Buffer{}) || isTerminal(os.NewFile(^uintptr(0), "none")) {
		t.Fatal("isTerminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Fatal("a regular file is a terminal")
	}
	before := iflag(t, slave)
	if before&syscall.IXON == 0 {
		t.Skip("IXON not set on the pty")
	}
	var errb bytes.Buffer
	e := &env{stdin: bufio.NewReader(strings.NewReader("typed ahead\n")), in: slave, stdout: slave, stderr: &errb}
	s, err := e.openScreen()
	if err != nil {
		t.Fatal(err)
	}
	if iflag(t, slave)&flowFlags != 0 {
		t.Fatal("flow control still on")
	}
	s.show("share\n")
	// Input typed ahead is dropped from the read buffer.
	e.stdin.Peek(1)
	if err := e.flushTyped(); err != nil || e.stdin.Buffered() != 0 {
		t.Fatalf("flushTyped: %v, %d bytes left", err, e.stdin.Buffered())
	}
	// The echo of stdin: off and read back, then restored.
	lflag := func() uint32 {
		var tio syscall.Termios
		if err := ioctl(slave.Fd(), ioctlGetTermios, unsafe.Pointer(&tio)); err != nil {
			t.Fatal(err)
		}
		return tio.Lflag
	}
	echo0 := lflag()
	if err := s.echoOff(); err != nil || lflag()&syscall.ECHO != 0 || s.echoOff() != nil {
		t.Fatalf("echo off: %v", err)
	}
	s.echoOn()
	if lflag() != echo0 {
		t.Fatal("echo not restored")
	}
	s.close()
	s.close()
	if iflag(t, slave) != before {
		t.Fatal("flow control not restored")
	}
	// The same terminal through two descriptors; a second terminal and a
	// file are not.
	again, err := os.OpenFile(slave.Name(), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	_, other := openPty(t)
	if !sameTerminal(slave, again) || sameTerminal(slave, other) || sameTerminal(slave, f) || sameTerminal(f, f) {
		t.Fatal("sameTerminal")
	}
	if _, ok := terminalID(f.Fd()); ok {
		t.Fatal("terminalID of a file")
	}
	// A disabled echo switch fails closed.
	if err := (&screen{e: e}).echoOff(); err != errNoEchoControl {
		t.Fatalf("echoOff without a terminal on stdin: %v", err)
	}
	// Not a terminal: flushTyped keeps the input of a pipe.
	e = &env{stdin: bufio.NewReader(strings.NewReader("keep\n")), in: f, stdout: f, stderr: &errb}
	e.stdin.Peek(1)
	if err := e.flushTyped(); err != nil || e.stdin.Buffered() == 0 {
		t.Fatal("flushTyped dropped piped input")
	}
	if _, err := e.openScreen(); err != errNoTerminal {
		t.Fatalf("openScreen on a file: %v", err)
	}
	if s, err := e.wordScreen(); s != nil || err != nil {
		t.Fatal("wordScreen on a file")
	}
}

// TestScreenAbort: an abort signal while a share is on the screen clears
// the screen and ends the program with exit code 130; nothing is written
// after the clear.
func TestScreenAbort(t *testing.T) {
	codes := make(chan int, 1)
	exit = func(code int) {
		codes <- code
		runtime.Goexit()
	}
	t.Cleanup(func() { exit = os.Exit })
	out := &tty{}
	var errb syncBuf
	e := &env{stdout: out, stderr: &errb}
	s, err := e.openScreen()
	if err != nil {
		t.Fatal(err)
	}
	// The abort path keeps the lock and never stops the signal handling
	// (the program ends); the test stops it.
	defer signal.Stop(s.sig)
	s.show("share words\n")
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-codes:
		if code != 130 {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no abort")
	}
	if !strings.HasSuffix(out.String(), "share words\n"+clearScreen) || !strings.Contains(errb.String(), "abgebrochen") {
		t.Fatalf("screen after the abort: %q, %q", out.String(), errb.String())
	}
	// The lock stays taken: nothing reaches the screen any more.
	if s.mu.TryLock() {
		t.Fatal("lock released after the abort")
	}
}
