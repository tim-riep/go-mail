//go:build linux && !ceremony_notty

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Tests of task 15l on pseudo terminals (pty_linux_test.go): standard
// error on a third terminal (point 1), descriptor 2 closed at the start
// (point 2).

// threeTerminals runs init 2-of-2 with stdin on terminal A, stdout on B
// and stderr on C, all three with IXON, IXOFF and IXANY set before, and
// types XOFF (Ctrl-S) on the terminal xoff ("stdout": B, "stderr": C)
// once holder 1 is called. The program clears the flow control of all
// three, so the XOFF stops nothing: share 1 appears on B, its holder is
// asked on C, and SIGINT ends the program within 2 s with exit code 130,
// the share cleared on B, the clear and "abgebrochen" on C, nothing
// written, all three terminals as before.
func threeTerminals(t *testing.T, w1, xoff string) {
	base := t.TempDir()
	a, b, c := openPTY(t), openPTY(t), openPTY(t)
	t.Cleanup(func() {
		b.master.Write([]byte("\x11"))
		c.master.Write([]byte("\x11"))
	})
	for _, p := range []*pty{a, b, c} {
		p.setIflag(flow)
	}
	out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	a.stderr = c.slave
	a.start(nil, b.slave, "init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1")
	b.exited, c.exited = a.exited, a.exited
	if c.next(regexp.MustCompile(`Inhaber von Anteil 1 von 2 an den Bildschirm, dann Eingabetaste: `)) == nil {
		t.Fatalf("exited early: A %q, B %q, C %q", a.output(), b.output(), c.output())
	}
	a.noFlow()
	b.noFlow()
	c.noFlow()
	map[string]*pty{"stdout": b, "stderr": c}[xoff].send("\x13")
	time.Sleep(100 * time.Millisecond)
	a.confirm()
	if b.next(regexp.MustCompile(`Anteil 1/2: [a-z ]+\r\n`)) == nil {
		t.Fatalf("share 1 not shown: B %q", b.output())
	}
	if c.next(regexp.MustCompile(`Anteil notiert\?`)) == nil {
		t.Fatalf("holder 1 not asked: C %q", c.output())
	}
	sent := time.Now()
	if err := a.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.exited:
	case <-time.After(2 * time.Second):
		t.Fatalf("no exit within 2 s after SIGINT; B %q, C %q", b.output(), c.output())
	}
	took := time.Since(sent)
	if code := a.wait(); code != exitAbort {
		t.Fatalf("exit code %d\nB %q\nC %q", code, b.output(), c.output())
	}
	a.restored()
	b.restored()
	c.restored()
	screen := b.output()
	i := strings.Index(screen, "Anteil 1/2: ")
	if i < 0 || !strings.Contains(screen[i:], clearScreen) || !strings.HasSuffix(screen, clearScreen) {
		t.Fatalf("stdout %q", screen)
	}
	if errs := c.output(); !strings.HasSuffix(errs, clearScreen+"gomail-ceremony: abgebrochen\r\n") || strings.Count(errs, clearScreen) < 2 {
		t.Fatalf("stderr %q", errs)
	}
	if strings.Contains(a.output(), "Anteil") {
		t.Fatalf("stdin terminal %q", a.output())
	}
	for _, d := range []string{out, kd} {
		if exists(d) {
			t.Fatalf("%s written", d)
		}
	}
	t.Logf("exit 130 %v after SIGINT", took.Round(time.Millisecond))
}

// TestPTYThreeTerminals (task 15l point 1): stdin on terminal A, stdout
// on B, stderr on C.
//
// "XOFF on stderr" and "XOFF on stdout": see threeTerminals; before task
// 15l the flow control of C stayed on, the XOFF on C stopped the prompt
// "Anteil notiert?" and the clear of C in the abort path, and with it
// the clear of the share on B (written after that of C): the share
// stayed on B after the exit.
//
// "stderr blocked": C takes no output at all once holder 1 is called
// (nobody reads its master side and its buffer is full), so the prompt
// "Anteil notiert?" blocks with share 1 on B. SIGINT ends the program
// within 2 s with exit code 130, the share cleared on B (stdout is
// cleared first, and each write of the abort path is bounded on its
// own), nothing written, all three terminals as before.
func TestPTYThreeTerminals(t *testing.T) {
	w1 := witnessArg(t, "w1")
	t.Run("XOFF on stderr", func(t *testing.T) { threeTerminals(t, w1, "stderr") })
	t.Run("XOFF on stdout", func(t *testing.T) { threeTerminals(t, w1, "stdout") })
	t.Run("stderr blocked", func(t *testing.T) {
		base := t.TempDir()
		a, b := openPTY(t), openPTY(t)
		cm, cs, name := rawPTY(t)
		defer cm.Close()
		defer cs.Close()
		var before syscall.Termios
		if err := sysIoctl(cs.Fd(), syscall.TCGETS, unsafe.Pointer(&before)); err != nil {
			t.Fatal(err)
		}
		mfd, err := syscall.Dup(int(cm.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Close(mfd)
		syscall.SetNonblock(mfd, true)
		var errs []byte
		buf := make([]byte, 65536)
		readC := func() {
			for {
				n, err := syscall.Read(mfd, buf)
				if n <= 0 || err != nil {
					return
				}
				errs = append(errs, buf[:n]...)
			}
		}
		out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
		a.stderr = cs
		a.start(nil, b.slave, "init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1")
		b.exited = a.exited
		holder := []byte("Inhaber von Anteil 1 von 2 an den Bildschirm, dann Eingabetaste: ")
		for deadline := time.Now().Add(60 * time.Second); !bytes.Contains(errs, holder); time.Sleep(5 * time.Millisecond) {
			readC()
			select {
			case <-a.exited:
				t.Fatalf("exited early: C %q", errs)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("holder 1 not called: C %q", errs)
			}
		}
		// From now on nobody reads C. Fill it until it takes no more
		// output, through a second, non-blocking open file description
		// (the program's stderr stays blocking).
		fd, err := syscall.Open(name, syscall.O_WRONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		filled := 0
		chunk := bytes.Repeat([]byte("."), 256)
		for refused := 0; refused < 20 && filled < 16<<20; {
			n, err := syscall.Write(fd, chunk)
			if n > 0 {
				filled += n
				refused = 0
			}
			if errors.Is(err, syscall.EAGAIN) {
				refused++
				time.Sleep(20 * time.Millisecond)
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		syscall.Close(fd)
		a.confirm()
		if b.next(regexp.MustCompile(`Anteil 1/2: [a-z ]+\r\n`)) == nil {
			t.Fatalf("share 1 not shown: B %q", b.output())
		}
		// The program now blocks in the prompt "Anteil notiert?" on C.
		time.Sleep(300 * time.Millisecond)
		select {
		case <-a.exited:
			t.Fatal("exited before the signal")
		default:
		}
		sent := time.Now()
		if err := a.cmd.Process.Signal(syscall.SIGINT); err != nil {
			t.Fatal(err)
		}
		select {
		case <-a.exited:
		case <-time.After(2 * time.Second):
			t.Fatalf("no exit within 2 s after SIGINT with stderr blocked; B %q", b.output())
		}
		took := time.Since(sent)
		if code := a.wait(); code != exitAbort {
			t.Fatalf("exit code %d\nB %q", code, b.output())
		}
		a.restored()
		b.restored()
		var after syscall.Termios
		if err := sysIoctl(cs.Fd(), syscall.TCGETS, unsafe.Pointer(&after)); err != nil {
			t.Fatal(err)
		}
		if after.Iflag != before.Iflag || after.Lflag != before.Lflag {
			t.Fatalf("terminal C: input modes %#x, local modes %#x after; %#x, %#x before", after.Iflag, after.Lflag, before.Iflag, before.Lflag)
		}
		screen := b.output()
		i := strings.Index(screen, "Anteil 1/2: ")
		if i < 0 || !strings.HasSuffix(screen, clearScreen) {
			t.Fatalf("share left on stdout: %q", screen)
		}
		for _, d := range []string{out, kd} {
			if exists(d) {
				t.Fatalf("%s written", d)
			}
		}
		readC()
		if bytes.Contains(errs, []byte("Anteil 1/2")) {
			t.Fatalf("share on C")
		}
		t.Logf("C filled with %d bytes; exit 130 %v after SIGINT", filled, took.Round(time.Millisecond))
	})
}

// startClosedStderr runs the program with stdin on in (the slave of p
// when nil), stdout on the slave of p and descriptor 2 closed: the
// runtime of the program opens /dev/null in its slot. The controlling
// terminal is p.
func (p *pty) startClosedStderr(in *os.File, args ...string) {
	p.t.Helper()
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOTRACEBACK=") {
			env = append(env, kv)
		}
	}
	env = append(env, runMainEnv+"=1")
	stdin, ctty := p.slave.Fd(), 0
	if in != nil {
		stdin, ctty = in.Fd(), 1
	}
	pid, err := syscall.ForkExec(os.Args[0], append([]string{os.Args[0]}, args...), &syscall.ProcAttr{
		Env:   env,
		Files: []uintptr{stdin, p.slave.Fd(), ^uintptr(0)}, // -1: descriptor 2 closed in the child
		Sys:   &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: ctty},
	})
	if err != nil {
		p.t.Fatal(err)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		p.t.Fatal(err)
	}
	go func() {
		st, err := proc.Wait()
		if err == nil && !st.Success() {
			err = &exitStatus{st}
		}
		p.err = err
		close(p.exited)
	}()
	p.t.Cleanup(func() {
		proc.Kill()
		<-p.exited
	})
}

// exitStatus is the error of a program started by startClosedStderr
// that exited with a code other than 0.
type exitStatus struct{ st *os.ProcessState }

func (e *exitStatus) Error() string { return e.st.String() }

// TestPTYStderrNull (task 15l point 2): every command that shows or
// reads shares, started with descriptor 2 closed (the runtime puts
// /dev/null there) or with standard error on /dev/null, refuses with a
// usage error (exit code 2) before the terminal check: nothing on the
// terminal (no prompt, no clear), the terminal modes untouched, nothing
// written; with standard input a pipe as well, where the terminal check
// would refuse with exit code 1. Before task 15l the program wrote its
// prompts into /dev/null and waited, invisible, for an answer.
func TestPTYStderrNull(t *testing.T) {
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	out := filepath.Join(base, "out")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", filepath.Join(base, "keys"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	refused := func(p *pty, what string) {
		t.Helper()
		select {
		case <-p.exited:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s waits instead of refusing", what)
		}
		time.Sleep(50 * time.Millisecond)
		code := -1
		var es *exitStatus
		switch {
		case p.err == nil:
			code = 0
		case errors.As(p.err, &es):
			if ws := es.st.Sys().(syscall.WaitStatus); !ws.Signaled() {
				code = ws.ExitStatus()
			}
		default:
			code = p.wait()
		}
		if code != exitUsage {
			t.Fatalf("%s: exit %d (%v), terminal %q", what, code, p.err, p.output())
		}
		if s := p.output(); s != "" {
			t.Fatalf("%s: on the terminal %q", what, s)
		}
		p.restored()
	}
	for _, args := range shareCommands(base, filepath.Join(out, "identity-1.pin"), w1) {
		p := openPTY(t)
		p.startClosedStderr(nil, args...)
		refused(p, args[0]+" with descriptor 2 closed")

		p = openPTY(t)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		w.WriteString("\n\n")
		w.Close()
		p.startClosedStderr(r, args...)
		refused(p, args[0]+" with descriptor 2 closed and stdin a pipe")
		left := make([]byte, 8)
		if n, _ := r.Read(left); n != 2 {
			t.Fatalf("%s: stdin pipe read", args[0])
		}
		r.Close()

		p = openPTY(t)
		p.stderr = null
		p.start(nil, nil, args...)
		refused(p, args[0]+" with stderr on /dev/null")
	}
	for _, d := range []string{"o2", "k2"} {
		if _, err := os.Lstat(filepath.Join(base, d)); err == nil {
			t.Fatalf("%s written", d)
		}
	}
}
