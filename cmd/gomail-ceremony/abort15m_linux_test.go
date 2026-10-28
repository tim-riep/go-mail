//go:build linux && !ceremony_notty

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Tests of task 15m on pseudo terminals: the abort path with a terminal
// that takes no output (points 1 and 2), standard error not open for
// writing or at RLIMIT_FSIZE (point 3), SIGPIPE before openTerm
// (point 4). The attacks follow the driver of the review of task 15l
// (multi.py): stdin, stdout and stderr spread over the terminals A, B
// and C, the output of one of them stopped or full, and a signal before
// or after the prompt that blocks.

// vt is a pseudo terminal whose master side a poller reads; the test
// can pause the poller (paused), and the terminal then takes output
// until its buffer is full, and no more.
type vt struct {
	t      *testing.T
	m, s   *os.File
	name   string
	mfd    int
	paused atomic.Bool
	before syscall.Termios
	// prompts is the terminal of standard error, where the prompts
	// appear (confirm); nil: this one.
	prompts *vt

	mu  sync.Mutex
	buf []byte

	stop, stopped chan struct{}
}

// newVT opens a pseudo terminal with IXON, IXOFF and IXANY set, as a
// terminal in its default settings has them.
func newVT(t *testing.T) *vt {
	t.Helper()
	m, s, name := rawPTY(t)
	v := &vt{t: t, m: m, s: s, name: name, stop: make(chan struct{}), stopped: make(chan struct{})}
	var tio syscall.Termios
	if err := sysIoctl(s.Fd(), syscall.TCGETS, unsafe.Pointer(&tio)); err != nil {
		t.Fatal(err)
	}
	tio.Iflag |= flow
	if err := sysIoctl(s.Fd(), syscall.TCSETS, unsafe.Pointer(&tio)); err != nil {
		t.Fatal(err)
	}
	v.before = v.termios()
	fd, err := syscall.Dup(int(m.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	syscall.SetNonblock(fd, true)
	v.mfd = fd
	go func() {
		defer close(v.stopped)
		b := make([]byte, 65536)
		for {
			select {
			case <-v.stop:
				return
			default:
			}
			if !v.paused.Load() {
				for {
					n, err := syscall.Read(fd, b)
					if n <= 0 || err != nil {
						break
					}
					v.mu.Lock()
					v.buf = append(v.buf, b[:n]...)
					v.mu.Unlock()
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	t.Cleanup(func() {
		v.paused.Store(true)
		restartOutput(v.s.Fd())
		close(v.stop)
		<-v.stopped
		syscall.Close(fd)
		s.Close()
		m.Close()
	})
	return v
}

func (v *vt) termios() syscall.Termios {
	v.t.Helper()
	var tio syscall.Termios
	if err := sysIoctl(v.s.Fd(), syscall.TCGETS, unsafe.Pointer(&tio)); err != nil {
		v.t.Fatal(err)
	}
	return tio
}

func (v *vt) output() []byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	return bytes.Clone(v.buf)
}

func (v *vt) send(s string) {
	v.t.Helper()
	if _, err := v.m.Write([]byte(s)); err != nil {
		v.t.Fatal(err)
	}
}

// confirm answers a confirmation with Enter answerPause after the prompt
// appeared (pty.confirm), and again when the program took it as too
// early (answerEarly on the terminal of the prompts, task 20a point 7).
func (v *vt) confirm() {
	v.t.Helper()
	time.Sleep(answerPause)
	src := v
	if v.prompts != nil {
		src = v.prompts
	}
	off := len(src.output())
	v.send("\n")
	go answerEarly(src.output, off, func() { v.m.Write([]byte("\n")) }, v.stop)
}

// waitFor waits until the terminal showed a match of re; false if the
// program exited before.
func (v *vt) waitFor(re *regexp.Regexp, exited <-chan struct{}) bool {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if re.Match(v.output()) {
			return true
		}
		select {
		case <-exited:
			time.Sleep(50 * time.Millisecond)
			return re.Match(v.output())
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	v.t.Fatalf("timeout waiting for %v: %q", re, v.output())
	return false
}

// stopOutput stops the output of the terminal as another program can
// (tcflow TCOOFF) and as Scroll Lock on the Linux console does.
func (v *vt) stopOutput() {
	v.t.Helper()
	if err := ioctlValue(v.s.Fd(), ioctlFlowCtl, flowOutOff); err != nil {
		v.t.Fatal(err)
	}
}

// xoff stops the output of the terminal with an XOFF typed while IXON
// is set: IXON is set again first (the program cleared it). This is the
// stop that Scroll Lock gives on the Linux console (stop_tty), which
// TCOON alone does not lift.
func (v *vt) xoff() {
	v.t.Helper()
	tio := v.termios()
	tio.Iflag |= syscall.IXON
	if err := sysIoctl(v.s.Fd(), syscall.TCSETS, unsafe.Pointer(&tio)); err != nil {
		v.t.Fatal(err)
	}
	v.send("\x13")
	time.Sleep(50 * time.Millisecond)
}

// fill stops reading the master side and fills the terminal through a
// second, non-blocking open file description until it takes no more
// output (the program's descriptors stay blocking).
func (v *vt) fill() int {
	v.t.Helper()
	time.Sleep(100 * time.Millisecond)
	v.paused.Store(true)
	time.Sleep(20 * time.Millisecond)
	fd, err := syscall.Open(v.name, syscall.O_WRONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		v.t.Fatal(err)
	}
	defer syscall.Close(fd)
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
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if err != nil {
			v.t.Fatal(err)
		}
	}
	return filled
}

// shareLeft reports whether a share line is on the screen of out: one
// was shown and no clear came after the last one.
func shareLeft(out []byte) bool {
	i := bytes.LastIndex(out, []byte("Anteil 1/2: "))
	return i >= 0 && !bytes.Contains(out[i:], []byte(clearScreen))
}

var (
	holder1   = regexp.MustCompile(`Inhaber von Anteil 1 von 2 an den Bildschirm, dann Eingabetaste: `)
	confirm1  = regexp.MustCompile(`Anteil notiert\?`)
	shareLine = regexp.MustCompile(`Anteil 1/2: [a-z ]+\r\n`)
)

// abortCase is one attack: layout gives the terminals of stdin, stdout
// and stderr ("ABA": stdin and stderr on A, stdout on B); the output of
// the terminal target is stopped (attack 's': TCOOFF), stopped by an
// XOFF with IXON set again (attack 'x': as Scroll Lock) or full (attack
// 'f': nobody reads it), before holder 1 confirms with Enter (pre: the
// next write to that terminal blocks) or once holder 1 is asked to note
// the share (post: the clear and the abort path's writes block).
type abortCase struct {
	layout string
	attack byte
	target byte
	pre    bool
	sig    syscall.Signal
}

func (c abortCase) String() string {
	when := "post"
	if c.pre {
		when = "pre"
	}
	return c.layout + "/" + string(c.attack) + string(c.target) + "/" + when
}

// abortRun runs init 2-of-2 under the attack c and sends c.sig. The
// program ends within 2 s with exit code 130 (not by a signal), no share
// is left on the screen of stdout, every terminal has its modes of
// before, nothing is written. With a stopped terminal no share is left
// even at the exit (the program let the output run again itself); with
// a full one the clear is behind the last share once the terminal is
// read again.
func abortRun(t *testing.T, w1 string, c abortCase) {
	base := t.TempDir()
	vts := map[byte]*vt{}
	for i := 0; i < 3; i++ {
		if vts[c.layout[i]] == nil {
			vts[c.layout[i]] = newVT(t)
		}
	}
	in, out, errw := vts[c.layout[0]], vts[c.layout[1]], vts[c.layout[2]]
	in.prompts = errw
	target := vts[c.target]
	outDir, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	cmd := exec.Command(os.Args[0], "init", "--shares", "2-of-2", "--out", outDir, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOTRACEBACK=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, runMainEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in.s, out.s, errw.s
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	var werr error
	go func() {
		werr = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-exited
	})
	if !errw.waitFor(holder1, exited) {
		t.Fatalf("exited early: stderr %q", errw.output())
	}
	attack := func() {
		switch c.attack {
		case 's':
			target.stopOutput()
		case 'x':
			target.xoff()
		case 'f':
			t.Logf("filled with %d bytes", target.fill())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if c.pre {
		attack()
	}
	in.confirm()
	time.Sleep(600 * time.Millisecond)
	if !c.pre {
		if !errw.waitFor(confirm1, exited) {
			t.Fatalf("holder 1 not asked: stderr %q", errw.output())
		}
		if !shareLine.Match(out.output()) {
			t.Fatalf("share 1 not shown: stdout %q", out.output())
		}
		attack()
		time.Sleep(200 * time.Millisecond)
	}
	select {
	case <-exited:
		t.Fatalf("exited before the signal: %v", werr)
	default:
	}
	sent := time.Now()
	if err := cmd.Process.Signal(c.sig); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatalf("no exit within 2 s after %v; stdout %q", c.sig, out.output())
	}
	took := time.Since(sent)
	var ee *exec.ExitError
	switch {
	case werr == nil:
		t.Fatal("exit code 0")
	case !errors.As(werr, &ee):
		t.Fatal(werr)
	case ee.Sys().(syscall.WaitStatus).Signaled():
		t.Fatalf("ended by %v", ee.Sys().(syscall.WaitStatus).Signal())
	case ee.ExitCode() != exitAbort:
		t.Fatalf("exit code %d", ee.ExitCode())
	}
	if c.attack != 'f' {
		// Nothing of the test restarted the output: what the screen
		// shows now is what the program left.
		time.Sleep(100 * time.Millisecond)
		if screen := out.output(); shareLeft(screen) {
			t.Fatalf("share left on stdout at the exit: %q", screen)
		}
	}
	for _, v := range vts {
		v.paused.Store(false)
		restartOutput(v.s.Fd())
	}
	time.Sleep(300 * time.Millisecond)
	screen := out.output()
	if shareLeft(screen) {
		t.Fatalf("share left on stdout: %q", screen[max(0, len(screen)-400):])
	}
	if !bytes.Contains(screen, []byte(clearScreen)) {
		t.Fatalf("stdout never cleared: %q", screen)
	}
	for k, v := range vts {
		if now := v.termios(); now.Iflag != v.before.Iflag || now.Lflag != v.before.Lflag {
			t.Fatalf("terminal %c: input modes %#x, local modes %#x after; %#x, %#x before", k, now.Iflag, now.Lflag, v.before.Iflag, v.before.Lflag)
		}
	}
	for _, d := range []string{outDir, kd} {
		if exists(d) {
			t.Fatalf("%s written", d)
		}
	}
	t.Logf("exit 130 %v after %v", took.Round(time.Millisecond), c.sig)
}

// TestPTYAbortBlockedOutput (task 15m points 1 and 2).
//
// ABA, AAA, AAB: the terminal A of stdin (and stderr, stdout) takes no
// output, stopped (TCOOFF, as Scroll Lock) or full, before or after the
// prompt that blocks on it. Before task 15m the abort path discarded
// the input of A with TCSETSF, which waits for the write lock of A as
// long as a prompt is blocked in a write to A: the program hung (more
// than 5 s), with share 1 on the screen.
//
// ABC: the terminal B of stdout takes no output once share 1 is shown,
// or before. Before task 15m the clear of stdout blocked behind the stop
// until the program ended (abortWait): share 1 stayed on B, also once B
// ran again.
func TestPTYAbortBlockedOutput(t *testing.T) {
	w1 := witnessArg(t, "w1")
	var cases []abortCase
	for _, layout := range []string{"ABA", "AAA", "AAB"} {
		for _, attack := range []byte{'s', 'f'} {
			for _, pre := range []bool{true, false} {
				sig := syscall.SIGINT
				if !pre {
					sig = syscall.SIGTERM
				}
				cases = append(cases, abortCase{layout, attack, 'A', pre, sig})
			}
		}
	}
	cases = append(cases, abortCase{"ABA", 'x', 'A', false, syscall.SIGINT})
	for _, attack := range []byte{'s', 'f', 'x'} {
		for _, pre := range []bool{true, false} {
			cases = append(cases, abortCase{"ABC", attack, 'B', pre, syscall.SIGINT})
		}
	}
	for _, c := range cases {
		t.Run(c.String(), func(t *testing.T) { abortRun(t, w1, c) })
	}
}

// startFd2 runs the program with stdin and stdout on the slave of p and
// standard error on errFile, with the child hook hook ("" for none).
func (p *pty) startFd2(errFile *os.File, hook string, args ...string) {
	p.t.Helper()
	if hook != "" {
		p.env = append(p.env, hookEnv+"="+hook)
	}
	p.stderr = errFile
	p.start(nil, nil, args...)
}

// exitCode returns the exit code of the program started on p; it fails
// if a signal ended it.
func (p *pty) exitCode(what string) int {
	p.t.Helper()
	select {
	case <-p.exited:
	case <-time.After(10 * time.Second):
		p.t.Fatalf("%s: waits instead of ending; terminal %q", what, p.output())
	}
	time.Sleep(50 * time.Millisecond)
	var ee *exec.ExitError
	if errors.As(p.err, &ee) {
		if ws := ee.Sys().(syscall.WaitStatus); ws.Signaled() {
			p.t.Fatalf("%s: ended by %v", what, ws.Signal())
		}
		return ee.ExitCode()
	}
	if p.err != nil {
		p.t.Fatal(p.err)
	}
	return 0
}

// TestPTYStderrUnwritable (task 15m point 3): standard error open, but
// not for writing (a terminal, the same or another one, or a regular
// file opened read-only, the read end of a pipe, a file opened with
// O_PATH), is refused by every command that shows or reads shares with
// a usage error (exit code 2) before the terminal check: nothing on the
// terminal, its modes untouched, nothing written. Before task 15m only
// the kind of file was checked: the prompts failed unseen and the
// ceremony went on to show share 1.
//
// RLIMIT_FSIZE 0 with standard error on a regular file: the first
// prompt fails with EFBIG (and the kernel raises SIGXFSZ, which the
// program takes in): the ceremony takes the abort path before any share
// is shown, exit code 130, the reason and "abgebrochen" on stdout,
// terminal restored, nothing written. Before task 15m only EPIPE took
// the abort path, and the ceremony showed share 1 behind prompts nobody
// saw.
func TestPTYStderrUnwritable(t *testing.T) {
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	out := filepath.Join(base, "out")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", filepath.Join(base, "keys"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	file := filepath.Join(base, "fehler.log")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const oPath = 0x200000 // O_PATH on every Linux architecture Go supports
	kinds := []struct {
		name string
		open func(p *pty) *os.File
	}{
		{"same terminal read-only", func(p *pty) *os.File {
			f, err := os.OpenFile(p.slave.Name(), os.O_RDONLY|syscall.O_NOCTTY, 0)
			if err != nil {
				p.t.Fatal(err)
			}
			return f
		}},
		{"other terminal read-only", func(p *pty) *os.File {
			m, s, name := rawPTY(p.t)
			p.t.Cleanup(func() { m.Close(); s.Close() })
			f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOCTTY, 0)
			if err != nil {
				p.t.Fatal(err)
			}
			return f
		}},
		{"file read-only", func(p *pty) *os.File {
			f, err := os.Open(file)
			if err != nil {
				p.t.Fatal(err)
			}
			return f
		}},
		{"read end of a pipe", func(p *pty) *os.File {
			r, w, err := os.Pipe()
			if err != nil {
				p.t.Fatal(err)
			}
			p.t.Cleanup(func() { w.Close() })
			return r
		}},
		{"O_PATH", func(p *pty) *os.File {
			fd, err := syscall.Open(file, oPath|syscall.O_CLOEXEC, 0)
			if err != nil {
				p.t.Skip("O_PATH:", err)
			}
			return os.NewFile(uintptr(fd), file)
		}},
	}
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			for _, args := range shareCommands(base, filepath.Join(out, "identity-1.pin"), w1) {
				p := openPTY(t)
				f := k.open(p)
				p.startFd2(f, "", args...)
				f.Close()
				what := args[0] + ", stderr " + k.name
				if code := p.exitCode(what); code != exitUsage {
					t.Fatalf("%s: exit code %d, terminal %q", what, code, p.output())
				}
				if s := p.output(); s != "" {
					t.Fatalf("%s: on the terminal %q", what, s)
				}
				p.restored()
			}
			for _, d := range []string{"o2", "k2"} {
				if _, err := os.Lstat(filepath.Join(base, d)); err == nil {
					t.Fatalf("%s written", d)
				}
			}
		})
	}

	t.Run("RLIMIT_FSIZE 0", func(t *testing.T) {
		base := t.TempDir()
		p := openPTY(t)
		f, err := os.OpenFile(filepath.Join(base, "fehler.log"), os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		outDir, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
		p.startFd2(f, "fsize0", "init", "--shares", "2-of-2", "--out", outDir, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1")
		f.Close()
		// The program waits for no answer: it ends by itself.
		if code := p.exitCode("RLIMIT_FSIZE 0"); code != exitAbort {
			t.Fatalf("exit code %d, terminal %q", code, p.output())
		}
		screen := p.output()
		if strings.Contains(screen, "Anteil 1/2") {
			t.Fatalf("share shown: %q", screen)
		}
		if !strings.HasSuffix(screen, clearScreen+"gomail-ceremony: "+errPromptLost.Error()+"\r\ngomail-ceremony: abgebrochen\r\n") {
			t.Fatalf("terminal %q", screen)
		}
		p.restored()
		for _, d := range []string{outDir, kd} {
			if exists(d) {
				t.Fatalf("%s written", d)
			}
		}
		if st, err := os.Stat(filepath.Join(base, "fehler.log")); err != nil || st.Size() != 0 {
			t.Fatalf("stderr file: %v %v", st, err)
		}
	})
}

// TestPTYNoReaderBeforeTerm (task 15m point 4): a usage error, a
// refusal of standard error and a refusal by the terminal check write to
// standard error before openTerm. With standard error a pipe without a
// reader or a socket without a peer, the program ends with its exit code
// (2, or 1 for the terminal check), not by SIGPIPE: SIGPIPE is taken in
// from the first step of run. Before task 15m the runtime ended the
// program by SIGPIPE at the first of these writes.
func TestPTYNoReaderBeforeTerm(t *testing.T) {
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	initArgs := []string{"init", "--shares", "2-of-2", "--out", filepath.Join(base, "out"), "--keys", filepath.Join(base, "keys"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"}
	pipe := func() *os.File {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		r.Close()
		return w
	}
	socket := func() *os.File {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		syscall.Close(fds[1])
		return os.NewFile(uintptr(fds[0]), "socket")
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	for _, tc := range []struct {
		name   string
		stderr func() *os.File
		stdout *os.File // nil: the terminal
		args   []string
		want   int
	}{
		{"pipe, no arguments", pipe, nil, nil, exitUsage},
		{"pipe, unknown flag", pipe, nil, []string{"init", "--bogus"}, exitUsage},
		{"pipe, publish without flags", pipe, nil, []string{"publish"}, exitUsage},
		{"pipe, stdout no terminal", pipe, null, initArgs, exitFail},
		{"socket, unknown flag", socket, nil, []string{"reshare", "--bogus"}, exitUsage},
		{"socket, init refused", socket, nil, initArgs, exitUsage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := openPTY(t)
			f := tc.stderr()
			p.stderr = f
			p.start(nil, tc.stdout, tc.args...)
			f.Close()
			if code := p.exitCode(tc.name); code != tc.want {
				t.Fatalf("%s: exit code %d, want %d; terminal %q", tc.name, code, tc.want, p.output())
			}
			if s := p.output(); s != "" {
				t.Fatalf("%s: on the terminal %q", tc.name, s)
			}
			p.restored()
		})
	}
	if exists(filepath.Join(base, "out")) || exists(filepath.Join(base, "keys")) {
		t.Fatal("written")
	}
}
