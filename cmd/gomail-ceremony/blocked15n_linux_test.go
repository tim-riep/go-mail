//go:build linux && !ceremony_notty

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Tests of task 15n on pseudo terminals (vt, abort15m_linux_test.go): a
// clear or a share line that fails or blocks in the normal path
// (finding 1), a prompt or a clear held up while a share is on the
// screen (finding 2), and Enter typed twice with a gap (finding 3). The
// attacks follow the drivers of the review of task 15m (nonblock.py,
// errstop.py, hold.py with tcooffloop, dblenter.py).

// stuckLimit is how long a share may stay on the screen with the program
// stuck: outputGrace and the abort path (at most 2 s, task 15m), and a
// margin for a loaded test machine.
const stuckLimit = outputGrace + 2*time.Second + 500*time.Millisecond

// ceremony15n is init 2-of-2 on the terminals of layout (stdin, stdout
// and stderr, as in abortCase).
type ceremony15n struct {
	t             *testing.T
	vts           map[byte]*vt
	in, out, errw *vt
	cmd           *exec.Cmd
	exited        chan struct{}
	werr          error
	outDir, kd    string
}

func start15n(t *testing.T, w1, layout string, env ...string) *ceremony15n {
	t.Helper()
	base := t.TempDir()
	c := &ceremony15n{t: t, vts: map[byte]*vt{}, exited: make(chan struct{})}
	for i := 0; i < 3; i++ {
		if c.vts[layout[i]] == nil {
			c.vts[layout[i]] = newVT(t)
		}
	}
	c.in, c.out, c.errw = c.vts[layout[0]], c.vts[layout[1]], c.vts[layout[2]]
	c.in.prompts = c.errw
	c.outDir, c.kd = filepath.Join(base, "out"), filepath.Join(base, "keys")
	cmd := exec.Command(os.Args[0], "init", "--shares", "2-of-2", "--out", c.outDir, "--keys", c.kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOTRACEBACK=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(append(cmd.Env, runMainEnv+"=1"), env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.in.s, c.out.s, c.errw.s
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c.cmd = cmd
	go func() {
		c.werr = cmd.Wait()
		close(c.exited)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-c.exited
	})
	return c
}

// until waits at most d for a match of re on v after offset from; it
// reports whether one came.
func (v *vt) until(re *regexp.Regexp, from int, d time.Duration) bool {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
		if out := v.output(); len(out) >= from && re.Match(out[from:]) {
			return true
		}
	}
	return false
}

// toShare1 calls holder 1, confirms, and waits until share 1 is shown
// and its holder asked whether it is noted.
func (c *ceremony15n) toShare1() {
	c.t.Helper()
	if !c.errw.waitFor(holder1, c.exited) {
		c.t.Fatalf("exited early: stderr %q", c.errw.output())
	}
	c.in.confirm()
	if !c.out.waitFor(shareLine, c.exited) || !c.errw.waitFor(confirm1, c.exited) {
		c.t.Fatalf("share 1 not shown: stdout %q, stderr %q", c.out.output(), c.errw.output())
	}
	time.Sleep(50 * time.Millisecond)
}

// exitWithin waits at most d for the program to exit; it fails unless
// the program ended with exit code 130 (not by a signal).
func (c *ceremony15n) exitWithin(d time.Duration, what string) time.Duration {
	c.t.Helper()
	start := time.Now()
	if !c.ended(d) {
		c.t.Fatalf("%s: no exit within %v; stdout %q", what, d, tail(c.out.output()))
	}
	took := time.Since(start)
	var ee *exec.ExitError
	switch {
	case c.werr == nil:
		c.t.Fatalf("%s: exit code 0", what)
	case !errors.As(c.werr, &ee):
		c.t.Fatal(c.werr)
	case ee.Sys().(syscall.WaitStatus).Signaled():
		c.t.Fatalf("%s: ended by %v", what, ee.Sys().(syscall.WaitStatus).Signal())
	case ee.ExitCode() != exitAbort:
		c.t.Fatalf("%s: exit code %d; stdout %q, stderr %q", what, ee.ExitCode(), tail(c.out.output()), tail(c.errw.output()))
	}
	return took
}

// ended waits at most d for the program to exit and reports whether it
// did.
func (c *ceremony15n) ended(d time.Duration) bool {
	select {
	case <-c.exited:
		return true
	default:
	}
	select {
	case <-c.exited:
		return true
	case <-time.After(d):
		return false
	}
}

// poll waits at most d until one of conds holds and returns its index,
// or -1.
func poll(d time.Duration, conds ...func() bool) int {
	for deadline := time.Now().Add(d); ; time.Sleep(2 * time.Millisecond) {
		for i, f := range conds {
			if f() {
				return i
			}
		}
		if time.Now().After(deadline) {
			return -1
		}
	}
}

// release lets every terminal run and be read again.
func (c *ceremony15n) release() {
	for _, v := range c.vts {
		setNonblock(c.t, v.s, false)
		v.paused.Store(false)
		restartOutput(v.s.Fd())
	}
	time.Sleep(300 * time.Millisecond)
}

// finalChecks checks the end: no share and no part of one behind the
// last clear of stdout, holder 2 never called (unless holder2), every
// terminal with its modes of before, nothing written.
func (c *ceremony15n) finalChecks(what string, holder2 bool) {
	c.t.Helper()
	screen := c.out.output()
	last := bytes.LastIndex(screen, []byte(clearScreen))
	if last < 0 {
		c.t.Fatalf("%s: stdout never cleared: %q", what, tail(screen))
	}
	if rest := string(screen[last+len(clearScreen):]); rest != "" && rest != "gomail-ceremony: abgebrochen\r\n" &&
		rest != "gomail-ceremony: "+errScreenLost.Error()+"\r\ngomail-ceremony: abgebrochen\r\n" {
		c.t.Fatalf("%s: behind the last clear of stdout %q", what, rest)
	}
	if shareLeft(screen) {
		c.t.Fatalf("%s: share left on stdout: %q", what, tail(screen))
	}
	for k, v := range c.vts {
		if !holder2 && bytes.Contains(v.output(), []byte("Inhaber von Anteil 2")) {
			c.t.Fatalf("%s: holder 2 called on %c: %q", what, k, tail(v.output()))
		}
		if now := v.termios(); now.Iflag != v.before.Iflag || now.Lflag != v.before.Lflag {
			c.t.Fatalf("%s: terminal %c: input modes %#x, local modes %#x after; %#x, %#x before", what, k, now.Iflag, now.Lflag, v.before.Iflag, v.before.Lflag)
		}
	}
	for _, d := range []string{c.outDir, c.kd} {
		if exists(d) {
			c.t.Fatalf("%s: %s written", what, d)
		}
	}
}

func tail(b []byte) string { return string(b[max(0, len(b)-300):]) }

// setNonblock sets or clears O_NONBLOCK on the open file description of
// f, which the program shares (its descriptors are dups of the slave).
func setNonblock(t *testing.T, f *os.File, on bool) {
	t.Helper()
	fl, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFL, 0)
	if e != 0 {
		t.Fatal(e)
	}
	if on {
		fl |= syscall.O_NONBLOCK
	} else {
		fl &^= syscall.O_NONBLOCK
	}
	if _, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_SETFL, fl); e != 0 {
		t.Fatal(e)
	}
}

// TestPTYNonblockClear (task 15n finding 1): share 1 on the screen, then
// another program that shares the open file description of stdout sets
// O_NONBLOCK on it (a job of the same shell in the background) and the
// terminal of stdout takes no more output (nobody reads it). Layouts
// ABA, AAA and ABC.
//
// SIGINT: exit code 130, and once the terminal is read again, share 1 is
// cleared. Before task 15n the clear of the abort path failed at once
// with EAGAIN and counted as done: the share stayed (nonblock.py).
//
// Enter (holder 1 noted the share): the clear does not get through, the
// ceremony takes the abort path (exit code 130, share cleared) and
// holder 2 is never called. Before task 15n the clear failed with EAGAIN,
// wipe ignored it and called holder 2 with share 1 on the screen.
func TestPTYNonblockClear(t *testing.T) {
	w1 := witnessArg(t, "w1")
	for _, layout := range []string{"ABA", "AAA", "ABC"} {
		for _, end := range []string{"SIGINT", "Enter"} {
			t.Run(layout+"/"+end, func(t *testing.T) {
				c := start15n(t, w1, layout)
				c.toShare1()
				setNonblock(t, c.out.s, true)
				t.Logf("filled with %d bytes", c.out.fill())
				limit := 2 * time.Second
				if end == "SIGINT" {
					if err := c.cmd.Process.Signal(syscall.SIGINT); err != nil {
						t.Fatal(err)
					}
				} else {
					c.in.confirm()
					limit = stuckLimit
				}
				took := c.exitWithin(limit, end)
				c.release()
				c.finalChecks(end, false)
				t.Logf("exit 130 %v after %s", took.Round(time.Millisecond), end)
			})
		}
	}
}

// leaveRoom stops reading the master side of v and fills the terminal
// until it takes only room bytes more. The terminal frees its buffer in
// chunks: once it is full, the master side is read until it takes a
// byte again, the size of the chunk freed is taken from a write that
// fills it, and after one more chunk freed the same way the terminal is
// filled up to room bytes.
func (v *vt) leaveRoom(room int) {
	v.t.Helper()
	time.Sleep(100 * time.Millisecond)
	v.paused.Store(true)
	time.Sleep(20 * time.Millisecond)
	fd, err := syscall.Open(v.name, syscall.O_WRONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		v.t.Fatal(err)
	}
	defer syscall.Close(fd)
	for _, size := range []int{256, 1} {
		chunk := bytes.Repeat([]byte("."), size)
		for refused := 0; refused < 20; {
			if _, err := syscall.Write(fd, chunk); errors.Is(err, syscall.EAGAIN) {
				refused++
				time.Sleep(5 * time.Millisecond)
			} else if err != nil {
				v.t.Fatal(err)
			} else {
				refused = 0
			}
		}
	}
	b := make([]byte, 64)
	free := func() {
		for i := 0; i < 1000; i++ {
			if n, _ := syscall.Read(v.mfd, b); n > 0 {
				v.mu.Lock()
				v.buf = append(v.buf, b[:n]...)
				v.mu.Unlock()
			}
			time.Sleep(2 * time.Millisecond)
			if n, _ := syscall.Write(fd, []byte(".")); n == 1 {
				return
			}
		}
		v.t.Fatal("the terminal takes nothing more")
	}
	free()
	n, _ := syscall.Write(fd, bytes.Repeat([]byte("."), 4096))
	chunk := n + 1
	if chunk <= room+1 {
		v.t.Fatalf("chunk of %d bytes", chunk)
	}
	free()
	if n, err := syscall.Write(fd, bytes.Repeat([]byte("."), chunk-1-room)); n != chunk-1-room {
		v.t.Fatalf("filled %d of %d bytes: %v", n, chunk-1-room, err)
	}
	v.t.Logf("room %d of a chunk of %d bytes", room, chunk)
}

// TestPTYPartialShare (task 15n finding 1): the terminal of stdout takes
// only 40 bytes more when holder 1 confirms, so share 1 is written only
// in part. "blocked": the write of the share line waits for room; it
// does not get through within outputGrace, and the ceremony takes the
// abort path. "nonblock": another program sets O_NONBLOCK on stdout
// again and again; the write of the share line ends after its first 40
// bytes with EAGAIN, and the ceremony takes the abort path at once. In
// both cases the part shown counts as shown: exit code 130, and once the
// terminal is read again nothing of the share is behind the last clear;
// holder 1 is not asked whether the share is noted. Before task 15n the
// blocked write held the ceremony (no exit), and after EAGAIN the
// ceremony ended with exit code 1 behind a clear that failed the same
// way, the part of the share on the screen.
func TestPTYPartialShare(t *testing.T) {
	w1 := witnessArg(t, "w1")
	for _, mode := range []string{"blocked", "nonblock"} {
		t.Run(mode, func(t *testing.T) {
			c := start15n(t, w1, "ABA")
			if !c.errw.waitFor(holder1, c.exited) {
				t.Fatalf("exited early: stderr %q", c.errw.output())
			}
			c.out.leaveRoom(40)
			var stop atomic.Bool
			looped := make(chan struct{})
			if mode == "nonblock" {
				go func() {
					defer close(looped)
					for !stop.Load() {
						fl, _, _ := syscall.Syscall(syscall.SYS_FCNTL, c.out.s.Fd(), syscall.F_GETFL, 0)
						syscall.Syscall(syscall.SYS_FCNTL, c.out.s.Fd(), syscall.F_SETFL, fl|syscall.O_NONBLOCK)
					}
				}()
			} else {
				close(looped)
			}
			c.in.confirm()
			took := c.exitWithin(stuckLimit, mode)
			stop.Store(true)
			<-looped
			c.release()
			c.finalChecks(mode, false)
			if bytes.Contains(c.errw.output(), []byte("Anteil notiert")) {
				t.Fatalf("holder 1 asked although the share line failed: %q", tail(c.errw.output()))
			}
			t.Logf("exit 130 %v after Enter; stdout %q", took.Round(time.Millisecond), tail(c.out.output()))
		})
	}
}

// stopLoop stops the output of v (TCOOFF) again and again until stop is
// called or d has passed, as tcooffloop.c of the review does; it runs on
// a thread of its own.
func (v *vt) stopLoop(d time.Duration) (stop func()) {
	var quit atomic.Bool
	done := make(chan struct{})
	fd := v.s.Fd()
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		end := time.Now().Add(d)
		for n := 0; !quit.Load(); n++ {
			syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlFlowCtl, flowOutOff)
			if n%1024 == 0 && time.Now().After(end) {
				return
			}
		}
	}()
	return func() {
		quit.Store(true)
		<-done
	}
}

// TestPTYPromptBlocked (task 15n finding 2a): share 1 on stdout, and the
// terminal of stderr takes the prompt "Anteil notiert?" not: full
// (nobody reads it) or stopped again and again (TCOOFF in a loop, the
// prompt written while it runs). Layouts ABA (stderr with stdin) and ABC
// (stderr a third terminal). The prompt does not get through within
// outputGrace: the abort path clears stdout and ends the program with
// exit code 130, at most outputGrace and the abort path after share 1
// appeared. Before task 15n the prompt held the ceremony in write(2)
// with share 1 on the screen until a signal came (errstop.py: more than
// 5 s).
//
// Should the prompt get through all the same while the loop runs (the
// restart of the output won the race), it is on the screen and the
// ceremony rightly waits: the test then confirms and checks that share 1
// is cleared within the same limit.
func TestPTYPromptBlocked(t *testing.T) {
	w1 := witnessArg(t, "w1")
	for _, layout := range []string{"ABA", "ABC"} {
		for _, attack := range []string{"full", "stopped"} {
			t.Run(layout+"/"+attack, func(t *testing.T) {
				c := start15n(t, w1, layout)
				if !c.errw.waitFor(holder1, c.exited) {
					t.Fatalf("exited early: stderr %q", c.errw.output())
				}
				var stop func()
				if attack == "full" {
					t.Logf("filled with %d bytes", c.errw.fill())
				} else {
					stop = c.errw.stopLoop(30 * time.Second)
					defer stop()
				}
				from := len(c.errw.output())
				c.in.confirm()
				if !c.out.waitFor(shareLine, c.exited) {
					t.Fatalf("share 1 not shown: stdout %q", c.out.output())
				}
				shown := time.Now()
				share := bytes.LastIndex(c.out.output(), []byte("Anteil 1/2"))
				through := false
				switch poll(stuckLimit, func() bool { return c.ended(0) }, func() bool { return confirm1.Match(c.errw.output()[from:]) }) {
				case 0:
					c.exitWithin(0, attack)
					t.Logf("exit 130 %v after share 1 appeared", time.Since(shown).Round(time.Millisecond))
				case 1:
					if attack == "full" {
						t.Fatalf("prompt through a full terminal: %q", tail(c.errw.output()))
					}
					t.Logf("the prompt got through the loop after %v; holder 1 confirms", time.Since(shown).Round(time.Millisecond))
					through = true
					c.in.confirm()
					confirmed := time.Now()
					if poll(stuckLimit, func() bool { return c.ended(0) }, func() bool { return bytes.Contains(c.out.output()[share:], []byte(clearScreen)) }) < 0 {
						t.Fatalf("share 1 neither cleared nor the program ended within %v of the confirmation", stuckLimit)
					}
					t.Logf("share 1 cleared or program ended %v after the confirmation", time.Since(confirmed).Round(time.Millisecond))
					c.cmd.Process.Signal(syscall.SIGINT)
					c.exitWithin(stuckLimit, attack)
				default:
					t.Fatalf("no exit within %v of share 1, prompt not shown; stdout %q", stuckLimit, tail(c.out.output()))
				}
				if stop != nil {
					stop()
				}
				c.release()
				c.finalChecks(attack, through)
			})
		}
	}
}

// TestPTYStopLoop (task 15n finding 2b): share 1 on stdout (layout ABA),
// another program stops the output of stdout again and again (TCOOFF in
// a loop for 2.5 s), and holder 1 confirms. In each of 20 runs the
// clear of share 1 gets through (the output restarted every wakeEvery
// races the loop), or the ceremony takes the abort path after
// outputGrace, whose clear gets through once the loop ends: no run keeps
// share 1 on the screen with the program stuck longer than outputGrace
// and the abort path, and after the loop share 1 is cleared. Before task
// 15n the clear raced the loop once, and lost in 3 of 10 runs: the
// ceremony then hung with share 1 on the screen, also after the loop
// (hold.py).
func TestPTYStopLoop(t *testing.T) {
	w1 := witnessArg(t, "w1")
	const loop = 2500 * time.Millisecond
	var normal, aborted int
	for i := 0; i < 20; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c := start15n(t, w1, "ABA")
			c.toShare1()
			from := bytes.LastIndex(c.out.output(), []byte("Anteil 1/2"))
			stop := c.out.stopLoop(loop)
			defer stop()
			time.Sleep(20 * time.Millisecond)
			c.in.confirm()
			confirmed := time.Now()
			hasClear := func() bool { return bytes.Contains(c.out.output()[from:], []byte(clearScreen)) }
			if poll(stuckLimit, hasClear, func() bool { return c.ended(0) }) < 0 {
				t.Fatalf("share 1 neither cleared nor the program ended within %v", stuckLimit)
			}
			visible := time.Since(confirmed)
			cleared := hasClear()
			stop()
			select {
			case <-c.exited:
				aborted++
			default:
				// The clear got through: holder 2 is called; the test ends
				// the program.
				if !c.errw.until(regexp.MustCompile(`Inhaber von Anteil 2 von 2`), 0, 2*time.Second) {
					t.Fatalf("holder 2 not called after the clear; stderr %q", tail(c.errw.output()))
				}
				normal++
				c.cmd.Process.Signal(syscall.SIGINT)
			}
			c.exitWithin(stuckLimit, "end")
			c.release()
			screen := c.out.output()
			if shareLeft(screen) || !bytes.Contains(screen[from:], []byte(clearScreen)) {
				t.Fatalf("share 1 left after the loop: %q", tail(screen))
			}
			for k, v := range c.vts {
				if now := v.termios(); now.Iflag != v.before.Iflag || now.Lflag != v.before.Lflag {
					t.Fatalf("terminal %c: modes changed", k)
				}
			}
			for _, d := range []string{c.outDir, c.kd} {
				if exists(d) {
					t.Fatalf("%s written", d)
				}
			}
			t.Logf("share 1 visible %v after the confirmation (cleared %v)", visible.Round(time.Millisecond), cleared)
		})
	}
	t.Logf("%d runs cleared in the normal path, %d through the abort path", normal, aborted)
}

// earlyNoted is the prompt "Anteil notiert?" asked again after an input
// that came too early (confirm).
var earlyNoted = regexp.MustCompile(`Eingabe zu früh, bitte erneut bestätigen\.\r\nAnteil notiert\? Eingabetaste löscht den Bildschirm: `)

// enterTwice types Enter on v, and again gap later (measured on the
// clock, not slept: a sleep that short overshoots).
func enterTwice(v *vt, gap time.Duration) {
	v.send("\n")
	for end := time.Now().Add(gap); time.Now().Before(end); {
	}
	v.send("\n")
}

// TestPTYEarlyEnter (task 15n finding 3), with confirmDelay of the
// program (1 s, confirmEnv): holder 1 noted share 1 and presses Enter
// twice, the second 0.2 ms, 1 ms, 50 ms or 500 ms after the first.
// Share 2 does not appear: the prompt for holder 2 is asked again with
// the hint, and only an Enter confirmDelay after that prompt shows share
// 2. Before task 15n a second Enter more than about 0.2 ms after the
// first (after the discard before the prompt) called holder 2 and showed
// share 2 with holder 1 at the screen (dblenter.py).
//
// "holder 1": Enter twice 50 ms apart when holder 1 is called: the
// second does not answer "Anteil notiert?", share 1 stays on the screen
// until holder 1 confirms after confirmDelay.
func TestPTYEarlyEnter(t *testing.T) {
	w1 := witnessArg(t, "w1")
	wait := confirmWait + 300*time.Millisecond
	for _, gap := range []time.Duration{200 * time.Microsecond, time.Millisecond, 50 * time.Millisecond, 500 * time.Millisecond} {
		t.Run(gap.String(), func(t *testing.T) {
			c := start15n(t, w1, "AAA", confirmEnv+"=real")
			a := c.in
			if !a.waitFor(holder1, c.exited) {
				t.Fatalf("exited early: %q", a.output())
			}
			time.Sleep(wait)
			a.send("\n")
			if !a.waitFor(shareLine, c.exited) || !a.waitFor(confirm1, c.exited) {
				t.Fatalf("share 1 not shown: %q", a.output())
			}
			time.Sleep(wait)
			from := len(a.output())
			enterTwice(a, gap)
			if !a.until(earlyPrompt2, from, gap+wait+2*time.Second) {
				t.Fatalf("prompt for holder 2 not asked again: %q", a.output()[from:])
			}
			asked := len(a.output())
			time.Sleep(wait)
			if out := a.output(); bytes.Contains(out[from:], []byte("Anteil 2/2")) {
				t.Fatalf("share 2 shown without a new confirmation: %q", out[from:])
			}
			if n := bytes.Count(a.output()[from:], []byte("Inhaber von Anteil 2")); n != 2 {
				t.Fatalf("holder 2 asked %d times: %q", n, a.output()[from:])
			}
			a.send("\n")
			if !a.until(regexp.MustCompile(`Anteil 2/2: [a-z ]+\r\n`), asked, 3*time.Second) {
				t.Fatalf("share 2 not shown after a confirmation confirmDelay after the prompt: %q", a.output()[asked:])
			}
			c.cmd.Process.Signal(syscall.SIGINT)
			c.exitWithin(2*time.Second, "SIGINT")
			c.release()
			if i := bytes.LastIndex(a.output(), []byte("Anteil 2/2")); !bytes.Contains(a.output()[i:], []byte(clearScreen)) {
				t.Fatalf("share 2 not cleared: %q", tail(a.output()))
			}
		})
	}
	t.Run("holder 1", func(t *testing.T) {
		c := start15n(t, w1, "AAA", confirmEnv+"=real")
		a := c.in
		if !a.waitFor(holder1, c.exited) {
			t.Fatalf("exited early: %q", a.output())
		}
		time.Sleep(wait)
		from := len(a.output())
		enterTwice(a, 50*time.Millisecond)
		if !a.until(earlyNoted, from, wait+2*time.Second) {
			t.Fatalf("prompt \"Anteil notiert?\" not asked again: %q", a.output()[from:])
		}
		time.Sleep(wait)
		out := a.output()
		i := bytes.LastIndex(out, []byte("Anteil 1/2: "))
		if i < from || bytes.Contains(out[i:], []byte(clearScreen)) || bytes.Contains(out[from:], []byte("Inhaber von Anteil 2")) {
			t.Fatalf("share 1 cleared by the second Enter: %q", out[from:])
		}
		asked := len(out)
		a.send("\n")
		if !a.until(regexp.MustCompile(`Inhaber von Anteil 2 von 2`), asked, 3*time.Second) {
			t.Fatalf("holder 2 not called after a confirmation confirmDelay after the prompt: %q", a.output()[asked:])
		}
		if !shareLine.Match(a.output()[from:]) || shareLeft(a.output()) {
			t.Fatalf("share 1 not cleared: %q", tail(a.output()))
		}
		c.cmd.Process.Signal(syscall.SIGINT)
		c.exitWithin(2*time.Second, "SIGINT")
	})
}
