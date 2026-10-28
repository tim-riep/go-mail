//go:build linux && !ceremony_notty

package main

import (
	"bytes"
	"errors"
	"regexp"
	"syscall"
	"testing"
	"time"
)

// outputStopped reports whether the output of the terminal v is
// stopped: a write of one byte through a description of its own with
// O_NONBLOCK is refused (EAGAIN) again and again, although the master
// side is read.
func outputStopped(t *testing.T, v *vt) bool {
	t.Helper()
	fd, err := syscall.Open(v.name, syscall.O_WRONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	for i := 0; i < 50; i++ {
		n, err := syscall.Write(fd, []byte("."))
		if n == 1 {
			return false
		}
		if !errors.Is(err, syscall.EAGAIN) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

// TestPTYExitNotStopped (task 20a point 3): the abort path ends with a
// restart of the output of stdout and stderr (resume: TCOON alone), so
// that no terminal is left stopped at the exit. The hook stop-at-exit
// stops both (TCOOFF) during the abort path, after the clears, as a
// restart of the program (TCOOFF, then TCOON) would that runs late,
// before the goroutines of waking were waited for. Layouts AAA (one
// terminal) and ABC (stdout and stderr each a terminal of their own).
func TestPTYExitNotStopped(t *testing.T) {
	w1 := witnessArg(t, "w1")
	for _, layout := range []string{"AAA", "ABC"} {
		t.Run(layout, func(t *testing.T) {
			c := start15n(t, w1, layout, hookEnv+"=stop-at-exit")
			if !c.errw.waitFor(holder1, c.exited) {
				t.Fatalf("exited early: stderr %q", c.errw.output())
			}
			if err := c.cmd.Process.Signal(syscall.SIGINT); err != nil {
				t.Fatal(err)
			}
			took := c.exitWithin(stuckLimit, "SIGINT")
			time.Sleep(100 * time.Millisecond) // the poller reads the rest
			c.finalChecks("SIGINT", false)
			// The probe writes a byte to each terminal: after the
			// checks of the screen.
			for _, v := range []*vt{c.out, c.errw} {
				if outputStopped(t, v) {
					t.Fatalf("terminal %s left stopped at the exit", v.name)
				}
			}
			t.Logf("exit 130 %v after SIGINT", took.Round(time.Millisecond))
		})
	}
}

// TestPTYUnblockBrief (task 20a point 7, task 15n finding 1): another
// program that shares the open file description of stdout set
// O_NONBLOCK on it, and the terminal of stdout takes nothing for a
// moment when holder 1 confirms (nobody reads it for 300 ms; nothing is
// discarded). The program clears O_NONBLOCK before the share line
// (unblock), its write waits until the terminal takes it again, and the
// normal path goes on: share 1 shown, noted, cleared, holder 2 called,
// no abort. With unblock a no-op, the share line fails at once with
// EAGAIN and the ceremony takes the abort path.
//
// The terminal is filled instead of stopped by a single TCOOFF: the
// program restarts the output of stdout before every share line and
// every clear (outWake: TCOOFF, then TCOON), so that a single TCOOFF
// before the write never makes it fail, with O_NONBLOCK or without.
func TestPTYUnblockBrief(t *testing.T) {
	w1 := witnessArg(t, "w1")
	c := start15n(t, w1, "ABA")
	if !c.errw.waitFor(holder1, c.exited) {
		t.Fatalf("exited early: stderr %q", c.errw.output())
	}
	setNonblock(t, c.out.s, true)
	t.Logf("filled with %d bytes", c.out.fill())
	from := len(c.errw.output())
	c.in.confirm()
	time.Sleep(300 * time.Millisecond)
	c.out.paused.Store(false)
	if !c.errw.until(confirm1, from, stuckLimit) {
		t.Fatalf("holder 1 not asked whether share 1 is noted: stderr %q", tail(c.errw.output()[from:]))
	}
	// The poller of stdout, paused until now, may show the share line a
	// moment after the prompt on the other terminal.
	if poll(2*time.Second, func() bool { return shareLine.Match(c.out.output()) }) < 0 {
		t.Fatalf("share 1 not shown: stdout %q", tail(c.out.output()))
	}
	from = len(c.errw.output())
	c.in.confirm()
	if !c.errw.until(regexp.MustCompile(`Inhaber von Anteil 2 von 2`), from, stuckLimit) {
		t.Fatalf("holder 2 not called: stderr %q", tail(c.errw.output()[from:]))
	}
	// The clear of stdout was written before holder 2 was called; the
	// poller of the other terminal may show it a moment later.
	if poll(2*time.Second, func() bool { return !shareLeft(c.out.output()) }) < 0 {
		t.Fatalf("share 1 left on stdout: %q", tail(c.out.output()))
	}
	if out := c.errw.output(); bytes.Contains(out, []byte("abgebrochen")) || bytes.Contains(out, []byte(errScreenLost.Error())) {
		t.Fatalf("abort path: stderr %q", tail(out))
	}
	if err := c.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	c.exitWithin(stuckLimit, "SIGINT")
	c.release()
	c.finalChecks("SIGINT", true)
}
