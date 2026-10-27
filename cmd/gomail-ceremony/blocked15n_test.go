package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Tests of task 15n with the stand-in terminals. The tests on pseudo
// terminals are in blocked15n_linux_test.go.

// screenOut is stdout of the stand-in terminal with a fault once share 1
// is on it: writes that hold what (clearScreen, or the share line) fail
// fails times, each after a part of them is written, with EAGAIN as
// os.File reports it (a terminal behind an O_NONBLOCK set by another
// program); with block they wait forever instead (a terminal stopped or
// full).
type screenOut struct {
	ttyOut
	mu      sync.Mutex
	what    string
	fails   int
	block   bool
	armed   bool
	written int // writes of what that failed or wait
}

func (o *screenOut) Write(p []byte) (int, error) {
	o.mu.Lock()
	if strings.Contains(string(p), "Anteil 1/2") && o.what == clearScreen {
		o.armed = true
		o.mu.Unlock()
		return o.ttyOut.Write(p)
	}
	if !strings.Contains(string(p), o.what) || (o.what != clearScreen && !strings.Contains(string(p), "Anteil 1/2")) {
		o.mu.Unlock()
		return o.ttyOut.Write(p)
	}
	if o.what == clearScreen && !o.armed {
		o.mu.Unlock()
		return o.ttyOut.Write(p)
	}
	if o.block {
		o.written++
		o.mu.Unlock()
		select {}
	}
	if o.fails > 0 {
		o.fails--
		o.written++
		o.mu.Unlock()
		n, _ := o.ttyOut.Write(p[:len(p)/2])
		return n, &os.PathError{Op: "write", Path: "/dev/stdout", Err: syscall.EAGAIN}
	}
	o.mu.Unlock()
	return o.ttyOut.Write(p)
}

// runInit runs init 2-of-2 on the stand-ins with exit stubbed and
// returns the exit code, from the abort path or from run.
func runInit(t *testing.T, tt *tty, out, errw interface {
	Write([]byte) (int, error)
}) int {
	t.Helper()
	defer signal.Reset(abortSignals...)
	codes := stubExit(t)
	base := t.TempDir()
	done := make(chan int, 1)
	w1 := witnessArg(t, "w1")
	go func() {
		done <- run([]string{"init", "--shares", "2-of-2", "--out", filepath.Join(base, "out"), "--keys", filepath.Join(base, "keys"),
			"--origin", "o", "--witness", w1, "--min-witnesses", "1"}, ttyIn{tt}, out, errw)
	}()
	select {
	case code := <-codes:
		return code
	case code := <-done:
		return code
	case <-time.After(outputGrace + 10*time.Second):
		t.Fatal("init hangs")
	}
	return 0
}

// TestClearFails (task 15n finding 1): the clear of share 1 in the
// normal path fails three times with a part written and EAGAIN. The
// ceremony takes the abort path at once: holder 2 is never called, the
// abort path writes the clear again until it gets through, exit code
// 130, the reason on stderr. Before task 15n wipe ignored the error and
// called holder 2 with share 1 on the screen.
func TestClearFails(t *testing.T) {
	fixClock(t)
	tt := newTTY()
	out := &screenOut{ttyOut: ttyOut{tt}, what: clearScreen, fails: 3}
	if code := runInit(t, tt, out, ttyErr{tt}); code != exitAbort {
		t.Fatalf("exit code %d\n%q", code, tt.screen.String())
	}
	if strings.Contains(tt.msgs.String(), "Inhaber von Anteil 2") {
		t.Fatalf("holder 2 called: %q", tt.msgs.String())
	}
	screen := tt.out.String()
	if i := strings.LastIndex(screen, "Anteil 1/2"); i < 0 || !strings.HasSuffix(screen, clearScreen) {
		t.Fatalf("stdout %q", screen)
	}
	if want := "gomail-ceremony: " + errScreenLost.Error() + "\ngomail-ceremony: abgebrochen\n"; !strings.HasSuffix(tt.msgs.String(), want) {
		t.Fatalf("stderr %q", tt.msgs.String())
	}
	if out.written != 3 || tt.echoOff || tt.flowOff {
		t.Fatalf("%d clears failed; echo off %v, flow control off %v", out.written, tt.echoOff, tt.flowOff)
	}
}

// TestShareLineFails (task 15n finding 1): the share line fails after
// half of it is written (EAGAIN). The part shown counts as shown: the
// abort path clears it, exit code 130, holder 1 is not asked whether it
// is noted. Before task 15n the ceremony failed (exit code 1) behind a
// clear that did not reach a terminal behind O_NONBLOCK either.
func TestShareLineFails(t *testing.T) {
	fixClock(t)
	tt := newTTY()
	out := &screenOut{ttyOut: ttyOut{tt}, what: "Anteil 1/2", fails: 1}
	if code := runInit(t, tt, out, ttyErr{tt}); code != exitAbort {
		t.Fatalf("exit code %d\n%q", code, tt.screen.String())
	}
	screen := tt.out.String()
	if i := strings.LastIndex(screen, "Anteil 1/2"); i < 0 || !strings.Contains(screen[i:], clearScreen) {
		t.Fatalf("part of share 1 not cleared: %q", screen)
	}
	if strings.Contains(tt.msgs.String(), "Anteil notiert") {
		t.Fatalf("holder 1 asked: %q", tt.msgs.String())
	}
}

// blockedErr is stderr of the stand-in terminal whose write of the
// prompt "Anteil notiert?" waits forever (a terminal stopped or full).
type blockedErr struct{ ttyErr }

func (e blockedErr) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "Anteil notiert?") {
		select {}
	}
	return e.ttyErr.Write(p)
}

// slowScreen is stdout (out) and stderr (!out) of the stand-in terminal
// tt that take their time over share 1 and over the prompt "Anteil
// notiert?": each write returns after three quarters of outputGrace,
// which alone is below it. The writes to tt are serialized (the slow
// prompt is still written while the abort path writes), and busy counts
// the slow writes still running.
type slowScreen struct {
	tt   *tty
	out  bool
	mu   *sync.Mutex
	busy *atomic.Int32
}

// terminal makes it a stand-in terminal for stdout (isTerminal).
func (s *slowScreen) terminal() bool { return true }

func (s *slowScreen) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "Anteil 1/2") || strings.Contains(string(p), "Anteil notiert?") {
		s.busy.Add(1)
		defer s.busy.Add(-1)
		time.Sleep(outputGrace * 3 / 4)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.out {
		return ttyOut{s.tt}.Write(p)
	}
	return ttyErr{s.tt}.Write(p)
}

// TestStuckWithShare (task 15n finding 2): share 1 on the screen, and
// the prompt "Anteil notiert?" or the clear after it does not return
// ("prompt", "clear"), or share 1 and that prompt each take three
// quarters of outputGrace ("slow"). The ceremony takes the abort path
// once outputGrace has passed since share 1 was written: exit code 130
// within outputGrace and the abort path (2 s), holder 2 never called;
// the clear of stdout comes when the prompt is stuck or slow (the clear
// that does not return is the last limit). Before task 15n the program
// waited with share 1 on the screen until a signal came.
func TestStuckWithShare(t *testing.T) {
	fixClock(t)
	for _, tc := range []string{"prompt", "clear", "slow"} {
		t.Run(tc, func(t *testing.T) {
			tt := newTTY()
			var out interface{ Write([]byte) (int, error) } = ttyOut{tt}
			var errw interface{ Write([]byte) (int, error) } = blockedErr{ttyErr{tt}}
			var mu sync.Mutex
			var busy atomic.Int32
			switch tc {
			case "clear":
				out, errw = &screenOut{ttyOut: ttyOut{tt}, what: clearScreen, block: true}, ttyErr{tt}
			case "slow":
				out, errw = &slowScreen{tt, true, &mu, &busy}, &slowScreen{tt, false, &mu, &busy}
			}
			start := time.Now()
			code := runInit(t, tt, out, errw)
			took := time.Since(start)
			// The slow prompt is written after the abort path ran.
			for time.Sleep(10 * time.Millisecond); busy.Load() != 0; time.Sleep(10 * time.Millisecond) {
			}
			mu.Lock()
			defer mu.Unlock()
			if code != exitAbort {
				t.Fatalf("exit code %d\n%q", code, tt.screen.String())
			}
			if took > outputGrace+2*time.Second+500*time.Millisecond {
				t.Fatalf("exit after %v", took)
			}
			if strings.Contains(tt.msgs.String(), "Inhaber von Anteil 2") {
				t.Fatalf("holder 2 called: %q", tt.msgs.String())
			}
			if screen := tt.out.String(); tc != "clear" && !strings.HasSuffix(screen, clearScreen) {
				t.Fatalf("stdout %q", screen)
			}
			t.Logf("exit 130 after %v", took.Round(time.Millisecond))
		})
	}
}

// TestConfirmEarly (task 15n finding 3): an Enter already there when a
// holder is called, or when holder 1 is asked whether share 1 is noted,
// is discarded, and the prompt is asked again with the hint; the Enter
// that comes after confirmDelay counts. Before task 15n Handover
// discarded the input only before its prompt, and settle not at all.
func TestConfirmEarly(t *testing.T) {
	defer signal.Reset(abortSignals...)
	tt := newTTY()
	e := newEnv(ttyIn{tt}, ttyOut{tt}, ttyErr{tt})
	tm, err := e.openTerm()
	if err != nil {
		t.Fatal(err)
	}
	defer signal.Stop(tm.sig)
	tt.in.WriteString("\n")
	if err := tm.Handover(1, 2); err != nil {
		t.Fatal(err)
	}
	display{tm}.Write([]byte("Anteil 1/2: abandon ability able\n"))
	tt.in.WriteString("\n")
	if err := tm.Handover(2, 2); err != nil {
		t.Fatal(err)
	}
	want := "Inhaber von Anteil 1 von 2 an den Bildschirm, dann Eingabetaste: " +
		earlyHint + "Inhaber von Anteil 1 von 2 an den Bildschirm, dann Eingabetaste: " +
		"Anteil notiert? Eingabetaste löscht den Bildschirm: " +
		earlyHint + "Anteil notiert? Eingabetaste löscht den Bildschirm: " +
		"Inhaber von Anteil 2 von 2 an den Bildschirm, dann Eingabetaste: "
	if got := tt.msgs.String(); got != want {
		t.Fatalf("prompts %q, want %q", got, want)
	}
	if got := strings.Join(tt.events, " "); got != "clear prompt input share confirm input clear prompt input" {
		t.Fatalf("events %q", got)
	}
	if err := tm.finish(nil); err != nil {
		t.Fatal(err)
	}
}
