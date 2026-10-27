package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Tests of task 15i with the stand-in terminals: standard error loses
// its reader (EPIPE) while a ceremony runs. The tests on a pseudo
// terminal, with a real pipe and SIGPIPE, are in
// sigpipe15i_linux_test.go.

// lostErr is stderr in a pipe whose reader goes away: every write fails
// with EPIPE, as os.File reports it, once gone is set, and gone is set
// by the first write that holds after (that write still reaches the
// stand-in and is answered). With other set, the writes fail with other
// instead of EPIPE (task 15m point 3: EIO, EFBIG, ENOSPC, EBADF).
type lostErr struct {
	ttyErr
	after string
	gone  bool
	other error
}

func (l *lostErr) Write(p []byte) (int, error) {
	if l.gone {
		err := l.other
		if err == nil {
			err = syscall.EPIPE
		}
		return 0, &os.PathError{Op: "write", Path: "/dev/stderr", Err: err}
	}
	n, err := l.ttyErr.Write(p)
	if strings.Contains(string(p), l.after) {
		l.gone = true
	}
	return n, err
}

// lostTail is what the abort path writes behind its last clear when a
// prompt was lost: on stdout, because stderr takes nothing.
var lostTail = "gomail-ceremony: " + errPromptLost.Error() + "\ngomail-ceremony: abgebrochen\n"

// TestPromptLost (task 15i, task 15m point 3): a prompt that fails, with
// EPIPE or any other write error, ends the ceremony through the abort
// path at once, before it waits for an answer and before another share
// is shown: exit code 130, every share shown cleared, the echo and the
// flow control restored, nothing written, the reason on stdout behind
// the last clear. Before task 15m another write error than EPIPE was
// ignored, and the ceremony went on behind prompts nobody saw.
func TestPromptLost(t *testing.T) {
	fixClock(t)
	w1 := witnessArg(t, "w1")
	for _, tc := range []struct {
		name   string
		err    *lostErr
		shares int // shares shown before the abort
	}{
		{"start", &lostErr{gone: true}, 0},
		{"holder 1", &lostErr{after: "Inhaber von Anteil 1 von"}, 1},
		{"holder 2", &lostErr{after: "Inhaber von Anteil 2 von"}, 2},
		{"share input", &lostErr{after: "Anteil Nr."}, 2},
		{"EIO at the start", &lostErr{gone: true, other: syscall.EIO}, 0},
		{"EFBIG holder 1", &lostErr{after: "Inhaber von Anteil 1 von", other: syscall.EFBIG}, 1},
		{"EBADF holder 2", &lostErr{after: "Inhaber von Anteil 2 von", other: syscall.EBADF}, 2},
		{"ENOSPC share input", &lostErr{after: "Anteil Nr.", other: syscall.ENOSPC}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer signal.Reset(abortSignals...)
			codes := stubExit(t)
			base := t.TempDir()
			out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
			tt := newTTY()
			tc.err.ttyErr = ttyErr{tt}
			atStart := tc.err.gone
			done := make(chan int, 1)
			go func() {
				done <- run([]string{"init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1"},
					ttyIn{tt}, ttyOut{tt}, tc.err)
			}()
			var code int
			select {
			case code = <-codes:
			case code = <-done:
			}
			if tt.echoOff || tt.flowOff {
				t.Fatalf("echo off %v, flow control off %v", tt.echoOff, tt.flowOff)
			}
			if len(tt.shares) != tc.shares {
				t.Fatalf("%d shares shown, want %d", len(tt.shares), tc.shares)
			}
			checkScreen(t, tt.screen.String(), shareLines(tt.shares), 1)
			screen := tt.out.String()
			tail := screen[strings.LastIndex(screen, clearScreen)+len(clearScreen):]
			if code != exitAbort {
				t.Fatalf("exit code %d\n%q", code, tt.screen.String())
			}
			if tail != lostTail {
				t.Fatalf("behind the last clear %q, want %q", tail, lostTail)
			}
			for _, d := range []string{out, kd} {
				if _, err := os.Lstat(d); err == nil {
					t.Fatalf("%s written", d)
				}
			}
			// No holder was called whom nobody saw called: the prompt that
			// failed is the last one, and no input was read after it.
			if atStart && tt.reads != 0 {
				t.Fatalf("%d reads from stdin", tt.reads)
			}
		})
	}
}

// TestPromptAfterAbort (task 15i, found by TestPTYSignalSalvo once the
// prompts went through prompt): the ceremony goes on in its own
// goroutine while the abort path runs, and a prompt written then landed
// behind "abgebrochen" ("(12 von 30 Wörtern)"). Once the abort path
// runs, a prompt writes nothing.
func TestPromptAfterAbort(t *testing.T) {
	codes := stubExit(t)
	in := newTTY()
	e := newEnv(ttyIn{in}, ttyOut{in}, ttyErr{in})
	tm, err := e.openTerm()
	if err != nil {
		t.Fatal(err)
	}
	defer signal.Stop(tm.sig)
	tm.sig <- os.Interrupt
	if code := <-codes; code != exitAbort {
		t.Fatalf("exit code %d", code)
	}
	before := in.msgs.String()
	if !strings.HasSuffix(before, "gomail-ceremony: abgebrochen\n") {
		t.Fatalf("stderr %q", before)
	}
	written := make(chan struct{})
	go func() {
		defer close(written)
		tm.prompt("(%d von %d Wörtern)\n", 12, 30)
	}()
	select {
	case <-written:
		if got := in.msgs.String(); got != before {
			t.Fatalf("prompt written after the abort: %q", got[len(before):])
		}
	case <-time.After(200 * time.Millisecond):
		// The prompt waits for t.out, which the abort path keeps until
		// the exit: nothing is written.
	}
}
