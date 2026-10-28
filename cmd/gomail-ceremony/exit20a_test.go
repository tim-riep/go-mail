package main

import (
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"testing"
	"time"
)

// TestWakingStop (task 20a point 3): the function that waking returns
// returns only once its goroutine has ended, also while a restart of
// the output is running; no restart comes after it. Before, it only
// closed the channel, and a restart (on Linux TCOOFF, then TCOON) could
// run on past the last step of the abort path and the exit.
func TestWakingStop(t *testing.T) {
	var running, calls atomic.Int32
	entered := make(chan struct{}, 1)
	wake := func(bool) error {
		running.Store(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		time.Sleep(30 * time.Millisecond)
		calls.Add(1)
		running.Store(0)
		return nil
	}
	stop := waking(nil, wake)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("no restart")
	}
	stop()
	if running.Load() != 0 {
		t.Fatal("stop returned while a restart was running")
	}
	n := calls.Load()
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != n || running.Load() != 0 {
		t.Fatal("a restart after stop")
	}
	// Without a terminal there is no goroutine, and stop returns.
	waking(nil, nil)()
}

// TestAbortEndsWaking (task 20a point 3): the abort path ends every
// goroutine of waking of the term before the exit (stopWaking), also
// the one of a write of the command that is still blocked (push, whose
// outputGrace runs longer than the abort path); no restart of the
// output (on Linux TCOOFF, then TCOON) comes after the exit. Before, the
// goroutine of push ran on until outputGrace was up and could leave the
// terminal stopped at the exit.
func TestAbortEndsWaking(t *testing.T) {
	e := newEnv(ttyIn{newTTY()}, &lockedBuffer{}, io.Discard)
	codes := stubExit(t)
	tm := e.newTerm()
	defer signal.Stop(tm.sig)
	var calls atomic.Int64
	wake := func(bool) error {
		calls.Add(1)
		return nil
	}
	tm.outWake = wake
	release := make(chan struct{})
	pushed := make(chan error, 1)
	tm.out <- struct{}{}
	go func() {
		pushed <- tm.push(time.Now().Add(time.Hour), func() error {
			<-release
			return nil
		}, wake)
	}()
	for deadline := time.Now().Add(10 * time.Second); calls.Load() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no restart while the write is blocked")
		}
	}
	tm.sig <- os.Interrupt
	select {
	case code := <-codes:
		if code != exitAbort {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the abort path does not end")
	}
	n := calls.Load()
	time.Sleep(50 * time.Millisecond)
	if m := calls.Load(); m != n {
		t.Fatalf("%d restarts of the output after the exit", m-n)
	}
	// After the abort path no goroutine of waking starts.
	stop := tm.waking(wake)
	time.Sleep(20 * time.Millisecond)
	stop()
	if m := calls.Load(); m != n {
		t.Fatalf("%d restarts of the output by a waking after the abort path", m-n)
	}
	close(release)
	if err := <-pushed; err != nil {
		t.Fatal(err)
	}
}
