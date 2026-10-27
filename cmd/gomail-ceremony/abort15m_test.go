package main

import (
	"os"
	"os/signal"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Tests of task 15m with the stand-in terminals. The tests on pseudo
// terminals are in abort15m_linux_test.go.

// orderIn is a stand-in stdin that records, among the events of its
// tty, the steps of the abort path on stdin: "flush" (the input
// discarded), "echo-restore" and "flow-restore".
type orderIn struct{ ttyIn }

func (o orderIn) disableEcho() (func() error, error) {
	o.echoOff = true
	return func() error {
		o.echoOff = false
		o.events = append(o.events, "echo-restore")
		return nil
	}, nil
}

func (o orderIn) flushInput() error {
	o.events = append(o.events, "flush")
	return nil
}

// TestAbortStdinAfterClear (task 15m point 1): the abort path clears
// stdout before every step on stdin (input discarded, echo restored)
// and restores the flow control after the clear (task 15b point 0c).
// Before task 15m it discarded the input and restored the echo first; on
// a terminal where a prompt was blocked in a write, the discard
// (TCSETSF) waited for that write, and the clear never came.
func TestAbortStdinAfterClear(t *testing.T) {
	defer signal.Reset(abortSignals...)
	codes := stubExit(t)
	tt := newTTY()
	e := newEnv(orderIn{ttyIn{tt}}, ttyOut{tt}, ttyErr{tt})
	tm, err := e.openTerm()
	if err != nil {
		t.Fatal(err)
	}
	defer signal.Stop(tm.sig)
	if err := tm.echoOff(); err != nil {
		t.Fatal(err)
	}
	tt.events = nil
	tm.sig <- os.Interrupt
	select {
	case code := <-codes:
		if code != exitAbort {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no exit")
	}
	ev := tt.events
	clear := slices.Index(ev, "clear")
	for _, step := range []string{"flush", "echo-restore", "flow-restore"} {
		i := slices.Index(ev, step)
		if i < 0 || clear < 0 || i < clear {
			t.Fatalf("events %q: %s before the clear of stdout", ev, step)
		}
	}
	if tt.echoOff || tt.flowOff {
		t.Fatalf("echo off %v, flow control off %v", tt.echoOff, tt.flowOff)
	}
}

// TestPromptErrorAfterCommit (task 15m point 3): a prompt that fails
// before the commit takes the abort path, whatever the error (EIO,
// EFBIG, ENOSPC, EBADF and EPIPE are in TestPromptLost); once the files
// are written (BeginCommit) or the commit point is passed, a write error
// changes nothing and the ceremony goes on.
func TestPromptErrorAfterCommit(t *testing.T) {
	defer signal.Reset(abortSignals...)
	codes := stubExit(t)
	tt := newTTY()
	lost := &lostErr{ttyErr: ttyErr{tt}, gone: true, other: syscall.EIO}
	e := newEnv(ttyIn{tt}, ttyOut{tt}, lost)
	tm, err := e.openTerm()
	if err != nil {
		t.Fatal(err)
	}
	defer signal.Stop(tm.sig)
	tm.BeginCommit()
	tm.prompt("während des Commits\n")
	if err := tm.CommitPoint(); err != nil {
		t.Fatal(err)
	}
	tm.prompt("nach dem Commit-Punkt\n")
	tm.EndCommit(true)
	tm.prompt("danach\n")
	if err := tm.finish(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-codes:
		t.Fatalf("abort path after the commit: exit code %d", code)
	default:
	}
	if tm.lost {
		t.Fatal("prompt reported lost after the commit")
	}
}

// stuck makes the stand-in terminals hang, once armed: every write and
// every request on stdin (discard, restore of the echo or of the flow
// control) waits forever, as on a terminal whose requests wait for an
// output that never drains.
type stuck struct {
	armed atomic.Bool
	never chan struct{}
}

func (s *stuck) wait() {
	if s.armed.Load() {
		<-s.never
	}
}

type stuckIn struct {
	ttyIn
	s *stuck
}

func (i stuckIn) disableEcho() (func() error, error) {
	r, err := i.ttyIn.disableEcho()
	return func() error { i.s.wait(); return r() }, err
}

func (i stuckIn) disableFlow() (func() error, error) {
	r, err := i.ttyIn.disableFlow()
	return func() error { i.s.wait(); return r() }, err
}

func (i stuckIn) flushInput() error { i.s.wait(); return i.ttyIn.flushInput() }

type stuckOut struct {
	ttyOut
	s *stuck
}

func (o stuckOut) Write(p []byte) (int, error) { o.s.wait(); return o.ttyOut.Write(p) }

type stuckErr struct {
	ttyErr
	s *stuck
}

func (e stuckErr) Write(p []byte) (int, error) { e.s.wait(); return e.ttyErr.Write(p) }

// TestAbortBounded (task 15m point 1): every step of the abort path is
// bounded and the whole path ends within 2 s, even when every write and
// every request on stdin hangs and a prompt holds t.out. Before task
// 15m the input was discarded and the echo restored without a bound,
// and the abort path hung.
func TestAbortBounded(t *testing.T) {
	defer signal.Reset(abortSignals...)
	codes := stubExit(t)
	tt := newTTY()
	s := &stuck{never: make(chan struct{})}
	e := newEnv(stuckIn{ttyIn{tt}, s}, stuckOut{ttyOut{tt}, s}, stuckErr{ttyErr{tt}, s})
	tm, err := e.openTerm()
	if err != nil {
		t.Fatal(err)
	}
	defer signal.Stop(tm.sig)
	if err := tm.echoOff(); err != nil {
		t.Fatal(err)
	}
	s.armed.Store(true)
	go tm.prompt("Anteil notiert? ")
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	tm.sig <- os.Interrupt
	select {
	case code := <-codes:
		if code != exitAbort {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the abort path hangs")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("abort path took %v", took)
	} else {
		t.Logf("abort path ended after %v", took.Round(time.Millisecond))
	}
}
