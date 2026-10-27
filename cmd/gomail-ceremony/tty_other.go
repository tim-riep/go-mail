//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly) || ceremony_notty

package main

import (
	"errors"
	"os"
	"syscall"
)

// On these systems (and in a build with the tag ceremony_notty, which
// the tests use to run this file on Linux) the terminal attributes
// cannot be read or written with syscall. isTerminalFd is always false,
// so every command that shows or reads shares (init, reshare,
// ingest-rotate, succeed) refuses with errNoTerminal before it shows,
// reads or writes anything (checkTerminal, task 10c finding 1).

// abortSignals are the signals of the abort path of term; it is never
// reached here (no command gets that far), the list only keeps the
// program portable.
var abortSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

// brokenPipe is taken in from the start of run until the program exits
// (task 15m point 4), as on the systems of tty_unix.go: the refusal of
// a command on a standard error without a reader fails with EPIPE
// instead of ending the program by SIGPIPE before its exit code (where
// there is no SIGPIPE, the notification never fires).
var brokenPipe = []os.Signal{syscall.SIGPIPE}

// isTerminalFd reports false: no file is a terminal here.
func isTerminalFd(uintptr) bool { return false }

// disableEcho is unreachable: checkTerminal refuses first because
// isTerminalFd is false. Should it ever be called, it fails closed.
func disableEcho(uintptr) (func() error, error) {
	return nil, errors.New("echo cannot be switched off on this system")
}

// disableFlow is unreachable as disableEcho is; it fails closed.
func disableFlow(uintptr) (func() error, error) {
	return nil, errors.New("flow control cannot be switched off on this system")
}

// wakeOutput is unreachable as disableEcho is; it fails closed.
func wakeOutput(uintptr, bool) error {
	return errors.New("the output cannot be restarted on this system")
}

// flushInput is unreachable as disableEcho is; it fails closed.
func flushInput(uintptr) error {
	return errors.New("input cannot be discarded on this system")
}

// blockingOutput is unreachable as disableEcho is; it fails closed.
func blockingOutput(uintptr) error {
	return errors.New("O_NONBLOCK cannot be cleared on this system")
}

// inputPending is unreachable as disableEcho is; it fails closed.
func inputPending(uintptr) (int, error) {
	return 0, errors.New("input cannot be counted on this system")
}

// stderrFile passes every standard error: checkTerminal refuses next,
// because no file is a terminal here (task 15l point 2 needs fstat).
func stderrFile(uintptr) error { return nil }

// disableFlowOut is unreachable as disableEcho is; it fails closed.
func disableFlowOut(uintptr) (func() error, error) {
	return nil, errors.New("flow control cannot be switched off on this system")
}

// sameTerminal is unreachable (no file is a terminal here); it reports
// true, so that the flow control of stdout is never switched.
func sameTerminal(uintptr, uintptr) bool { return true }
