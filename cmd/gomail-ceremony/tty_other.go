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

// flushInput is unreachable as disableEcho is; it fails closed.
func flushInput(uintptr) error {
	return errors.New("input cannot be discarded on this system")
}
