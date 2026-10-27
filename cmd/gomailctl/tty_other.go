//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

import (
	"errors"
	"os"
)

// On these systems the terminal attributes cannot be read with syscall:
// isTerminalFd is always false, so keygen refuses before it shows or
// reads anything (errNoTerminal), and seed and share words are read
// only from a file or a pipe, without the screen handling.

var abortSignals = []os.Signal{os.Interrupt}

// brokenPipe is empty: a write to a broken pipe fails with an error.
var brokenPipe []os.Signal

func sameControlling(uintptr, uintptr) bool { return false }

func isTerminalFd(uintptr) bool { return false }

func isPtyMaster(uintptr) bool { return false }

func terminalID(uintptr) (uint64, bool) { return 0, false }

func disableEcho(uintptr) (func() error, error) {
	return nil, errors.New("echo cannot be switched off on this system")
}

func disableFlow(uintptr) (func() error, error) {
	return nil, errors.New("flow control cannot be switched off on this system")
}

func flushInput(uintptr) error {
	return errors.New("input cannot be discarded on this system")
}
