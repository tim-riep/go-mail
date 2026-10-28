//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// Terminal control for the screen of shares and seed words (screen.go),
// the subset of gomail-ceremony's tty_unix.go that gomailctl needs:
// whether a file is a terminal and which one, switching off the echo of
// standard input and the software flow control of standard output, and
// discarding input typed ahead.

// abortSignals end the program while a share or seed words may be on
// the screen: the echo and the flow control are restored and the screen
// is cleared first (screen.abort), as in gomail-ceremony:
//
//   - SIGINT, SIGTERM, SIGHUP and SIGQUIT;
//   - SIGTSTP: a command showing a share or the seed is not suspended
//     with it on the screen, a stop request ends it;
//   - SIGABRT, SIGILL, SIGTRAP, SIGBUS, SIGFPE, SIGSEGV and SIGSYS when
//     sent with kill: unhandled, the runtime would end the program with
//     a stack trace on the terminal, the echo off and the screen as it
//     is. A real fault is still a run-time panic.
var abortSignals = []os.Signal{
	os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT,
	syscall.SIGTSTP,
	syscall.SIGABRT, syscall.SIGILL, syscall.SIGTRAP, syscall.SIGBUS, syscall.SIGFPE, syscall.SIGSEGV, syscall.SIGSYS,
}

// brokenPipe is taken over for the whole run of gomailctl
// (relayBrokenPipe in screen.go, task 13d finding 2): a write to a pipe
// without a reader fails with EPIPE instead of ending the program.
var brokenPipe = []os.Signal{syscall.SIGPIPE}

func ioctl(fd, req uintptr, arg unsafe.Pointer) error {
	for {
		_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg))
		switch e {
		case 0:
			return nil
		case syscall.EINTR:
			continue
		}
		return e
	}
}

// isTerminalFd reports whether fd is a terminal of the user: whether
// its terminal attributes can be read and it is not the master side of
// a pseudo terminal (task 13d finding 1). A master answers the requests
// for the attributes for its slave, but what is written to it is the
// input of the slave (read by the program there, echoed on its screen),
// and what is read from it is the output of the slave: the seed written
// to it would land in the input of the shell on the other side, and the
// clear of the screen would be typed there literally.
func isTerminalFd(fd uintptr) bool {
	var t syscall.Termios
	return ioctl(fd, ioctlGetTermios, unsafe.Pointer(&t)) == nil && !isPtyMaster(fd)
}

// flowFlags are the input modes of software flow control. Cleared, a
// Ctrl-S (XOFF) cannot stop the output of the terminal while a share is
// on the screen, so that the clear of the screen and the abort path
// never block behind it (gomail-ceremony, task 10e finding 1).
const flowFlags = syscall.IXON | syscall.IXOFF | syscall.IXANY

// errEchoStays reports a terminal that keeps ECHO set after it was
// cleared.
var errEchoStays = errors.New("ECHO bleibt gesetzt")

// errFlowStays reports a terminal that keeps IXON, IXOFF or IXANY set
// after they were cleared.
var errFlowStays = errors.New("IXON, IXOFF oder IXANY bleibt gesetzt")

// quietFlags are the local modes cleared while seed or share words are
// typed: ECHO, so that the terminal does not show them. Unlike
// gomail-ceremony, ISIG stays set: gomailctl has no commit that defers
// a signal, and every signal the keyboard raises (Ctrl-C, Ctrl-\,
// Ctrl-Z) is among abortSignals, so it ends the command at once through
// the abort path (echo restored, screen cleared, exit code 130).
const quietFlags = syscall.ECHO

// disableEcho clears quietFlags on the terminal fd, reads the attributes
// back (errEchoStays if ECHO stays set, with the old attributes
// restored) and returns the function that restores the attributes read
// before. The restore discards the input received and not read yet in
// the same request (ioctlSetTermiosFlush): words typed while the echo
// was off and not yet read when it comes back (an abort in the middle
// of the input) would be echoed then.
func disableEcho(fd uintptr) (func() error, error) {
	return clearModes(fd, func(t *syscall.Termios) { t.Lflag &^= quietFlags },
		func(t *syscall.Termios) bool { return t.Lflag&quietFlags != 0 }, errEchoStays, ioctlSetTermiosFlush)
}

// disableFlow clears flowFlags on the terminal fd, reads the attributes
// back (errFlowStays if a flag stays set, with the old attributes
// restored) and returns the function that restores the attributes read
// before.
func disableFlow(fd uintptr) (func() error, error) {
	return clearModes(fd, func(t *syscall.Termios) { t.Iflag &^= flowFlags },
		func(t *syscall.Termios) bool { return t.Iflag&flowFlags != 0 }, errFlowStays, ioctlSetTermios)
}

// clearModes applies off to the attributes of the terminal fd, reads
// them back and fails with stays (the old attributes restored) when set
// still reports a mode set; otherwise it returns the function that
// restores the attributes read before with the request restoreReq.
func clearModes(fd uintptr, off func(*syscall.Termios), set func(*syscall.Termios) bool, stays error, restoreReq uintptr) (func() error, error) {
	var old syscall.Termios
	if err := ioctl(fd, ioctlGetTermios, unsafe.Pointer(&old)); err != nil {
		return nil, err
	}
	t := old
	off(&t)
	if err := ioctl(fd, ioctlSetTermios, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	restore := func() error { return ioctl(fd, restoreReq, unsafe.Pointer(&old)) }
	var now syscall.Termios
	err := ioctl(fd, ioctlGetTermios, unsafe.Pointer(&now))
	if err == nil && set(&now) {
		err = stays
	}
	if err != nil {
		restore()
		return nil, err
	}
	return restore, nil
}

// flushInput discards the input that the terminal fd received and the
// program has not read yet: the attributes are set again unchanged with
// ioctlSetTermiosFlush, which discards the input queue first.
func flushInput(fd uintptr) error {
	var t syscall.Termios
	if err := ioctl(fd, ioctlGetTermios, unsafe.Pointer(&t)); err != nil {
		return err
	}
	return ioctl(fd, ioctlSetTermiosFlush, unsafe.Pointer(&t))
}

// terminalID identifies the terminal fd: its device number (fstat
// st_rdev) and the device of the file system of its node (st_dev,
// termID); ok is false if fd is no terminal.
func terminalID(fd uintptr) (id termID, ok bool) {
	if !isTerminalFd(fd) {
		return termID{}, false
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(fd), &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		return termID{}, false
	}
	return termID{rdev: uint64(st.Rdev), dev: uint64(st.Dev)}, true
}

// devTTY is the path of the controlling terminal of a process.
const devTTY = "/dev/tty"

// isDevTTY reports whether rdev is the device of /dev/tty, a device of
// its own (5:0 on Linux) that stands for the controlling terminal of the
// process that opened it: by the device number of /dev/tty or, where
// that number is fixed (Linux, isDevTTYNumber), by that number, so that a
// missing /dev/tty does not make a descriptor of it a terminal of its
// own.
func isDevTTY(rdev uint64) bool {
	var st syscall.Stat_t
	if err := syscall.Stat(devTTY, &st); err == nil && st.Mode&syscall.S_IFMT == syscall.S_IFCHR && uint64(st.Rdev) == rdev {
		return true
	}
	return isDevTTYNumber(rdev)
}

// sameControlling reports whether the terminals a and b, one of them or
// both /dev/tty (isDevTTY), are the same terminal: both must be the
// controlling terminal of the program and answer TIOCGPGRP with the same
// foreground process group. The kernel answers that request on a
// terminal only for the session it controls (ENOTTY otherwise), and a
// foreground process group belongs to one session and so to one
// terminal; none (0) counts as no answer.
//
// With one side /dev/tty (task 13c finding 2), the other side must also
// be the controlling terminal by its device number (isControllingDevice,
// tty_nr of /proc/self/stat on Linux, task 13d finding 1): the master
// side of a pseudo terminal answers TIOCGPGRP for its slave, so the
// master of the controlling terminal would pass; terminalID refuses
// every master (isTerminalFd) as well.
//
// With both sides /dev/tty (task 13e point 1), the device number names
// no terminal: a descriptor of /dev/tty opened in another session (and
// inherited) names the controlling terminal of that session, not the
// one of the program, and two such descriptors from two sessions have
// the same device number 5:0. Both must then be the controlling terminal
// of the program (isControllingFd: on Linux TIOCGDEV, the terminal behind
// the descriptor, is tty_nr) and answer TIOCGPGRP; otherwise they are
// refused, even if both name the same terminal of another session.
//
// TIOCGPGRP is the check that carries the decision (task 20a point 4):
// the device numbers here (isControllingDevice compares tty_nr, a device
// number as well) only pick the cases; in two instances of devpts one
// device number names two terminals, and only the kernel's answer for
// the controlling terminal of the program's session tells them apart.
func sameControlling(a, b uintptr) bool {
	x, ok1 := terminalID(a)
	y, ok2 := terminalID(b)
	if !ok1 || !ok2 {
		return false
	}
	ttyA, ttyB := isDevTTY(x.rdev), isDevTTY(y.rdev)
	switch {
	case ttyA && ttyB:
		if !isControllingFd(a) || !isControllingFd(b) {
			return false
		}
	case ttyA:
		if !isControllingDevice(y.rdev) {
			return false
		}
	case ttyB:
		if !isControllingDevice(x.rdev) {
			return false
		}
	default:
		return false
	}
	p, ok1 := foreground(a)
	q, ok2 := foreground(b)
	return ok1 && ok2 && p > 0 && p == q
}

// foreground returns the foreground process group of the terminal fd if
// it is the controlling terminal of the program (TIOCGPGRP).
func foreground(fd uintptr) (int32, bool) {
	var pgrp int32
	if ioctl(fd, syscall.TIOCGPGRP, unsafe.Pointer(&pgrp)) != nil {
		return 0, false
	}
	return pgrp, true
}
