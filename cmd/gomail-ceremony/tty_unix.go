//go:build (linux || darwin || freebsd || netbsd || openbsd || dragonfly) && !ceremony_notty

package main

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// abortSignals are the signals that end a ceremony through the abort
// path of term (echo restored, screen cleared, exit code 130; deferred
// while the files are written):
//
//   - SIGINT, SIGTERM, SIGHUP and SIGQUIT (task 10b, 10c, 10d finding 1b);
//   - SIGTSTP: a ceremony is not suspended, a stop request ends it (task
//     10d finding 1d);
//   - SIGABRT, SIGILL, SIGTRAP, SIGBUS, SIGFPE, SIGSEGV and SIGSYS when
//     sent with kill: unhandled, the runtime ends the program with a
//     stack trace on the terminal and the echo as it is, whatever the
//     traceback level (task 10d finding 1c; see main). A real fault is
//     still a run-time panic, these handlers do not catch it.
//
// The other signals are ignored by the runtime (SIGUSR1, SIGALRM, ...),
// stop the program before it changed the terminal (SIGTTIN, SIGTTOU:
// a ceremony started in the background) or cannot be caught (SIGKILL,
// SIGSTOP).
var abortSignals = []os.Signal{
	os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT,
	syscall.SIGTSTP,
	syscall.SIGABRT, syscall.SIGILL, syscall.SIGTRAP, syscall.SIGBUS, syscall.SIGFPE, syscall.SIGSEGV, syscall.SIGSYS,
}

// ioctl calls ioctl(2) with a pointer argument. It is a variable so
// that a test can stand in a terminal that ignores a request (task 10d
// finding 2).
var ioctl = sysIoctl

func sysIoctl(fd, req uintptr, arg unsafe.Pointer) error {
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

// isTerminalFd reports whether fd is a terminal: whether its terminal
// attributes can be read.
func isTerminalFd(fd uintptr) bool {
	var t syscall.Termios
	return ioctl(fd, ioctlGetTermios, unsafe.Pointer(&t)) == nil
}

// errEchoStays reports a terminal that keeps ECHO, ISIG or IEXTEN set
// after they were cleared.
var errEchoStays = errors.New("ECHO, ISIG oder IEXTEN bleibt gesetzt")

// errFlowStays reports a terminal that keeps IXON, IXOFF or IXANY set
// after they were cleared.
var errFlowStays = errors.New("IXON, IXOFF oder IXANY bleibt gesetzt")

// quietFlags are the local modes cleared while a share is typed: ECHO
// (the share is not shown), ISIG (the control characters of the input,
// such as Ctrl-\ for SIGQUIT, raise no signal; task 10d finding 1a) and
// IEXTEN (no implementation-defined input processing, such as the
// literal-next character or the status request of the BSDs). ICANON
// stays: input is still read line by line.
const quietFlags = syscall.ECHO | syscall.ISIG | syscall.IEXTEN

// flowFlags are the input modes of software flow control, cleared from
// openTerm to close (task 10e finding 1): with IXON a Ctrl-S (XOFF,
// 0x13) typed by anyone at the keyboard stops the output of the
// terminal, and every write of the program blocks until Ctrl-Q, the
// clear of the screen in the abort path included, with a share left on
// the screen and the signals unable to end the program. Cleared, Ctrl-S
// and Ctrl-Q are input bytes like any other, and the word check refuses
// them. IXOFF (the terminal sends XOFF itself) and IXANY (any key
// restarts the output) go with IXON.
const flowFlags = syscall.IXON | syscall.IXOFF | syscall.IXANY

// disableEcho clears quietFlags on the terminal fd, reads the attributes
// back to check that they are clear (errEchoStays otherwise, with the
// old attributes restored), and returns the function that restores the
// attributes read before. The restore discards the input received and
// not read yet in the same request (ioctlSetTermiosFlush): a share typed
// while the echo was off and not yet taken in by the terminal when the
// echo comes back (an abort in the middle of the input) would be echoed
// then; input typed ahead is dropped with it, as scrubInput drops it.
func disableEcho(fd uintptr) (func() error, error) {
	return clearModes(fd, func(t *syscall.Termios) { t.Lflag &^= quietFlags },
		func(t *syscall.Termios) bool { return t.Lflag&quietFlags != 0 }, errEchoStays, ioctlSetTermiosFlush)
}

// disableFlow clears flowFlags on the terminal fd as disableEcho clears
// quietFlags (errFlowStays if they stay set) and returns the function
// that restores the attributes read before. On Linux, clearing IXON
// also restarts an output that an XOFF typed before had stopped.
func disableFlow(fd uintptr) (func() error, error) {
	return clearModes(fd, func(t *syscall.Termios) { t.Iflag &^= flowFlags },
		func(t *syscall.Termios) bool { return t.Iflag&flowFlags != 0 }, errFlowStays, ioctlSetTermiosFlush)
}

// disableFlowOut clears flowFlags on the terminal fd of stdout when that
// is another terminal than stdin (task 15b point 0b), as disableFlow
// does; the restore sets the attributes read before without discarding
// input or waiting for the output (ioctlSetTermios): nothing is read
// from that terminal, and the abort path must not wait for an output
// that does not drain.
func disableFlowOut(fd uintptr) (func() error, error) {
	return clearModes(fd, func(t *syscall.Termios) { t.Iflag &^= flowFlags },
		func(t *syscall.Termios) bool { return t.Iflag&flowFlags != 0 }, errFlowStays, ioctlSetTermios)
}

// sameTerminal reports whether the files a and b are the same terminal:
// character devices with the same device number. Two names of one
// terminal (/dev/tty and /dev/pts/N) count as two; their flow control is
// then switched on both, and restored in reverse order (restoreFlow).
func sameTerminal(a, b uintptr) bool {
	var sa, sb syscall.Stat_t
	if syscall.Fstat(int(a), &sa) != nil || syscall.Fstat(int(b), &sb) != nil {
		return false
	}
	return sa.Mode&syscall.S_IFMT == syscall.S_IFCHR && sb.Mode&syscall.S_IFMT == syscall.S_IFCHR && sa.Rdev == sb.Rdev
}

// clearModes applies off to the attributes of the terminal fd, reads
// them back and fails with stays (the old attributes restored) when set
// still reports a mode set; otherwise it returns the function that
// restores the attributes read before with the request restoreReq
// (ioctlSetTermiosFlush: discarding the input not read yet).
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
// program has not read yet (task 10e finding 4): the attributes are read
// and set again unchanged with ioctlSetTermiosFlush (TCSETSF, TIOCSETAF),
// which discards the input queue first; then flushPending discards the
// input that the terminal has received but not processed yet (Linux).
func flushInput(fd uintptr) error {
	var t syscall.Termios
	if err := ioctl(fd, ioctlGetTermios, unsafe.Pointer(&t)); err != nil {
		return err
	}
	if err := ioctl(fd, ioctlSetTermiosFlush, unsafe.Pointer(&t)); err != nil {
		return err
	}
	return flushPending(fd)
}
