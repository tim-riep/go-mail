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

// brokenPipe is taken in from the start of run until the program exits
// (lostOutput; task 15i, task 15m point 4): a write to a pipe without a
// reader or a socket without a peer on standard error, where the prompts
// and the usage go, fails with EPIPE instead of ending the program past
// the abort path or before its exit code; a write to a regular file
// beyond RLIMIT_FSIZE fails with EFBIG instead of raising SIGXFSZ (task
// 15m point 3; the runtime discards SIGXFSZ by itself, it is taken in
// all the same so that this does not rest on the runtime). They are not
// abortSignals: the runtime raises SIGPIPE for every write to standard
// error that fails with EPIPE, also for a message during the commit or
// after it, which must not roll back or abort a ceremony; a lost prompt
// is caught where it is written (promptLost). signal.Ignore is not used
// for them, as close explains for the abortSignals.
var brokenPipe = []os.Signal{syscall.SIGPIPE, syscall.SIGXFSZ}

// ioctl calls ioctl(2) with a pointer argument. It is a variable so
// that a test can stand in a terminal that ignores a request (task 10d
// finding 2).
var ioctl = sysIoctl

func sysIoctl(fd, req uintptr, arg unsafe.Pointer) error {
	return ioctlValue(fd, req, uintptr(arg))
}

// ioctlValue calls ioctl(2) with an integer argument (TCFLSH, TCXONC,
// TIOCSTART), again after EINTR.
func ioctlValue(fd, req, arg uintptr) error {
	for {
		_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg)
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
// not read yet, before and after it sets the attributes (restoreInput):
// a share typed while the echo was off and not yet taken in by the
// terminal when the echo comes back (an abort in the middle of the
// input) would be echoed then; input typed ahead is dropped with it, as
// scrubInput drops it.
func disableEcho(fd uintptr) (func() error, error) {
	return clearModes(fd, func(t *syscall.Termios) { t.Lflag &^= quietFlags },
		func(t *syscall.Termios) bool { return t.Lflag&quietFlags != 0 }, errEchoStays, true)
}

// disableFlow clears flowFlags on the terminal fd as disableEcho clears
// quietFlags (errFlowStays if they stay set) and returns the function
// that restores the attributes read before. On Linux, clearing IXON
// also restarts an output that an XOFF typed before had stopped.
func disableFlow(fd uintptr) (func() error, error) {
	return clearModes(fd, func(t *syscall.Termios) { t.Iflag &^= flowFlags },
		func(t *syscall.Termios) bool { return t.Iflag&flowFlags != 0 }, errFlowStays, true)
}

// disableFlowOut clears flowFlags on the terminal fd of stdout when that
// is another terminal than stdin (task 15b point 0b), as disableFlow
// does; the restore sets the attributes read before without discarding
// input: nothing is read from that terminal.
func disableFlowOut(fd uintptr) (func() error, error) {
	return clearModes(fd, func(t *syscall.Termios) { t.Iflag &^= flowFlags },
		func(t *syscall.Termios) bool { return t.Iflag&flowFlags != 0 }, errFlowStays, false)
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

// stderrFile reports whether the file fd, standard error, can take the
// prompts (task 15l point 2, checkStderr): a terminal, a pipe or a
// regular file. A descriptor that cannot be examined, the null device
// (character device with the device number of /dev/null) and the file
// that a fresh open of /dev/null gives (same device and inode) are
// errStderrClosed: the runtime opens /dev/null in the slot of a
// descriptor 2 that is closed when the program starts. Every other kind
// of file (a socket, a device that is no terminal) is errStderrKind. A
// descriptor that is not open for writing (writable: the read end of a
// pipe, a terminal or file opened read-only, O_PATH) is
// errStderrReadOnly, a kind of errStderrClosed (task 15m point 3).
func stderrFile(fd uintptr) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(fd), &st); err != nil {
		return errStderrClosed
	}
	if !writable(fd) {
		return errStderrReadOnly
	}
	kind := st.Mode & syscall.S_IFMT
	var null syscall.Stat_t
	if syscall.Stat(os.DevNull, &null) == nil && null.Mode&syscall.S_IFMT == syscall.S_IFCHR &&
		kind == syscall.S_IFCHR && st.Rdev == null.Rdev {
		return errStderrClosed
	}
	if f, err := os.Open(os.DevNull); err == nil {
		var fresh syscall.Stat_t
		same := syscall.Fstat(int(f.Fd()), &fresh) == nil && fresh.Dev == st.Dev && fresh.Ino == st.Ino
		f.Close()
		if same {
			return errStderrClosed
		}
	}
	switch kind {
	case syscall.S_IFREG, syscall.S_IFIFO:
		return nil
	case syscall.S_IFCHR:
		if isTerminalFd(fd) {
			return nil
		}
	}
	return errStderrKind
}

// clearModes applies off to the attributes of the terminal fd, reads
// them back and fails with stays (the old attributes restored) when set
// still reports a mode set; otherwise it returns the function that
// restores the attributes read before, discarding the input not read
// yet before and after when input is set (restoreInput).
//
// No request here waits (task 15m point 1): the attributes are set with
// ioctlSetTermios (TCSETS, TIOCSETA), never with the requests that
// discard the input or wait for the output in the same call (TCSETSF,
// TCSETSW, TIOCSETAF, TIOCSETAW). Linux takes the write lock of the
// terminal for those and waits until its output has drained: as long
// as another thread of the program is blocked in a write to the same
// terminal (a prompt on a terminal that takes no output: stopped or
// full), the request waited with it, and with it the abort path, a
// share left on the screen.
func clearModes(fd uintptr, off func(*syscall.Termios), set func(*syscall.Termios) bool, stays error, input bool) (func() error, error) {
	var old syscall.Termios
	if err := ioctl(fd, ioctlGetTermios, unsafe.Pointer(&old)); err != nil {
		return nil, err
	}
	t := old
	off(&t)
	if err := ioctl(fd, ioctlSetTermios, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	restore := func() error { return ioctl(fd, ioctlSetTermios, unsafe.Pointer(&old)) }
	if input {
		restore = func() error { return restoreInput(fd, &old) }
	}
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

// restoreInput sets the attributes old on the terminal fd of stdin and
// discards the input received and not read yet, before and after (task
// 15m point 1): before, so that a share typed while the echo was off is
// not echoed once it is on; after, so that what the terminal took in
// meanwhile (on Linux the driver hands input on to the line discipline
// in the background) is gone as well. The attributes are set even when
// the first discard fails; the first error is returned.
func restoreInput(fd uintptr, old *syscall.Termios) error {
	e1 := flushInput(fd)
	e2 := ioctl(fd, ioctlSetTermios, unsafe.Pointer(old))
	e3 := flushInput(fd)
	for _, err := range []error{e1, e2, e3} {
		if err != nil {
			return err
		}
	}
	return nil
}

// flushInput discards the input that the terminal fd received and the
// program has not read yet (task 10e finding 4) with discardInput
// (tcflush(fd, TCIFLUSH): TCFLSH on Linux, which empties the buffers
// between the driver and the line discipline as well as the line
// discipline's; TIOCFLUSH with FREAD on the BSDs and macOS). It does not
// wait, not for the output to drain nor for another write to the
// terminal (task 15m point 1): before task 15m it set the attributes
// again with TCSETSF (TIOCSETAF), which waits for both.
func flushInput(fd uintptr) error { return discardInput(fd) }

// wakeOutput lets the output of the terminal fd run again (task 15m
// point 2). With discard, discardOutput first drops the output written
// and not yet sent (tcflush(fd, TCOFLUSH)), so that a write blocked on a
// full output buffer (a terminal nobody reads) and the clear behind it
// go through. Then restartOutput lifts every stop of the output, by a
// TCOOFF of another program, by an XOFF received while IXON was set,
// and on the Linux console by Scroll Lock, which stops the output the
// same way as an XOFF (stop_tty). The order matters: on Linux a discard
// does not wake a write that waits for room, the restart does; woken
// before the discard, the write found no room and slept on (found by
// TestPTYAbortBlockedOutput). Nothing here waits. Both steps run; the
// first error is returned.
func wakeOutput(fd uintptr, discard bool) error {
	var err error
	if discard {
		err = discardOutput(fd)
	}
	if e := restartOutput(fd); err == nil {
		err = e
	}
	return err
}

// blockingOutput clears O_NONBLOCK on the open file description of fd
// (fcntl F_GETFL, F_SETFL) when it is set (task 15n finding 1; why the
// program may change a description it shares: term.unblock). Neither
// request waits.
func blockingOutput(fd uintptr) error {
	fl, _, e := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
	if e != 0 {
		return e
	}
	if int(fl)&syscall.O_NONBLOCK == 0 {
		return nil
	}
	if _, _, e := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFL, fl&^uintptr(syscall.O_NONBLOCK)); e != 0 {
		return e
	}
	return nil
}

// inputPending returns how many bytes of input the terminal fd received
// and the program has not read yet (ioctlInputCount: TIOCINQ on Linux,
// FIONREAD on the BSDs and macOS; task 15n finding 3). In canonical
// mode these count complete lines only. It waits for nothing.
func inputPending(fd uintptr) (int, error) {
	var n int32
	if err := ioctl(fd, ioctlInputCount, unsafe.Pointer(&n)); err != nil {
		return 0, err
	}
	return int(n), nil
}

// writable reports whether the file fd was opened for writing: its
// access mode (fcntl F_GETFL) is O_WRONLY or O_RDWR (task 15m point 3).
// A descriptor opened read-only (the read end of a pipe, a terminal or
// a file opened with O_RDONLY) or with O_PATH (access mode 0, O_RDONLY)
// is not.
func writable(fd uintptr) bool {
	fl, _, e := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
	if e != 0 {
		return false
	}
	switch int(fl) & syscall.O_ACCMODE {
	case syscall.O_WRONLY, syscall.O_RDWR:
		return true
	}
	return false
}
