//go:build (darwin || freebsd || netbsd || openbsd || dragonfly) && !ceremony_notty

package main

import (
	"syscall"
	"unsafe"
)

// Requests that read and write the terminal attributes (termios). The
// attributes are always set with TIOCSETA, which does not wait for the
// output (task 15m point 1); TIOCSETAF and TIOCSETAW wait until it has
// drained and are not used.
const (
	ioctlGetTermios = syscall.TIOCGETA
	ioctlSetTermios = syscall.TIOCSETA
)

// ioctlInputCount is FIONREAD, the number of bytes of input received and
// not read (inputPending): _IOR('f', 127, int) of sys/filio.h, the same
// on macOS and every BSD; the syscall package does not define it there.
const ioctlInputCount = 0x4004667f

// flushRead and flushWrite are FREAD and FWRITE of sys/fcntl.h, the
// argument of TIOCFLUSH (the same on macOS and every BSD).
const (
	flushRead  = 1
	flushWrite = 2
)

// discardInput discards the input that the terminal fd received and has
// not been read (tcflush(fd, TCIFLUSH): TIOCFLUSH with FREAD). These
// systems hand input on to the line discipline when it arrives; nothing
// is left in between. It waits for nothing.
func discardInput(fd uintptr) error {
	which := int32(flushRead)
	return ioctl(fd, syscall.TIOCFLUSH, unsafe.Pointer(&which))
}

// discardOutput discards the output written to the terminal fd and not
// yet sent (tcflush(fd, TCOFLUSH): TIOCFLUSH with FWRITE).
func discardOutput(fd uintptr) error {
	which := int32(flushWrite)
	return ioctl(fd, syscall.TIOCFLUSH, unsafe.Pointer(&which))
}

// restartOutput lets the output of the terminal fd run again
// (tcflow(fd, TCOON): TIOCSTART), which on these systems lifts every
// stop of the output, by an XOFF as well.
func restartOutput(fd uintptr) error { return ioctlValue(fd, syscall.TIOCSTART, 0) }
