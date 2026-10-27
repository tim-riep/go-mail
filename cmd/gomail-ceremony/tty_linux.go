//go:build linux && !ceremony_notty

package main

import "syscall"

// Requests that read and write the terminal attributes (termios). The
// attributes are always set with TCSETS, which neither waits for the
// output nor takes the write lock of the terminal (task 15m point 1);
// TCSETSF and TCSETSW do both and are not used.
const (
	ioctlGetTermios = syscall.TCGETS
	ioctlSetTermios = syscall.TCSETS
)

// ioctlInputCount is TIOCINQ (FIONREAD), the number of bytes of input
// received and not read (inputPending).
const ioctlInputCount = syscall.TIOCINQ

// ioctlFlowCtl is TCXONC (tcflow), which the syscall package does not
// define: TCFLSH - 1 on every Linux architecture (asm-generic/ioctls.h
// 0x540A/0x540B, mips 0x5406/0x5407, powerpc _IO('t', 30)/_IO('t', 31)).
// flowOutOff and flowOutOn are its arguments TCOOFF and TCOON, the same
// on every architecture.
const (
	ioctlFlowCtl = ioctlFlush - 1
	flowOutOff   = 0
	flowOutOn    = 1
)

// discardInput discards the input that the terminal fd received and has
// not been read (tcflush(fd, TCIFLUSH)). TCFLSH empties the buffers
// between the driver and the line discipline as well as the line
// discipline's: Linux hands input on to the line discipline in the
// background, and a share typed just before an abort and not processed
// yet when the echo comes back would be echoed then, on the screen just
// cleared (task 15b, found by TestPTYSignalSalvo). It takes no write
// lock and waits for no output.
func discardInput(fd uintptr) error { return ioctlValue(fd, ioctlFlush, syscall.TCIFLUSH) }

// discardOutput discards the output written to the terminal fd and not
// yet sent (tcflush(fd, TCOFLUSH)); it waits for nothing.
func discardOutput(fd uintptr) error { return ioctlValue(fd, ioctlFlush, syscall.TCOFLUSH) }

// restartOutput lets the output of the terminal fd run again: TCOOFF,
// then TCOON. TCOON alone lifts only a stop by TCOOFF (tco_stopped);
// a stop by an XOFF received while IXON was set, or by Scroll Lock on
// the Linux console (stop_tty: the same stop as an XOFF), stays until
// a START character, a stop_tty from the keyboard, or a TCOON after a
// TCOOFF. TCOON runs even when TCOOFF failed, so that this never leaves
// the output stopped itself. Neither request takes the write lock of
// the terminal or waits.
func restartOutput(fd uintptr) error {
	err := ioctlValue(fd, ioctlFlowCtl, flowOutOff)
	if e := ioctlValue(fd, ioctlFlowCtl, flowOutOn); e != nil {
		return e
	}
	return err
}
