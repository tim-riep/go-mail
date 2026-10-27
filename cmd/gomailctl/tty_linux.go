//go:build linux

package main

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// Requests that read and write the terminal attributes (termios), as in
// gomail-ceremony (tty_linux.go there). ioctlSetTermiosFlush is TCSETSF:
// it discards the input received and not read yet, then sets the
// attributes; on every Linux architecture it is TCSETS + 2.
const (
	ioctlGetTermios      = syscall.TCGETS
	ioctlSetTermios      = syscall.TCSETS
	ioctlSetTermiosFlush = syscall.TCSETS + 2
)

// isPtyMaster reports whether fd is the master side of a pseudo terminal
// (task 13d finding 1): TIOCGPTN (the number of the pseudo terminal)
// succeeds only on the master of a Unix 98 pseudo terminal, not on its
// slave or any other terminal. The masters of the legacy BSD pseudo
// terminals (CONFIG_LEGACY_PTYS) do not answer it; they are known by
// their device number (major 2, Documentation/admin-guide/devices.txt),
// as are the Unix 98 master majors 128 to 135.
func isPtyMaster(fd uintptr) bool {
	var n uint32
	if ioctl(fd, syscall.TIOCGPTN, unsafe.Pointer(&n)) == nil {
		return true
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(fd), &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		return false
	}
	major := linuxMajor(uint64(st.Rdev))
	return major == 2 || (major >= 128 && major <= 135)
}

// linuxMajor is the major number of the device number dev as the kernel
// encodes it for stat (new_encode_dev, glibc gnu_dev_major).
func linuxMajor(dev uint64) uint64 {
	return (dev>>8)&0xfff | (dev>>32)&^0xfff
}

// procStat is the status file of the program; tests replace it.
var procStat = "/proc/self/stat"

// isControllingDevice reports whether rdev is the device of the
// controlling terminal of the program, field tty_nr of /proc/self/stat
// (task 13d finding 1): the side of sameControlling that is not /dev/tty
// must be that terminal. Without the file, or without a controlling
// terminal (tty_nr 0), nothing is.
func isControllingDevice(rdev uint64) bool {
	f, err := os.Open(procStat)
	if err != nil {
		return false
	}
	defer f.Close()
	// The fields up to tty_nr take less than 100 bytes after a command
	// name of at most 64; the rest of the line is not read.
	b, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return false
	}
	nr, ok := parseTTYNr(b)
	return ok && nr == rdev
}

// parseTTYNr returns field 7, tty_nr, of a line of /proc/<pid>/stat: the
// fifth field after the command name, which ends with the last ")" of
// the line (it may hold spaces and parentheses itself). A missing or
// malformed field and 0 (no controlling terminal) give ok false. The
// kernel prints the encoded device number as a signed int.
func parseTTYNr(stat []byte) (uint64, bool) {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, false
	}
	f := bytes.Fields(stat[i+1:])
	if len(f) < 5 {
		return 0, false
	}
	n, err := strconv.ParseInt(string(f[4]), 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint64(uint32(int32(n))), true
}
