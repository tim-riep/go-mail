//go:build openbsd

package main

import "syscall"

// ptyMasterSample is a master of a pseudo terminal on every OpenBSD
// system (MAKEDEV pty0); its major number is that of all masters (ptc),
// which differs between the architectures.
const ptyMasterSample = "/dev/ptyp0"

// isPtyMaster reports whether fd is the master side of a pseudo terminal
// (task 13d finding 1). OpenBSD has no request that only the master
// answers without changing it (TIOCPKT, TIOCREMOTE and TIOCUCNTL set a
// mode); /dev/ptm hands out the masters /dev/ptyXX, so a master is a
// character device with the major number of ptyMasterSample. If that
// cannot be read, every terminal counts as a master (fail closed).
func isPtyMaster(fd uintptr) bool {
	var st, ptc syscall.Stat_t
	if err := syscall.Fstat(int(fd), &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		return false
	}
	if err := syscall.Stat(ptyMasterSample, &ptc); err != nil || ptc.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		return true
	}
	return openbsdMajor(st.Rdev) == openbsdMajor(ptc.Rdev)
}

// openbsdMajor is major(3) of OpenBSD.
func openbsdMajor(dev int32) uint32 { return uint32(dev) >> 8 & 0xff }
