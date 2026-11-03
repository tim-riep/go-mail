//go:build unix

package store

import "syscall"

// openNoCTTY is added to the flags of OpenRegular (task 20i point 4): a
// terminal device put in place of a file must not become the
// controlling terminal of a process that has none, such as a session
// leader without one (a daemon). The open of a terminal without
// O_NOCTTY would make it that before the fstat of OpenRegular refuses
// the device.
const openNoCTTY = syscall.O_NOCTTY
