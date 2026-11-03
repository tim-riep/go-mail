//go:build unix

package client

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByMe reports whether fi (from os.Lstat) belongs to the effective
// user of this process.
func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// ownersKnown reports that files have owners here (ownedByMe).
const ownersKnown = true
