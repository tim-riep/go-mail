//go:build unix

package main

import (
	"io/fs"
	"os"
	"syscall"
)

// fileGroup returns the group ID of fi.
func fileGroup(fi fs.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Gid), true
}

// inGroup reports whether the process belongs to group gid.
func inGroup(gid int) bool {
	if os.Getegid() == gid {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, g := range groups {
		if g == gid {
			return true
		}
	}
	return false
}
