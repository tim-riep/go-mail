//go:build !unix

package client

import "io/fs"

// ownedByMe reports whether fi belongs to the user of this process; where
// syscall has no owner of a file it is false, so nothing is removed.
func ownedByMe(fs.FileInfo) bool { return false }
