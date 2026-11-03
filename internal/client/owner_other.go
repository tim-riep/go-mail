//go:build !unix

package client

import "io/fs"

// ownedByMe reports whether fi belongs to the user of this process; where
// syscall has no owner of a file it is false, so nothing is removed.
func ownedByMe(fs.FileInfo) bool { return false }

// ownersKnown reports that files have no owner ownedByMe could check
// here; openTempDir then does not check the owner.
const ownersKnown = false
