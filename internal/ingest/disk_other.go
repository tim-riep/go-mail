//go:build !(linux || darwin || freebsd || dragonfly || openbsd)

package ingest

import "errors"

// diskSpace is unknown on this platform (NetBSD among others: package
// syscall has neither statfs nor statvfs there, and golang.org/x/sys must
// not be imported; Windows as well). Accepting then refuses every mail
// (5.1, fail closed) unless Config.DiskSpace is set; gomail-server says
// so at its start (Ingest.DiskSpace, task 15c finding 5).
func diskSpace(string) (uint64, uint64, error) {
	return 0, 0, errors.New("ingest: free space unknown on this platform")
}
