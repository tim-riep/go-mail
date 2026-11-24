//go:build !unix

package store

import "os"

// holdFile keeps no second descriptor where syscall has no Dup or where
// one would be in the way (written.held): on Windows a second handle,
// which os opens without FILE_SHARE_DELETE, would make the rename of
// the temporary file fail; Plan 9, js and wasip1 are not run. The
// comparison of written.differs rests on os.SameFile alone there (on
// Windows the file ID of NTFS, which carries a sequence number).
func holdFile(*os.File) (*os.File, error) { return nil, nil }
