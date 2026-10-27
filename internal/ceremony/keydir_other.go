//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package ceremony

import (
	"fmt"
	"io/fs"
	"os"
)

// checkKeyDirInfo fails closed where owner and mode cannot be checked.
func checkKeyDirInfo(fs.FileInfo) error {
	return fmt.Errorf("%w: owner and mode cannot be checked on this system", ErrKeyDir)
}

// openKeyDir fails closed where owner and mode cannot be checked.
func openKeyDir(string) (*os.Root, error) {
	return nil, fmt.Errorf("%w: owner and mode cannot be checked on this system", ErrKeyDir)
}
