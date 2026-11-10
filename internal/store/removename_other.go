//go:build !(unix || windows)

package store

import "os"

// removeName is os.Remove where syscall has no Unlink (Plan 9): it would
// also remove an empty directory put under the name meanwhile. The PoC
// runs on Unix.
func removeName(path string) error { return os.Remove(path) }
