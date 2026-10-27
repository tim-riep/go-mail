//go:build !linux

package translog

import "errors"

// memLimitSupported reports whether limitMemory can bound the address
// space of the test process.
const memLimitSupported = false

func limitMemory(uint64) error { return errors.New("not supported") }
