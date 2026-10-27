//go:build linux

package translog

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// memLimitSupported reports whether limitMemory can bound the address
// space of the test process.
const memLimitSupported = true

// limitMemory bounds the address space of this process to its current
// size plus extra bytes (RLIMIT_AS, as "ulimit -v" does), so that an
// allocation sized by a forged tree.rec fails at once with "out of
// memory" instead of exhausting the machine. It is only used in the
// child process of runBounded, which runs nothing else.
func limitMemory(extra uint64) error {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return err
	}
	defer f.Close()
	var size uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "VmSize:"); ok {
			kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			if err != nil {
				return err
			}
			size = kb << 10
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if size == 0 {
		return syscall.EINVAL
	}
	lim := &syscall.Rlimit{Cur: size + extra, Max: size + extra}
	return syscall.Setrlimit(syscall.RLIMIT_AS, lim)
}
