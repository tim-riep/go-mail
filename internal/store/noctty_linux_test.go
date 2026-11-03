//go:build linux

package store

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// nocttyEnv names, in the helper process, the terminal device it opens;
// nocttyModeEnv says how (store: OpenRegular and ReadFileLimited; plain:
// os.OpenFile without O_NOCTTY, the control).
const (
	nocttyEnv     = "GOMAIL_STORE_NOCTTY_PATH"
	nocttyModeEnv = "GOMAIL_STORE_NOCTTY_MODE"
)

// TestOpenRegularNoCTTY (task 20i point 4): a terminal device in place
// of a file, opened by OpenRegular or ReadFileLimited, is refused as not
// regular and does not become the controlling terminal of a process
// that has none. The process is this test binary started again as the
// leader of a new session (Setsid), which has no controlling terminal;
// it opens the slave of a new pseudo terminal from /dev/ptmx and then
// tries /dev/tty, which opens only with a controlling terminal. The
// control opens such a slave without O_NOCTTY and must get one; if it
// does not, this system does not assign controlling terminals that way
// and the test is skipped. No root is needed.
func TestOpenRegularNoCTTY(t *testing.T) {
	if got := runNoCTTYHelper(t, newPtySlave(t), "plain"); got != "tty:ok" {
		t.Skipf("the control got no controlling terminal: %s", got)
	}
	if got := runNoCTTYHelper(t, newPtySlave(t), "store"); got != "tty:"+syscall.ENXIO.Error() {
		t.Fatalf("after OpenRegular and ReadFileLimited of a terminal: %s", got)
	}
}

// newPtySlave opens a pseudo terminal and returns the path of its slave;
// the master stays open until the test ends.
func newPtySlave(t *testing.T) string {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no /dev/ptmx:", err)
	}
	t.Cleanup(func() { m.Close() })
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		t.Skip("TIOCGPTN:", e)
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Skip("TIOCSPTLCK:", e)
	}
	return "/dev/pts/" + strconv.FormatUint(uint64(n), 10)
}

// runNoCTTYHelper runs TestHelperNoCTTY in a new session and returns its
// last output line.
func runNoCTTYHelper(t *testing.T, slave, mode string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperNoCTTY$", "-test.count=1")
	cmd.Env = append(os.Environ(), nocttyEnv+"="+slave, nocttyModeEnv+"="+mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper %s: %v\n%s", mode, err, out)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "tty:") {
			return l
		}
	}
	t.Fatalf("helper %s printed no result:\n%s", mode, out)
	return ""
}

// TestHelperNoCTTY is not a test: started by runNoCTTYHelper as the
// leader of a new session, it opens the terminal named by nocttyEnv as
// nocttyModeEnv says and prints whether /dev/tty opens afterwards.
func TestHelperNoCTTY(t *testing.T) {
	path := os.Getenv(nocttyEnv)
	if path == "" {
		t.Skip("helper process only")
	}
	switch os.Getenv(nocttyModeEnv) {
	case "plain":
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	case "store":
		if _, _, err := OpenRegular(path); !errors.Is(err, ErrNotRegular) {
			t.Fatalf("OpenRegular of a terminal: %v", err)
		}
		if _, err := ReadFileLimited(path, MaxRecordFile); !errors.Is(err, ErrNotRegular) {
			t.Fatalf("ReadFileLimited of a terminal: %v", err)
		}
	default:
		t.Fatal("unknown mode")
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			fmt.Println("tty:" + errno.Error())
			return
		}
		fmt.Println("tty:" + err.Error())
		return
	}
	tty.Close()
	fmt.Println("tty:ok")
}
