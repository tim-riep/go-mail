//go:build linux

package client_test

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

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
)

// keystoreCTTYEnv names, in the helper process, the terminal device it
// opens; keystoreCTTYModeEnv says how (keystore: the key store read of
// Open and DeviceLost; plain: os.OpenFile without O_NOCTTY, the
// control).
const (
	keystoreCTTYEnv     = "GOMAIL_CLIENT_KEYSTORE_CTTY_PATH"
	keystoreCTTYModeEnv = "GOMAIL_CLIENT_KEYSTORE_CTTY_MODE"
)

// TestKeystoreNoCTTY (task 20l point 2, F3 of the attack review of task
// 20i), as store.TestOpenRegularNoCTTY: a terminal device in place of
// the key store, read as Open and DeviceLost read it, is refused as not
// regular and does not become the controlling terminal of a process
// that has none. keys.ReadKeystoreFile, which they used before, opens
// without O_NOCTTY and gives the process that terminal. The process is
// this test binary started again as the leader of a new session; it
// opens the slave of a new pseudo terminal and then tries /dev/tty. If
// the control gets no controlling terminal, the test is skipped.
func TestKeystoreNoCTTY(t *testing.T) {
	if got := runKeystoreCTTYHelper(t, newKeystorePtySlave(t), "plain"); got != "tty:ok" {
		t.Skipf("the control got no controlling terminal: %s", got)
	}
	if got := runKeystoreCTTYHelper(t, newKeystorePtySlave(t), "keystore"); got != "tty:"+syscall.ENXIO.Error() {
		t.Fatalf("after reading a terminal as key store: %s", got)
	}
}

// newKeystorePtySlave opens a pseudo terminal and returns the path of
// its slave; the master stays open until the test ends.
func newKeystorePtySlave(t *testing.T) string {
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

// runKeystoreCTTYHelper runs TestHelperKeystoreCTTY in a new session and
// returns its result line.
func runKeystoreCTTYHelper(t *testing.T, slave, mode string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperKeystoreCTTY$", "-test.count=1")
	cmd.Env = append(os.Environ(), keystoreCTTYEnv+"="+slave, keystoreCTTYModeEnv+"="+mode)
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

// TestHelperKeystoreCTTY is not a test: started by runKeystoreCTTYHelper
// as the leader of a new session, it opens the terminal named by
// keystoreCTTYEnv as keystoreCTTYModeEnv says and prints whether
// /dev/tty opens afterwards.
func TestHelperKeystoreCTTY(t *testing.T) {
	path := os.Getenv(keystoreCTTYEnv)
	if path == "" {
		t.Skip("helper process only")
	}
	switch os.Getenv(keystoreCTTYModeEnv) {
	case "plain":
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	case "keystore":
		if _, err := client.ReadKeystore(path); !errors.Is(err, keys.ErrKeystore) {
			t.Fatalf("key store read of a terminal: %v", err)
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
