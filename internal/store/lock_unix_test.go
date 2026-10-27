//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package store

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// TestPermissions checks the modes of 9.1 under a umask that clears the
// group bits: files 0660 and directories 2770 in the data directory,
// private files 0600 outside it.
func TestPermissions(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	base := t.TempDir()
	root := filepath.Join(base, "data")
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	mode := func(p string) fs.FileMode {
		t.Helper()
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode() & modeBits
	}
	for _, d := range append([]string{root}, s.Path("platform"), s.Path("mailboxes"), s.Path("spool"), s.Path(locksDir)) {
		if m := mode(d); m != DirPerm {
			t.Fatalf("%s: mode %v", d, m)
		}
	}
	// An existing root is set to 2770 by Init.
	os.Chmod(root, 0o700)
	if _, err := Init(root); err != nil || mode(root) != DirPerm {
		t.Fatalf("Init on an existing root: %v %v", err, mode(root))
	}
	nested := s.Path("mailboxes", "a", "b", "c")
	if err := MkdirAll(nested); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{s.Path("mailboxes", "a"), s.Path("mailboxes", "a", "b"), nested} {
		if m := mode(d); m != DirPerm {
			t.Fatalf("MkdirAll %s: mode %v", d, m)
		}
	}
	// MkdirAll leaves existing directories alone.
	os.Chmod(nested, 0o750)
	MkdirAll(nested)
	if mode(nested) != 0o750 {
		t.Fatal("MkdirAll changed an existing directory")
	}
	w, c := filepath.Join(nested, "w"), filepath.Join(nested, "c")
	if err := WriteFileAtomic(w, []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(w, []byte("2")); err != nil {
		t.Fatal(err)
	}
	if err := CreateFileAtomic(c, []byte("1")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{w, c} {
		if m := mode(p); m != FilePerm {
			t.Fatalf("%s: mode %v", p, m)
		}
	}
	// Files written by the store operations.
	tu := newTestUser(t, 1, 1)
	if err := s.CreateUser(tu.user); err != nil {
		t.Fatal(err)
	}
	e, _ := newTestEpoch(t, tu, ID{9}, 1, 1, nil)
	if _, err := s.WriteEpoch(e); err != nil {
		t.Fatal(err)
	}
	unlock, err := s.LockMailbox(ID{9})
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	release, err := s.HoldRoleLock(RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	release()
	for _, p := range []string{s.UserFile(tu.user.ID), s.EpochFile(ID{9}, 1), filepath.Join(s.EpochDir(ID{9}, 1), "content.pub"),
		filepath.Join(s.MailboxDir(ID{9}), "lock"), s.Path(locksDir, "server")} {
		if m := mode(p); m != FilePerm {
			t.Fatalf("%s: mode %v", p, m)
		}
	}
	for _, d := range []string{filepath.Dir(s.UserFile(tu.user.ID)), s.EpochDir(ID{9}, 1), filepath.Join(s.EpochDir(ID{9}, 1), "members")} {
		if m := mode(d); m != DirPerm {
			t.Fatalf("%s: mode %v", d, m)
		}
	}
	// Private files outside the data directory.
	pw, pc := filepath.Join(base, "pw"), filepath.Join(base, "pc")
	if err := WritePrivateFileAtomic(pw, []byte("k")); err != nil {
		t.Fatal(err)
	}
	if err := CreatePrivateFileAtomic(pc, []byte("k")); err != nil {
		t.Fatal(err)
	}
	if err := CreatePrivateFileAtomic(pc, []byte("k")); !errors.Is(err, ErrExists) {
		t.Fatal("private file created twice")
	}
	for _, p := range []string{pw, pc} {
		if m := mode(p); m != PrivateFilePerm {
			t.Fatalf("%s: mode %v", p, m)
		}
	}
	// A root that cannot be created.
	if _, err := Init(filepath.Join(w, "data")); err == nil {
		t.Fatal("Init below a file")
	}
}

// TestTwoDescriptors shows that two descriptors of one file compete for
// the lock (Linux: open file description locks, also within a process).
func TestTwoDescriptors(t *testing.T) {
	if !ofdLocks {
		t.Skip("process locks do not conflict within a process; see TestRoleLocks")
	}
	p := filepath.Join(t.TempDir(), "lock")
	f1, err := openLockFile(p)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := openLockFile(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	if err := fcntlLock(f1, syscall.F_WRLCK, false); err != nil {
		t.Fatal(err)
	}
	if err := fcntlLock(f2, syscall.F_WRLCK, false); !conflict(err) {
		t.Fatalf("second descriptor got the lock: %v", err)
	}
	if err := fcntlLock(f2, syscall.F_RDLCK, false); !conflict(err) {
		t.Fatalf("second descriptor got a shared lock: %v", err)
	}
	// A lock taken through the registry is in force against a raw
	// descriptor as well.
	f1.Close()
	unlock, err := LockFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := fcntlLock(f2, syscall.F_WRLCK, false); !conflict(err) {
		t.Fatalf("raw descriptor got a registered lock: %v", err)
	}
	if err := probeLock(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("probe of a held lock: %v", err)
	}
	unlock()
	unlock()
	// Closing the holder released the lock.
	if err := fcntlLock(f2, syscall.F_WRLCK, false); err != nil {
		t.Fatal(err)
	}
	if err := probeLock(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("probe of a raw lock: %v", err)
	}
	// Shared locks coexist.
	fcntlLock(f2, syscall.F_RDLCK, false)
	f3, _ := openLockFile(p)
	defer f3.Close()
	if err := fcntlLock(f3, syscall.F_RDLCK, false); err != nil {
		t.Fatalf("two shared locks: %v", err)
	}
	if err := fcntlLock(f3, syscall.F_UNLCK, false); err != nil {
		t.Fatal(err)
	}
}

// TestLockWaits checks that a waiting lock is granted after the release.
func TestLockWaits(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock")
	unlock, err := lockFile(p)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan func())
	go func() {
		u, err := lockFile(p)
		if err != nil {
			t.Error(err)
		}
		got <- u
	}()
	select {
	case <-got:
		t.Fatal("lock granted twice")
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	(<-got)()
	if _, err := lockFile(filepath.Join(p, "below-a-file")); err == nil {
		t.Fatal("lock below a file")
	}
	if err := probeLock(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("probe of a missing file")
	}
}

const helperEnv = "GOMAIL_STORE_LOCK_HELPER"

// TestHelperHoldRoleLock is not a test: started by TestRoleLocks as a
// second process, it holds the role lock until its standard input ends.
func TestHelperHoldRoleLock(t *testing.T) {
	root := os.Getenv(helperEnv)
	if root == "" {
		t.Skip("helper process only")
	}
	role, _ := strconv.Atoi(os.Getenv(helperEnv + "_ROLE"))
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	release, err := s.HoldRoleLock(Role(role))
	if err != nil {
		os.Stdout.WriteString("error " + err.Error() + "\n")
		return
	}
	defer release()
	os.Stdout.WriteString("locked\n")
	io.Copy(io.Discard, os.Stdin)
}

// holdInOtherProcess starts the helper with role and returns once it
// holds the lock; the returned function ends it.
func holdInOtherProcess(t *testing.T, s *Store, role Role) func() {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldRoleLock$")
	cmd.Env = append(os.Environ(), helperEnv+"="+s.Root, helperEnv+"_ROLE="+strconv.Itoa(int(role)))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		stdin.Close()
		cmd.Wait()
		t.Fatalf("helper: %q %v", line, err)
	}
	return func() {
		stdin.Close()
		io.Copy(io.Discard, stdout)
		cmd.Wait()
	}
}

// TestRoleLocks shows both outcomes of CheckPeerLock with a second
// process: nil while the other side holds its lock, ErrPeerLock when it
// does not.
func TestRoleLocks(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// No server has ever run: no lock file.
	if err := s.CheckPeerLock(RoleServer); !errors.Is(err, ErrPeerLock) {
		t.Fatalf("missing server lock: %v", err)
	}
	// A running server (other process) holds its lock.
	stop := holdInOtherProcess(t, s, RoleServer)
	if err := s.CheckPeerLock(RoleServer); err != nil {
		t.Fatalf("running server not seen: %v", err)
	}
	if _, err := s.HoldRoleLock(RoleServer); !errors.Is(err, ErrLocked) {
		t.Fatalf("second server: %v", err)
	}
	stop()
	// The server has ended: its lock file remains, the lock is free.
	if err := s.CheckPeerLock(RoleServer); !errors.Is(err, ErrPeerLock) {
		t.Fatalf("ended server: %v", err)
	}
	// Clients share their lock; the server sees a running client.
	stop = holdInOtherProcess(t, s, RoleClient)
	if err := s.CheckPeerLock(RoleClient); err != nil {
		t.Fatalf("running client not seen: %v", err)
	}
	release, err := s.HoldRoleLock(RoleClient)
	if err != nil {
		t.Fatalf("second client: %v", err)
	}
	if _, err := s.HoldRoleLock(RoleClient); !errors.Is(err, ErrLocked) {
		t.Fatalf("second client lock in one process: %v", err)
	}
	stop()
	if err := s.CheckPeerLock(RoleClient); err != nil {
		t.Fatalf("client of this process not seen: %v", err)
	}
	release()
	release()
	if err := s.CheckPeerLock(RoleClient); !errors.Is(err, ErrPeerLock) {
		t.Fatalf("ended clients: %v", err)
	}
	// The server of this process and the client check of another one.
	release, err = s.HoldRoleLock(RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckPeerLock(RoleServer); err != nil {
		t.Fatalf("server of this process: %v", err)
	}
	release()
	if _, err := s.HoldRoleLock(Role(9)); err == nil {
		t.Fatal("unknown role")
	}
	if err := s.CheckPeerLock(Role(0)); err == nil || errors.Is(err, ErrPeerLock) {
		t.Fatal("unknown peer")
	}
	// A lock directory that cannot be created.
	os.RemoveAll(s.Path(locksDir))
	os.WriteFile(s.Path(locksDir), nil, 0o600)
	if _, err := s.HoldRoleLock(RoleServer); err == nil {
		t.Fatal("role lock below a file")
	}
	if err := s.CheckPeerLock(RoleServer); err == nil || errors.Is(err, ErrPeerLock) || errors.Is(err, ErrLocked) {
		t.Fatalf("unreadable lock file: %v", err)
	}
}
