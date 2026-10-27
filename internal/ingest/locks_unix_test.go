//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ingest

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

const lockHelperEnv = "GOMAIL_INGEST_LOCK_HELPER"

// TestHelperHoldRoleLock is not a test: started by the tests below as a
// second process, it holds a role lock on the data directory until its
// standard input ends.
func TestHelperHoldRoleLock(t *testing.T) {
	root := os.Getenv(lockHelperEnv)
	if root == "" {
		t.Skip("helper process only")
	}
	role, _ := strconv.Atoi(os.Getenv(lockHelperEnv + "_ROLE"))
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	release, err := s.HoldRoleLock(store.Role(role))
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
func holdInOtherProcess(t *testing.T, s *store.Store, role store.Role) func() {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldRoleLock$")
	cmd.Env = append(os.Environ(), lockHelperEnv+"="+s.Root, lockHelperEnv+"_ROLE="+strconv.Itoa(int(role)))
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
	stop := func() {
		stdin.Close()
		io.Copy(io.Discard, stdout)
		cmd.Wait()
	}
	t.Cleanup(stop)
	return stop
}

func lockConfig(env *testenv.Env) Config {
	return Config{Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1, Now: env.Clock.Now}
}

// TestServerLock: New holds locks/server until Close (9.1); a second
// server in this process or in another one cannot start meanwhile, and a
// client sees the running server.
func TestServerLock(t *testing.T) {
	env := testenv.New(t)
	if err := env.Store.CheckPeerLock(store.RoleServer); !errors.Is(err, store.ErrPeerLock) {
		t.Fatalf("server lock before New: %v", err)
	}
	in, err := New(lockConfig(env))
	if err != nil {
		t.Fatal(err)
	}
	// What a client checks at its start.
	if err := env.Store.CheckPeerLock(store.RoleServer); err != nil {
		t.Fatalf("running server not seen: %v", err)
	}
	// A second server in this process (a second descriptor).
	if _, err := New(lockConfig(env)); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("second server: %v", err)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if err := env.Store.CheckPeerLock(store.RoleServer); !errors.Is(err, store.ErrPeerLock) {
		t.Fatalf("server lock after Close: %v", err)
	}
	// A server in another process.
	stop := holdInOtherProcess(t, env.Store, store.RoleServer)
	if _, err := New(lockConfig(env)); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("server while another process holds the lock: %v", err)
	}
	stop()
	in, err = New(lockConfig(env))
	if err != nil {
		t.Fatalf("after the other server ended: %v", err)
	}
	in.Close()
}

// TestPeerCheck: with PeerCheck, New requires a running client (9.1) and
// releases its own lock when there is none; without it, New does not
// look at the client lock.
func TestPeerCheck(t *testing.T) {
	env := testenv.New(t)
	peer := func(c Config) Config { c.PeerCheck = true; return c }
	// No client has ever run.
	if _, err := New(peer(lockConfig(env))); !errors.Is(err, store.ErrPeerLock) {
		t.Fatalf("no client: %v", err)
	}
	// The failed New released the server lock.
	if err := env.Store.CheckPeerLock(store.RoleServer); !errors.Is(err, store.ErrPeerLock) {
		t.Fatalf("server lock kept after a failed New: %v", err)
	}
	// The default does not require a client.
	in, err := New(lockConfig(env))
	if err != nil {
		t.Fatal(err)
	}
	in.Close()
	// A client in another process.
	stop := holdInOtherProcess(t, env.Store, store.RoleClient)
	in, err = New(peer(lockConfig(env)))
	if err != nil {
		t.Fatalf("client in another process not seen: %v", err)
	}
	in.Close()
	stop()
	// The client has ended: its lock file remains, the lock is free.
	if _, err := New(peer(lockConfig(env))); !errors.Is(err, store.ErrPeerLock) {
		t.Fatalf("ended client: %v", err)
	}
	// A client in this process (a second descriptor).
	release, err := env.Store.HoldRoleLock(store.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	in, err = New(peer(lockConfig(env)))
	if err != nil {
		t.Fatalf("client in this process not seen: %v", err)
	}
	in.Close()
	release()
	// A lock file of the client that cannot be probed: fail closed.
	os.Remove(env.Store.Path("locks", "client"))
	if err := os.Mkdir(env.Store.Path("locks", "client"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(peer(lockConfig(env))); err == nil {
		t.Fatal("unprobeable client lock accepted")
	}
	if err := env.Store.CheckPeerLock(store.RoleServer); !errors.Is(err, store.ErrPeerLock) {
		t.Fatalf("server lock kept: %v", err)
	}
	// The server lock itself cannot be taken.
	os.Remove(env.Store.Path("locks", "server"))
	if err := os.Mkdir(env.Store.Path("locks", "server"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(lockConfig(env)); err == nil {
		t.Fatal("New without the server lock")
	}
}
