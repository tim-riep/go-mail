package client_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 25 package B (N1 and N2 of the review of task 24 package
// B, follow-up B2): the message of a client directory that cannot be
// checked against the data directory, and of one below a regular file.

// clientDirOps runs keygen, restore, Open, Register and DeviceLost on the
// client directory dir and returns their errors by name.
func clientDirOps(env *testenv.Env, u *testenv.User, dir string) map[string]error {
	cfg := env.ClientConfig(dir)
	out := map[string]error{}
	_, out["keygen"] = client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
	_, out["restore"] = client.Restore(cfg, client.RestoreOptions{Words: u.Words}, testenv.Passphrase)
	c, err := client.Open(cfg, testenv.Passphrase)
	if c != nil {
		c.Close()
	}
	out["open"] = err
	_, out["register"] = client.Register(cfg, store.ID{})
	_, out["device lost"] = client.DeviceLost(cfg, testenv.Passphrase, u.Words)
	return out
}

// TestClientDirUncheckedMessage: a client directory whose path cannot be
// resolved (a cycle of links: ELOOP; a name longer than NAME_MAX:
// ENAMETOOLONG; without CAP_DAC_OVERRIDE also a directory below one
// without search permission: EACCES) is refused by every command with an
// error that errors.Is matches with ErrInsideDataDir and with the errno,
// and whose message names the errno, not the path, instead of claiming
// the directory is inside the data directory. Nothing is created in the
// data directory.
func TestClientDirUncheckedMessage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links and permission bits")
	}
	env := testenv.New(t)
	u := env.NewUser("alice")
	before := entries(t, env.Store.Root)
	if err := os.Symlink("cycB", filepath.Join(env.Base, "cycA")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("cycA", filepath.Join(env.Base, "cycB")); err != nil {
		t.Fatal(err)
	}
	nox := filepath.Join(env.Base, "nox")
	if err := os.MkdirAll(filepath.Join(nox, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nox, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(nox, 0o700) })
	cases := []struct {
		dir   string
		errno syscall.Errno
	}{
		{filepath.Join(env.Base, "cycA", "client"), syscall.ELOOP},
		{filepath.Join(env.Base, strings.Repeat("y", 300), "client"), syscall.ENAMETOOLONG},
	}
	if _, err := os.Lstat(filepath.Join(nox, "sub")); err == nil {
		t.Log("privileged: the EACCES case needs a process without CAP_DAC_OVERRIDE")
	} else {
		cases = append(cases, struct {
			dir   string
			errno syscall.Errno
		}{filepath.Join(nox, "sub", "client"), syscall.EACCES})
	}
	for _, c := range cases {
		for op, err := range clientDirOps(env, u, c.dir) {
			msg := ""
			if err != nil {
				msg = err.Error()
			}
			if !errors.Is(err, client.ErrInsideDataDir) || !errors.Is(err, c.errno) ||
				!strings.Contains(msg, c.errno.Error()) || strings.Contains(msg, client.ErrInsideDataDir.Error()) ||
				strings.Contains(msg, env.Base) {
				t.Errorf("%s (%v): %v, want ErrInsideDataDir naming %q and no path", op, c.errno, err, c.errno.Error())
			}
		}
	}
	if got := entries(t, env.Store.Root); !slices.Equal(got, before) {
		t.Errorf("data directory: %v, was %v", got, before)
	}
}

// TestClientDirBelowFile: a client directory below a regular file
// (gomailctl --dir <file>/x) is not inside the data directory: keygen,
// restore and Open fail with "not a directory" (ENOTDIR), Register and
// DeviceLost find no registered user, none with ErrInsideDataDir, and
// the file stays as it was (N2 of the review of
// task 24 package B, follow-up B2). resolveExisting keeps a component
// below something that is not a directory as a plain name.
func TestClientDirBelowFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ENOTDIR")
	}
	env := testenv.New(t)
	u := env.NewUser("alice")
	file := filepath.Join(env.Base, "file")
	if err := os.WriteFile(file, []byte("f"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := entries(t, env.Store.Root)
	for _, dir := range []string{filepath.Join(file, "x"), filepath.Join(file, "x", "client")} {
		for op, err := range clientDirOps(env, u, dir) {
			if errors.Is(err, client.ErrInsideDataDir) {
				t.Errorf("%s in %s: %v, want no ErrInsideDataDir", op, dir, err)
			}
			if op == "register" || op == "device lost" {
				if !errors.Is(err, client.ErrNotRegistered) {
					t.Errorf("%s in %s: %v, want ErrNotRegistered", op, dir, err)
				}
				continue
			}
			if !errors.Is(err, syscall.ENOTDIR) || !strings.Contains(err.Error(), "not a directory") {
				t.Errorf("%s in %s: %v, want not a directory", op, dir, err)
			}
		}
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "f" {
		t.Errorf("file: %q, %v", b, err)
	}
	if got := entries(t, env.Store.Root); !slices.Equal(got, before) {
		t.Errorf("data directory: %v, was %v", got, before)
	}
}
