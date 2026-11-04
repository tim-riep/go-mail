package client_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 22 point 3 (review of task 20o: resolveExisting stopped
// at a dangling symbolic link).

// TestClientDirDanglingLinkIntoDataDir: a client directory named through
// a dangling symbolic link into the data directory (absolute or
// relative target, at the directory itself, at a parent, or a chain of
// dangling links) is inside it for Config.check (keygen, restore, Open,
// Register, DeviceLost: ErrInsideDataDir, not an error of mkdir), and
// nothing is created in the data directory.
func TestClientDirDanglingLinkIntoDataDir(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	work := filepath.Join(env.Store.Root, "work22")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	before := entries(t, env.Store.Root)
	links := filepath.Join(env.Base, "links")
	if err := os.Mkdir(links, 0o700); err != nil {
		t.Fatal(err)
	}
	link := func(name, target string) string {
		t.Helper()
		p := filepath.Join(links, name)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	abs := link("abs", filepath.Join(work, "missing"))
	rel, err := filepath.Rel(links, filepath.Join(work, "missing-rel"))
	if err != nil {
		t.Fatal(err)
	}
	relLink := link("rel", rel)
	parent := link("parent", filepath.Join(env.Store.Root, "missing", "deeper"))
	chain := link("chain", filepath.Join(links, "chain2"))
	link("chain2", filepath.Join(work, "missing-chain"))
	for _, dir := range []string{abs, relLink, filepath.Join(parent, "client"), chain, filepath.Join(chain, "client")} {
		cfg := env.ClientConfig(dir)
		if _, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{}); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("keygen in %s: %v", dir, err)
		}
		if _, err := client.Restore(cfg, client.RestoreOptions{Words: u.Words}, testenv.Passphrase); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("restore in %s: %v", dir, err)
		}
		if c, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrInsideDataDir) {
			if c != nil {
				c.Close()
			}
			t.Fatalf("open in %s: %v", dir, err)
		}
		if _, err := client.Register(cfg, store.ID{}); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("register in %s: %v", dir, err)
		}
		if _, err := client.DeviceLost(cfg, testenv.Passphrase, u.Words); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("device lost in %s: %v", dir, err)
		}
	}
	if got := entries(t, env.Store.Root); !slices.Equal(got, before) {
		t.Fatalf("data directory: %v, was %v", got, before)
	}
	if got := entries(t, work); len(got) != 0 {
		t.Fatalf("work/: %v", got)
	}
}

// TestResolveExisting: resolveExisting follows dangling symbolic links
// (absolute and relative targets, a ".." in a relative target applied to
// the resolved directory of the link) and stops on a cycle of dangling
// links, keeping the prefix as it is.
func TestResolveExisting(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mk := func(p string) {
		t.Helper()
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ln := func(target, p string) {
		t.Helper()
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	mk(filepath.Join(base, "real", "sub"))
	mk(filepath.Join(base, "other"))
	// base/via -> real/sub: a link to a directory, holding a dangling
	// link up ("..") into real.
	ln(filepath.Join(base, "real", "sub"), filepath.Join(base, "via"))
	ln(filepath.Join("..", "gone"), filepath.Join(base, "real", "sub", "up"))
	ln(filepath.Join(base, "real", "missing"), filepath.Join(base, "other", "abs"))
	ln("loop2", filepath.Join(base, "other", "loop1"))
	ln("loop1", filepath.Join(base, "other", "loop2"))
	for _, c := range []struct{ in, want string }{
		{filepath.Join(base, "other", "abs", "x"), filepath.Join(base, "real", "missing", "x")},
		{filepath.Join(base, "via", "up", "x"), filepath.Join(base, "real", "gone", "x")},
		{filepath.Join(base, "via", "new"), filepath.Join(base, "real", "sub", "new")},
		{filepath.Join(base, "other", "loop1", "x"), filepath.Join(base, "other", "loop1", "x")},
		{filepath.Join(base, "missing", "x"), filepath.Join(base, "missing", "x")},
	} {
		if got := client.ResolveExisting(c.in); got != c.want {
			t.Errorf("%s: %s, want %s", c.in, got, c.want)
		}
	}
}
