package client_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 24 package B, backlog 57 (N4 of the attack review and N1
// of the specification review of task 22: resolveExisting cleaned a ".."
// in the target of a dangling link lexically).

// TestClientDirLinkDotDotIntoDataDir: links/sub is a symbolic link to the
// data directory (<base>/data) and links/L a dangling link to
// "sub/../data/client". The system resolves the ".." on the target of
// sub, so L names <base>/data/client, inside the data directory; cleaned
// lexically it would be links/data/client, outside. A client directory
// named through L (at the directory itself, at a parent, or through a
// further link to L, and through a ".." two levels up from a directory
// inside the data directory) is inside it for Config.check
// (ErrInsideDataDir), and nothing is created in the data directory.
func TestClientDirLinkDotDotIntoDataDir(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	work := filepath.Join(env.Store.Root, "work24")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	before := entries(t, env.Store.Root)
	links := filepath.Join(env.Base, "links24")
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
	if filepath.Base(env.Store.Root) != "data" {
		t.Fatalf("data directory %s: the targets below assume <base>/data", env.Store.Root)
	}
	link("sub", env.Store.Root)
	link("sub2", work)
	l := link("L", "sub/../data/client")
	l2 := link("L2", "sub2/../../data/client2")
	chain := link("chain", "L")
	// Cleaned lexically, L would be outside the data directory: the
	// case the test is about.
	lexR, err1 := client.ResolveExisting(filepath.Join(links, "data", "client"))
	inR, err2 := client.ResolveExisting(filepath.Join(env.Store.Root, "client"))
	if err1 != nil || err2 != nil || lexR == inR {
		t.Fatalf("the lexical reading of L is inside the data directory (%v, %v)", err1, err2)
	}
	for _, dir := range []string{l, filepath.Join(l, "client"), l2, chain, filepath.Join(chain, "client")} {
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
		t.Fatalf("work24/: %v", got)
	}
}

// TestResolveExistingStepwise: resolveExisting resolves a link target
// component by component: a ".." after a link applies to the target of
// the link, a ".." after a missing component removes it again, and a
// link reached through a ".." is followed. At most 40 links are followed
// in all: a chain of 40 dangling links resolves to its target, a chain of
// 41 is an error (fail closed, task 24 package B, follow-up B2; want "").
func TestResolveExistingStepwise(t *testing.T) {
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
	mk(filepath.Join(base, "real", "a", "b"))
	mk(filepath.Join(base, "links"))
	mk(filepath.Join(base, "chain40"))
	mk(filepath.Join(base, "chain41"))
	// links/deep -> real/a/b; links/up -> deep/../../gone: real/gone.
	ln(filepath.Join(base, "real", "a", "b"), filepath.Join(base, "links", "deep"))
	ln("deep/../../gone", filepath.Join(base, "links", "up"))
	// links/miss -> nothere/../deep/new: the ".." removes nothere, then
	// deep is a link again: real/a/b/new.
	ln("nothere/../deep/new", filepath.Join(base, "links", "miss"))
	// links/twice -> up/../x: up resolves to real/gone (missing), ".."
	// to real.
	ln("up/../x", filepath.Join(base, "links", "twice"))
	chain := func(dir string, n int) {
		t.Helper()
		for i := 1; i < n; i++ {
			ln(fmt.Sprintf("l%d", i+1), filepath.Join(dir, fmt.Sprintf("l%d", i)))
		}
		ln(filepath.Join(base, "real", "end"), filepath.Join(dir, fmt.Sprintf("l%d", n)))
	}
	chain(filepath.Join(base, "chain40"), 40)
	chain(filepath.Join(base, "chain41"), 41)
	for _, c := range []struct{ in, want string }{
		{filepath.Join(base, "links", "deep", "x"), filepath.Join(base, "real", "a", "b", "x")},
		{filepath.Join(base, "links", "up", "x"), filepath.Join(base, "real", "gone", "x")},
		{filepath.Join(base, "links", "miss", "x"), filepath.Join(base, "real", "a", "b", "new", "x")},
		{filepath.Join(base, "links", "twice", "y"), filepath.Join(base, "real", "x", "y")},
		{filepath.Join(base, "chain40", "l1", "x"), filepath.Join(base, "real", "end", "x")},
		{filepath.Join(base, "chain41", "l1", "x"), ""},
		{filepath.Join(base, "real"), filepath.Join(base, "real")},
		{string(filepath.Separator), string(filepath.Separator)},
	} {
		got, err := client.ResolveExisting(c.in)
		if got != c.want || (err != nil) != (c.want == "") {
			t.Errorf("%s: %q (%v), want %q", c.in, got, err, c.want)
		}
	}
}
