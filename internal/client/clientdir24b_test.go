package client_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 24 package B, follow-up B2: resolveExisting fails closed
// where it cannot examine a component, and after more than 40 links.

// TestClientDirLongRealPath: a directory whose real path is longer than
// PATH_MAX holds a link M to the data directory (absolute or relative
// target). The client directory <base>/L/<rest>/M/client24b, with L a
// link to the upper part of the deep directory, is about 2 KB long and
// inside the data directory for the system; resolved as a string it is
// longer than PATH_MAX and Lstat fails with ENAMETOOLONG. Keygen and
// Open refuse it with ErrInsideDataDir and create nothing in the data
// directory (finding 1 of the robustness review of package B; before
// B2, M was kept as a plain name and both created data/client24b).
// Linux only: the deep directory is built through /proc/self/fd.
func TestClientDirLongRealPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("builds the deep directory through /proc/self/fd")
	}
	for _, tc := range []string{"keygen/abs", "open/abs", "keygen/rel", "open/rel"} {
		op, mode, _ := strings.Cut(tc, "/")
		t.Run(tc, func(t *testing.T) {
			env := testenv.New(t)
			base, err := filepath.EvalSymlinks(env.Base)
			if err != nil {
				t.Fatal(err)
			}
			const levels = 24 // 24 * 201 bytes > PATH_MAX (4096)
			cur, comps := deepDir(t, base, levels)
			target := env.Store.Root
			if mode == "rel" {
				rd, err := filepath.Rel(base, env.Store.Root)
				if err != nil {
					t.Fatal(err)
				}
				target = strings.Repeat("../", levels) + rd
			}
			if err := os.Symlink(target, "/proc/self/fd/"+strconv.Itoa(int(cur.Fd()))+"/M"); err != nil {
				t.Fatal(err)
			}
			cur.Close()
			if err := os.Symlink(filepath.Join(append([]string{base}, comps[:14]...)...), filepath.Join(base, "L")); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(append(append([]string{base, "L"}, comps[14:]...), "M", "client24b")...)
			if len(dir) >= 4096 {
				t.Fatalf("client directory %d bytes: the system would refuse it itself", len(dir))
			}
			// The system reaches the data directory through dir.
			if fi, err := os.Stat(filepath.Dir(dir)); err != nil || !fi.IsDir() {
				t.Fatalf("system: %v", err)
			}
			if _, err := client.ResolveExisting(dir); !errors.Is(err, syscall.ENAMETOOLONG) {
				t.Errorf("resolveExisting: %v, want ENAMETOOLONG", err)
			}
			before := entries(t, env.Store.Root)
			cfg := env.ClientConfig(dir)
			switch op {
			case "keygen":
				_, err = client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
			case "open":
				var c *client.Client
				c, err = client.Open(cfg, testenv.Passphrase)
				if c != nil {
					c.Close()
				}
			}
			if !errors.Is(err, client.ErrInsideDataDir) {
				t.Errorf("%s: %v, want ErrInsideDataDir", op, err)
			}
			if after := entries(t, env.Store.Root); !slices.Equal(after, before) {
				t.Errorf("%s created in the data directory: %v, was %v", op, after, before)
			}
		})
	}
}

// deepDir creates below base a chain of levels directories with names of
// 200 bytes, through /proc/self/fd so that no path string is longer than
// PATH_MAX, and returns an open handle on the deepest one and the names.
func deepDir(t *testing.T, base string, levels int) (*os.File, []string) {
	t.Helper()
	cur, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	var comps []string
	for i := 0; i < levels; i++ {
		name := fmt.Sprintf("%02d", i) + strings.Repeat("x", 198)
		p := "/proc/self/fd/" + strconv.Itoa(int(cur.Fd())) + "/" + name
		if err := os.Mkdir(p, 0o700); err != nil {
			cur.Close()
			t.Fatal(err)
		}
		next, err := os.Open(p)
		cur.Close()
		if err != nil {
			t.Fatal(err)
		}
		cur = next
		comps = append(comps, name)
	}
	return cur, comps
}

// TestClientDirChain41IntoDataDir: a chain of 41 symbolic links whose
// last one names the data directory is refused by every command with
// ErrInsideDataDir, as one of 40 links, and nothing is created in the
// data directory (N1 of the specification review of package B: before
// B2, chains of 41 to 255 links were outside for the check). The system
// itself refuses more than 40 links (ELOOP); resolveExisting does too.
func TestClientDirChain41IntoDataDir(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	before := entries(t, env.Store.Root)
	for _, n := range []int{40, 41} {
		dir := filepath.Join(env.Base, fmt.Sprintf("chain24b_%d", n))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= n; i++ {
			target := fmt.Sprintf("l%d", i+1)
			if i == n {
				target = env.Store.Root
			}
			if err := os.Symlink(target, filepath.Join(dir, fmt.Sprintf("l%d", i))); err != nil {
				t.Fatal(err)
			}
		}
		cdir := filepath.Join(dir, "l1", "client")
		_, err := client.ResolveExisting(cdir)
		if n == 41 && !errors.Is(err, syscall.ELOOP) || n == 40 && err != nil {
			t.Errorf("chain of %d: resolveExisting: %v", n, err)
		}
		cfg := env.ClientConfig(cdir)
		if _, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{}); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("chain of %d: keygen: %v", n, err)
		}
		if _, err := client.Restore(cfg, client.RestoreOptions{Words: u.Words}, testenv.Passphrase); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("chain of %d: restore: %v", n, err)
		}
		if c, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrInsideDataDir) {
			if c != nil {
				c.Close()
			}
			t.Fatalf("chain of %d: open: %v", n, err)
		}
		if _, err := client.Register(cfg, store.ID{}); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("chain of %d: register: %v", n, err)
		}
		if _, err := client.DeviceLost(cfg, testenv.Passphrase, u.Words); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("chain of %d: device lost: %v", n, err)
		}
	}
	if got := entries(t, env.Store.Root); !slices.Equal(got, before) {
		t.Fatalf("data directory: %v, was %v", got, before)
	}
}

// TestResolveExistingDotAndRoot: a "." in a link target, in the path
// itself and in an absolute target stays in the directory resolved so
// far (it is not a ".."), and a link to "/" restarts at the root, where a
// ".." stays.
func TestResolveExistingDotAndRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a link to the root of a volume")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "real", "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	links := filepath.Join(base, "links")
	if err := os.Mkdir(links, 0o700); err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)
	ln := func(target, name string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(links, name)); err != nil {
			t.Fatal(err)
		}
	}
	ln("../real/./a/./b/.", "dot")                  // real/a/b
	ln("./../real/a/.", "dot2")                     // real/a
	ln(base+sep+"."+sep+"real"+sep+".", "absdot")   // real
	ln(sep, "top")                                  // /
	ln(sep+".."+sep+".."+base+sep+"real", "topdot") // real
	rel := strings.TrimPrefix(base, sep)
	for _, c := range []struct{ in, want string }{
		{filepath.Join(links, "dot", "x"), filepath.Join(base, "real", "a", "b", "x")},
		{filepath.Join(links, "dot2", "b", "x"), filepath.Join(base, "real", "a", "b", "x")},
		{filepath.Join(links, "absdot", "a", "x"), filepath.Join(base, "real", "a", "x")},
		{base + sep + "real" + sep + "." + sep + "a" + sep + "." + sep + "x", filepath.Join(base, "real", "a", "x")},
		{filepath.Join(links, "top", rel, "real", "a", "x"), filepath.Join(base, "real", "a", "x")},
		{filepath.Join(links, "top") + sep + ".." + sep + rel + sep + "real", filepath.Join(base, "real")},
		{filepath.Join(links, "top"), sep},
		{filepath.Join(links, "topdot", "a"), filepath.Join(base, "real", "a")},
	} {
		got, err := client.ResolveExisting(c.in)
		if err != nil || got != c.want {
			t.Errorf("%s: %q (%v), want %q", c.in, got, err, c.want)
		}
	}
}
