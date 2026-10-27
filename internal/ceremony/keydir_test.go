//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/witness"
)

// TestKeyDirSwap: the key directory is swapped for a symbolic link to
// another directory between the checks and the writing of the keys
// (injection point "export", task 10b finding 3). commit refuses with
// ErrKeyDir, and nothing is written there or into the export.
func TestKeyDirSwap(t *testing.T) {
	f := &fixture{base: t.TempDir(), w: []witness.Key{witnessKey(t, "w")}}
	defer func() { crashHook = nil }()
	for n, c := range []struct {
		name   string
		exists bool                        // key directory exists before the ceremony
		swap   func(kd, evil string) error // at "export" or "keydir"
		point  string
	}{
		{"replaced by a link after the checks of commit", true, func(kd, evil string) error {
			if err := os.Rename(kd, kd+".old"); err != nil {
				return err
			}
			return os.Symlink(evil, kd)
		}, "keydir"},
		{"existing replaced by a link", true, func(kd, evil string) error {
			if err := os.Rename(kd, kd+".old"); err != nil {
				return err
			}
			return os.Symlink(evil, kd)
		}, "export"},
		{"missing, a link appears", false, func(kd, evil string) error { return os.Symlink(evil, kd) }, "export"},
		{"existing replaced by a link to a link", true, func(kd, evil string) error {
			if err := os.Rename(kd, kd+".old"); err != nil {
				return err
			}
			if err := os.Symlink(evil, kd+".l"); err != nil {
				return err
			}
			return os.Symlink(kd+".l", kd)
		}, "export"},
		{"existing replaced by an open directory", true, func(kd, evil string) error {
			if err := os.Rename(kd, kd+".old"); err != nil {
				return err
			}
			if err := os.Mkdir(kd, 0o700); err != nil {
				return err
			}
			return os.Chmod(kd, 0o755)
		}, "export"},
	} {
		base := filepath.Join(f.base, fmt.Sprint(n))
		os.Mkdir(base, 0o700)
		out, kd, evil := filepath.Join(base, "out"), filepath.Join(base, "keys"), filepath.Join(base, "evil")
		if err := os.Mkdir(evil, 0o700); err != nil {
			t.Fatal(err)
		}
		if c.exists {
			if err := os.Mkdir(kd, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		crashHook = func(point string) error {
			if point == c.point {
				return c.swap(kd, evil)
			}
			return nil
		}
		p := &prompter{scr: &screen{}}
		o := f.opts(out, kd, p)
		o.MinWitnesses = 1
		_, err := Init(o)
		crashHook = nil
		if !errors.Is(err, ErrKeyDir) {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, d := range []string{evil, kd + ".old", kd} {
			if fi, err := os.Lstat(d); err != nil || !fi.IsDir() {
				continue
			}
			if names := listDir(t, d); len(names) != 0 {
				t.Fatalf("%s: %s holds %v", c.name, d, names)
			}
		}
		if _, err := os.Lstat(out); err == nil {
			t.Fatalf("%s: export written", c.name)
		}
		assertNoStaging(t, base)
	}
}

// TestKeyDirSwapAfterOpen: the key directory is swapped for a symbolic
// link after commit opened and checked it (injection point "root", task
// 10c finding 2). The keys are written relative to the opened directory
// (now kd+".old"), never by path: the target of the link stays empty and
// the ceremony succeeds.
func TestKeyDirSwapAfterOpen(t *testing.T) {
	f := &fixture{base: t.TempDir(), w: []witness.Key{witnessKey(t, "w")}}
	defer func() { crashHook = nil }()
	for _, exists := range []bool{true, false} {
		base := filepath.Join(f.base, fmt.Sprint(exists))
		os.Mkdir(base, 0o700)
		out, kd, evil := filepath.Join(base, "out"), filepath.Join(base, "keys"), filepath.Join(base, "evil")
		if err := os.Mkdir(evil, 0o700); err != nil {
			t.Fatal(err)
		}
		if exists {
			if err := os.Mkdir(kd, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		swapped := false
		crashHook = func(point string) error {
			if point != "root" {
				return nil
			}
			swapped = true
			if err := os.Rename(kd, kd+".old"); err != nil {
				return err
			}
			return os.Symlink(evil, kd)
		}
		p := &prompter{scr: &screen{}}
		o := f.opts(out, kd, p)
		o.MinWitnesses = 1
		res, err := Init(o)
		crashHook = nil
		if err != nil || !swapped {
			t.Fatalf("exists %v: %v (swapped %v)", exists, err, swapped)
		}
		if names := listDir(t, evil); len(names) != 0 {
			t.Fatalf("exists %v: keys in the link target: %v", exists, names)
		}
		if names := listDir(t, kd+".old"); fmt.Sprint(names) != "[admin-1.key ingest-1.key]" {
			t.Fatalf("exists %v: opened directory holds %v", exists, names)
		}
		for _, n := range []string{"admin-1.key", "ingest-1.key"} {
			fi, err := os.Lstat(filepath.Join(kd+".old", n))
			if err != nil || fi.Mode() != 0o600 {
				t.Fatalf("%s: %v", n, err)
			}
		}
		priv, _, err := ReadKey(filepath.Join(kd+".old", "admin-1.key"), store.KeyRoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(filepath.Join(res.Out, "platform", "admin-1.pub"))
		if !bytes.Equal(data, priv.Public().(ed25519.PublicKey)) {
			t.Fatal("admin key does not match the export")
		}
		assertNoStaging(t, base)
	}
}

// TestKeyDirMode: an existing key directory must have mode 0700 and
// belong to the user, and its last element must not be a symbolic link;
// it is refused before anything is shown.
func TestKeyDirMode(t *testing.T) {
	f := &fixture{base: t.TempDir(), w: []witness.Key{witnessKey(t, "w")}}
	kd := filepath.Join(f.base, "keys")
	os.Mkdir(kd, 0o700)
	for _, mode := range []os.FileMode{0o750, 0o705, 0o500, os.ModeSticky | 0o700, os.ModeSetgid | 0o700} {
		if err := os.Chmod(kd, mode); err != nil {
			t.Fatal(err)
		}
		p := &prompter{scr: &screen{}}
		o := f.opts(filepath.Join(f.base, "out"), kd, p)
		o.MinWitnesses = 1
		if _, err := Init(o); !errors.Is(err, ErrKeyDir) || len(p.handovers) != 0 {
			t.Fatalf("mode %04o: %v", mode, err)
		}
	}
	os.Chmod(kd, 0o700)
	// A link as the last element of the key directory is refused before
	// it is resolved and before any share is shown (task 10e finding 5),
	// with or without a trailing slash, also when its target would pass
	// the checks; a link to a missing directory as well.
	f2 := newFixture(t)
	link := filepath.Join(f.base, "link")
	os.Symlink(kd, link)
	dangling := filepath.Join(f.base, "dangling")
	os.Symlink(filepath.Join(f.base, "missing"), dangling)
	for _, l := range []string{link, link + "/", dangling} {
		p := &prompter{scr: &screen{}}
		o := f.opts(filepath.Join(f.base, "out"), l, p)
		o.MinWitnesses = 1
		if _, err := Init(o); !errors.Is(err, ErrKeyDir) || !strings.Contains(err.Error(), "symbolic link") || len(p.handovers) != 0 {
			t.Fatalf("%s: %v, %d handovers", l, err, len(p.handovers))
		}
		u, up := f2.unlock(1, 2, 3)
		if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: filepath.Join(f.base, "rot"), KeyDir: l, Gen: 2, ValidFrom: testNow}); !errors.Is(err, ErrKeyDir) || len(up.asked) != 0 {
			t.Fatalf("rotate %s: %v, asked %v", l, err, up.asked)
		}
	}
	if names := listDir(t, kd); len(names) != 0 {
		t.Fatalf("keys behind the link: %v", names)
	}
	for _, d := range []string{"out", "rot", "missing"} {
		if _, err := os.Lstat(filepath.Join(f.base, d)); err == nil {
			t.Fatalf("%s written", d)
		}
	}
	// A link in an element before the last is resolved: the keys go to
	// the directory it leads to.
	parentLink := filepath.Join(f.base, "parent")
	os.Symlink(f.base, parentLink)
	o := f.opts(filepath.Join(f.base, "out"), filepath.Join(parentLink, "keys"), &prompter{scr: &screen{}})
	o.MinWitnesses = 1
	if _, err := Init(o); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"admin-1.key", "ingest-1.key"} {
		fi, err := os.Lstat(filepath.Join(kd, n))
		if err != nil || fi.Mode() != 0o600 {
			t.Fatalf("%s: %v %v", n, fi.Mode(), err)
		}
	}
	if os.Getuid() != 0 {
		t.Log("not root: the owner check is not tested")
		return
	}
	kd2 := filepath.Join(f.base, "keys2")
	os.Mkdir(kd2, 0o700)
	if err := os.Chown(kd2, 12345, 12345); err != nil {
		t.Fatal(err)
	}
	p := &prompter{scr: &screen{}}
	o = f.opts(filepath.Join(f.base, "out2"), kd2, p)
	o.MinWitnesses = 1
	if _, err := Init(o); !errors.Is(err, ErrKeyDir) || len(p.handovers) != 0 {
		t.Fatalf("foreign owner: %v", err)
	}
	// Swapped at "export" for a directory of another user.
	kd3 := filepath.Join(f.base, "keys3")
	os.Mkdir(kd3, 0o700)
	defer func() { crashHook = nil }()
	crashHook = func(point string) error {
		if point == "export" {
			os.Rename(kd3, kd3+".old")
			os.Mkdir(kd3, 0o700)
			return os.Chown(kd3, 12345, 12345)
		}
		return nil
	}
	o = f.opts(filepath.Join(f.base, "out3"), kd3, &prompter{scr: &screen{}})
	o.MinWitnesses = 1
	if _, err := Init(o); !errors.Is(err, ErrKeyDir) {
		t.Fatalf("swapped for a foreign directory: %v", err)
	}
	if names := listDir(t, kd3); len(names) != 0 {
		t.Fatalf("keys in the foreign directory: %v", names)
	}
}
