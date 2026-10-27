package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of task 15k (findings of the verification of task 15h).

// treeState describes every entry below root: its mode and, for a
// regular file, its content.
func treeState(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		line := rel + " " + fi.Mode().String()
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			line += " " + string(b)
		}
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// setInitHook sets initHook until the test ends.
func setInitHook(t *testing.T, h func(stage, root string) error) {
	t.Helper()
	initHook = h
	t.Cleanup(func() { initHook = nil })
}

// TestDevPinRefusedInProduction (finding 1): a build without the
// development ceremony refuses a development pin in serve, address add,
// log repair and init with exit status 2 and the fixed message, before
// any lock or log: the server lock is held meanwhile (a command that
// tried to take it would end with exit status 1), and the data directory
// stays unchanged (no lock file, nothing in log/).
func TestDevPinRefusedInProduction(t *testing.T) {
	if ceremony.DevBuild {
		t.Skip("build with the development ceremony (gomail_dev)")
	}
	dir := t.TempDir()
	_, pin := testPin(t, dir, "identity-1.pin", false, 1, 1)
	_, devPin := testPin(t, dir, "dev.pin", true, 1, 1)
	data := filepath.Join(dir, "data")
	if code, _, errb := runInit("--data", data, "--pin", pin); code != 0 {
		t.Fatalf("init: %d %s", code, errb)
	}
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	release, err := st.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	before := treeState(t, data)
	mbx, _ := store.NewID(nil)
	for name, args := range map[string][]string{
		"serve": {"serve", "--data", data, "--listen", "127.0.0.1:0", "--ingest-key", filepath.Join(dir, "ingest-1.key"),
			"--pin", devPin, "--log-listen", "127.0.0.1:0"},
		"address add": {"address", "add", "info@example.org", "--mailbox", mbx.String(), "--data", data,
			"--admin-key", filepath.Join(dir, "admin-1.key"), "--pin", devPin},
		"log repair": {"log", "repair", "--data", data, "--pin", devPin},
		"init":       {"init", "--data", filepath.Join(dir, "data2"), "--pin", devPin},
	} {
		var out, errb bytes.Buffer
		code := run(context.Background(), args, &out, &errb, func(string, string) { t.Fatalf("%s: server started", name) })
		if code != 2 || !strings.Contains(errb.String(), devPinRefused) {
			t.Fatalf("%s with a development pin: %d %s", name, code, errb.String())
		}
	}
	if after := treeState(t, data); after != before {
		t.Fatalf("data directory changed:\n%s\n---\n%s", before, after)
	}
	if _, err := os.Lstat(filepath.Join(dir, "data2")); err == nil {
		t.Fatal("init created a data directory with a development pin")
	}
	if err := checkDevPin(&store.PlatformPin{Dev: true}); !errors.As(err, new(usageError)) {
		t.Fatalf("checkDevPin: %v", err)
	}
	if err := checkDevPin(&store.PlatformPin{}); err != nil {
		t.Fatalf("checkDevPin on a real pin: %v", err)
	}
}

// TestDevPinDevBuild (finding 1): a build with the development ceremony
// starts the server with a development pin and warns; address add and
// log repair run and warn.
func TestDevPinDevBuild(t *testing.T) {
	s := newLogSetup(t) // skips without gomail_dev
	if !s.p.Dev {
		t.Fatal("InitDev made no development pin")
	}
	logs := s.start(t)
	if !strings.Contains(logs.String(), "development pin") {
		t.Fatalf("no warning: %s", logs.String())
	}
	s2 := newLogSetup(t)
	var out, errb bytes.Buffer
	if code := run(context.Background(), s2.addArgs("info@example.org", s2.newMailbox(t)), &out, &errb, nil); code != 0 || !strings.Contains(errb.String(), devPinWarning) {
		t.Fatalf("address add: %d %s", code, errb.String())
	}
	errb.Reset()
	if code := run(context.Background(), []string{"log", "repair", "--data", s2.data, "--pin", s2.pin}, &out, &errb, nil); code != 0 || !strings.Contains(errb.String(), devPinWarning) {
		t.Fatalf("log repair: %d %s", code, errb.String())
	}
}

// TestInitSymlinks (finding 2): --data that is a symbolic link (to an
// empty directory, to a full one, dangling) and a parent whose last
// element is one are refused with exit status 2; nothing is created or
// changed.
func TestInitSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links")
	}
	dir := t.TempDir()
	_, pin := testPin(t, dir, "identity-1.pin", false, 1, 1)
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	before := treeState(t, target)
	if code, _, errb := runInit("--data", link, "--pin", pin); code != 2 || !strings.Contains(errb, "symbolischer Link") {
		t.Fatalf("link to an empty directory: %d %s", code, errb)
	}
	if after := treeState(t, target); after != before {
		t.Fatalf("target changed:\n%s", after)
	}
	// The parent's last element is a link.
	realParent := filepath.Join(dir, "real")
	if err := os.Mkdir(realParent, 0o750); err != nil {
		t.Fatal(err)
	}
	lparent := filepath.Join(dir, "lparent")
	if err := os.Symlink(realParent, lparent); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := runInit("--data", filepath.Join(lparent, "data"), "--pin", pin); code != 2 || !strings.Contains(errb, "Elternverzeichnis") {
		t.Fatalf("link as parent: %d %s", code, errb)
	}
	if ents, _ := os.ReadDir(realParent); len(ents) != 0 {
		t.Fatalf("created through the parent link: %v", ents)
	}
	// A link as an earlier element of the path is followed (only the
	// last element of the parent is checked).
	if code, _, errb := runInit("--data", filepath.Join(lparent, "sub", "..", "data2"), "--pin", pin); code != 2 {
		t.Fatalf("cleaned path through the parent link: %d %s", code, errb)
	}
	inner := filepath.Join(realParent, "inner")
	if err := os.Mkdir(inner, 0o750); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := runInit("--data", filepath.Join(lparent, "inner", "data"), "--pin", pin); code != 0 {
		t.Fatalf("link before the parent: %d %s", code, errb)
	}
	checkInitLayout(t, filepath.Join(inner, "data"), pinWitnessRec(t, mustPin(t, pin), 0))
}

func mustPin(t *testing.T, path string) *store.PlatformPin {
	t.Helper()
	p, err := store.ReadPlatformPin(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestInitRaceSymlink (finding 2): between the checks and the creation
// (initHook "checked") --data is replaced by a symbolic link to a
// foreign directory, inside the parent or outside it, or by another
// directory. init refuses (exit status 1 or 2); the foreign directory
// keeps its rights and content, and the link stays.
func TestInitRaceSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links")
	}
	dir := t.TempDir()
	_, pin := testPin(t, dir, "identity-1.pin", false, 1, 1)
	outside := t.TempDir()
	for _, tc := range []struct {
		name          string
		existing      bool
		foreignInside bool
	}{
		{"missing, link inside the parent", false, true},
		{"missing, link outside the parent", false, false},
		{"empty, link inside the parent", true, true},
		{"empty, link outside the parent", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
			if err := os.Mkdir(parent, 0o750); err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(outside, strings.ReplaceAll(tc.name, " ", "-"))
			if tc.foreignInside {
				foreign = filepath.Join(parent, "foreign")
			}
			if err := os.Mkdir(foreign, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, "keep.txt"), []byte("foreign"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(foreign, "empty"), 0o755); err != nil {
				t.Fatal(err)
			}
			before := treeState(t, foreign)
			data := filepath.Join(parent, "data")
			if tc.existing {
				if err := os.Mkdir(data, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			setInitHook(t, func(stage, root string) error {
				if stage != "checked" {
					return nil
				}
				if tc.existing {
					if err := os.Remove(root); err != nil {
						t.Error(err)
					}
				}
				if err := os.Symlink(foreign, root); err != nil {
					t.Error(err)
				}
				return nil
			})
			code, _, errb := runInit("--data", data, "--pin", pin)
			if code != 1 && code != 2 {
				t.Fatalf("exit %d %s", code, errb)
			}
			if after := treeState(t, foreign); after != before {
				t.Fatalf("foreign directory changed:\n%s\n---\n%s", before, after)
			}
			if li, err := os.Lstat(data); err != nil || li.Mode()&fs.ModeSymlink == 0 {
				t.Fatalf("link removed: %v %v", li, err)
			}
		})
	}
	// An empty directory replaced by another empty directory: refused,
	// the other one unchanged.
	parent := filepath.Join(dir, "replaced")
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(parent, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	setInitHook(t, func(stage, root string) error {
		if stage == "checked" {
			if err := os.Rename(root, root+".old"); err != nil {
				t.Error(err)
			}
			if err := os.Mkdir(root, 0o751); err != nil {
				t.Error(err)
			}
		}
		return nil
	})
	if code, _, errb := runInit("--data", data, "--pin", pin); code != 1 || !strings.Contains(errb, errInitRace.Error()) {
		t.Fatalf("replaced directory: %d %s", code, errb)
	}
	if fi, err := os.Stat(data); err != nil || fi.Mode()&dirModeBits != 0o751 {
		t.Fatalf("other directory changed: %v %v", fi, err)
	}
	if ents, _ := os.ReadDir(data); len(ents) != 0 {
		t.Fatalf("other directory filled: %v", ents)
	}
}

// TestInitRollbackForeign (finding 2): a failure after the directories
// were created (initHook "created") removes only what init made, by
// identity: a foreign empty directory, a directory swapped in for one of
// init's and an existing root keep standing; a root that was moved away
// is not removed at its old path when another directory took its place.
func TestInitRollbackForeign(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes")
	}
	dir := t.TempDir()
	_, pin := testPin(t, dir, "identity-1.pin", false, 1, 1)
	stop := errors.New("injected")

	// Foreign entries in a root init created.
	data := filepath.Join(dir, "data")
	setInitHook(t, func(stage, root string) error {
		if stage != "created" {
			return nil
		}
		if err := os.Mkdir(filepath.Join(root, "foreign"), 0o700); err != nil {
			t.Error(err)
		}
		// users/ moved away (a new directory cannot reuse its inode),
		// spool/ removed (its inode may be reused, not its mode 2770).
		if err := os.Rename(filepath.Join(root, "users"), filepath.Join(root, "users.init")); err != nil {
			t.Error(err)
		}
		for _, d := range []string{"users", "spool"} {
			if d == "spool" {
				if err := os.Remove(filepath.Join(root, d)); err != nil {
					t.Error(err)
				}
			}
			if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
				t.Error(err)
			}
		}
		return stop
	})
	if code, _, errb := runInit("--data", data, "--pin", pin); code != 1 || !strings.Contains(errb, "injected") {
		t.Fatalf("injected failure: %d %s", code, errb)
	}
	ents, err := os.ReadDir(data)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, " ") != "foreign spool users users.init" {
		t.Fatalf("after the rollback: %v", names)
	}

	// The root moved away, another empty directory in its place.
	data = filepath.Join(dir, "moved")
	setInitHook(t, func(stage, root string) error {
		if stage != "created" {
			return nil
		}
		if err := os.Rename(root, root+".away"); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(root, 0o751); err != nil {
			t.Error(err)
		}
		return stop
	})
	if code, _, errb := runInit("--data", data, "--pin", pin); code != 1 {
		t.Fatalf("moved root: %d %s", code, errb)
	}
	if fi, err := os.Stat(data); err != nil || fi.Mode()&dirModeBits != 0o751 {
		t.Fatalf("directory in place of the root: %v %v", fi, err)
	}
	if ents, _ := os.ReadDir(data + ".away"); len(ents) != 0 {
		t.Fatalf("moved root not emptied by identity: %v", ents)
	}

	// Without foreign entries: a created root is removed, an existing
	// empty one gets its mode back.
	setInitHook(t, func(stage, root string) error {
		if stage == "created" {
			return stop
		}
		return nil
	})
	data = filepath.Join(dir, "clean")
	if code, _, _ := runInit("--data", data, "--pin", pin); code != 1 {
		t.Fatal("clean failure")
	}
	if _, err := os.Lstat(data); err == nil {
		t.Fatal("created root not removed")
	}
	existing := filepath.Join(dir, "existing")
	if err := os.Mkdir(existing, 0o750); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runInit("--data", existing, "--pin", pin); code != 1 {
		t.Fatal("existing failure")
	}
	if fi, err := os.Stat(existing); err != nil || fi.Mode()&dirModeBits != 0o750 {
		t.Fatalf("existing root: %v %v", fi, err)
	}
	if ents, _ := os.ReadDir(existing); len(ents) != 0 {
		t.Fatalf("existing root not emptied: %v", ents)
	}
}

// TestInitContext (finding 3): init ends when its context ends (SIGINT
// through main's signal.NotifyContext): before anything is created, and
// after the directories, which it removes again.
func TestInitContext(t *testing.T) {
	dir := t.TempDir()
	_, pin := testPin(t, dir, "identity-1.pin", false, 1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := filepath.Join(dir, "data")
	var out, errb bytes.Buffer
	if code := run(ctx, []string{"init", "--data", data, "--pin", pin}, &out, &errb, nil); code != 1 || !strings.Contains(errb.String(), "abgebrochen") {
		t.Fatalf("canceled: %d %s", code, errb.String())
	}
	if _, err := os.Lstat(data); err == nil {
		t.Fatal("created after the cancel")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	setInitHook(t, func(stage, root string) error {
		if stage == "created" {
			cancel()
		}
		return nil
	})
	errb.Reset()
	if code := run(ctx, []string{"init", "--data", data, "--pin", pin}, &out, &errb, nil); code != 1 || !strings.Contains(errb.String(), "abgebrochen") {
		t.Fatalf("canceled after creating: %d %s", code, errb.String())
	}
	if _, err := os.Lstat(data); err == nil {
		t.Fatal("not rolled back after the cancel")
	}
}

// TestInitWitnessesMessage (finding 4): a --witnesses file that differs
// from the pin is errWitnessFile, without the prefix of
// translog.ErrMismatch (there is no data directory yet); the output
// names the source of platform/witnesses.rec.
func TestInitWitnessesMessage(t *testing.T) {
	dir := t.TempDir()
	p, pin := testPin(t, dir, "identity-1.pin", false, 3, 2)
	other, _ := testPin(t, dir, "other.pin", false, 3, 2)
	wrong := filepath.Join(dir, "wrong.rec")
	if err := os.WriteFile(wrong, pinWitnessRec(t, other, 0, 1, 2), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := initWitnesses(pin, wrong); !errors.Is(err, errWitnessFile) {
		t.Fatalf("initWitnesses: %v", err)
	}
	code, _, errb := runInit("--data", filepath.Join(dir, "d1"), "--pin", pin, "--witnesses", wrong)
	if code != 1 || !strings.Contains(errb, "--witnesses weicht von Zeugen und Quorum des Pins ab") || strings.Contains(errb, "translog") ||
		strings.Contains(errb, "data directory") {
		t.Fatalf("wrong witnesses: %d %s", code, errb)
	}
	right := filepath.Join(dir, "right.rec")
	if err := os.WriteFile(right, pinWitnessRec(t, p, 2, 1, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := runInit("--data", filepath.Join(dir, "d2"), "--pin", pin, "--witnesses", right)
	if code != 0 || !strings.Contains(out, "platform/witnesses.rec aus --witnesses") || strings.Contains(out, "aus dem Pin") {
		t.Fatalf("from --witnesses: %d %s %s", code, out, errb)
	}
	code, out, errb = runInit("--data", filepath.Join(dir, "d3"), "--pin", pin)
	if code != 0 || !strings.Contains(out, "platform/witnesses.rec aus dem Pin") {
		t.Fatalf("from the pin: %d %s %s", code, out, errb)
	}
}
