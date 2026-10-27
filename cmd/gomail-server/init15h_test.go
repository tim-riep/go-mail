package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/witness"
)

// initDirsSorted are the directories "gomail-server init" creates below
// the root, sorted: the top-level directories of store.Init, locks/ and
// log/.
var initDirsSorted = []string{"invites", "locks", "log", "mailboxes", "platform", "spool", "users", "work"}

// testPin writes a pin of the real ceremony (or, with dev, a
// development pin) with n witnesses and quorum min to dir/name and
// returns it.
func testPin(t *testing.T, dir, name string, dev bool, n, min int) (*store.PlatformPin, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := &store.PlatformPin{Gen: 1, Pub: pub, Dev: dev, Origin: "init.go-mail.test/log", MinWitnesses: min,
		Identities: []store.PlatformIdentity{{Gen: 1, Pub: pub}}}
	for i := 0; i < n; i++ {
		wpub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		p.Witnesses = append(p.Witnesses, store.Witness{Name: "w" + string(rune('a'+i)), Pub: wpub})
	}
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, path
}

// pinWitnessRec is the encoding of the pin's witnesses, in the order
// given by order (indexes into p.Witnesses).
func pinWitnessRec(t *testing.T, p *store.PlatformPin, order ...int) []byte {
	t.Helper()
	w := &witness.Witnesses{Min: p.MinWitnesses}
	for _, i := range order {
		w.List = append(w.List, witness.Key{Name: p.Witnesses[i].Name, Pub: p.Witnesses[i].Pub})
	}
	b, err := w.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runInit(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), append([]string{"init"}, args...), &out, &errb, nil)
	return code, out.String(), errb.String()
}

// checkInitLayout checks a data directory made by init: the root and
// the directories of initDirs with exactly 2770, nothing else, all
// empty except platform/witnesses.rec (mode 0660, content wrec), and
// store.Open accepts it.
func checkInitLayout(t *testing.T, root string, wrec []byte) {
	t.Helper()
	fi, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&dirModeBits != store.DirPerm {
		t.Fatalf("root mode %v", fi.Mode())
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
		fi, err := os.Lstat(filepath.Join(root, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if !fi.IsDir() || fi.Mode()&dirModeBits != store.DirPerm {
			t.Fatalf("%s: mode %v", e.Name(), fi.Mode())
		}
		sub, err := os.ReadDir(filepath.Join(root, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case e.Name() == "platform":
			if len(sub) != 1 || sub[0].Name() != ceremony.WitnessesFile {
				t.Fatalf("platform/: %v", sub)
			}
		case len(sub) != 0:
			t.Fatalf("%s/ not empty: %v", e.Name(), sub)
		}
	}
	sort.Strings(names)
	if strings.Join(names, " ") != strings.Join(initDirsSorted, " ") {
		t.Fatalf("entries %v, want %v", names, initDirsSorted)
	}
	wpath := filepath.Join(root, "platform", ceremony.WitnessesFile)
	wfi, err := os.Stat(wpath)
	if err != nil {
		t.Fatal(err)
	}
	if wfi.Mode() != store.FilePerm {
		t.Fatalf("witnesses.rec mode %v", wfi.Mode())
	}
	got, err := os.ReadFile(wpath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wrec) {
		t.Fatal("witnesses.rec differs")
	}
	if _, err := store.Open(root); err != nil {
		t.Fatal(err)
	}
}

// TestInitCreates (task 15h): init on a missing directory (its parent
// exists) and on an empty one creates the layout of section 4 with
// rights 2770, platform/witnesses.rec (0660) from the pin, and nothing
// else; a second init on it is refused.
func TestInitCreates(t *testing.T) {
	dir := t.TempDir()
	p, pin := testPin(t, dir, "identity-1.pin", false, 3, 2)
	want := pinWitnessRec(t, p, 0, 1, 2)

	missing := filepath.Join(dir, "data")
	code, out, errb := runInit("--data", missing, "--pin", pin)
	if code != 0 || !strings.Contains(out, "gomail-ceremony publish --from <export> --data "+missing) {
		t.Fatalf("missing directory: %d %s %s", code, out, errb)
	}
	checkInitLayout(t, missing, want)

	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := runInit("--data", empty, "--pin", pin); code != 0 {
		t.Fatalf("empty directory: %d %s", code, errb)
	}
	checkInitLayout(t, empty, want)

	// Again on a directory made by init: not empty, refused, unchanged.
	if code, _, errb := runInit("--data", missing, "--pin", pin); code != 2 || !strings.Contains(errb, "nicht leer") {
		t.Fatalf("second init: %d %s", code, errb)
	}
	checkInitLayout(t, missing, want)
}

// TestInitRefuses (task 15h): init refuses, before it creates anything,
// a directory that exists and is not empty, a missing parent, a file or
// a dangling link as --data, a pin it cannot read, and wrong arguments.
func TestInitRefuses(t *testing.T) {
	dir := t.TempDir()
	_, pin := testPin(t, dir, "identity-1.pin", false, 1, 1)

	full := filepath.Join(dir, "full")
	if err := os.Mkdir(full, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := runInit("--data", full, "--pin", pin); code != 2 || !strings.Contains(errb, "nicht leer") {
		t.Fatalf("not empty: %d %s", code, errb)
	}
	if ents, _ := os.ReadDir(full); len(ents) != 1 {
		t.Fatalf("not empty: changed to %v", ents)
	}
	if fi, _ := os.Stat(full); fi.Mode()&dirModeBits != 0o700 {
		t.Fatalf("not empty: mode changed to %v", fi.Mode())
	}
	// A non-empty directory whose only entry is an empty directory.
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(filepath.Join(sub, "platform"), 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runInit("--data", sub, "--pin", pin); code != 2 {
		t.Fatalf("directory with a subdirectory: %d", code)
	}

	noParent := filepath.Join(dir, "a", "b")
	if code, _, errb := runInit("--data", noParent, "--pin", pin); code != 2 || !strings.Contains(errb, "Elternverzeichnis") {
		t.Fatalf("missing parent: %d %s", code, errb)
	}
	if _, err := os.Stat(filepath.Join(dir, "a")); err == nil {
		t.Fatal("missing parent created")
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runInit("--data", file, "--pin", pin); code != 2 {
		t.Fatalf("file as --data: %d", code)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runInit("--data", dangling, "--pin", pin); code != 2 {
		t.Fatalf("dangling link as --data: %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "nowhere")); err == nil {
		t.Fatal("dangling link followed")
	}

	data := filepath.Join(dir, "data")
	garbage := filepath.Join(dir, "garbage.pin")
	if err := os.WriteFile(garbage, []byte("not a pin"), 0o600); err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(dir, "unreadable.pin")
	if err := os.Mkdir(unreadable, 0o700); err != nil { // a directory cannot be read as a pin
		t.Fatal(err)
	}
	for name, p := range map[string]string{"missing pin": filepath.Join(dir, "none.pin"), "garbage pin": garbage, "unreadable pin": unreadable} {
		if code, _, errb := runInit("--data", data, "--pin", p); code != 1 || !strings.Contains(errb, "Pin") {
			t.Fatalf("%s: %d %s", name, code, errb)
		}
		if _, err := os.Lstat(data); err == nil {
			t.Fatalf("%s: data directory created", name)
		}
	}
	for _, args := range [][]string{{}, {"--data", data}, {"--pin", pin}, {"--data", data, "--pin", pin, "extra"}, {"--data", data, "--pin", pin, "--dev"}} {
		if code, _, _ := runInit(args...); code != 2 {
			t.Fatalf("%v: %d", args, code)
		}
	}
	if _, err := os.Lstat(data); err == nil {
		t.Fatal("data directory created")
	}
}

// TestInitDevPin (task 15h): a development pin is refused by a
// production build (no tag gomail_dev) before anything is created; a
// test build with the development ceremony (ceremony.DevBuild) accepts
// it with a warning.
func TestInitDevPin(t *testing.T) {
	dir := t.TempDir()
	p, pin := testPin(t, dir, "identity-1.pin", true, 1, 1)
	data := filepath.Join(dir, "data")
	code, _, errb := runInit("--data", data, "--pin", pin)
	if !ceremony.DevBuild {
		if code != 2 || !strings.Contains(errb, "Entwicklungs-Pin") {
			t.Fatalf("development pin in a production build: %d %s", code, errb)
		}
		if _, err := os.Lstat(data); err == nil {
			t.Fatal("data directory created with a development pin")
		}
		return
	}
	if code != 0 || !strings.Contains(errb, "WARNUNG: Entwicklungs-Pin") {
		t.Fatalf("development pin in a test build: %d %s", code, errb)
	}
	checkInitLayout(t, data, pinWitnessRec(t, p, 0))
}

// TestInitWitnessesFile (task 15h): --witnesses must hold exactly the
// witnesses and the quorum of the pin, in any order; its bytes become
// platform/witnesses.rec. Another quorum, another witness, a file that
// does not decode are refused before anything is created.
func TestInitWitnessesFile(t *testing.T) {
	dir := t.TempDir()
	p, pin := testPin(t, dir, "identity-1.pin", false, 3, 2)
	write := func(name string, b []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	reordered := pinWitnessRec(t, p, 2, 0, 1)
	data := filepath.Join(dir, "data")
	if code, _, errb := runInit("--data", data, "--pin", pin, "--witnesses", write("ok.rec", reordered)); code != 0 {
		t.Fatalf("matching witnesses.rec: %d %s", code, errb)
	}
	checkInitLayout(t, data, reordered)

	other, _ := testPin(t, dir, "other.pin", false, 3, 2)
	quorum := &witness.Witnesses{Min: 3}
	for _, w := range p.Witnesses {
		quorum.List = append(quorum.List, witness.Key{Name: w.Name, Pub: w.Pub})
	}
	qb, err := quorum.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"other witnesses": pinWitnessRec(t, other, 0, 1, 2),
		"other quorum":    qb,
		"garbage":         []byte("x"),
	} {
		d := filepath.Join(dir, "data-"+strings.ReplaceAll(name, " ", "-"))
		if code, _, errb := runInit("--data", d, "--pin", pin, "--witnesses", write(name, b)); code != 1 || !strings.Contains(errb, "witnesses") {
			t.Fatalf("%s: %d %s", name, code, errb)
		}
		if _, err := os.Lstat(d); err == nil {
			t.Fatalf("%s: data directory created", name)
		}
	}
	if code, _, _ := runInit("--data", filepath.Join(dir, "d2"), "--pin", pin, "--witnesses", filepath.Join(dir, "none.rec")); code != 1 {
		t.Fatalf("missing --witnesses file: %d", code)
	}
}

// TestInitForeignGroup (task 15h): on an empty directory whose group
// the process does not belong to, init refuses after creating, removes
// the directories it made and restores the mode of the root. Needs root
// (chown to a foreign group) on Unix.
func TestInitForeignGroup(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() != 0 {
		t.Skip("needs root to give a directory a foreign group")
	}
	dir := t.TempDir()
	_, pin := testPin(t, dir, "identity-1.pin", false, 1, 1)
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o750); err != nil {
		t.Fatal(err)
	}
	const foreign = 54321
	if inGroup(foreign) {
		t.Skip("the process is in the test group")
	}
	if err := os.Chown(data, -1, foreign); err != nil {
		t.Skip(err)
	}
	if code, _, errb := runInit("--data", data, "--pin", pin); code != 1 || !strings.Contains(errb, "Gruppe") {
		t.Fatalf("foreign group: %d %s", code, errb)
	}
	ents, err := os.ReadDir(data)
	if err != nil || len(ents) != 0 {
		t.Fatalf("not rolled back: %v %v", ents, err)
	}
	if fi, _ := os.Stat(data); fi.Mode()&dirModeBits != fs.FileMode(0o750) {
		t.Fatalf("mode not restored: %v", fi.Mode())
	}
}
