package client

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
)

// Internal tests of task 24 package B, follow-up B2: insideDataDir and
// createClientDir fail closed where resolveExisting cannot examine a
// component, and for relative paths.

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// TestInsideDataDirLongRealPath: a directory whose real path is longer
// than PATH_MAX, reached through a link L with a short path, holds a
// link M to the data directory. <B>/L/<rest>/M/client is in the data
// directory for the system; resolved as a string it is too long for
// Lstat (ENAMETOOLONG). insideDataDir reports it inside, and
// createClientDir refuses it with errInsideDataDir and creates nothing in
// the data directory (finding 1 of the robustness review of package B).
func TestInsideDataDirLongRealPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("builds the deep directory through /proc/self/fd")
	}
	b, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(b, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	cur, err := os.Open(b)
	if err != nil {
		t.Fatal(err)
	}
	var comps []string
	for i := 0; i < 24; i++ { // 24 * 201 bytes > PATH_MAX (4096)
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
	err = os.Symlink(data, "/proc/self/fd/"+strconv.Itoa(int(cur.Fd()))+"/M")
	cur.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(append([]string{b}, comps[:14]...)...), filepath.Join(b, "L")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(append(append([]string{b, "L"}, comps[14:]...), "M", "client")...)
	if fi, err := os.Stat(filepath.Dir(dir)); err != nil || !fi.IsDir() {
		t.Fatalf("system: %v", err)
	}
	if _, err := resolveExisting(dir); !errors.Is(err, syscall.ENAMETOOLONG) {
		t.Errorf("resolveExisting: %v, want ENAMETOOLONG", err)
	}
	if !insideDataDir(dir, data) {
		t.Error("insideDataDir: false")
	}
	err = createClientDir(dir, data, "keygen", func(r *os.Root) error {
		return r.WriteFile("marker", []byte("x"), 0o600)
	})
	if !errors.Is(err, errInsideDataDir) {
		t.Errorf("createClientDir: %v, want errInsideDataDir", err)
	}
	if got := dirNames(t, data); len(got) != 0 {
		t.Errorf("data directory: %v", got)
	}
}

// TestInsideDataDirRelative: insideDataDir makes both paths absolute
// (Store.Root is an exported field) and resolveExisting refuses a
// relative path instead of reading it from the root (finding 3 of the
// robustness review of package B). An empty data directory is inside
// everything.
func TestInsideDataDirRelative(t *testing.T) {
	b, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"data", "other"} {
		if err := os.Mkdir(filepath.Join(b, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(b, "data"), filepath.Join(b, "l")); err != nil {
		t.Fatal(err)
	}
	elsewhere, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(b)
	for _, c := range []struct {
		dir, root string
		want      bool
	}{
		{"data/client", "data", true},
		{filepath.Join(b, "data", "client"), "data", true},
		{"l/client", "data", true},
		{"data/client", filepath.Join(b, "data"), true},
		{"other/client", "data", false},
		{filepath.Join(b, "other", "client"), "data", false},
		{"other/../l/client", filepath.Join(b, "data"), true},
		{filepath.Join(b, "other", "client"), "", true},
		{filepath.Join(elsewhere, "client"), "", true},
	} {
		if got := insideDataDir(c.dir, c.root); got != c.want {
			t.Errorf("insideDataDir(%q, %q): %v, want %v", c.dir, c.root, got, c.want)
		}
	}
	for _, p := range []string{"data", "l/client", "."} {
		if r, err := resolveExisting(p); err == nil {
			t.Errorf("resolveExisting(%q): %q, want an error", p, r)
		}
	}
}

// TestInsideDataDirUnexaminable: a component that Lstat cannot examine
// for another reason than ENOENT or ENOTDIR fails closed. A name longer
// than NAME_MAX (ENAMETOOLONG) and, without CAP_DAC_OVERRIDE, a
// directory without search permission (EACCES): its link L to the data
// directory is found inside, and so is a client directory below it that
// leads nowhere, which the client could not create there anyway. A
// directory without read but with search permission is examined as
// before.
func TestInsideDataDirUnexaminable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits")
	}
	b, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(b, "data")
	for _, d := range []string{"data", "nox/sub", "nor/sub"} {
		if err := os.MkdirAll(filepath.Join(b, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	long := filepath.Join(b, strings.Repeat("y", 300), "client")
	if _, err := resolveExisting(long); !errors.Is(err, syscall.ENAMETOOLONG) {
		t.Errorf("resolveExisting(<300 bytes>/client): %v, want ENAMETOOLONG", err)
	}
	if !insideDataDir(long, data) {
		t.Error("insideDataDir(<300 bytes>/client): false")
	}
	for _, d := range []string{"nox", "nor"} {
		if err := os.Symlink(data, filepath.Join(b, d, "L")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("nox/L", filepath.Join(b, "toNoxL")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(b, "nox"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(b, "nor"), 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Chmod(filepath.Join(b, "nox"), 0o700)
		os.Chmod(filepath.Join(b, "nor"), 0o700)
	})
	if _, err := os.Lstat(filepath.Join(b, "nox", "L")); err == nil {
		t.Skip("privileged: needs a process without CAP_DAC_OVERRIDE")
	}
	for _, c := range []struct {
		dir  string
		want bool
	}{
		{"nox/L/client", true},
		{"toNoxL/client", true},
		{"nox/sub/client", true},
		{"nor/L/client", true},
		{"nor/sub/client", false},
	} {
		p := filepath.Join(b, c.dir)
		if got := insideDataDir(p, data); got != c.want {
			t.Errorf("insideDataDir(%s): %v, want %v", c.dir, got, c.want)
		}
	}
	for _, d := range []string{"nox/L/client", "toNoxL/client"} {
		err := createClientDir(filepath.Join(b, d), data, "keygen", func(r *os.Root) error {
			return r.WriteFile("marker", []byte("x"), 0o600)
		})
		if !errors.Is(err, errInsideDataDir) {
			t.Errorf("createClientDir(%s): %v, want errInsideDataDir", d, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(b, "nox", "sub", "client"), 0o700); !errors.Is(err, os.ErrPermission) {
		t.Errorf("mkdir below nox: %v, want a permission error", err)
	}
	if got := dirNames(t, data); !slices.Equal(got, []string(nil)) {
		t.Errorf("data directory: %v", got)
	}
}
