package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// releasePrograms are the four programs of cmd/... that are shipped.
var releasePrograms = []string{"gomail-ceremony", "gomail-server", "gomail-witness", "gomailctl"}

// releaseTools are the programs that scripts/check-release.sh calls.
var releaseTools = []string{"go", "awk", "tr", "grep", "sort"}

// releaseEnv is the environment of the builds of TestCheckRelease: that
// of the test without GOFLAGS. The tags of a build are given by
// buildRelease on the command line, always, also when empty; a flag
// there overrides the same flag in GOFLAGS, from the environment or from
// the go env file (go env -w), which the removal here does not reach.
// The tags of the test run itself do not reach the builds either: they
// are a flag of go test, not of the go build below.
func releaseEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOFLAGS=") {
			env = append(env, kv)
		}
	}
	return env
}

// buildRelease builds the packages pkgs (none: the four programs) with
// exactly the given tags (empty: none) and without VCS stamp into the
// new directory dir/name and returns it. Without -buildvcs=false, every
// build fails in a checkout that belongs to another user (git refuses
// it).
func buildRelease(t *testing.T, goBin, dir, name, tags string, pkgs ...string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if len(pkgs) == 0 {
		pkgs = []string{"github.com/tim-riep/go-mail/cmd/..."}
	}
	args := []string{"build", "-buildvcs=false", "-tags=" + tags, "-o", out + string(os.PathSeparator)}
	build := exec.Command(goBin, append(args, pkgs...)...)
	build.Env = releaseEnv()
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build with tags %q: %v\n%s", tags, err, b)
	}
	return out
}

// checkRelease runs scripts/check-release.sh with args by the command
// shell (a shell, possibly behind a wrapper) in the directory cwd (empty:
// that of the test) and returns its exit status, standard output and
// standard error.
func checkRelease(t *testing.T, shell []string, script, cwd string, env []string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(shell[0], append(append(append([]string{}, shell[1:]...), script), args...)...)
	cmd.Env, cmd.Dir = env, cwd
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, stdout.String(), stderr.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), stdout.String(), stderr.String()
	}
	t.Fatalf("check-release.sh: %v", err)
	return -1, "", ""
}

// toolPath makes the directory dir/name with links to the tools of the
// script as found in PATH, except those in omit; a tool named in stubs
// is instead a shell script with the given text. It returns env with
// PATH set to that directory alone.
func toolPath(t *testing.T, env []string, dir, name string, omit []string, stubs map[string]string) []string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tool := range releaseTools {
		dst := filepath.Join(p, tool)
		if stub, ok := stubs[tool]; ok {
			if err := os.WriteFile(dst, []byte("#!/bin/sh\n"+stub+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		skip := false
		for _, o := range omit {
			skip = skip || o == tool
		}
		if skip {
			continue
		}
		src, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(src, dst); err != nil {
			t.Fatal(err)
		}
	}
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "PATH=") {
			out = append(out, kv)
		}
	}
	return append(out, "PATH="+p)
}

// TestCheckRelease (task 27 package 27B; AUDIT R35, list after M1 no. 19):
// scripts/check-release.sh passes the four programs built without tags
// (exit status 0) and refuses each of them built with the tags
// gomail_dev,gomail_test, with gomail_test alone and with gomail_dev
// alone (exit status 1, the tag named), one at a time and all four in one
// call (exit status 1, not the count). gomail-witness has no code under
// either tag, and gomail-server and gomailctl have no mark under
// gomail_dev alone, so only the check of the build setting -tags refuses
// them there; the test holds that. gomail-server built with the tags
// gomail_dev,x" (a value go prints quoted) is refused as not readable.
// A production program with the name of a test switch or a mark of the
// development ceremony appended (the build information still readable),
// followed by a NUL byte or at the very end of the file, is refused for
// the mark, and so are a program whose build information lacks the
// setting GOOS (also under a file name that holds a line of build
// information), files without build information, a directory, an
// unreadable file, a missing file, no argument, a PATH without go or
// without awk, a go command that fails or prints nothing, a tool that
// fails or prints no number, a tr that exits with 0 but prints
// nothing, and a grep or sort in the search for test switches that
// passes its whole output on and then exits with a status other than 0
// (task 33 package 33B; list after M1 no. 110; for grep also 1, as it
// always selects the line -end-), while the same wrappers exiting with 0
// leave the program clean. A production program that ends with a
// capital letter (as a darwin/arm64 program may) passes. Programs named
// -m and a\cb are checked as files and named as given. The test program of
// gomail-witness that go test -c builds without tags (its build
// information is that of a production build) is refused for the marks
// testing.tRunner and testing.MainStart (task 28 package 28B, list after
// M1 no. 97 H3); a test program whose TestMain exits without m.Run (it
// holds no testing.tRunner), of a module the test writes, for
// testing.MainStart. GOFLAGS=-json in the environment or in the go env
// file does not keep a production program from passing (H4).
//
// The test builds the programs itself, with exactly the tags of each
// case, without VCS stamp and without GOFLAGS, whatever the tags of the
// test run; so it tells the same with and without -tags
// gomail_dev,gomail_test. It runs only on Linux, not with -short, and
// only with go, sh, awk, tr, grep and sort in PATH; otherwise it skips.
func TestCheckRelease(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only on Linux")
	}
	if testing.Short() {
		t.Skip("builds the programs four times and gomail-server once more")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command in PATH:", err)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, tool := range releaseTools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s missing", tool)
		}
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "check-release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	shell := []string{sh}
	env := os.Environ()
	dir := t.TempDir()
	paths := func(bin string) []string {
		var p []string
		for _, n := range releasePrograms {
			p = append(p, filepath.Join(bin, n))
		}
		return p
	}

	prod := buildRelease(t, goBin, dir, "none", "")
	witness, err := os.ReadFile(filepath.Join(prod, "gomail-witness"))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("production", func(t *testing.T) {
		code, stdout, stderr := checkRelease(t, shell, script, "", env, paths(prod)...)
		if code != 0 || stderr != "" {
			t.Fatalf("exit status %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		for _, p := range paths(prod) {
			if !strings.Contains(stdout, p+": Produktionsbuild (") {
				t.Fatalf("no line for %s:\n%s", p, stdout)
			}
		}
	})

	for _, c := range []struct {
		tags string
		want []string
		// tagsOnly are the programs that carry no mark of the tags.
		tagsOnly []string
	}{
		{"gomail_dev,gomail_test", []string{"gomail_dev", "gomail_test"}, []string{"gomail-witness"}},
		{"gomail_test", []string{"gomail_test"}, []string{"gomail-witness"}},
		{"gomail_dev", []string{"gomail_dev"}, []string{"gomail-server", "gomail-witness", "gomailctl"}},
	} {
		t.Run(c.tags, func(t *testing.T) {
			bin := buildRelease(t, goBin, dir, strings.ReplaceAll(c.tags, ",", "+"), c.tags)
			defer os.RemoveAll(bin)
			for _, p := range paths(bin) {
				code, stdout, stderr := checkRelease(t, shell, script, "", env, p)
				if code != 1 || stdout != "" {
					t.Fatalf("%s: exit status %d, want 1\nstdout:\n%s\nstderr:\n%s", p, code, stdout, stderr)
				}
				for _, tag := range c.want {
					if !strings.Contains(stderr, p+": mit dem Tag "+tag+" gebaut (-tags="+c.tags+")") {
						t.Fatalf("%s: tag %s not named:\n%s", p, tag, stderr)
					}
				}
				if !strings.Contains(stderr, "1 von 1 Programmen kein Produktionsbuild") {
					t.Fatalf("%s: no summary:\n%s", p, stderr)
				}
				for _, n := range c.tagsOnly {
					if filepath.Base(p) == n && strings.Contains(stderr, "enthält") {
						t.Fatalf("%s: a mark found; the comments on check 2 of the script and of this test need an update:\n%s", p, stderr)
					}
				}
			}
			// All four in one call: exit status 1, not the count.
			code, stdout, stderr := checkRelease(t, shell, script, "", env, paths(bin)...)
			if code != 1 || stdout != "" || !strings.Contains(stderr, "4 von 4 Programmen kein Produktionsbuild") {
				t.Fatalf("four: exit status %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			// One program of a test build among production programs.
			mixed := append(paths(prod)[:3:3], filepath.Join(bin, "gomailctl"))
			code, stdout, stderr = checkRelease(t, shell, script, "", env, mixed...)
			if code != 1 || strings.Count(stdout, ": Produktionsbuild (") != 3 || !strings.Contains(stderr, "1 von 4 Programmen") {
				t.Fatalf("mixed: exit status %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
		})
	}

	t.Run("quoted tags", func(t *testing.T) {
		// go version -m prints -tags="gomail_dev,x\"": read naively, the
		// tag gomail_dev would be "gomail_dev and gomail-server would
		// pass, as it has no mark under gomail_dev.
		bin := buildRelease(t, goBin, dir, "quoted", `gomail_dev,x"`, "github.com/tim-riep/go-mail/cmd/gomail-server")
		defer os.RemoveAll(bin)
		p := filepath.Join(bin, "gomail-server")
		code, stdout, stderr := checkRelease(t, shell, script, "", env, p)
		want := p + `: Build-Tags nicht eindeutig lesbar (-tags="gomail_dev,x\"")`
		if code != 1 || stdout != "" || !strings.Contains(stderr, want) {
			t.Fatalf("exit status %d, want 1 and %q\nstdout:\n%s\nstderr:\n%s", code, want, stdout, stderr)
		}
		if strings.Contains(stderr, "enthält") {
			t.Fatalf("a mark found; the case no longer tests the check of -tags alone:\n%s", stderr)
		}
	})

	t.Run("marks", func(t *testing.T) {
		for _, c := range []struct{ mark, want string }{
			{"GOMAIL_TEST_MIN_FREE", "enthält den Testschalter GOMAIL_TEST_MIN_FREE"},
			{"GOMAIL_TEST_DEV_IDENTITY", "enthält den Testschalter GOMAIL_TEST_DEV_IDENTITY"},
			{"GOMAIL_TEST_HEAD_GAP", "enthält den Testschalter GOMAIL_TEST_HEAD_GAP"},
			{"GOMAILCTL_TEST_KEYGEN_PIPE", "enthält den Testschalter GOMAILCTL_TEST_KEYGEN_PIPE"},
			{"GOMAIL_CEREMONY_TEST_NEW", "enthält den Namen GOMAIL_CEREMONY_TEST_NEW (Muster"},
			{"INSECURE - DEVELOPMENT ONLY", `enthält "INSECURE - DEVELOPMENT ONLY" (Entwicklungszeremonie)`},
			{"platform-root.INSECURE-DEV-ONLY.txt", `enthält "platform-root.INSECURE-DEV-ONLY.txt" (Entwicklungszeremonie)`},
		} {
			// The mark followed by a NUL byte, and at the very end of the
			// file (tr then ends without a newline).
			for _, tail := range []string{"\x00", ""} {
				p := filepath.Join(dir, "marked")
				b := append(append(append(append([]byte{}, witness...), 0), c.mark...), tail...)
				if err := os.WriteFile(p, b, 0o700); err != nil {
					t.Fatal(err)
				}
				code, stdout, stderr := checkRelease(t, shell, script, "", env, p)
				if code != 1 || stdout != "" || !strings.Contains(stderr, p+": "+c.want) {
					t.Fatalf("%q+%q: exit status %d, want 1 and %q\nstdout:\n%s\nstderr:\n%s", c.mark, tail, code, c.want, stdout, stderr)
				}
				if strings.Contains(stderr, "Build-") || strings.Contains(stderr, "gescheitert") {
					t.Fatalf("%q+%q: build information not read or a search failed after the append:\n%s", c.mark, tail, stderr)
				}
			}
		}
		// A production program that ends with a capital letter, as a
		// darwin/arm64 program may (its last bytes are a hash of its code
		// signature): clean.
		p := filepath.Join(dir, "marked")
		if err := os.WriteFile(p, append(append([]byte{}, witness...), 'A'), 0o700); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := checkRelease(t, shell, script, "", env, p)
		if code != 0 || stderr != "" || !strings.HasPrefix(stdout, p+": Produktionsbuild (") {
			t.Fatalf("ends with A: exit status %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		os.Remove(p)
	})

	t.Run("build settings", func(t *testing.T) {
		// Build information without the setting GOOS (a program of cmd/go
		// always has it): the tags are unknown, the program is refused.
		// The build information is in the program twice (the section
		// that go version reads and the copy of runtime/debug); both
		// change. go version -m prints the file name as it is, so the
		// second name puts a line "\tbuild\tGOOS=linux" into its output;
		// it must not count.
		old, repl := []byte("build\tGOOS="), []byte("build\tGOXS=")
		if !bytes.Contains(witness, old) {
			t.Fatal("no setting GOOS in the program")
		}
		for _, name := range []string{"nogoos", "nogoos\n\tbuild\tGOOS=linux"} {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, bytes.ReplaceAll(witness, old, repl), 0o700); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := checkRelease(t, shell, script, "", env, p)
			os.Remove(p)
			want := p + ": keine Build-Einstellungen in den Build-Informationen; Build-Tags unbekannt"
			if code != 1 || stdout != "" || !strings.Contains(stderr, want) {
				t.Fatalf("%q: exit status %d, want 1 and %q\nstdout:\n%s\nstderr:\n%s", name, code, want, stdout, stderr)
			}
			// The search of check 3 requires the word GOOS only where
			// check 1 found the setting.
			if strings.Contains(stderr, "gescheitert") {
				t.Fatalf("%q: a search failed:\n%s", name, stderr)
			}
		}
	})

	t.Run("names", func(t *testing.T) {
		// A file name starting with - is a file, not an option of go
		// version; a file name with \c is printed as it is (echo of dash
		// would end the line there).
		cwd := filepath.Join(dir, "cwd")
		if err := os.Mkdir(cwd, 0o700); err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(cwd)
		for _, name := range []string{"-m", `a\cb`} {
			if err := os.WriteFile(filepath.Join(cwd, name), witness, 0o700); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := checkRelease(t, shell, script, cwd, env, name)
			if code != 0 || stderr != "" || !strings.HasPrefix(stdout, name+": Produktionsbuild (go") {
				t.Fatalf("%q: exit status %d, want 0\nstdout:\n%s\nstderr:\n%s", name, code, stdout, stderr)
			}
		}
	})

	t.Run("not checkable", func(t *testing.T) {
		text := filepath.Join(dir, "text")
		if err := os.WriteFile(text, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			args []string
			want string
		}{
			{nil, "kein Programm angegeben; nichts geprüft"},
			{[]string{text}, text + ": keine Build-Informationen"},
			{[]string{prod}, prod + ": keine lesbare reguläre Datei"},
			{[]string{filepath.Join(dir, "missing")}, "missing: nicht vorhanden"},
			{[]string{"-m"}, "-m: nicht vorhanden"},
		} {
			code, stdout, stderr := checkRelease(t, shell, script, "", env, c.args...)
			if code != 1 || stdout != "" || !strings.Contains(stderr, c.want) {
				t.Fatalf("%q: exit status %d, want 1 and %q\nstdout:\n%s\nstderr:\n%s", c.args, code, c.want, stdout, stderr)
			}
		}

		// A program the script cannot read. root reads any file, so as
		// root the script runs without the capabilities that override
		// file permissions (setpriv); where that is not possible, the
		// case is skipped.
		unreadable := filepath.Join(dir, "unreadable")
		if err := os.WriteFile(unreadable, witness, 0); err != nil {
			t.Fatal(err)
		}
		dropped := shell
		skip := ""
		if os.Geteuid() == 0 {
			if sp, err := exec.LookPath("setpriv"); err == nil {
				caps := "-dac_override,-dac_read_search"
				dropped = []string{sp, "--inh-caps=" + caps, "--bounding-set=" + caps, sh}
			} else {
				skip = "running as root without setpriv in PATH, the file stays readable"
			}
		}
		if skip == "" {
			probe := exec.Command(dropped[0], append(append([]string{}, dropped[1:]...), "-c", `[ -f "$1" ] && [ ! -r "$1" ]`, "sh", unreadable)...)
			if b, err := probe.CombinedOutput(); err != nil {
				skip = fmt.Sprintf("probe with %s: %v %q (the file stays readable, or %s fails)", dropped[0], err, b, dropped[0])
			}
		}
		if skip != "" {
			t.Logf("unreadable file: %s; case skipped", skip)
		} else {
			code, stdout, stderr := checkRelease(t, dropped, script, "", env, unreadable)
			want := unreadable + ": keine lesbare reguläre Datei"
			if code != 1 || stdout != "" || !strings.Contains(stderr, want) {
				t.Fatalf("unreadable: exit status %d, want 1 and %q\nstdout:\n%s\nstderr:\n%s", code, want, stdout, stderr)
			}
		}
		os.Remove(unreadable)

		// A PATH without go, and one with go but without awk: nothing is
		// checked.
		for _, c := range []struct{ omit, want string }{
			{"go", "kein go-Befehl im PATH"},
			{"awk", "kein awk im PATH"},
		} {
			noTool := toolPath(t, env, dir, "no-"+c.omit, []string{c.omit}, nil)
			code, stdout, stderr := checkRelease(t, shell, script, "", noTool, paths(prod)...)
			if code != 1 || stdout != "" || !strings.Contains(stderr, c.want) || !strings.Contains(stderr, "Hilfsprogramm fehlt; nichts geprüft") {
				t.Fatalf("no %s: exit status %d, want 1 and %q\nstdout:\n%s\nstderr:\n%s", c.omit, code, c.want, stdout, stderr)
			}
		}

		// A go command that fails (the stub prints what go prints when
		// GOTOOLCHAIN names a toolchain it cannot download): named once
		// with its last line of output; nothing is checked.
		failingGo := toolPath(t, env, dir, "failing-go", nil, map[string]string{
			"go": "echo 'go: downloading go1.99.1 (linux/amd64)' >&2\necho 'go: download go1.99.1: toolchain not available' >&2\nexit 1",
		})
		code, stdout, stderr := checkRelease(t, shell, script, "", failingGo, paths(prod)...)
		want := "check-release.sh: go version gescheitert (Status 1: go: download go1.99.1: toolchain not available); nichts geprüft\n"
		if code != 1 || stdout != "" || stderr != want {
			t.Fatalf("failing go: exit status %d, want 1 and %q\nstdout:\n%s\nstderr:\n%s", code, want, stdout, stderr)
		}

		// A go command that exits with 0 but prints nothing (list after
		// M1 no. 97 H2): nothing is checked either.
		silentGo := toolPath(t, env, dir, "silent-go", nil, map[string]string{"go": "exit 0"})
		code, stdout, stderr = checkRelease(t, shell, script, "", silentGo, paths(prod)...)
		want = "check-release.sh: go version gescheitert (Status 0: keine Ausgabe); nichts geprüft\n"
		if code != 1 || stdout != "" || stderr != want {
			t.Fatalf("silent go: exit status %d, want 1 and %q\nstdout:\n%s\nstderr:\n%s", code, want, stdout, stderr)
		}
	})

	t.Run("failing tools", func(t *testing.T) {
		// A tool that fails, or awk that prints no number, makes the
		// program not clean.
		p := filepath.Join(prod, "gomail-witness")
		tool := map[string]string{}
		for _, n := range []string{"tr", "grep", "sort"} {
			path, err := exec.LookPath(n)
			if err != nil {
				t.Fatal(err)
			}
			tool[n] = "'" + path + "'"
		}
		// grepE runs grep and then exits with the status given, when
		// called as grep -E (the search for test switches), and runs grep
		// alone otherwise (the searches with grep -q).
		grepE := func(status string) string {
			return "case $1 in -E) " + tool["grep"] + " \"$@\"; exit " + status + " ;; esac\nexec " + tool["grep"] + " \"$@\""
		}
		const search = "Suche nach Testschaltern gescheitert (tr, grep, sort); nicht geprüft"
		for i, c := range []struct {
			tool, stub string
			want       []string
			// n is the number of findings, also counting those not in
			// want.
			n int
		}{
			{"awk", "exit 2", []string{"Auswertung der Build-Informationen gescheitert (awk)"}, 1},
			{"awk", "echo x", []string{"Auswertung der Build-Informationen gescheitert (awk)"}, 1},
			{"tr", "exit 2", []string{search}, 1},
			// A tr that prints its whole output and then fails: the word
			// GOOS is there, only the missing line -end- tells.
			{"tr", tool["tr"] + " \"$@\"\nexit 2", []string{search}, 1},
			// A tr that exits with 0 and prints nothing (list after M1
			// no. 97 H1): the word GOOS of the build information is
			// missing from its output.
			{"tr", "exit 0", []string{search}, 1},
			{"grep", "exit 2", []string{search, `Suche nach "INSECURE - DEVELOPMENT ONLY" gescheitert (grep)`}, 5},
			{"sort", "exit 2", []string{search}, 1},
			// A grep or sort in the search for test switches that passes
			// all its output on, the line -end- included, and then fails
			// (task 33 package 33B, list after M1 no. 110): only its exit
			// status tells. For grep, 1 fails as well: it selects -end-
			// at least. The searches with grep -q succeed.
			{"grep", grepE("2"), []string{search}, 1},
			{"grep", grepE("1"), []string{search}, 1},
			{"sort", tool["sort"] + " \"$@\"\nexit 2", []string{search}, 1},
			{"sort", tool["sort"] + " \"$@\"\nexit 1", []string{search}, 1},
		} {
			failing := toolPath(t, env, dir, "failing-"+string(rune('a'+i)), nil, map[string]string{c.tool: c.stub})
			code, stdout, stderr := checkRelease(t, shell, script, "", failing, p)
			if code != 1 || stdout != "" {
				t.Fatalf("%s %q: exit status %d, want 1\nstdout:\n%s\nstderr:\n%s", c.tool, c.stub, code, stdout, stderr)
			}
			for _, w := range c.want {
				if !strings.Contains(stderr, p+": "+w) {
					t.Fatalf("%s %q: %q missing\nstderr:\n%s", c.tool, c.stub, w, stderr)
				}
			}
			if n := strings.Count(stderr, "check-release.sh: "+p+": "); n != c.n {
				t.Fatalf("%s %q: %d findings, want %d\nstderr:\n%s", c.tool, c.stub, n, c.n, stderr)
			}
		}

		// Controls: the same wrappers of grep and sort exiting with 0
		// leave the program clean, so the cases above fail for the exit
		// status alone, not for the wrapper.
		for i, c := range []struct{ tool, stub string }{
			{"grep", "case $1 in -E) " + tool["grep"] + " \"$@\"; exit 0 ;; esac\nexec " + tool["grep"] + " \"$@\""},
			{"sort", tool["sort"] + " \"$@\"\nexit 0"},
		} {
			passing := toolPath(t, env, dir, "passing-"+string(rune('a'+i)), nil, map[string]string{c.tool: c.stub})
			code, stdout, stderr := checkRelease(t, shell, script, "", passing, p)
			if code != 0 || stderr != "" || !strings.HasPrefix(stdout, p+": Produktionsbuild (") {
				t.Fatalf("%s %q: exit status %d, want 0\nstdout:\n%s\nstderr:\n%s", c.tool, c.stub, code, stdout, stderr)
			}
		}
	})

	t.Run("test program", func(t *testing.T) {
		// go test -c without tags (list after M1 no. 97 H3): the build
		// information of the test program of a main package is that of
		// a production build without VCS stamp, and gomail-witness holds
		// no test switch; only the marks testing.tRunner and
		// testing.MainStart refuse it.
		bin := filepath.Join(dir, "testprog")
		if err := os.Mkdir(bin, 0o700); err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(bin)
		p := filepath.Join(bin, "gomail-witness.test")
		build := exec.Command(goBin, "test", "-c", "-tags=", "-o", p, "github.com/tim-riep/go-mail/cmd/gomail-witness")
		build.Env = releaseEnv()
		if b, err := build.CombinedOutput(); err != nil {
			t.Fatalf("go test -c: %v\n%s", err, b)
		}
		code, stdout, stderr := checkRelease(t, shell, script, "", env, p)
		for _, m := range []string{"testing.tRunner", "testing.MainStart"} {
			want := p + `: enthält "` + m + `" (Testprogramm von go test -c)`
			if code != 1 || stdout != "" || !strings.Contains(stderr, want) {
				t.Fatalf("exit status %d, want 1 and %q\nstdout:\n%s\nstderr:\n%s", code, want, stdout, stderr)
			}
		}
		if strings.Count(stderr, p+": ") != 2 {
			t.Fatalf("another finding; the case no longer tests the marks alone:\n%s", stderr)
		}
	})

	t.Run("TestMain without m.Run", func(t *testing.T) {
		// A test program whose TestMain exits without calling m.Run
		// holds no testing.tRunner (the linker drops it), but
		// testing.MainStart, which the main function that go test
		// generates calls. The module is written here: a main package
		// with such a TestMain and one test.
		mod := t.TempDir()
		for name, text := range map[string]string{
			"go.mod":       "module example.com/nomrun\n\ngo 1.21\n",
			"main.go":      "package main\n\nfunc main() {}\n",
			"main_test.go": "package main\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) { os.Exit(0) }\n\nfunc TestNothing(t *testing.T) {}\n",
		} {
			if err := os.WriteFile(filepath.Join(mod, name), []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		p := filepath.Join(mod, "nomrun.test")
		build := exec.Command(goBin, "test", "-c", "-o", p, ".")
		build.Env, build.Dir = append(releaseEnv(), "GOWORK=off"), mod
		if b, err := build.CombinedOutput(); err != nil {
			t.Fatalf("go test -c: %v\n%s", err, b)
		}
		code, stdout, stderr := checkRelease(t, shell, script, "", env, p)
		want := p + `: enthält "testing.MainStart" (Testprogramm von go test -c)`
		if code != 1 || stdout != "" || !strings.Contains(stderr, want) {
			t.Fatalf("exit status %d, want 1 and %q\nstdout:\n%s\nstderr:\n%s", code, want, stdout, stderr)
		}
		if strings.Count(stderr, p+": ") != 1 || strings.Contains(stderr, "testing.tRunner") {
			t.Fatalf("another finding; the case no longer tests testing.MainStart alone:\n%s", stderr)
		}
	})

	t.Run("GOFLAGS", func(t *testing.T) {
		// GOFLAGS=-json makes go version -m print JSON (list after M1
		// no. 97 H4); the script overrides it, from the environment and
		// from the go env file (an empty GOFLAGS would not reach the
		// latter). The go env file of the test is the one go uses, with
		// GOFLAGS=-json added.
		var base []string
		for _, kv := range env {
			if !strings.HasPrefix(kv, "GOFLAGS=") && !strings.HasPrefix(kv, "GOENV=") {
				base = append(base, kv)
			}
		}
		out, err := exec.Command(goBin, "env", "GOENV").Output()
		if err != nil {
			t.Fatal(err)
		}
		var file []byte
		if name := strings.TrimSpace(string(out)); name != "" && name != "off" {
			if file, err = os.ReadFile(name); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		}
		goenv := filepath.Join(dir, "goenv")
		if err := os.WriteFile(goenv, append(append([]byte{}, file...), "\nGOFLAGS=-json\n"...), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			name string
			env  []string
		}{
			{"environment", append(append([]string{}, base...), "GOFLAGS=-json")},
			{"go env file", append(append([]string{}, base...), "GOENV="+goenv)},
		} {
			code, stdout, stderr := checkRelease(t, shell, script, "", c.env, paths(prod)...)
			if code != 0 || stderr != "" || strings.Count(stdout, ": Produktionsbuild (") != len(releasePrograms) {
				t.Fatalf("%s: exit status %d, want 0\nstdout:\n%s\nstderr:\n%s", c.name, code, stdout, stderr)
			}
		}
	})
}
