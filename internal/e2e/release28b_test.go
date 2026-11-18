package e2e

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// releaseTags are the tags of a test build that scripts/check-release.sh
// refuses.
var releaseTags = []string{"gomail_test", "gomail_dev"}

// releaseScriptVar returns the value of the line name='value' of the
// script src; exactly one such line must exist.
func releaseScriptVar(t *testing.T, src, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^`+name+`='([^']*)'$`).FindAllStringSubmatch(src, -1)
	if len(m) != 1 {
		t.Fatalf("scripts/check-release.sh: %d lines %s='...', want 1", len(m), name)
	}
	return m[0][1]
}

// testBuildOnly reports whether the build constraint of a file names one
// of releaseTags and keeps the file out of a build without them: the
// constraint is false with both tags false, once with every other tag
// true and once with every other tag false. Where that is wrong for
// some other mix of tags, the file counts as well (more names to check,
// never fewer).
func testBuildOnly(expr constraint.Expr) bool {
	// Eval calls its function for every tag of the expression.
	named := false
	expr.Eval(func(tag string) bool {
		for _, r := range releaseTags {
			named = named || tag == r
		}
		return true
	})
	if !named {
		return false
	}
	for _, others := range []bool{true, false} {
		if expr.Eval(func(tag string) bool {
			for _, r := range releaseTags {
				if tag == r {
					return false
				}
			}
			return others
		}) {
			return false
		}
	}
	return true
}

// fileConstraint returns the build constraint of the Go file f (nil:
// none): the //go:build line, or else the // +build lines.
func fileConstraint(f *ast.File) (constraint.Expr, error) {
	var plus []constraint.Expr
	for _, g := range f.Comments {
		if g.Pos() >= f.Package {
			break
		}
		for _, c := range g.List {
			switch {
			case constraint.IsGoBuild(c.Text):
				return constraint.Parse(c.Text)
			case constraint.IsPlusBuild(c.Text):
				e, err := constraint.Parse(c.Text)
				if err != nil {
					return nil, err
				}
				plus = append(plus, e)
			}
		}
	}
	if len(plus) == 0 {
		return nil, nil
	}
	e := plus[0]
	for _, p := range plus[1:] {
		e = &constraint.AndExpr{X: e, Y: p}
	}
	return e, nil
}

// envRead is one environment variable that a file reads.
type envRead struct {
	pos  string
	name string
}

// envSelectors are the names of the functions and methods that read the
// environment: of os and syscall, and methods such as (*exec.Cmd).Environ.
// A selector with one of these names in a file of releaseEnvReads is a
// problem whatever its receiver, unless it is os.Getenv or os.LookupEnv
// called with a constant name.
var envSelectors = map[string]bool{"Environ": true, "Getenv": true, "LookupEnv": true, "ExpandEnv": true}

// releaseEnvReads returns the names of the environment variables that
// the non-test Go files of the module under root read when only a build
// with gomail_test or gomail_dev compiles them, and the problems: a read
// whose name is not a constant, any other selector named in envSelectors
// (whatever its receiver), any dot import, and any Go file or directory
// that go build would read and this function does not (a symbolic link
// to a directory, a non-test file *.go that is not a regular file).
// Like go/build it skips files and directories whose names begin with
// "." or "_", and directories named testdata or vendor or holding a
// go.mod (another module; as for go, only a go.mod that os.Stat finds
// and that is not a directory counts).
//
// Every symbolic link to a directory is a problem, wherever it is and
// whatever the directory holds (even nothing, or no Go file, or a
// directory that the walk reads anyway), unless the link itself is
// skipped: its name begins with "." or "_", it is named testdata or
// vendor, or it lies under a skipped directory. That is fail closed: the
// test does not decide whether go build would compile something there.
// root itself must be a directory, not a symbolic link (WalkDir would
// read nothing below it); the caller resolves it (releaseRoot). Otherwise,
// and when the walk fails (a file that does not parse, a directory that
// cannot be read), the error is returned.
func releaseEnvReads(root string) ([]envRead, []string, error) {
	if fi, err := os.Lstat(root); err != nil {
		return nil, nil, err
	} else if !fi.IsDir() {
		return nil, nil, fmt.Errorf("%s: not a directory (%s); the walk would read nothing below it, resolve it first", root, fi.Mode().Type())
	}
	fset := token.NewFileSet()
	// pkgs holds the parsed non-test files of each directory, for
	// constants declared in another file of the package.
	pkgs := map[string][]*ast.File{}
	var tagged []*ast.File
	var problems []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		name := d.Name()
		// go build ignores files and directories whose names begin with
		// "." or "_" (go/build), whatever they hold; it never parses them.
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if name == "testdata" || name == "vendor" {
				return filepath.SkipDir
			}
			// Another module: not built with this one. go decides as here
			// (os.Stat, not a directory): a dangling link go.mod or a
			// directory go.mod does not make one.
			if fi, err := os.Stat(filepath.Join(path, "go.mod")); err == nil && !fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// WalkDir does not follow a symbolic link, but go build does: a
		// link to a directory can be a package, a link named *.go is
		// compiled. The test reads neither, so either is a problem.
		if d.Type()&fs.ModeSymlink != 0 && name != "testdata" && name != "vendor" {
			if fi, err := os.Stat(path); err == nil && fi.IsDir() {
				problems = append(problems, fmt.Sprintf("%s: symbolic link to a directory; go build may compile the files under it, this test does not read them", path))
				return nil
			}
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		if !d.Type().IsRegular() {
			kind := "not a regular file"
			if d.Type()&fs.ModeSymlink != 0 {
				kind = "symbolic link"
			}
			problems = append(problems, fmt.Sprintf("%s: %s; go build may compile it, this test does not read it", path, kind))
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		dir := filepath.Dir(path)
		pkgs[dir] = append(pkgs[dir], f)
		expr, err := fileConstraint(f)
		if err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
		if expr != nil && testBuildOnly(expr) {
			tagged = append(tagged, f)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	var reads []envRead
	for _, f := range tagged {
		file := fset.Position(f.Package).Filename
		pkg := pkgs[filepath.Dir(file)]
		imports := map[string]string{} // local name -> import path
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			local := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				local = imp.Name.Name
			}
			// A dot import hides the package of a call (Getenv of any
			// package would read as a plain function); none is allowed.
			if local == "." {
				problems = append(problems, fmt.Sprintf("%s: dot import of %s", fset.Position(imp.Pos()), path))
			}
			imports[local] = path
		}
		// calls are the selectors that are called directly; any other use
		// of os.Getenv and os.LookupEnv is a problem.
		calls := map[*ast.SelectorExpr]*ast.CallExpr{}
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
					calls[sel] = c
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !envSelectors[sel.Sel.Name] {
				return true
			}
			pos := fset.Position(sel.Pos()).String()
			// imported is the import path where the selector is a name
			// of an imported package (an identifier that the parser did
			// not resolve in the file and that an import of the file
			// declares); what is that path and the name, or else the
			// expression as written (only for the message: an expression
			// os.Getenv whose os is not the import of os is not
			// os.Getenv).
			imported, what := "", types.ExprString(sel)
			if x, ok := sel.X.(*ast.Ident); ok && x.Obj == nil {
				if path, ok := imports[x.Name]; ok {
					imported, what = path, path+"."+sel.Sel.Name
				}
			}
			switch {
			case imported == "os" && (sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv"):
				c := calls[sel]
				if c == nil || len(c.Args) != 1 {
					problems = append(problems, fmt.Sprintf("%s: %s not called with one argument", pos, what))
					return true
				}
				name, err := constString(c.Args[0], f, pkg, 0)
				if err != nil {
					problems = append(problems, fmt.Sprintf("%s: %s: name not a constant: %v", pos, what, err))
					return true
				}
				reads = append(reads, envRead{pos, name})
			default:
				problems = append(problems, fmt.Sprintf("%s: %s: selector %s may read the environment; only os.Getenv and os.LookupEnv with a constant name are allowed", pos, what, sel.Sel.Name))
			}
			return true
		})
	}
	return reads, problems, nil
}

// releaseRoot returns the module root that TestReleaseSwitches walks: two
// directories above the working directory, with symbolic links resolved.
// A working directory reached through a symbolic link (cd to a link to
// the checkout) leaves an unresolved root that WalkDir does not descend
// into.
func releaseRoot() (string, error) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(root)
}

// constString returns the value of the string constant expression e of
// file f in package pkg: a string literal, a constant of the file or of
// the package (by name), and + of those.
func constString(e ast.Expr, f *ast.File, pkg []*ast.File, depth int) (string, error) {
	if depth > 16 {
		return "", fmt.Errorf("constants nested too deep")
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", fmt.Errorf("literal %s", e.Value)
		}
		return strconv.Unquote(e.Value)
	case *ast.ParenExpr:
		return constString(e.X, f, pkg, depth+1)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", fmt.Errorf("operator %s", e.Op)
		}
		x, err := constString(e.X, f, pkg, depth+1)
		if err != nil {
			return "", err
		}
		y, err := constString(e.Y, f, pkg, depth+1)
		if err != nil {
			return "", err
		}
		return x + y, nil
	case *ast.Ident:
		if e.Obj != nil {
			// Declared in this file (the parser resolves its scopes).
			if e.Obj.Kind != ast.Con {
				return "", fmt.Errorf("%s is a %s", e.Name, e.Obj.Kind)
			}
			return specValue(e.Obj.Decl, e.Name, f, pkg, depth)
		}
		// Declared at package level in another file of the package;
		// every declaration found (files of other tags or systems) must
		// agree.
		var vals []string
		for _, g := range pkg {
			if g == f {
				continue
			}
			obj := g.Scope.Lookup(e.Name)
			if obj == nil {
				continue
			}
			if obj.Kind != ast.Con {
				return "", fmt.Errorf("%s is a %s", e.Name, obj.Kind)
			}
			v, err := specValue(obj.Decl, e.Name, g, pkg, depth)
			if err != nil {
				return "", err
			}
			vals = append(vals, v)
		}
		if len(vals) == 0 {
			return "", fmt.Errorf("%s not declared in the package", e.Name)
		}
		for _, v := range vals[1:] {
			if v != vals[0] {
				return "", fmt.Errorf("%s declared with different values", e.Name)
			}
		}
		return vals[0], nil
	}
	return "", fmt.Errorf("expression %T", e)
}

// specValue returns the value of the constant name declared by decl in
// file f.
func specValue(decl any, name string, f *ast.File, pkg []*ast.File, depth int) (string, error) {
	spec, ok := decl.(*ast.ValueSpec)
	if !ok {
		return "", fmt.Errorf("%s: declaration %T", name, decl)
	}
	for i, n := range spec.Names {
		if n.Name == name {
			if i >= len(spec.Values) {
				return "", fmt.Errorf("%s: no value of its own", name)
			}
			return constString(spec.Values[i], f, pkg, depth+1)
		}
	}
	return "", fmt.Errorf("%s: not in its declaration", name)
}

// TestReleaseSwitches (task 28 package 28B; list after M1 no. 96): every
// environment variable that a non-test file of the module reads, when
// only a build with gomail_test or gomail_dev compiles that file, is
// named in switches of scripts/check-release.sh or matches its pattern;
// so the script finds the name in a test build. The names are collected
// with go/ast from os.Getenv and os.LookupEnv; a name that is not a
// constant (a string literal, a constant of the package, + of those)
// fails the test, and so does, in such a file, any other selector named
// Environ, Getenv, LookupEnv or ExpandEnv, whatever its receiver and
// whether called or not (os.Environ, os.ExpandEnv, syscall.Getenv,
// (*exec.Cmd).Environ, Getenv of another package, os.Getenv or
// os.LookupEnv not called directly), and any dot import (of any
// package). A symbolic link named *.go (not *_test.go) or to a
// directory, and any other non-test file *.go that is not a regular file,
// fails the test as well: go build follows the link, the walk does not.
// So does every other symbolic link to a directory that is not skipped
// (fail closed, see releaseEnvReads), even one to an empty directory or
// outside cmd/ and internal/. Files and directories that go build
// ignores (names beginning with "." or "_", testdata, vendor, other
// modules) are skipped, not parsed. The module root is resolved with
// filepath.EvalSymlinks first (releaseRoot): reached through a symbolic
// link, the walk would read nothing. Each name in switches
// matches pattern (otherwise grep would not pass it to the script) and
// is read by such a file: the list is the one its comment names, and the
// collection is not empty.
//
// Not covered: a read through a function of a file that production
// builds compile as well (the name then passes as an argument), through
// a function or method of another package under another name, or
// through cgo; files of another module or under testdata.
func TestReleaseSwitches(t *testing.T) {
	root, err := releaseRoot()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(root, "scripts", "check-release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	switches := strings.Fields(releaseScriptVar(t, string(src), "switches"))
	pat := releaseScriptVar(t, string(src), "pattern")
	pattern, err := regexp.Compile(pat)
	if err != nil {
		t.Fatalf("pattern %q: %v", pat, err)
	}
	if len(switches) == 0 {
		t.Fatal("scripts/check-release.sh: switches is empty")
	}
	for _, s := range switches {
		if !pattern.MatchString(s) {
			t.Errorf("switch %s does not match the pattern %s; grep would never pass it to the script", s, pat)
		}
	}

	reads, problems, err := releaseEnvReads(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	read := map[string]bool{}
	for _, r := range reads {
		read[r.name] = true
		known := false
		for _, s := range switches {
			known = known || r.name == s
		}
		if !known && !pattern.MatchString(r.name) {
			t.Errorf("%s: %q is neither in switches of scripts/check-release.sh nor matches its pattern %s", r.pos, r.name, pat)
		}
	}
	for _, s := range switches {
		if !read[s] {
			t.Errorf("switch %s of scripts/check-release.sh is read by no file of the tags %s", s, strings.Join(releaseTags, ", "))
		}
	}
	var names []string
	for n := range read {
		names = append(names, n)
	}
	sort.Strings(names)
	t.Logf("names read under %s: %s", strings.Join(releaseTags, ", "), strings.Join(names, " "))
}

// TestReleaseEnvReadsWalk (task 29 package 29D): releaseEnvReads skips
// what go build ignores and fails on what go build reads and it does
// not. In a tree under t.TempDir(): files named _*.go and .*.go are not
// parsed (one does not parse at all, the others read the environment); a
// symbolic link named *.go, a dangling one, a link to a directory and a
// chain of links to a directory through a link named _* are problems,
// each once, and so is a Unix socket named *.go (never opened); links
// named *_test.go, _*.go, .*.go or not *.go, and links to a directory
// named _*, testdata or vendor, are not. A directory with a regular
// go.mod or a link go.mod to a regular file is another module and not
// read; one with a dangling link go.mod or a directory go.mod is read, as
// go builds it. A root that is a symbolic link is an error, not an empty
// walk.
//
// The socket must be made on Linux (the test fails otherwise); where it
// cannot be made on another system, the other cases are checked and the
// test then ends in a skip that names why.
func TestReleaseEnvReadsWalk(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "mod")
	outside := filepath.Join(dir, "outside")
	tagged := func(name string) string {
		return "//go:build gomail_test\n\npackage main\n\nimport \"os\"\n\nvar v = os.Getenv(\"" + name + "\")\n"
	}
	files := map[string]string{
		"mod/cmd/a/main.go":             "package main\n\nfunc main() {}\n",
		"mod/cmd/a/env_tagged.go":       tagged("GOMAIL_TEST_A"),
		"mod/cmd/a/_bad.go":             "package main\n\nfunc (\n",
		"mod/cmd/a/.env_tagged.go":      tagged("GOMAIL_TEST_HIDDEN"),
		"mod/cmd/a/_env_tagged.go":      "//go:build gomail_test\n\npackage main\n\nimport \"os\"\n\nvar e = os.Environ()\n",
		"mod/internal/b/b.go":           "package b\n",
		"mod/internal/m1/go.mod":        "module m1\n",
		"mod/internal/m1/env_tagged.go": tagged("GOMAIL_TEST_MODULE"),
		"mod/internal/m2/env_tagged.go": tagged("GOMAIL_TEST_MODULE_LINK"),
		"mod/internal/m3/env_tagged.go": tagged("GOMAIL_TEST_GOMOD_DANGLING"),
		"mod/internal/m4/go.mod/x.txt":  "not a module\n",
		"mod/internal/m4/env_tagged.go": tagged("GOMAIL_TEST_GOMOD_DIR"),
		"outside/env.go":                tagged("GOMAIL_TEST_LINKED"),
		"outside/go.mod":                "module outside\n",
		"outside/pkg/env_tagged.go":     tagged("GOMAIL_TEST_LINKED_DIR"),
	}
	for name, text := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// In this order: a link is made after the one it points to (Windows
	// marks a link to a directory when it is made).
	links := []struct{ name, target string }{
		{"internal/b/link.go", filepath.Join(outside, "env.go")},
		{"internal/b/link_test.go", filepath.Join(outside, "env.go")},
		{"internal/b/_link.go", filepath.Join(outside, "env.go")},
		{"internal/b/.link.go", filepath.Join(outside, "env.go")},
		{"internal/b/link.txt", filepath.Join(outside, "env.go")},
		{"internal/b/dead.go", filepath.Join(outside, "missing.go")},
		{"internal/c", filepath.Join(outside, "pkg")},
		{"internal/_c", filepath.Join(outside, "pkg")},
		{"internal/b/testdata", filepath.Join(outside, "pkg")},
		{"internal/vendor", filepath.Join(outside, "pkg")},
		// A chain: d -> _hop -> outside/pkg; the walk skips _hop.
		{"internal/_hop", filepath.Join(outside, "pkg")},
		{"internal/d", "_hop"},
		{"internal/m2/go.mod", filepath.Join(outside, "go.mod")},
		{"internal/m3/go.mod", filepath.Join(outside, "missing.mod")},
	}
	for _, l := range links {
		if err := os.Symlink(l.target, filepath.Join(root, filepath.FromSlash(l.name))); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
	}
	want := []string{
		filepath.Join(root, "internal", "b", "dead.go") + ": symbolic link;",
		filepath.Join(root, "internal", "b", "link.go") + ": symbolic link;",
		filepath.Join(root, "internal", "c") + ": symbolic link to a directory;",
		filepath.Join(root, "internal", "d") + ": symbolic link to a directory;",
	}
	// A Unix socket named *.go: releaseEnvReads must report it without
	// opening it. Should it open the socket all the same, however often,
	// each open fails at once (ENXIO on Linux), so the walk fails instead
	// of hanging as it could on a FIFO.
	sock := filepath.Join(root, "internal", "b", "sock.go")
	skip := ""
	if err := makeSocket(t, sock); err == nil {
		want = append(want, sock+": not a regular file;")
	} else if runtime.GOOS == "linux" {
		t.Fatalf("no Unix socket: %v", err)
	} else {
		skip = fmt.Sprintf("no Unix socket on %s, the case of a file that is not regular is not checked: %v", runtime.GOOS, err)
	}

	// The root through a symbolic link: an error, not an empty walk.
	link := filepath.Join(dir, "modlink")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if reads, problems, err := releaseEnvReads(link); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("releaseEnvReads(%s) = %q, %q, %v; want the error not a directory", link, reads, problems, err)
	}

	reads, problems, err := releaseEnvReads(root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range reads {
		names = append(names, r.name)
	}
	sort.Strings(names)
	wantNames := []string{"GOMAIL_TEST_A", "GOMAIL_TEST_GOMOD_DANGLING", "GOMAIL_TEST_GOMOD_DIR"}
	if strings.Join(names, " ") != strings.Join(wantNames, " ") {
		t.Errorf("names read: %q, want %q", names, wantNames)
	}
	if len(problems) != len(want) {
		t.Errorf("%d problems, want %d: %q", len(problems), len(want), problems)
	}
	for _, w := range want {
		n := 0
		for _, p := range problems {
			if strings.HasPrefix(p, w) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%d problems beginning %q, want 1: %q", n, w, problems)
		}
	}
	if skip != "" {
		t.Skip(skip)
	}
}

// makeSocket makes the Unix socket path; it is removed with its directory.
// The name is bound relative to the directory (t.Chdir until the test
// ends): the absolute path may be longer than a socket address allows
// (108 bytes on Linux). On success path is a socket for Lstat; on an
// error no entry is left at path, or the test fails.
func makeSocket(t *testing.T, path string) error {
	t.Chdir(filepath.Dir(path))
	l, err := net.Listen("unix", filepath.Base(path))
	if err != nil {
		return err
	}
	// Close must not remove a relative name from another directory.
	if u, ok := l.(*net.UnixListener); ok {
		u.SetUnlinkOnClose(false)
	}
	t.Cleanup(func() { l.Close() })
	fi, err := os.Lstat(path)
	if err == nil && fi.Mode().Type() != fs.ModeSocket {
		err = fmt.Errorf("%s: %s, not a socket", path, fi.Mode().Type())
	}
	if err != nil {
		// Listen may have left an entry that is no socket for Lstat:
		// remove it, so that the walk does not report it and the test
		// ends with Skip outside Linux (task 32A).
		l.Close()
		if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			t.Fatalf("%v; not removed: %v", err, rerr)
		}
		return err
	}
	return nil
}

// TestReleaseSwitchesRootLink (task 30 package 30B): reached through a
// symbolic link to the checkout, releaseRoot returns the resolved module
// root, the one TestReleaseSwitches walks from the checkout itself.
func TestReleaseSwitchesRootLink(t *testing.T) {
	root, err := releaseRoot()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "repo")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	wd := filepath.Join(link, "internal", "e2e")
	t.Chdir(wd)
	// filepath.Abs starts from os.Getwd, which keeps the path through the
	// link only where the system reports it ($PWD on Linux, set by
	// t.Chdir); otherwise this test would not reach the link.
	if got, err := os.Getwd(); err != nil {
		t.Fatal(err)
	} else if got != wd {
		if runtime.GOOS == "linux" {
			t.Fatalf("working directory %s, want %s through the link", got, wd)
		}
		t.Skipf("working directory %s, not %s through the link", got, wd)
	}
	got, err := releaseRoot()
	if err != nil {
		t.Fatal(err)
	}
	if got != root {
		t.Errorf("releaseRoot() through %s = %s, want %s", link, got, root)
	}
}
