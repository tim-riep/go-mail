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
	"syscall"
	"testing"
	"time"
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
	if len(namedReleaseTags(expr)) == 0 {
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

// namedReleaseTags returns the tags of releaseTags that the build
// constraint expr names, in the order of releaseTags.
func namedReleaseTags(expr constraint.Expr) []string {
	named := map[string]bool{}
	// Eval calls its function for every tag of the expression.
	expr.Eval(func(tag string) bool {
		named[tag] = true
		return true
	})
	var tags []string
	for _, r := range releaseTags {
		if named[r] {
			tags = append(tags, r)
		}
	}
	return tags
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
// go build ./... skips a directory whose name begins with "." or "_" or
// that is named testdata, but a program can import it (import
// "<module>/internal/_x" builds). Such a directory, and a symbolic link
// of such a name to a directory, is not read for names; skippedTagged
// searches the tree under it instead, and each file there that a program
// importing it would compile and whose build constraint names
// gomail_test or gomail_dev is a problem (see skippedTagged). vendor is
// skipped as before.
//
// Every symbolic link to a directory is a problem, wherever it is and
// whatever the directory holds (even nothing, or no Go file, or a
// directory that the walk reads anyway), unless its name begins with "."
// or "_" or is testdata (skippedTagged searches the directory it points
// to, as above), it is named vendor, or it lies under a skipped
// directory (under one named _*, .* or testdata, skippedTagged decides).
// That is fail closed: the test does not decide whether go build would
// compile something there.
// root itself must be a directory, not a symbolic link (WalkDir would
// read nothing below it); the caller resolves it (releaseRoot). Otherwise,
// and when the walk fails (a file that does not parse, a directory that
// cannot be read), the error is returned.
//
// An entry below root that is removed while the walk runs is skipped,
// as if the walk had come later (task 33, rework 33B2): a directory whose
// reading fails with fs.ErrNotExist, a regular file *.go that is gone
// when it is parsed, and a directory named _*, .* or testdata that is
// gone (or now a dangling link) when skippedTagged fails with
// fs.ErrNotExist. A link of such a name that os.Stat finds gone or
// dangling is not searched; one that cannot be followed for another
// reason (ELOOP, EACCES, ENAMETOOLONG) fails the walk (task 38 package
// 38A). A real directory of such a name goes to skippedTagged
// without os.Stat (only a link is followed first), so one that is
// renamed away and back during the walk is searched or skipped, but
// never read as a directory of the module; a link of such a name that is
// gone is skipped alone, its siblings are still walked (task 36 package
// 36B). In the checkout of a developer, .git/worktrees and
// .claude/worktrees change while agents start and end. root itself
// remains an error. A problem that such a change shows for a moment (a
// checkout without its go.mod yet) is not skipped here; see
// settledEnvReads.
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
			// WalkDir reports an error after it called this function
			// for the entry: reading a directory (it does not follow a
			// link there), or the root itself.
			if path != root && errors.Is(err, fs.ErrNotExist) {
				return filepath.SkipDir
			}
			return err
		}
		if releaseWalkHook != nil {
			releaseWalkHook(path)
		}
		if path == root {
			return nil
		}
		name := d.Name()
		// go build ./... ignores files and directories whose names begin
		// with "." or "_" (go/build), whatever they hold, and directories
		// named testdata; it never parses them. A program can import
		// such a directory all the same: skippedTagged searches it.
		hidden := strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
		if hidden || name == "testdata" {
			// A real directory goes to skippedTagged as it is, without
			// asking os.Stat first: a directory that is gone for a
			// moment (renamed away and back) must not fall through to
			// the walk below, which would read it as a directory of the
			// module (task 36 package 36B). Only a symbolic link is
			// followed with os.Stat; one that dangles, or is gone, or
			// leads to no directory is not searched. One that cannot be
			// followed for another reason (a loop, also a chain _l ->
			// _m -> _l, a target it may not search, a path too long, a
			// path through a regular file, ENOTDIR) fails the walk, as
			// skippedTagged fails on a directory at this path that it
			// cannot read (task 38 packages 38A, 38A2): fail closed.
			top := d.IsDir()
			if !top && d.Type()&fs.ModeSymlink != 0 {
				fi, err := os.Stat(path)
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return err
				}
				top = err == nil && fi.IsDir()
			}
			if top {
				p, err := skippedTagged(path)
				if err != nil {
					// skippedTagged fails with fs.ErrNotExist only when
					// top itself is gone (or, a link, now dangles): a
					// directory is skipped, and a link as well, but
					// SkipDir on a link would skip its siblings. Any
					// other error (a path too long) fails the walk.
					if errors.Is(err, fs.ErrNotExist) {
						if d.IsDir() {
							return filepath.SkipDir
						}
						return nil
					}
					return err
				}
				problems = append(problems, p...)
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if hidden {
				return nil
			}
		}
		if d.IsDir() {
			if name == "vendor" {
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
		// compiled. The test reads neither, so either is a problem. (A
		// link named _*, .* or testdata to a directory was searched
		// above.)
		if d.Type()&fs.ModeSymlink != 0 && name != "vendor" {
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
			// A regular file (not a link) that was removed.
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
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

// skippedTagged returns the problems in the tree under top, a directory
// (or a symbolic link to one) that go build ./... skips, its name
// beginning with "." or "_" or named testdata, but that a program can
// import (task 33 package 33B, list after M1 no. 119). A program that
// imports top or a directory under it compiles its files whose names
// end in .go, but not in _test.go, and do not begin with "." or "_",
// where their build constraint holds. Such a file is a problem when its
// constraint names gomail_test or gomail_dev (whatever else it says;
// only the package clause and the comments before it are parsed), when
// that much does not parse, and when it is not a regular file or a
// symbolic link to one (go build would read it or fail). A symbolic link
// to a directory under top is a problem as well, whatever it holds (fail
// closed, as in releaseEnvReads). A directory with a go.mod (another
// module, decided as in releaseEnvReads), top included, is not searched.
// Untagged files are not read for names: go build ./... does not
// compile them, and the generators under testdata (package main without
// a tag) are none of a program. top may be a symbolic link: the tree of
// its target is searched and named under top. A tree that cannot be read
// is an error, but a directory below top that is removed while the walk
// runs (reading it fails with fs.ErrNotExist) is skipped, as in
// releaseEnvReads; top itself gone is an error. A file removed while the
// walk runs can show as a problem (not a regular file, does not parse),
// and so can a checkout whose go.mod is not there yet or no more; see
// settledEnvReads.
func skippedTagged(top string) ([]string, error) {
	dir, err := filepath.EvalSymlinks(top)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var problems []string
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path != dir && errors.Is(err, fs.ErrNotExist) {
				return filepath.SkipDir
			}
			return err
		}
		if releaseWalkHook != nil {
			releaseWalkHook(path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		at := filepath.Join(top, rel)
		problem := func(what string) {
			problems = append(problems, fmt.Sprintf("%s: %s; go build ./... skips %s, but a program may import it, this test does not read it", at, what, top))
		}
		name := d.Name()
		if d.IsDir() {
			if fi, err := os.Stat(filepath.Join(path, "go.mod")); err == nil && !fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if fi, err := os.Stat(path); err == nil && fi.IsDir() {
				problem("symbolic link to a directory")
				return nil
			}
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return nil
		}
		if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
			problem("not a regular file")
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly|parser.ParseComments)
		if err != nil {
			problem(fmt.Sprintf("does not parse (%v)", err))
			return nil
		}
		expr, err := fileConstraint(f)
		if err != nil {
			problem(fmt.Sprintf("build constraint does not parse (%v)", err))
			return nil
		}
		if expr != nil {
			if tags := namedReleaseTags(expr); len(tags) > 0 {
				problem("build constraint names " + strings.Join(tags, " and "))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return problems, nil
}

// releaseWalkHook, when not nil, is called with the path of each entry
// that releaseEnvReads and skippedTagged visit (their roots included),
// before they look at it, but not for an error that WalkDir reports. It
// lets TestReleaseEnvReadsVanish remove entries during the walk; no test
// that sets it runs in parallel.
var releaseWalkHook func(path string)

// releaseSettle is how long TestReleaseSwitches waits before it walks the
// tree again to confirm problems (settledEnvReads).
const releaseSettle = 3 * time.Second

// settledEnvReads calls walk and, when that finds problems, wait, and
// then walk once more (task 33, rework 33B2). The problems it returns are
// those that both walks find (each as often as in both), the reads those
// of the first walk; an error of either walk is returned. In the
// checkout of a developer a directory can change during a walk: a
// checkout under .claude/worktrees that git is making has cmd/ before
// its go.mod (git writes them in this order), one being removed can lose
// its go.mod first, and a file removed during the walk shows as not a
// regular file. skippedTagged then reports the files of such a moment
// as problems of a directory that a program may import; a moment later
// the directory is a module again or gone. A problem in the tree itself
// is found by both walks: nothing that go build would compile is left
// out. A change that lasts longer than the wait is still reported (the
// test fails, fail closed), and so is one at the same path in both walks
// (a checkout made again under the same name).
func settledEnvReads(walk func() ([]envRead, []string, error), wait func()) ([]envRead, []string, error) {
	reads, problems, err := walk()
	if err != nil || len(problems) == 0 {
		return reads, problems, err
	}
	wait()
	_, again, err := walk()
	if err != nil {
		return nil, nil, err
	}
	n := map[string]int{}
	for _, p := range again {
		n[p]++
	}
	var both []string
	for _, p := range problems {
		if n[p] > 0 {
			n[p]--
			both = append(both, p)
		}
	}
	return reads, both, nil
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
// outside cmd/ and internal/. Files and directories that go build ./...
// ignores (names beginning with "." or "_", testdata, vendor, other
// modules) are not read for names. A directory named _*, .* or testdata
// (or a symbolic link of such a name to one) can be imported all the
// same; a file under it that such an import compiles fails the test when
// its build constraint names gomail_test or gomail_dev (skippedTagged;
// task 33 package 33B, list after M1 no. 119). The module root is
// resolved with filepath.EvalSymlinks first (releaseRoot): reached
// through a symbolic link, the walk would read nothing. Each name in
// switches matches pattern (otherwise grep would not pass it to the
// script) and is read by such a file: the list is the one its comment
// names, and the collection is not empty.
//
// In the checkout of a developer, .git and .claude/worktrees (both
// searched: a program can import a directory under them, go build does)
// change while agents start and end (task 33, rework 33B2). An entry
// removed during the walk is skipped, and a problem counts only when a
// second walk releaseSettle later finds it as well (settledEnvReads): a
// checkout being made or removed lacks its go.mod for a moment.
//
// Not covered: a read through a function of a file that production
// builds compile as well (the name then passes as an argument), through
// a function or method of another package under another name, or
// through cgo; files of another module or under vendor; a file without
// such a tag under a skipped directory that a tagged program imports.
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

	reads, problems, err := settledEnvReads(func() ([]envRead, []string, error) {
		return releaseEnvReads(root)
	}, func() { time.Sleep(releaseSettle) })
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
// named *_test.go, _*.go, .*.go or not *.go, and a link to a directory
// named vendor, are not. A directory with a regular go.mod or a link
// go.mod to a regular file is another module and not read; one with a
// dangling link go.mod or a directory go.mod is read, as go builds it. A
// root that is a symbolic link is an error, not an empty walk.
//
// Since task 33 (package 33B, list after M1 no. 119): real directories
// _x, .x, testdata and vendor with Go files that read the environment
// are not read for names, as go build ./... does not compile them. Under
// those named _*, .* and testdata (and the links of such names to a
// directory, _c, _hop and testdata, which were no problem before), which
// a program can import, each file that such an import compiles and whose
// constraint names gomail_test or gomail_dev is a problem, once, also
// through a link *.go and below a subdirectory, and so are a link to a
// directory, a dangling link *.go and a file whose package clause or
// build constraint does not parse. Not problems there: files without
// such a tag (also one that reads the environment, like the generators
// under testdata), files named _*.go, .*.go, *_test.go or not *.go, a
// dangling link _*.go, a file with the constraint ignore whose body
// does not parse, another module (_m with go.mod), and anything under
// vendor.
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
	// untagged reads the environment like the generators under testdata.
	const untagged = "package main\n\nimport \"os\"\n\nfunc main() { _ = os.Getenv(\"GOMAIL_TEST_UNTAGGED\") + os.Environ()[0] }\n"
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
		// Real directories that go build ./... skips (task 33 package
		// 33B, list after M1 no. 119 fund D): none is read for names.
		// Those named _*, .* and testdata can be imported, so a file
		// there that an import compiles is a problem when its constraint
		// names gomail_test or gomail_dev; nothing else there is.
		"mod/internal/_x/env_tagged.go":           tagged("GOMAIL_TEST_UNDERSCORE_DIR"),
		"mod/internal/_x/plain.go":                untagged,
		"mod/internal/_x/_env_tagged.go":          tagged("GOMAIL_TEST_UNDERSCORE_FILE"),
		"mod/internal/_x/.env_tagged.go":          tagged("GOMAIL_TEST_DOT_FILE"),
		"mod/internal/_x/env_tagged_test.go":      tagged("GOMAIL_TEST_TEST_FILE"),
		"mod/internal/_x/notes.txt":               tagged("GOMAIL_TEST_TXT"),
		"mod/internal/.x/env_tagged.go":           tagged("GOMAIL_TEST_DOT_DIR"),
		"mod/internal/.x/sub/plain.go":            untagged,
		"mod/internal/e/e.go":                     "package e\n",
		"mod/internal/e/testdata/gen/main.go":     untagged,
		"mod/internal/e/testdata/x/sub/env.go":    "//go:build !gomail_dev\n\npackage sub\n",
		"mod/internal/e/testdata/x/env_tagged.go": tagged("GOMAIL_TEST_TESTDATA"),
		"mod/internal/e/testdata/x/bad.go":        "package (\n",
		"mod/internal/e/testdata/x/badtag.go":     "//go:build gomail_test &&\n\npackage x\n",
		"mod/internal/e/testdata/x/ignore.go":     "//go:build ignore\n\npackage main\n\nfunc (\n",
		"mod/internal/_m/go.mod":                  "module m\n",
		"mod/internal/_m/env_tagged.go":           tagged("GOMAIL_TEST_UNDERSCORE_MODULE"),
		"mod/vendor/example.com/v/env_tagged.go":  tagged("GOMAIL_TEST_VENDOR"),
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
		// Under a skipped directory: a link to a directory and a
		// dangling link *.go are problems, a link to a tagged file is
		// read through, one to an untagged file and a dangling link
		// _*.go are not problems.
		{"internal/_x/sub", filepath.Join(outside, "pkg")},
		{"internal/_x/dead.go", filepath.Join(outside, "missing.go")},
		{"internal/.x/link.go", filepath.Join(outside, "env.go")},
		{"internal/.x/plain_link.go", filepath.Join(root, "internal", "_x", "plain.go")},
		{"internal/.x/_dead.go", filepath.Join(outside, "missing.go")},
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
	// skipped is a problem of skippedTagged: under the directory top
	// (below root), the entry at, what was found.
	skipped := func(top, at, what string) string {
		top = filepath.Join(root, filepath.FromSlash(top))
		return filepath.Join(top, filepath.FromSlash(at)) + ": " + what + "; go build ./... skips " + top + ", but a program may import it"
	}
	const namesTest = "build constraint names gomail_test"
	want = append(want,
		skipped("internal/_x", "env_tagged.go", namesTest),
		skipped("internal/_x", "sub", "symbolic link to a directory"),
		skipped("internal/_x", "dead.go", "not a regular file"),
		skipped("internal/.x", "env_tagged.go", namesTest),
		skipped("internal/.x", "link.go", namesTest),
		skipped("internal/e/testdata", "x/sub/env.go", "build constraint names gomail_dev"),
		skipped("internal/e/testdata", "x/env_tagged.go", namesTest),
		// The links named _* and testdata to a directory with a
		// tagged file: an import compiles it as well.
		skipped("internal/_c", "env_tagged.go", namesTest),
		skipped("internal/_hop", "env_tagged.go", namesTest),
		skipped("internal/b/testdata", "env_tagged.go", namesTest),
	)
	// A file whose package clause or build constraint does not parse:
	// the message holds the error.
	x := filepath.Join(root, "internal", "e", "testdata", "x")
	want = append(want, filepath.Join(x, "bad.go")+": does not parse (", filepath.Join(x, "badtag.go")+": build constraint does not parse (")
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

// taggedEnvFile is a file of package main whose build constraint names
// gomail_test and that reads the environment variable name.
func taggedEnvFile(name string) string {
	return "//go:build gomail_test\n\npackage main\n\nimport \"os\"\n\nvar v = os.Getenv(\"" + name + "\")\n"
}

// writeTree writes files (slash-separated names below dir) and their
// directories.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, text := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestReleaseEnvReadsVanish (task 33, rework 33B2): an entry removed
// while releaseEnvReads walks is skipped, as if the walk had come later,
// and the walk goes on: a directory of the module, a directory under one
// named .* that skippedTagged searches (like .git/worktrees/<name> or
// .claude/worktrees/<name>), a regular file *.go before it is parsed,
// and a directory named _* after releaseEnvReads found it but before
// skippedTagged reads it. releaseWalkHook removes each when the walk
// visits the entry named in the case; WalkDir reads the entries of a
// directory before it visits them, so a file is removed from the visit
// of a sibling before it. The root removed during the walk is an error,
// of releaseEnvReads and of skippedTagged.
func TestReleaseEnvReadsVanish(t *testing.T) {
	t.Cleanup(func() { releaseWalkHook = nil })
	root := filepath.Join(t.TempDir(), "mod")
	writeTree(t, root, map[string]string{
		"cmd/a/env_tagged.go":                 taggedEnvFile("GOMAIL_TEST_A"),
		"internal/gone/env_tagged.go":         taggedEnvFile("GOMAIL_TEST_GONE_DIR"),
		"internal/v/a/a.go":                   "package a\n",
		"internal/v/b.go":                     taggedEnvFile("GOMAIL_TEST_GONE_FILE"),
		"internal/v/c.go":                     taggedEnvFile("GOMAIL_TEST_C"),
		".gitlike/worktrees/w1/a/b/f":         "",
		".gitlike/worktrees/w1/env_tagged.go": taggedEnvFile("GOMAIL_TEST_GONE_HIDDEN"),
		".gitlike/worktrees/w2/env_tagged.go": taggedEnvFile("GOMAIL_TEST_HIDDEN"),
		"_gone/env_tagged.go":                 taggedEnvFile("GOMAIL_TEST_GONE_SKIPPED"),
	})
	// At the visit nth of at (releaseEnvReads and skippedTagged both
	// visit _gone), gone is removed.
	cases := []struct {
		at   string
		nth  int
		gone string
	}{
		{"internal/gone", 1, "internal/gone"},
		{"internal/v/a", 1, "internal/v/b.go"},
		{".gitlike/worktrees/w1", 1, ".gitlike/worktrees/w1"},
		{"_gone", 2, "_gone"},
	}
	visits := map[string]int{}
	removed := map[string]bool{}
	releaseWalkHook = func(path string) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Error(err)
			return
		}
		rel = filepath.ToSlash(rel)
		visits[rel]++
		for _, c := range cases {
			if c.at == rel && c.nth == visits[rel] {
				if err := os.RemoveAll(filepath.Join(root, filepath.FromSlash(c.gone))); err != nil {
					t.Error(err)
				}
				removed[c.gone] = true
			}
		}
	}
	reads, problems, err := releaseEnvReads(root)
	releaseWalkHook = nil
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if !removed[c.gone] {
			t.Errorf("%s was not removed: the walk did not visit %s %d times", c.gone, c.at, c.nth)
		}
	}
	var names []string
	for _, r := range reads {
		names = append(names, r.name)
	}
	sort.Strings(names)
	if got, want := strings.Join(names, " "), "GOMAIL_TEST_A GOMAIL_TEST_C"; got != want {
		t.Errorf("names read: %s, want %s", got, want)
	}
	top := filepath.Join(root, ".gitlike")
	want := filepath.Join(top, "worktrees", "w2", "env_tagged.go") + ": build constraint names gomail_test; go build ./... skips " + top + ","
	if len(problems) != 1 || !strings.HasPrefix(problems[0], want) {
		t.Errorf("problems %q, want one beginning %q", problems, want)
	}

	// The root itself, of releaseEnvReads and of skippedTagged.
	for _, walk := range []struct {
		name string
		f    func(string) error
	}{
		{"releaseEnvReads", func(dir string) error { _, _, err := releaseEnvReads(dir); return err }},
		{"skippedTagged", func(dir string) error { _, err := skippedTagged(dir); return err }},
	} {
		dir := filepath.Join(t.TempDir(), "_root")
		writeTree(t, dir, map[string]string{"sub/env_tagged.go": taggedEnvFile("GOMAIL_TEST_ROOT")})
		releaseWalkHook = func(path string) {
			if path == dir {
				if err := os.RemoveAll(dir); err != nil {
					t.Error(err)
				}
			}
		}
		err := walk.f(dir)
		releaseWalkHook = nil
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s(%s), the root removed during the walk: %v, want an error fs.ErrNotExist", walk.name, dir, err)
		}
	}
}

// TestReleaseEnvReadsVanishLink (task 36 package 36B, R01 of the review
// of 33B2): a symbolic link named _* or testdata to a directory that is
// gone during the walk is skipped alone; the file after it in the same
// directory is still read (SkipDir on a link would skip its siblings).
// In v the link _l is removed when releaseEnvReads visits it (os.Stat
// fails); in w and u the directory a link points to is removed when
// skippedTagged visits it (skippedTagged fails). In z a real directory
// _d removed at its visit is skipped, and its sibling read as well; in k
// a link _l that stays is searched (its tagged file the only problem,
// compared as a whole text) and the entries after it are read. Each
// sibling comes after the entry in the order of WalkDir.
func TestReleaseEnvReadsVanishLink(t *testing.T) {
	t.Cleanup(func() { releaseWalkHook = nil })
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "mod")
	outside := filepath.Join(dir, "outside")
	writeTree(t, dir, map[string]string{
		"mod/internal/v/x.go":             taggedEnvFile("GOMAIL_TEST_V"),
		"mod/internal/w/x.go":             taggedEnvFile("GOMAIL_TEST_W"),
		"mod/internal/u/x.go":             taggedEnvFile("GOMAIL_TEST_U"),
		"mod/internal/z/x.go":             taggedEnvFile("GOMAIL_TEST_Z"),
		"mod/internal/z/_d/env.go":        taggedEnvFile("GOMAIL_TEST_GONE_D"),
		"outside/v/env_tagged.go":         taggedEnvFile("GOMAIL_TEST_GONE_V"),
		"outside/w/env_tagged.go":         taggedEnvFile("GOMAIL_TEST_GONE_W"),
		"outside/u/env_tagged.go":         taggedEnvFile("GOMAIL_TEST_GONE_U"),
		"outside/kept/env_tagged.go":      taggedEnvFile("GOMAIL_TEST_KEPT"),
		"mod/internal/k/x.go":             taggedEnvFile("GOMAIL_TEST_K"),
		"mod/internal/k/zz/env_tagged.go": taggedEnvFile("GOMAIL_TEST_K2"),
	})
	for _, l := range []struct{ name, target string }{
		{"internal/v/_l", filepath.Join(outside, "v")},
		{"internal/w/_l", filepath.Join(outside, "w")},
		{"internal/u/testdata", filepath.Join(outside, "u")},
		// A link that stays: searched, its file a problem, the
		// siblings read.
		{"internal/k/_l", filepath.Join(outside, "kept")},
	} {
		if err := os.Symlink(l.target, filepath.Join(root, filepath.FromSlash(l.name))); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
	}
	// At the visit of at, gone is removed.
	cases := map[string]string{
		filepath.Join(root, "internal", "v", "_l"): filepath.Join(root, "internal", "v", "_l"),
		filepath.Join(outside, "w"):                filepath.Join(outside, "w"),
		filepath.Join(outside, "u"):                filepath.Join(outside, "u"),
		filepath.Join(root, "internal", "z", "_d"): filepath.Join(root, "internal", "z", "_d"),
	}
	removed := map[string]bool{}
	releaseWalkHook = func(path string) {
		if gone, ok := cases[path]; ok && !removed[gone] {
			if err := os.RemoveAll(gone); err != nil {
				t.Error(err)
			}
			removed[gone] = true
		}
	}
	reads, problems, err := releaseEnvReads(root)
	releaseWalkHook = nil
	if err != nil {
		t.Fatal(err)
	}
	for at, gone := range cases {
		if !removed[gone] {
			t.Errorf("%s was not removed: the walk did not visit %s", gone, at)
		}
	}
	var names []string
	for _, r := range reads {
		names = append(names, r.name)
	}
	sort.Strings(names)
	if got, want := strings.Join(names, " "), "GOMAIL_TEST_K GOMAIL_TEST_K2 GOMAIL_TEST_U GOMAIL_TEST_V GOMAIL_TEST_W GOMAIL_TEST_Z"; got != want {
		t.Errorf("names read: %s, want %s", got, want)
	}
	top := filepath.Join(root, "internal", "k", "_l")
	want := filepath.Join(top, "env_tagged.go") + ": build constraint names gomail_test; go build ./... skips " + top + ", but a program may import it, this test does not read it"
	if len(problems) != 1 || problems[0] != want {
		t.Errorf("problems %q, want only %q", problems, want)
	}
}

// TestReleaseSettle (task 33, rework 33B2): settledEnvReads returns the
// problems that both walks find, each as often as in both, and the reads
// of the first; it waits and walks again only after problems, and an
// error of either walk is its error. Then in a tree: a checkout under
// .claude/worktrees without its go.mod (as git makes one: cmd/ first),
// another one that is being removed, and a skipped directory _p with a
// tagged file. The first walk reports all three; after the wait (which
// writes the go.mod and removes the other checkout) only _p is left.
// Each problem is compared as a whole text (task 36 package 36B).
func TestReleaseSettle(t *testing.T) {
	type result struct {
		reads    []envRead
		problems []string
		err      error
	}
	errWalk := errors.New("walk failed")
	r1 := []envRead{{"a.go:1:1", "GOMAIL_TEST_A"}}
	r2 := []envRead{{"b.go:1:1", "GOMAIL_TEST_B"}}
	for _, c := range []struct {
		name     string
		walks    []result
		waits    int
		problems []string
		err      error
	}{
		{"no problems", []result{{r1, nil, nil}}, 0, nil, nil},
		{"first fails", []result{{nil, nil, errWalk}}, 0, nil, errWalk},
		{"both", []result{{r1, []string{"a", "b", "b", "c"}, nil}, {r2, []string{"c", "b", "d"}, nil}}, 1, []string{"b", "c"}, nil},
		{"gone", []result{{r1, []string{"a"}, nil}, {r2, nil, nil}}, 1, nil, nil},
		{"second fails", []result{{r1, []string{"a"}, nil}, {r2, []string{"a"}, errWalk}}, 1, nil, errWalk},
	} {
		n, waits := 0, 0
		reads, problems, err := settledEnvReads(func() ([]envRead, []string, error) {
			n++
			if n > len(c.walks) {
				t.Fatalf("%s: walk %d, want at most %d", c.name, n, len(c.walks))
			}
			w := c.walks[n-1]
			return w.reads, w.problems, w.err
		}, func() { waits++ })
		if n != len(c.walks) || waits != c.waits {
			t.Errorf("%s: %d walks, %d waits, want %d, %d", c.name, n, waits, len(c.walks), c.waits)
		}
		if !errors.Is(err, c.err) {
			t.Errorf("%s: error %v, want %v", c.name, err, c.err)
		}
		if strings.Join(problems, " ") != strings.Join(c.problems, " ") {
			t.Errorf("%s: problems %q, want %q", c.name, problems, c.problems)
		}
		if first := len(reads) == 1 && reads[0] == r1[0]; first != (c.err == nil) {
			t.Errorf("%s: reads %q; want those of the first walk unless an error", c.name, reads)
		}
	}

	root := filepath.Join(t.TempDir(), "mod")
	writeTree(t, root, map[string]string{
		"go.mod":              "module example.com/mod\n",
		"cmd/a/env_tagged.go": taggedEnvFile("GOMAIL_TEST_A"),
		".claude/worktrees/new/cmd/a/env_tagged.go":  taggedEnvFile("GOMAIL_TEST_A"),
		".claude/worktrees/gone/cmd/a/env_tagged.go": taggedEnvFile("GOMAIL_TEST_A"),
		"_p/env_tagged.go":                           taggedEnvFile("GOMAIL_TEST_P"),
	})
	walk := func() ([]envRead, []string, error) { return releaseEnvReads(root) }
	// problem is the whole text of a problem of skippedTagged: the file
	// at (below root) under the skipped directory top (task 36 package
	// 36B, R04 of the review of 33B2: the text is compared whole).
	problem := func(top, at string) string {
		top = filepath.Join(root, top)
		return filepath.Join(top, filepath.FromSlash(at)) + ": build constraint names gomail_test; go build ./... skips " + top + ", but a program may import it, this test does not read it"
	}
	// In the order of WalkDir: .claude before _p, gone before new.
	first := []string{
		problem(".claude", "worktrees/gone/cmd/a/env_tagged.go"),
		problem(".claude", "worktrees/new/cmd/a/env_tagged.go"),
		problem("_p", "env_tagged.go"),
	}
	if _, problems, err := walk(); err != nil || strings.Join(problems, "\n") != strings.Join(first, "\n") {
		t.Fatalf("first walk: %q, %v; want %q", problems, err, first)
	}
	reads, problems, err := settledEnvReads(walk, func() {
		if err := os.WriteFile(filepath.Join(root, ".claude", "worktrees", "new", "go.mod"), []byte("module example.com/mod\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(root, ".claude", "worktrees", "gone")); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) != 1 || reads[0].name != "GOMAIL_TEST_A" {
		t.Errorf("reads %q, want GOMAIL_TEST_A", reads)
	}
	if want := first[2]; len(problems) != 1 || problems[0] != want {
		t.Errorf("problems %q, want only %q", problems, want)
	}
}

// TestReleaseEnvReadsErrors (task 33, rework 33B2): an error during the
// walk that does not say that an entry is gone fails releaseEnvReads; it
// is not skipped like a removed entry: a file of the module that does
// not parse, and a directory that cannot be read, of the module
// (internal/deep) and under _deep (an error of skippedTagged; _deep
// also as a symbolic link to a directory outside the module, which only
// skippedTagged reads). A test run as root reads every directory, so the
// error there is a path too long for the system: a chain of directories
// whose path exceeds PATH_MAX (4096 bytes on Linux), each made relative
// to its parent with os.Root. Since task 36 (package 36B) also a
// directory named _x, .x or testdata whose own path is too long while
// that of its parent is not: skippedTagged gets it without os.Stat, and
// its error ENAMETOOLONG fails the walk (only fs.ErrNotExist skips it).
// The paths only on Linux, where the limit is known.
func TestReleaseEnvReadsErrors(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mod")
	writeTree(t, root, map[string]string{"cmd/a/main.go": "package main\n\nfunc main() {}\n", "cmd/a/bad.go": "package (\n"})
	if reads, problems, err := releaseEnvReads(root); err == nil || !strings.Contains(err.Error(), "bad.go") {
		t.Errorf("releaseEnvReads, a file that does not parse: %q, %q, %v; want its error", reads, problems, err)
	}
	if runtime.GOOS != "linux" {
		t.Skipf("PATH_MAX of %s not known to this test", runtime.GOOS)
	}
	for _, under := range []string{"internal/deep", "_deep", "_deep link"} {
		dir := t.TempDir()
		root := filepath.Join(dir, "mod")
		deep := filepath.Join(root, filepath.FromSlash(under))
		if under == "_deep link" {
			deep = filepath.Join(dir, "outside")
		}
		writeTree(t, deep, map[string]string{"x.go": "package x\n"})
		writeTree(t, root, map[string]string{"cmd/a/main.go": "package main\n\nfunc main() {}\n"})
		if under == "_deep link" {
			if err := os.Symlink(deep, filepath.Join(root, "_deep")); err != nil {
				t.Fatal(err)
			}
		}
		r, err := os.OpenRoot(deep)
		if err != nil {
			t.Fatal(err)
		}
		name := strings.Repeat("d", 200)
		for i := 0; i < 25; i++ {
			if err := r.Mkdir(name, 0o755); err != nil {
				r.Close()
				t.Fatal(err)
			}
			next, err := r.OpenRoot(name)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			r = next
		}
		err = r.WriteFile("env_tagged.go", []byte(taggedEnvFile("GOMAIL_TEST_DEEP")), 0o644)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		reads, problems, err := releaseEnvReads(root)
		if !errors.Is(err, syscall.ENAMETOOLONG) {
			t.Errorf("releaseEnvReads, a path too long under %s: %q, %q, %v; want the error ENAMETOOLONG", under, reads, problems, err)
		}
	}

	// A directory named _*, .* or testdata whose own path is too long,
	// in a directory whose path is not (task 36 package 36B): the walk
	// reads the parent and finds it; skippedTagged cannot search it and
	// the walk fails, it is not skipped like one that is gone.
	for _, skipped := range []string{"_x", ".x", "testdata"} {
		root := filepath.Join(t.TempDir(), "mod")
		writeTree(t, root, map[string]string{"cmd/a/main.go": "package main\n\nfunc main() {}\n", "internal/long/x.go": "package long\n"})
		parent := filepath.Join(root, "internal", "long")
		r, err := os.OpenRoot(parent)
		if err != nil {
			t.Fatal(err)
		}
		// parent grows to 4094 or 4095 bytes: readable, but each entry
		// in it is longer than PATH_MAX allows (4096 with its NUL).
		for len(parent) < 4094 {
			name := strings.Repeat("d", min(200, 4094-len(parent)-1))
			if len(name) < 1 {
				name = "d"
			}
			if err := r.Mkdir(name, 0o755); err != nil {
				r.Close()
				t.Fatal(err)
			}
			next, err := r.OpenRoot(name)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			r, parent = next, filepath.Join(parent, name)
		}
		err = r.Mkdir(skipped, 0o755)
		if err == nil {
			err = r.WriteFile(skipped+"/env_tagged.go", []byte(taggedEnvFile("GOMAIL_TEST_LONG")), 0o644)
		}
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if n := len(filepath.Join(parent, skipped)); len(parent) > 4095 || n < 4096 {
			t.Fatalf("%s: %d bytes, %s: %d bytes; want at most 4095 and at least 4096", parent, len(parent), skipped, n)
		}
		reads, problems, err := releaseEnvReads(root)
		if !errors.Is(err, syscall.ENAMETOOLONG) {
			t.Errorf("releaseEnvReads, %s with a path too long: %q, %q, %v; want the error ENAMETOOLONG", skipped, reads, problems, err)
		}
	}
}

// TestReleaseSwitchesLinkStat (task 38 package 38A): a symbolic link
// named _*, .* or testdata that os.Stat cannot follow for a reason other
// than fs.ErrNotExist (also ENOTDIR, a path through a regular file)
// fails releaseEnvReads, as a directory at that path that cannot be
// read does; it is not skipped like a dangling link. A loop (a chain
// _l -> _m -> _l, ELOOP) for each kind of name, and a target below a
// directory the test may not search (EACCES), which a test run as root
// cannot make: that case is skipped then, with the reason. A dangling
// link of such a name is still skipped. For testdata the partner z sorts
// after it and is neither hidden nor testdata (task 38 package 38A2): the
// walk reaches the link testdata first, so the check must cover testdata,
// not only _* and .*.
func TestReleaseSwitchesLinkStat(t *testing.T) {
	const mainGo = "package main\n\nfunc main() {}\n"
	for _, n := range [][2]string{{"_l", "_m"}, {".l", ".m"}, {"testdata", "z"}} {
		root := filepath.Join(t.TempDir(), "mod")
		writeTree(t, root, map[string]string{"cmd/a/main.go": mainGo})
		if err := os.Symlink(n[1], filepath.Join(root, n[0])); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(n[0], filepath.Join(root, n[1])); err != nil {
			t.Fatal(err)
		}
		reads, problems, err := releaseEnvReads(root)
		if !errors.Is(err, syscall.ELOOP) {
			t.Errorf("releaseEnvReads, a chain %s -> %s -> %s: %q, %q, %v; want the error ELOOP", n[0], n[1], n[0], reads, problems, err)
		}
	}

	root := filepath.Join(t.TempDir(), "mod")
	writeTree(t, root, map[string]string{"cmd/a/main.go": mainGo})
	if err := os.Symlink("gone", filepath.Join(root, "_gone")); err != nil {
		t.Fatal(err)
	}
	if reads, problems, err := releaseEnvReads(root); err != nil {
		t.Errorf("releaseEnvReads, a dangling link _gone: %q, %q, %v; want no error", reads, problems, err)
	}

	t.Run("EACCES", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("run as root: os.Stat follows a link into a directory without search permission, EACCES cannot be made")
		}
		dir := t.TempDir()
		root := filepath.Join(dir, "mod")
		locked := filepath.Join(dir, "locked")
		writeTree(t, root, map[string]string{"cmd/a/main.go": mainGo})
		writeTree(t, filepath.Join(locked, "x"), map[string]string{"env_tagged.go": taggedEnvFile("GOMAIL_TEST_LOCKED")})
		if err := os.Symlink(filepath.Join(locked, "x"), filepath.Join(root, "_x")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(locked, 0o755) })
		if _, err := os.Stat(filepath.Join(root, "_x")); !errors.Is(err, syscall.EACCES) {
			t.Skipf("os.Stat of the link: %v; this system does not deny the search, EACCES cannot be made", err)
		}
		reads, problems, err := releaseEnvReads(root)
		if !errors.Is(err, syscall.EACCES) {
			t.Errorf("releaseEnvReads, a link _x into a directory without search permission: %q, %q, %v; want the error EACCES", reads, problems, err)
		}
	})
}
