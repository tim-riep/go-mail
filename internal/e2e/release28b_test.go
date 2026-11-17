package e2e

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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
// (whatever its receiver), and any dot import.
func releaseEnvReads(t *testing.T, root string) ([]envRead, []string) {
	t.Helper()
	fset := token.NewFileSet()
	// pkgs holds the parsed non-test files of each directory, for
	// constants declared in another file of the package.
	pkgs := map[string][]*ast.File{}
	var tagged []*ast.File
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root {
				if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" {
					return filepath.SkipDir
				}
				// Another module: not built with this one.
				if _, err := os.Lstat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || !d.Type().IsRegular() {
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
		t.Fatal(err)
	}

	var reads []envRead
	var problems []string
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
	return reads, problems
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
// package). Each name in switches matches pattern
// (otherwise grep would not pass it to the script) and is read by such a
// file: the list is the one its comment names, and the collection is
// not empty.
//
// Not covered: a read through a function of a file that production
// builds compile as well (the name then passes as an argument), through
// a function or method of another package under another name, or
// through cgo; files of another module or under testdata.
func TestReleaseSwitches(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
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

	reads, problems := releaseEnvReads(t, root)
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
