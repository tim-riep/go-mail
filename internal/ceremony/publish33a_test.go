package ceremony

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestNofileOnlyThroughSetNofile (task 33 A point 1; backlog 118,
// review of task 29 C, H2): every Go file of this package, of every
// build tag and test or not, changes a resource limit only through
// setNofile, and every function that calls setNofile calls keepNofile
// as well, which fails the test when the limit is not back afterwards.
// A file that calls Setrlimit or Prlimit of any package directly
// (syscall.Setrlimit sets RLIMIT_NOFILE so that every child started
// later inherits it: review of task 28 A2, robustness H1) or names
// SYS_SETRLIMIT or SYS_PRLIMIT64 outside setNofile is reported with its
// position. The files are parsed, not built, so that a file of another
// system counts as well.
func TestNofileOnlyThroughSetNofile(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var bad []string
	var callers []string
	defined := false
	for _, n := range names {
		src, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, n, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		// fn is the function declaration that holds the node, "" outside one.
		for _, d := range f.Decls {
			fn := ""
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				fn = fd.Name.Name
			}
			calls := map[string]bool{}
			ast.Inspect(d, func(x ast.Node) bool {
				switch x := x.(type) {
				case *ast.Ident:
					switch x.Name {
					case "Setrlimit", "Prlimit":
						bad = append(bad, fset.Position(x.Pos()).String()+": "+x.Name+" sets a limit directly; use setNofile and keepNofile")
					case "SYS_SETRLIMIT", "SYS_PRLIMIT64":
						if fn != "setNofile" {
							bad = append(bad, fset.Position(x.Pos()).String()+": "+x.Name+" outside setNofile")
						}
					}
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok {
						calls[id.Name] = true
					}
				}
				return true
			})
			if fn == "setNofile" {
				defined = true
				continue
			}
			if calls["setNofile"] && fn != "keepNofile" {
				callers = append(callers, fn)
				if !calls["keepNofile"] {
					bad = append(bad, n+": "+fn+" calls setNofile without keepNofile")
				}
			}
		}
	}
	slices.Sort(callers)
	t.Logf("%d files; functions that call setNofile: %s", len(names), strings.Join(callers, ", "))
	// The scan must have seen setNofile and its callers (a scan of the
	// wrong directory would find nothing and pass).
	if !defined || len(callers) == 0 {
		t.Fatalf("setNofile not found (%v) or never called (%q) in %d files", defined, callers, len(names))
	}
	for _, b := range bad {
		t.Error(b)
	}
}
