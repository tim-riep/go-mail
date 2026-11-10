package bench

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// readBenchScript returns scripts/bench.sh.
func readBenchScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "bench.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// braceExpand expands the brace groups of a word of bench.sh as bash
// does for the words of wantnames: every {a,b,...} (not nested) gives one
// word per alternative, from left to right; a brace without a comma
// inside stays as it is.
func braceExpand(w string) []string {
	i := strings.IndexByte(w, '{')
	if i < 0 {
		return []string{w}
	}
	j := strings.IndexByte(w[i:], '}')
	if j < 0 || !strings.Contains(w[i:i+j], ",") {
		// a literal brace: expand what follows it
		var out []string
		for _, rest := range braceExpand(w[i+1:]) {
			out = append(out, w[:i+1]+rest)
		}
		return out
	}
	var out []string
	for _, alt := range strings.Split(w[i+1:i+j], ",") {
		for _, rest := range braceExpand(w[i+j+1:]) {
			out = append(out, w[:i]+alt+rest)
		}
	}
	return out
}

// TestBraceExpand checks braceExpand against what bash prints for these
// words.
func TestBraceExpand(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"a", []string{"a"}},
		{"a/{b,c}", []string{"a/b", "a/c"}},
		{"x={1,2}/y={a,b,c}", []string{"x=1/y=a", "x=1/y=b", "x=1/y=c", "x=2/y=a", "x=2/y=b", "x=2/y=c"}},
		{"a{b}c/{d,e}", []string{"a{b}c/d", "a{b}c/e"}},
		{"m=@N@/{p,q}", []string{"m=@N@/p", "m=@N@/q"}},
	} {
		if got := braceExpand(c.in); !slices.Equal(got, c.want) {
			t.Errorf("braceExpand(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// benchFuncs returns the names of the benchmark functions of this
// package (func BenchmarkX(b *testing.B) in its Go files, whatever the
// name of the parameter).
func benchFuncs(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^func (Benchmark\w*)\(\w+ \*testing\.B\)`)
	var names []string
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			names = append(names, m[1])
		}
	}
	slices.Sort(names)
	return names
}

// The names of the benchmarks are read from the source of this package
// (benchSource) and worked out as go test makes them (benchNames): the
// statements of every benchmark function and of the function every
// b.Run gives are followed, a range over a list once per element, and
// every b.Run name is evaluated, with the constants, variables and
// types of the package as the source has them and the calls envInt,
// memConns and SizeByName made for real (so a variable or a default
// the benchmarks read is the one of the code, not of this test). A
// benchmark whose function runs no b.Run is a name of its own. What the
// evaluation does not know fails the test: a b.Run in a statement other
// than a range over a list (an if, a switch, a plain for, a function
// value: whether and how often it runs depends on the run), a name
// built by other means, a b.Run outside the benchmark functions (in a
// helper that gets b). A change to the benchmarks that the evaluation
// cannot follow then makes the test fail until the evaluation follows
// it, not pass with names it did not see.

// benchSource is the Go source of this package: every *.go file (all
// build tags), the top-level constants and variables (name and value)
// and struct types by name.
type benchSource struct {
	fset  *token.FileSet
	files []*ast.File
	decls map[string]ast.Expr // nil value: defined twice (build tags)
	types map[string]*ast.StructType
}

// readBenchSource parses the *.go files of this package.
func readBenchSource(t *testing.T) *benchSource {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return newBenchSource(fset, files)
}

// newBenchSource collects the top-level declarations of files.
func newBenchSource(fset *token.FileSet, files []*ast.File) *benchSource {
	src := &benchSource{fset: fset, files: files, decls: map[string]ast.Expr{}, types: map[string]*ast.StructType{}}
	for _, f := range files {
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, s := range g.Specs {
				switch s := s.(type) {
				case *ast.ValueSpec:
					for i, n := range s.Names {
						var v ast.Expr
						if len(s.Values) == len(s.Names) {
							v = s.Values[i]
						}
						if _, dup := src.decls[n.Name]; dup {
							v = nil
						}
						src.decls[n.Name] = v
					}
				case *ast.TypeSpec:
					if st, ok := s.Type.(*ast.StructType); ok {
						src.types[s.Name.Name] = st
					}
				}
			}
		}
	}
	return src
}

// isTestingB reports whether e is the type *testing.B.
func isTestingB(e ast.Expr) bool {
	s, ok := e.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := s.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing" && sel.Sel.Name == "B"
}

// benchParam returns the name of the only parameter of ft if it is a
// *testing.B ("" if it has no name).
func benchParam(ft *ast.FuncType) (string, bool) {
	if ft.Params == nil || len(ft.Params.List) != 1 || !isTestingB(ft.Params.List[0].Type) {
		return "", false
	}
	switch f := ft.Params.List[0]; len(f.Names) {
	case 0:
		return "", true
	case 1:
		return f.Names[0].Name, true
	}
	return "", false
}

// structVal is a value of a struct type: field name to value (a thunk
// until it is used).
type structVal map[string]any

// thunk is an expression evaluated only when its value is used (the
// fields of Sizes, for example, hold sizes as 4 << 10, which the names
// do not need).
type thunk struct {
	e  ast.Expr
	sc *nameScope
}

// binding is a variable of a benchmark: its value, or the expression
// that gives it (idx: the idx-th result of a call with several, -1 for
// a single value), evaluated when a name needs it.
type binding struct {
	val   any
	known bool
	e     ast.Expr
	idx   int
	sc    *nameScope
}

type nameScope struct {
	parent *nameScope
	vars   map[string]*binding
}

func newScope(parent *nameScope) *nameScope {
	return &nameScope{parent: parent, vars: map[string]*binding{}}
}

// nameEval evaluates the benchmark names of src (benchNames).
type nameEval struct {
	t       *testing.T
	src     *benchSource
	visited map[token.Pos]bool // b.Run calls followed
	names   []string
	tbNames []string // *testing.B parameters of the enclosing functions
}

func (ev *nameEval) errorf(n ast.Node, format string, args ...any) error {
	return fmt.Errorf("%s: %s", ev.src.fset.Position(n.Pos()), fmt.Sprintf(format, args...))
}

// lookup returns the value of the identifier id.
func (ev *nameEval) lookup(id *ast.Ident, sc *nameScope) (any, error) {
	for s := sc; s != nil; s = s.parent {
		b, ok := s.vars[id.Name]
		if !ok {
			continue
		}
		if !b.known {
			vals, err := ev.evalMulti(b.e, b.sc)
			if err != nil {
				return nil, err
			}
			switch {
			case b.idx < 0 && len(vals) == 1:
				b.val = vals[0]
			case b.idx >= 0 && b.idx < len(vals):
				b.val = vals[b.idx]
			default:
				return nil, ev.errorf(id, "%s: %d values for one variable", id.Name, len(vals))
			}
			b.known = true
		}
		return b.val, nil
	}
	e, ok := ev.src.decls[id.Name]
	if !ok || e == nil {
		return nil, ev.errorf(id, "%s is no constant or variable of the package with one value", id.Name)
	}
	return ev.eval(e, nil)
}

// eval evaluates e, an expression with one value.
func (ev *nameEval) eval(e ast.Expr, sc *nameScope) (any, error) {
	vals, err := ev.evalMulti(e, sc)
	if err != nil {
		return nil, err
	}
	if len(vals) != 1 {
		return nil, ev.errorf(e, "%d values, want 1", len(vals))
	}
	if th, ok := vals[0].(thunk); ok {
		return ev.eval(th.e, th.sc)
	}
	return vals[0], nil
}

func (ev *nameEval) evalMulti(e ast.Expr, sc *nameScope) ([]any, error) {
	switch e := e.(type) {
	case *ast.BasicLit:
		switch e.Kind {
		case token.STRING:
			s, err := strconv.Unquote(e.Value)
			return []any{s}, err
		case token.INT:
			n, err := strconv.ParseInt(e.Value, 0, 64)
			return []any{n}, err
		}
	case *ast.ParenExpr:
		return ev.evalMulti(e.X, sc)
	case *ast.Ident:
		v, err := ev.lookup(e, sc)
		return []any{v}, err
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			break
		}
		x, err := ev.eval(e.X, sc)
		if err != nil {
			return nil, err
		}
		y, err := ev.eval(e.Y, sc)
		if err != nil {
			return nil, err
		}
		if xs, ok := x.(string); ok {
			if ys, ok := y.(string); ok {
				return []any{xs + ys}, nil
			}
		}
		if xn, ok := x.(int64); ok {
			if yn, ok := y.(int64); ok {
				return []any{xn + yn}, nil
			}
		}
		return nil, ev.errorf(e, "+ of %T and %T", x, y)
	case *ast.SelectorExpr:
		x, err := ev.eval(e.X, sc)
		if err != nil {
			return nil, err
		}
		s, ok := x.(structVal)
		if !ok {
			return nil, ev.errorf(e, "field %s of a %T", e.Sel.Name, x)
		}
		f, ok := s[e.Sel.Name]
		if !ok {
			return nil, ev.errorf(e, "no field %s", e.Sel.Name)
		}
		if th, ok := f.(thunk); ok {
			v, err := ev.eval(th.e, th.sc)
			return []any{v}, err
		}
		return []any{f}, nil
	case *ast.CompositeLit:
		v, err := ev.composite(e, e.Type, sc)
		return []any{v}, err
	case *ast.CallExpr:
		return ev.call(e, sc)
	}
	return nil, ev.errorf(e, "cannot evaluate a %T", e)
}

// composite evaluates the composite literal e of type typ (e.Type, or
// the element type of the slice around it).
func (ev *nameEval) composite(e *ast.CompositeLit, typ ast.Expr, sc *nameScope) (any, error) {
	switch typ := typ.(type) {
	case *ast.ArrayType:
		if typ.Len != nil {
			break
		}
		var list []any
		for _, el := range e.Elts {
			if c, ok := el.(*ast.CompositeLit); ok && c.Type == nil {
				v, err := ev.composite(c, typ.Elt, sc)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
				continue
			}
			v, err := ev.eval(el, sc)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		return list, nil
	case *ast.Ident:
		st, ok := ev.src.types[typ.Name]
		if !ok {
			break
		}
		var fields []string
		for _, f := range st.Fields.List {
			for _, n := range f.Names {
				fields = append(fields, n.Name)
			}
		}
		v := structVal{}
		for i, el := range e.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				k, ok := kv.Key.(*ast.Ident)
				if !ok {
					return nil, ev.errorf(kv, "a key that is no field name")
				}
				v[k.Name] = thunk{kv.Value, sc}
				continue
			}
			if i >= len(fields) {
				return nil, ev.errorf(el, "more values than fields of %s", typ.Name)
			}
			v[fields[i]] = thunk{el, sc}
		}
		return v, nil
	}
	return nil, ev.errorf(e, "cannot evaluate a composite literal of this type")
}

// call evaluates the calls a benchmark name may come from: fmt.Sprintf,
// and envInt, memConns and SizeByName, which run as they are, in the
// environment of this test.
func (ev *nameEval) call(e *ast.CallExpr, sc *nameScope) ([]any, error) {
	args := func(from int) ([]any, error) {
		var vs []any
		for _, a := range e.Args[from:] {
			v, err := ev.eval(a, sc)
			if err != nil {
				return nil, err
			}
			vs = append(vs, v)
		}
		return vs, nil
	}
	if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" && sel.Sel.Name == "Sprintf" && len(e.Args) > 0 {
			vs, err := args(0)
			if err != nil {
				return nil, err
			}
			format, ok := vs[0].(string)
			if !ok {
				return nil, ev.errorf(e, "fmt.Sprintf with a format that is no string")
			}
			return []any{fmt.Sprintf(format, vs[1:]...)}, nil
		}
	}
	fn, ok := e.Fun.(*ast.Ident)
	if !ok {
		return nil, ev.errorf(e, "cannot evaluate this call")
	}
	switch {
	case fn.Name == "envInt" && len(e.Args) == 3:
		// the first argument is the benchmark's b; this test stands in
		vs, err := args(1)
		if err != nil {
			return nil, err
		}
		name, ok1 := vs[0].(string)
		def, ok2 := vs[1].(int64)
		if !ok1 || !ok2 {
			return nil, ev.errorf(e, "envInt with a %T and a %T", vs[0], vs[1])
		}
		return []any{int64(envInt(ev.t, name, int(def)))}, nil
	case fn.Name == "memConns" && len(e.Args) == 0:
		n, err := memConns()
		return []any{int64(n), err}, nil
	case fn.Name == "SizeByName" && len(e.Args) == 1:
		vs, err := args(0)
		if err != nil {
			return nil, err
		}
		name, _ := vs[0].(string)
		sz, ok := SizeByName(name)
		if !ok {
			return nil, ev.errorf(e, "SizeByName(%q): no size class", name)
		}
		return []any{structVal{"Name": sz.Name, "Bytes": int64(sz.Bytes)}, ok}, nil
	}
	return nil, ev.errorf(e, "calls %s, which this test does not evaluate", fn.Name)
}

// runCall returns the call of n if it is b.Run of one of the *testing.B
// parameters tbs.
func runCall(n ast.Node, tbs []string) (*ast.CallExpr, bool) {
	c, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Run" {
		return nil, false
	}
	x, ok := sel.X.(*ast.Ident)
	return c, ok && slices.Contains(tbs, x.Name)
}

// hasRun reports whether n has a b.Run of a *testing.B parameter of
// the functions the walk is in.
func (ev *nameEval) hasRun(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		if _, ok := runCall(m, ev.tbNames); ok {
			found = true
		}
		return !found
	})
	return found
}

// jumps reports whether n has a return, continue, break or goto
// (outside function literals).
func jumps(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		switch m := m.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			found = true
		case *ast.BranchStmt:
			found = found || m.Tok != token.FALLTHROUGH
		}
		return !found
	})
	return found
}

// walk follows the statements of a benchmark (or of the function its
// b.Run gives) named prefix, whose *testing.B is b, and notes the name
// of every benchmark that runs no b.Run. It returns the number of b.Run
// calls it followed.
func (ev *nameEval) walk(stmts []ast.Stmt, sc *nameScope, b, prefix string) (int, error) {
	runs := 0
	withRun := slices.ContainsFunc(stmts, func(st ast.Stmt) bool { return ev.hasRun(st) })
	for _, st := range stmts {
		// A return, continue, break or goto next to a b.Run may skip it.
		if withRun && !ev.hasRun(st) && jumps(st) {
			return 0, ev.errorf(st, "a return, continue, break or goto next to a b.Run: this test cannot tell whether every b.Run runs")
		}
		switch st := st.(type) {
		case *ast.AssignStmt:
			if ev.hasRun(st) {
				return 0, ev.errorf(st, "a b.Run in an assignment")
			}
			for i, l := range st.Lhs {
				id, ok := l.(*ast.Ident)
				if !ok || id.Name == "_" {
					continue
				}
				switch {
				case len(st.Rhs) == len(st.Lhs):
					sc.vars[id.Name] = &binding{e: st.Rhs[i], idx: -1, sc: sc}
				case len(st.Rhs) == 1:
					sc.vars[id.Name] = &binding{e: st.Rhs[0], idx: i, sc: sc}
				}
			}
			continue
		case *ast.DeclStmt:
			if ev.hasRun(st) {
				return 0, ev.errorf(st, "a b.Run in a declaration")
			}
			g, ok := st.Decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, s := range g.Specs {
				vs, ok := s.(*ast.ValueSpec)
				if !ok || len(vs.Values) != len(vs.Names) {
					continue
				}
				for i, id := range vs.Names {
					sc.vars[id.Name] = &binding{e: vs.Values[i], idx: -1, sc: sc}
				}
			}
			continue
		}
		if !ev.hasRun(st) {
			continue
		}
		switch st := st.(type) {
		case *ast.RangeStmt:
			if k, ok := st.Key.(*ast.Ident); st.Key != nil && (!ok || k.Name != "_") {
				return 0, ev.errorf(st, "a range with b.Run that uses the index")
			}
			x, err := ev.eval(st.X, sc)
			if err != nil {
				return 0, err
			}
			list, ok := x.([]any)
			if !ok {
				return 0, ev.errorf(st, "a range with b.Run over a %T, not a list", x)
			}
			for _, el := range list {
				inner := newScope(sc)
				if v, ok := st.Value.(*ast.Ident); ok && v.Name != "_" {
					inner.vars[v.Name] = &binding{val: el, known: true}
				}
				n, err := ev.walk(st.Body.List, inner, b, prefix)
				if err != nil {
					return 0, err
				}
				runs += n
			}
			continue
		case *ast.ExprStmt:
			c, ok := runCall(st.X, []string{b})
			if !ok {
				break
			}
			if len(c.Args) != 2 {
				return 0, ev.errorf(c, "b.Run with %d arguments", len(c.Args))
			}
			fl, ok := c.Args[1].(*ast.FuncLit)
			if !ok {
				return 0, ev.errorf(c, "b.Run with a function that is no function literal")
			}
			nb, ok := benchParam(fl.Type)
			if !ok {
				return 0, ev.errorf(c, "b.Run with a function that does not take one *testing.B")
			}
			v, err := ev.eval(c.Args[0], sc)
			if err != nil {
				return 0, err
			}
			name, ok := v.(string)
			if !ok {
				return 0, ev.errorf(c, "b.Run with a name that is a %T", v)
			}
			ev.visited[c.Pos()] = true
			full := prefix + "/" + name
			ev.tbNames = append(ev.tbNames, nb)
			n, err := ev.walk(fl.Body.List, newScope(sc), nb, full)
			ev.tbNames = ev.tbNames[:len(ev.tbNames)-1]
			if err != nil {
				return 0, err
			}
			if n == 0 {
				ev.names = append(ev.names, full)
			}
			runs++
			continue
		}
		return 0, ev.errorf(st, "a b.Run in a %T: this test cannot tell whether and how often it runs", st)
	}
	return runs, nil
}

// benchNames returns the full names of the benchmarks of src as go test
// makes them (without the -GOMAXPROCS suffix), function by function in
// the order of the source, and the names of the benchmark functions.
func benchNames(t *testing.T, src *benchSource) (names, funcs []string, err error) {
	ev := &nameEval{t: t, src: src, visited: map[token.Pos]bool{}}
	for _, f := range src.files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil || !strings.HasPrefix(fd.Name.Name, "Benchmark") {
				continue
			}
			b, ok := benchParam(fd.Type)
			if !ok {
				continue
			}
			funcs = append(funcs, fd.Name.Name)
			ev.tbNames = []string{b}
			n, err := ev.walk(fd.Body.List, newScope(nil), b, fd.Name.Name)
			if err != nil {
				return nil, nil, err
			}
			if n == 0 {
				ev.names = append(ev.names, fd.Name.Name)
			}
		}
	}
	// Every b.Run of a *testing.B parameter, wherever it is, must be one
	// the walk followed.
	for _, f := range src.files {
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			var tbs []string
			for _, s := range stack {
				var ft *ast.FuncType
				switch s := s.(type) {
				case *ast.FuncDecl:
					ft = s.Type
				case *ast.FuncLit:
					ft = s.Type
				}
				if ft == nil || ft.Params == nil {
					continue
				}
				for _, p := range ft.Params.List {
					if isTestingB(p.Type) {
						for _, id := range p.Names {
							tbs = append(tbs, id.Name)
						}
					}
				}
			}
			if c, ok := runCall(n, tbs); ok && !ev.visited[c.Pos()] && err == nil {
				err = ev.errorf(c, "a b.Run outside what this test follows (a benchmark function, a range, a b.Run)")
			}
			return true
		})
	}
	if err != nil {
		return nil, nil, err
	}
	slices.Sort(funcs)
	return ev.names, funcs, nil
}

// TestBenchScriptNames checks the lists of scripts/bench.sh that follow
// the benchmarks of this package: groups (one -bench pattern per
// benchmark function, ^Name$), wantnames (every benchmark by its full
// name as b.Run makes it; benchNames reads them from the benchmarks)
// and the placeholders @SYNC@, @MEMMAILS@ and @MEMCONNS@ of wantnames,
// which render fills in from the environment with defaults. It compares
// twice: with the variables of the placeholders set to test values (7,
// 8 and 9: a fixed number in wantnames, or a benchmark that reads
// another variable, shows) and with them unset (the defaults of render
// against those of the benchmarks). A benchmark that is added, renamed
// or dropped makes this test fail until bench.sh follows (render,
// without this test, would only fail on a name that is missing in the
// raw output).
func TestBenchScriptNames(t *testing.T) {
	script := readBenchScript(t)

	// groups=('^BenchmarkA$' '^BenchmarkB$' ...)
	gm := regexp.MustCompile(`(?m)^groups=\(([^)\n]*)\)$`).FindAllStringSubmatch(script, -1)
	if len(gm) != 1 {
		t.Fatalf("scripts/bench.sh has %d groups=(...) lines, want 1", len(gm))
	}
	var groups []string
	for _, w := range strings.Fields(gm[0][1]) {
		m := regexp.MustCompile(`^'\^(Benchmark\w*)\$'$`).FindStringSubmatch(w)
		if m == nil {
			t.Fatalf("group %s of scripts/bench.sh is not '^BenchmarkName$'", w)
		}
		groups = append(groups, m[1])
	}
	funcs := benchFuncs(t)
	if sorted := slices.Sorted(slices.Values(groups)); !slices.Equal(sorted, funcs) {
		t.Errorf("groups of scripts/bench.sh are %q, the benchmarks of internal/bench %q", groups, funcs)
	}

	// The placeholders: render fills them in with
	// gsub(/@X@/, envnum("VAR", default), s).
	type fill struct {
		env  string
		def  string
		test string
	}
	tests := map[string]string{"@SYNC@": "7", "@MEMMAILS@": "8", "@MEMCONNS@": "9"}
	ph := map[string]fill{}
	envs := map[string]bool{}
	for _, m := range regexp.MustCompile(`gsub\(/(@[A-Z]+@)/, envnum\("([A-Z_]+)", ([0-9]+)\), s\)`).FindAllStringSubmatch(script, -1) {
		if _, dup := ph[m[1]]; dup {
			t.Errorf("render fills in %s twice", m[1])
		}
		if envs[m[2]] {
			t.Errorf("render fills in two placeholders from %s", m[2])
		}
		test, ok := tests[m[1]]
		if !ok {
			t.Errorf("render fills in %s, which this test has no value for", m[1])
			continue
		}
		envs[m[2]] = true
		ph[m[1]] = fill{m[2], m[3], test}
	}
	for p := range tests {
		if _, ok := ph[p]; !ok {
			t.Errorf("render does not fill in %s", p)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	// wantnames=( ... ), one word or more per line, brace groups as bash
	// expands them.
	wm := regexp.MustCompile(`(?ms)^wantnames=\(\n(.*?)^\)$`).FindAllStringSubmatch(script, -1)
	if len(wm) != 1 {
		t.Fatalf("scripts/bench.sh has %d wantnames=( ... ) blocks, want 1", len(wm))
	}
	var words []string
	for _, w := range strings.Fields(wm[0][1]) {
		if strings.ContainsAny(w, `'"\$`+"`") {
			t.Fatalf("wantnames word %s has quoting or an expansion this test does not read", w)
		}
		words = append(words, braceExpand(w)...)
	}

	src := readBenchSource(t)
	for _, pass := range []string{"test values", "unset"} {
		for _, f := range ph {
			if pass == "unset" {
				t.Setenv(f.env, "") // empty counts as unset (lookupEnvInt)
			} else {
				t.Setenv(f.env, f.test)
			}
		}
		var got []string
		for _, w := range words {
			for p, f := range ph {
				if pass == "unset" {
					w = strings.ReplaceAll(w, p, f.def)
				} else {
					w = strings.ReplaceAll(w, p, f.test)
				}
			}
			if strings.Contains(w, "@") {
				t.Errorf("wantnames word %s has a placeholder render does not fill in", w)
			}
			got = append(got, w)
		}
		want, afuncs, err := benchNames(t, src)
		if err != nil {
			t.Fatalf("the names of the benchmarks of internal/bench: %v", err)
		}
		if !slices.Equal(afuncs, funcs) {
			t.Errorf("benchmark functions of the source are %q, benchFuncs finds %q", afuncs, funcs)
		}
		seen := map[string]bool{}
		for _, w := range want {
			if seen[w] {
				t.Errorf("%s: the benchmarks of internal/bench make %s twice (go test would rename one)", pass, w)
			}
			seen[w] = true
		}
		seen = map[string]bool{}
		for _, g := range got {
			if seen[g] {
				t.Errorf("%s: wantnames of scripts/bench.sh has %s twice", pass, g)
			}
			seen[g] = true
			if !slices.Contains(want, g) {
				t.Errorf("%s: wantnames of scripts/bench.sh has %s, no benchmark of internal/bench makes it", pass, g)
			}
		}
		for _, w := range want {
			if !seen[w] {
				t.Errorf("%s: wantnames of scripts/bench.sh lacks %s", pass, w)
			}
		}
		// syncSubs names the sub-benchmarks of BenchmarkSync in the
		// order they run.
		var subs []string
		for _, w := range want {
			if rest, ok := strings.CutPrefix(w, "BenchmarkSync/"); ok {
				_, sub, _ := strings.Cut(rest, "/")
				subs = append(subs, sub)
			}
		}
		if !slices.Equal(subs, syncSubs) {
			t.Errorf("%s: BenchmarkSync runs %q, syncSubs are %q", pass, subs, syncSubs)
		}
	}
}

// TestBenchNamesEval checks that benchNames refuses what it cannot
// follow and reads what it can, on small packages written here.
func TestBenchNamesEval(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string
		err       string
	}{
		{"plain", `func BenchmarkA(b *testing.B) {}`, []string{"BenchmarkA"}, ""},
		{"param", `func BenchmarkA(tb *testing.B) { tb.Run("x", func(b *testing.B) {}) }`, []string{"BenchmarkA/x"}, ""},
		{"range", `var l = []string{"p", "q"}
	const k = "k="
	func BenchmarkA(b *testing.B) { for _, s := range l { b.Run(k+s, func(b *testing.B) {}) } }`, []string{"BenchmarkA/k=p", "BenchmarkA/k=q"}, ""},
		{"sprintf", `var n = []int{1, 2}
	func BenchmarkA(b *testing.B) { for _, x := range n { b.Run(fmt.Sprintf("n=%d", x), func(b *testing.B) {}) } }`, []string{"BenchmarkA/n=1", "BenchmarkA/n=2"}, ""},
		{"struct", `type T struct{ Name string; N int }
	var ts = []T{{"a", 1 << 3}, {Name: "b"}}
	func BenchmarkA(b *testing.B) { for _, x := range ts { b.Run(x.Name, func(b *testing.B) {}) } }`, []string{"BenchmarkA/a", "BenchmarkA/b"}, ""},
		{"nested", `func BenchmarkA(b *testing.B) { b.Run("x", func(b *testing.B) { b.Run("y", func(b *testing.B) {}) }); b.Run("z", func(b *testing.B) {}) }`, []string{"BenchmarkA/x/y", "BenchmarkA/z"}, ""},
		{"if", `func BenchmarkA(b *testing.B) { if false { b.Run("x", func(b *testing.B) {}) } }`, nil, "a b.Run in a *ast.IfStmt"},
		{"for", `func BenchmarkA(b *testing.B) { for i := 0; i < 2; i++ { b.Run("x", func(b *testing.B) {}) } }`, nil, "a b.Run in a *ast.ForStmt"},
		{"funcvalue", `func BenchmarkA(b *testing.B) { f := func(b *testing.B) {}; b.Run("x", f) }`, nil, "no function literal"},
		{"helper", `func BenchmarkA(b *testing.B) { helper(b) }
	func helper(b *testing.B) { b.Run("x", func(b *testing.B) {}) }`, nil, "outside what this test follows"},
		{"unknowncall", `func BenchmarkA(b *testing.B) { b.Run(name(), func(b *testing.B) {}) }`, nil, "calls name"},
		{"unknownvar", `func BenchmarkA(b *testing.B) { b.Run(x, func(b *testing.B) {}) }`, nil, "x is no constant"},
		{"continue", `var l = []string{"p", "q"}
	func BenchmarkA(b *testing.B) { for _, s := range l { if s == "p" { continue }; b.Run(s, func(b *testing.B) {}) } }`, nil, "a return, continue, break or goto"},
		{"return", `func BenchmarkA(b *testing.B) { if testing.Short() { return }; b.Run("x", func(b *testing.B) {}) }`, nil, "a return, continue, break or goto"},
		{"leafreturn", `func BenchmarkA(b *testing.B) { b.Run("x", func(b *testing.B) { if testing.Short() { return } }) }`, []string{"BenchmarkA/x"}, ""},
		{"index", `var l = []string{"p"}
	func BenchmarkA(b *testing.B) { for i, s := range l { _ = i; b.Run(s, func(b *testing.B) {}) } }`, nil, "uses the index"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", "package x\n"+c.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			src := newBenchSource(fset, []*ast.File{f})
			names, _, err := benchNames(t, src)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want one with %q (names %q)", err, c.err, names)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(names, c.want) {
				t.Errorf("names = %q, want %q", names, c.want)
			}
		})
	}
}

// TestBenchScriptEnvNames checks the variables bench.sh checks with
// tablebad before anything runs against envNames, the variables of the
// env line of this package: the table shows that line, and a line
// break, a | or a backtick in one of them would break it. The variables
// render compares with the env lines of a -render FILE (envchk) must be
// among them.
func TestBenchScriptEnvNames(t *testing.T) {
	script := readBenchScript(t)
	m := regexp.MustCompile(`(?m)^for v in ((?:[A-Z0-9_ \t]|\\\n)+); do\n\tif tablebad "\$\{!v:-\}"; then$`).FindAllStringSubmatch(script, -1)
	if len(m) != 1 {
		t.Fatalf("scripts/bench.sh has %d tablebad loops over the variables, want 1", len(m))
	}
	got := strings.Fields(strings.ReplaceAll(m[0][1], "\\\n", " "))
	if !slices.Equal(got, envNames) {
		t.Errorf("tablebad of scripts/bench.sh checks %q, envNames are %q", got, envNames)
	}
	c := regexp.MustCompile(`nchk = split\("([A-Z0-9_ ]+)", envchk, " "\)`).FindAllStringSubmatch(script, -1)
	if len(c) != 1 {
		t.Fatalf("scripts/bench.sh has %d envchk lists, want 1", len(c))
	}
	for _, v := range strings.Fields(c[0][1]) {
		if !slices.Contains(envNames, v) {
			t.Errorf("render compares %s with the env lines, which are not in envNames", v)
		}
	}
}
