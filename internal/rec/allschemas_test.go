package rec_test

import (
	"bytes"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of task 20f for PLAN 10.1 "Kodieren und Dekodieren ist für alle
// Datensätze byte-identisch". TestRecordVectors pins the phase 0 record
// types, store.FuzzDecodeRecords the typed decoders of store; these tests
// cover every schema of the module and check that the list is complete.

// allSchemas lists every record schema of the module (3.6), the element
// schemas of lists included.
var allSchemas = []*rec.Schema{
	keys.GenerationCertSchema,
	keys.PlatformCertSchema,
	keys.PlatformSuccessionSchema,
	keys.KeystoreHeaderSchema,
	keys.KeystoreContentSchema,
	envelope.HeaderSchema,
	envelope.RecipientSchema,
	envelope.RecipientsSchema,
	envelope.TrailerSchema,
	envelope.SignedSchema,
	store.UserSchema,
	store.WrapAcceptSchema,
	store.RecoveryPubSchema,
	store.MailboxSchema,
	store.FolderSchema,
	store.FoldersSchema,
	store.PostingSchema,
	store.IndexSegmentSchema,
	store.CheckpointSchema,
	store.EpochKeysSchema,
	store.RcptSchema,
	store.MailMetaSchema,
	store.MetaSignedSchema,
	store.TermSchema,
	store.PendingEntrySchema,
	store.PendingSchema,
	store.EpochNoteSchema,
	store.MoveSchema,
	store.JournalSchema,
	store.PlatformKeySchema,
	store.WitnessSchema,
	store.PlatformIdentitySchema,
	store.PlatformPinSchema,
	store.AddressSchema,
	store.MemberSchema,
	store.DiscardSchema,
	store.EpochSchema,
	translog.EntrySchema,
	translog.TreeSchema,
	witness.WitnessesSchema,
}

// recPath is the import path of package rec.
const recPath = "github.com/tim-riep/go-mail/internal/rec"

// buildContext returns the build context of this test binary: its
// GOOS, GOARCH, cgo setting and build tags (-tags, and race for
// -race), read from the build information of the binary, so that the
// scan takes a file exactly when it is part of this build. A schema
// that only a build with the tag gomail_dev defines is then required
// only there, where allSchemas can name it.
func buildContext(t *testing.T) build.Context {
	t.Helper()
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("the test binary has no build information")
	}
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH = runtime.GOOS, runtime.GOARCH
	ctx.BuildTags = nil
	for _, s := range bi.Settings {
		switch s.Key {
		case "-tags":
			if s.Value != "" {
				ctx.BuildTags = append(ctx.BuildTags, strings.Split(s.Value, ",")...)
			}
		case "-race":
			if s.Value == "true" {
				ctx.BuildTags = append(ctx.BuildTags, "race")
			}
		case "CGO_ENABLED":
			ctx.CgoEnabled = s.Value == "1"
		}
	}
	// Cross-check the tags read with a constant the tag switches.
	if slices.Contains(ctx.BuildTags, "gomail_dev") != ceremony.DevBuild {
		t.Fatalf("build tags %v do not match ceremony.DevBuild %v", ctx.BuildTags, ceremony.DevBuild)
	}
	return ctx
}

// schemaDefs returns the schema definitions in f through package rec,
// imported under any name (also as "."): calls of MustSchema and
// NewSchema, and composite literals of rec.Schema, also those whose type
// is elided inside a slice, array or map literal of rec.Schema or
// *rec.Schema. Comments are not part of the syntax tree and never
// count. For every definition it returns the type string, or an error
// text with the position when the type is not a string literal.
func schemaDefs(fset *token.FileSet, f *ast.File) (types, bad []string) {
	names := map[string]bool{}
	dot := false
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err != nil || p != recPath {
			continue
		}
		switch {
		case imp.Name == nil:
			names["rec"] = true
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name != "_":
			names[imp.Name.Name] = true
		}
	}
	if len(names) == 0 && !dot {
		return nil, nil
	}
	isRec := func(x ast.Expr, sel string) bool {
		switch x := x.(type) {
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			return ok && names[id.Name] && x.Sel.Name == sel
		case *ast.Ident:
			return dot && x.Name == sel
		}
		return false
	}
	isSchema := func(x ast.Expr) bool {
		if st, ok := x.(*ast.StarExpr); ok {
			x = st.X
		}
		return isRec(x, "Schema")
	}
	typeString := func(x ast.Expr) {
		if lit, ok := x.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				types = append(types, s)
				return
			}
		}
		bad = append(bad, fset.Position(x.Pos()).String())
	}
	literal := func(cl *ast.CompositeLit) {
		for _, el := range cl.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Type" {
					typeString(kv.Value)
					return
				}
			}
		}
		if len(cl.Elts) > 0 {
			if _, ok := cl.Elts[0].(*ast.KeyValueExpr); !ok {
				typeString(cl.Elts[0]) // unkeyed: Type is the first field
				return
			}
		}
		bad = append(bad, fset.Position(cl.Pos()).String())
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if isRec(n.Fun, "MustSchema") || isRec(n.Fun, "NewSchema") {
				if len(n.Args) == 0 {
					bad = append(bad, fset.Position(n.Pos()).String())
				} else {
					typeString(n.Args[0])
				}
			}
		case *ast.CompositeLit:
			if isRec(n.Type, "Schema") {
				literal(n)
				return true
			}
			var elt ast.Expr
			switch tt := n.Type.(type) {
			case *ast.ArrayType:
				elt = tt.Elt
			case *ast.MapType:
				elt = tt.Value
			}
			if elt == nil || !isSchema(elt) {
				return true
			}
			for _, el := range n.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					el = kv.Value
				}
				if u, ok := el.(*ast.UnaryExpr); ok && u.Op == token.AND {
					el = u.X
				}
				if cl, ok := el.(*ast.CompositeLit); ok && cl.Type == nil {
					literal(cl)
				}
			}
		}
		return true
	})
	return types, bad
}

// TestAllSchemasListed: allSchemas names every schema that the production
// code of the module in this build defines (schemaDefs over every
// non-test Go file under internal/ and cmd/ that the build context of
// this test binary takes, buildContext), each once, so that
// TestAllSchemasRoundTrip cannot miss a record type added later.
func TestAllSchemasListed(t *testing.T) {
	listed := map[string]bool{}
	for _, s := range allSchemas {
		if listed[s.Type] {
			t.Errorf("schema %q listed twice", s.Type)
		}
		listed[s.Type] = true
	}
	ctx := buildContext(t)
	fset := token.NewFileSet()
	defined := map[string]string{}
	for _, dir := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() {
				if p != dir && (name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			if ok, err := ctx.MatchFile(filepath.Dir(p), name); err != nil || !ok {
				return err
			}
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			types, bad := schemaDefs(fset, f)
			for _, pos := range bad {
				t.Errorf("%s: schema without a literal type string; list it by hand and adapt this test", pos)
			}
			for _, typ := range types {
				if prev, ok := defined[typ]; ok {
					t.Errorf("type %q defined twice (%s, %s)", typ, prev, p)
				}
				defined[typ] = p
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(defined) < 30 {
		t.Fatalf("only %d schema definitions found; the scan is broken", len(defined))
	}
	for typ, p := range defined {
		if !listed[typ] {
			t.Errorf("schema %q (%s) is not in allSchemas", typ, p)
		}
	}
	for typ := range listed {
		if _, ok := defined[typ]; !ok {
			t.Errorf("schema %q in allSchemas has no definition in the production code of this build", typ)
		}
	}
}

// variant selects how sample fills a record.
type variant int

const (
	// required: the required fields only, with the smallest values.
	required variant = iota
	// full: every field; integers at their extremes; byte fields of
	// fixed size, the others of up to 300 bytes, at most MaxLen; strings
	// with umlauts of up to 52 bytes, at most MaxLen; up to three list
	// elements, filled the same way.
	full
)

// sample builds a valid record of s. Values depend on the field number so
// that fields of the same kind differ.
func sample(t *testing.T, s *rec.Schema, v variant, reverse bool) *rec.Record {
	t.Helper()
	fields := append([]rec.Field(nil), s.Fields...)
	if reverse {
		sort.Slice(fields, func(i, j int) bool { return fields[i].Num > fields[j].Num })
	}
	r := rec.New(s)
	for _, f := range fields {
		if v == required && !f.Required {
			continue
		}
		switch f.Kind {
		case rec.U8:
			if v == full {
				r.SetU8(f.Num, math.MaxUint8)
			} else {
				r.SetU8(f.Num, 0)
			}
		case rec.U32:
			if v == full {
				r.SetU32(f.Num, math.MaxUint32-uint32(f.Num))
			} else {
				r.SetU32(f.Num, 0)
			}
		case rec.I64:
			if v == full {
				r.SetI64(f.Num, math.MinInt64+int64(f.Num))
			} else {
				r.SetI64(f.Num, -1)
			}
		case rec.Bytes:
			n := f.Size
			if n == 0 {
				n = 1
				if v == full {
					n = min(f.MaxLen, 300)
				}
			}
			r.SetBytes(f.Num, bytes.Repeat([]byte{f.Num, 0}, n)[:n])
		case rec.String:
			str := "a"
			if v == full {
				str = "Grüße ✉ " + strings.Repeat("x", 40)
				for len(str) > f.MaxLen {
					// Cut at a rune boundary; the string stays NFC.
					str = string([]rune(str)[:len([]rune(str))-1])
				}
			}
			r.SetString(f.Num, str)
		case rec.List:
			n := 1
			if v == full {
				n = min(f.MaxCount, 3)
			}
			var l []*rec.Record
			for i := 0; i < n; i++ {
				l = append(l, sample(t, f.Elem, v, reverse))
			}
			r.SetList(f.Num, l)
		default:
			t.Fatalf("%s field %d: unknown kind %v", s.Type, f.Num, f.Kind)
		}
	}
	if err := r.Err(); err != nil {
		t.Fatalf("%s: %v", s.Type, err)
	}
	return r
}

// TestAllSchemasRoundTrip: for every schema of the module, a record with
// the required fields and one with every field encode, decode and encode
// again to exactly the same bytes; the encoding does not depend on the
// order in which fields were set; no other schema decodes it.
func TestAllSchemasRoundTrip(t *testing.T) {
	for _, s := range allSchemas {
		t.Run(s.Type, func(t *testing.T) {
			for _, v := range []variant{required, full} {
				enc, err := sample(t, s, v, false).Encode()
				if err != nil {
					t.Fatalf("variant %d: encode: %v", v, err)
				}
				if !bytes.HasPrefix(enc, s.Prefix()) {
					t.Fatalf("variant %d: encoding does not start with the type string and NUL", v)
				}
				rev, err := sample(t, s, v, true).Encode()
				if err != nil || !bytes.Equal(rev, enc) {
					t.Fatalf("variant %d: encoding depends on the order of the Set calls: %v", v, err)
				}
				dec, err := rec.Decode(s, enc)
				if err != nil {
					t.Fatalf("variant %d: decode: %v", v, err)
				}
				again, err := dec.Encode()
				if err != nil {
					t.Fatalf("variant %d: re-encode: %v", v, err)
				}
				if !bytes.Equal(again, enc) {
					t.Fatalf("variant %d: re-encoding differs", v)
				}
				for _, other := range allSchemas {
					if other.Type == s.Type {
						continue
					}
					if _, err := rec.Decode(other, enc); err == nil {
						t.Fatalf("variant %d: schema %q decodes a %q record", v, other.Type, s.Type)
					}
				}
			}
		})
	}
}
