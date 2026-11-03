package client_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of task 20h point 2: no method of a closed Client panics.

// closedArgs are the arguments of the calls of closedCalls: a mailbox,
// one of its mails, an unprocessed term list, another user and a
// recovery key, all valid before Close.
type closedArgs struct {
	me, mbx, mail, other store.ID
	epoch                uint32
	pending              store.ID
	folders              []store.Folder
	pub                  *store.RecoveryPub
}

// closedCall calls the exported method name of a closed client. For a
// method that returns an error, call returns it; one without an error
// result (noErr) checks its result itself and returns nil or the
// deviation.
type closedCall struct {
	name  string
	noErr bool
	call  func(c *client.Client, a *closedArgs) error
}

// closedCalls are the calls of every exported method of *client.Client
// (TestClosedCallsCoverMethods checks the list against the method set).
var closedCalls = []closedCall{
	{"ClearRecovery", false, func(c *client.Client, a *closedArgs) error { return c.ClearRecovery(a.mbx) }},
	{"Close", true, func(c *client.Client, a *closedArgs) error { c.Close(); return nil }},
	{"ConfirmRecovery", false, func(c *client.Client, a *closedArgs) error { return c.ConfirmRecovery(a.mbx, yes) }},
	{"CreateMailbox", false, func(c *client.Client, a *closedArgs) error {
		id, err := c.CreateMailbox("B")
		return errIfID(id, err)
	}},
	{"Folders", false, func(c *client.Client, a *closedArgs) error {
		l, err := c.Folders(a.mbx)
		return errIf(l != nil, err)
	}},
	{"Index", false, func(c *client.Client, a *closedArgs) error {
		n, err := c.Index(a.mbx)
		return errIf(n != 0, err)
	}},
	{"List", false, func(c *client.Client, a *closedArgs) error {
		l, err := c.List(a.mbx, store.ID{})
		return errIf(l != nil, err)
	}},
	{"MailboxName", false, func(c *client.Client, a *closedArgs) error {
		n, err := c.MailboxName(a.mbx)
		return errIf(n != "", err)
	}},
	{"Mailboxes", true, func(c *client.Client, a *closedArgs) error {
		// Public IDs from memory, as before Close.
		if got := c.Mailboxes(); len(got) != 1 || got[0] != a.mbx {
			return fmt.Errorf("mailboxes %v", got)
		}
		return nil
	}},
	{"OpenPending", false, func(c *client.Client, a *closedArgs) error {
		p, err := c.OpenPending(a.mbx, a.epoch, a.pending)
		return errIf(p != nil, err)
	}},
	{"Read", false, func(c *client.Client, a *closedArgs) error {
		m, body, err := c.Read(a.mbx, a.mail)
		return errIf(m != nil || body != nil, err)
	}},
	{"Rename", false, func(c *client.Client, a *closedArgs) error { return c.Rename(a.mbx, "B") }},
	{"Revoke", false, func(c *client.Client, a *closedArgs) error { return c.Revoke(a.mbx, a.other) }},
	{"Search", false, func(c *client.Client, a *closedArgs) error {
		l, err := c.Search(a.mbx, "from:s@x.example", client.SearchOptions{})
		return errIf(l != nil, err)
	}},
	{"SetFlags", false, func(c *client.Client, a *closedArgs) error {
		m, err := c.SetFlags(a.mbx, a.mail, []string{"seen"}, nil)
		return errIf(m != nil, err)
	}},
	{"SetFolders", false, func(c *client.Client, a *closedArgs) error { return c.SetFolders(a.mbx, a.folders) }},
	{"SetRecovery", false, func(c *client.Client, a *closedArgs) error { return c.SetRecovery(a.mbx, a.pub, yes) }},
	{"Share", false, func(c *client.Client, a *closedArgs) error {
		n, err := c.Share(a.mbx, a.other, client.ShareOptions{})
		return errIf(n != nil, err)
	}},
	{"Sync", false, func(c *client.Client, a *closedArgs) error { return c.Sync() }},
	{"UserID", true, func(c *client.Client, a *closedArgs) error {
		// The public user ID from memory, as before Close.
		if got := c.UserID(); got != a.me {
			return fmt.Errorf("user ID %s", got)
		}
		return nil
	}},
}

// errIf returns err, or an error naming a result if result is set
// (a closed client returns zero values with its error).
func errIf(result bool, err error) error {
	if result {
		return fmt.Errorf("result besides %w", err)
	}
	return err
}

func errIfID(id store.ID, err error) error { return errIf(!id.IsZero(), err) }

// TestNoPanicAfterClose calls every exported method of a closed client
// (twice, the second time after a second Close): none panics, every one
// that returns an error returns ErrClosed and zero results, and the
// client directory and the data directory are unchanged.
func TestNoPanicAfterClose(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	f.send(t, "s@x.example", header("s@x.example", "p"))
	f.flush(t)
	bob := f.env.NewUser("bob")
	c := f.u.Client
	folders, err := c.Folders(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.env.Store.ListPending(f.mbx, a.Epoch)
	if err != nil || len(pending) == 0 {
		t.Fatalf("no pending file: %v", err)
	}
	pub, _ := recoveryKey(t)
	args := &closedArgs{me: f.u.ID, mbx: f.mbx, mail: a.ID, other: bob.ID, epoch: a.Epoch, pending: pending[0], folders: folders, pub: pub}
	c.Close()
	before := treeOf(t, f.env.Base, f.u.Dir)
	for round := 1; round <= 2; round++ {
		for _, cc := range closedCalls {
			err, panicked := callRecover(cc, c, args)
			switch {
			case panicked != nil:
				t.Errorf("round %d: %s panicked after Close: %v", round, cc.name, panicked)
			case cc.noErr && err != nil:
				t.Errorf("round %d: %s after Close: %v", round, cc.name, err)
			case !cc.noErr && (!errors.Is(err, client.ErrClosed) || err.Error() != client.ErrClosed.Error()):
				t.Errorf("round %d: %s after Close: %v, want ErrClosed alone", round, cc.name, err)
			}
		}
		c.Close()
	}
	if after := treeOf(t, f.env.Base, f.u.Dir); !maps.Equal(before, after) {
		t.Fatal("a closed client changed a file")
	}
}

// callRecover calls cc and returns its error, or what it panicked with.
func callRecover(cc closedCall, c *client.Client, a *closedArgs) (err error, panicked any) {
	defer func() { panicked = recover() }()
	return cc.call(c, a), nil
}

// treeOf returns the size and modification time of every file under the
// directories dirs, by path.
func treeOf(t *testing.T, dirs ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range dirs {
		err := walkFiles(d, func(p string, fi os.FileInfo) {
			out[p] = fmt.Sprint(fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func walkFiles(dir string, fn func(string, os.FileInfo)) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		p := dir + "/" + e.Name()
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		fn(p, fi)
		if fi.IsDir() {
			if err := walkFiles(p, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

// TestClosedCallsCoverMethods checks closedCalls against the exported
// methods of Client declared in the files of this build that are not
// tests (go/parser), and the method set by reflection against those plus
// the methods that test files of the package export.
func TestClosedCallsCoverMethods(t *testing.T) {
	prod, tests := clientMethods(t)
	var listed []string
	for _, cc := range closedCalls {
		listed = append(listed, cc.name)
	}
	slices.Sort(listed)
	if !slices.Equal(listed, prod) {
		t.Fatalf("closedCalls %v, exported methods of Client %v", listed, prod)
	}
	rt := reflect.TypeOf((*client.Client)(nil))
	for i := range rt.NumMethod() {
		m := rt.Method(i).Name
		if !slices.Contains(prod, m) && !slices.Contains(tests, m) {
			t.Errorf("method %s of Client is not declared in the files of the package", m)
		}
	}
	for _, m := range prod {
		if _, ok := rt.MethodByName(m); !ok {
			t.Errorf("method %s not in the method set", m)
		}
	}
}

// clientMethods returns the sorted exported methods of Client declared
// in the Go files of this directory that the build of this test compiles
// (build constraints of the default context), first those in files that
// are not tests, then those in test files.
func clientMethods(t *testing.T) (prod, tests []string) {
	t.Helper()
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	ctx := build.Default
	ctx.BuildTags = append(ctx.BuildTags, "gomail_dev", "gomail_test")
	fset := token.NewFileSet()
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if ok, err := ctx.MatchFile(".", name); err != nil {
			t.Fatal(err)
		} else if !ok {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 || !fd.Name.IsExported() {
				continue
			}
			typ := fd.Recv.List[0].Type
			if st, ok := typ.(*ast.StarExpr); ok {
				typ = st.X
			}
			if id, ok := typ.(*ast.Ident); !ok || id.Name != "Client" {
				continue
			}
			if strings.HasSuffix(name, "_test.go") {
				tests = append(tests, fd.Name.Name)
			} else {
				prod = append(prod, fd.Name.Name)
			}
		}
	}
	slices.Sort(prod)
	slices.Sort(tests)
	if len(prod) == 0 {
		t.Fatal("no exported method of Client found")
	}
	return prod, tests
}
