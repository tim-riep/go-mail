package ceremony

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 24 package A (backlog 54, 55, 58): a symbolic link under
// a name of the export in data/platform/ is never taken for the export's
// file; publish replaces the link itself when freeName frees the name
// and refuses it otherwise, naming the link, before anything is written.
// TestV22PubUnderUnloggedSameCert and TestV22SymlinkOverLogged are the
// evidence tests of the spec review of task 22 (mutants P1-4 and P1-6).

// linkPlatform replaces platform/<name> of st by a symbolic link to
// target; the test is skipped where symbolic links cannot be made.
func linkPlatform(t *testing.T, st *store.Store, name, target string) string {
	t.Helper()
	p := st.Path("platform", name)
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Skipf("symbolic link: %v", err)
	}
	return p
}

// isLink reports whether path is a symbolic link.
func isLink(t *testing.T, path string) bool {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()&fs.ModeSymlink != 0
}

// regularExport fails unless platform/<n> of st is a regular file with
// the content of the export's file n of out, for every n.
func regularExport(t *testing.T, st *store.Store, out string, names ...string) {
	t.Helper()
	for _, n := range names {
		fi, err := os.Lstat(st.Path("platform", n))
		if err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("platform/%s is no regular file: %v %v", n, fi, err)
		}
	}
	samePlatform(t, st, out, names...)
}

// TestV22PubUnderUnloggedSameCert (spec review of 22, mutant P1-4): an
// unlogged certificate in data/platform/ equal to the export's and a
// foreign .pub beside it: the .pub is not replaced (no valid entry, and
// the certificate is not replaced either), nothing written.
func TestV22PubUnderUnloggedSameCert(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	a2pub, a2 := f.cert(t, 1, keys.RoleAdmin, 2)
	exp := writeExport(t, filepath.Join(f.base, "expA2"), map[string][]byte{"admin-2.pub": a2pub, "admin-2.cert": a2})
	if err := st.WritePlatformFile("admin-2.cert", a2); err != nil {
		t.Fatal(err)
	}
	foreign := bytes.Repeat([]byte{5}, 32)
	if err := st.WritePlatformFile("admin-2.pub", foreign); err != nil {
		t.Fatal(err)
	}
	before := listDir(t, st.Path("platform"))
	err := Publish(PublishOptions{From: exp, Data: st, Pin: f.res.Pin})
	if !errors.Is(err, store.ErrExists) || !strings.Contains(err.Error(), "replaced only together with its certificate") {
		t.Fatalf("foreign pub under an unlogged certificate equal to the export's: %v", err)
	}
	if !bytes.Equal(mustReadFile(t, st.Path("platform", "admin-2.pub")), foreign) {
		t.Fatal("replaced")
	}
	if fmt.Sprint(listDir(t, st.Path("platform"))) != fmt.Sprint(before) {
		t.Fatal("written")
	}
	if es := lookupCert(t, st, f.res.Pin, "admin-2.cert"); len(es) != 0 {
		t.Fatalf("logged: %+v", es)
	}
}

// TestV22SymlinkOverLogged (spec review of 22, mutant P1-6): a symbolic
// link over a logged certificate, pointing outside to a thief's
// certificate, is replaced by a regular file with the logged content;
// the file outside stays. Likewise a link as admin-1.pub to a foreign
// key.
func TestV22SymlinkOverLogged(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	_, tc := f.thiefCert(t, 1, keys.RoleIngest, 1, headAt.Add(time.Hour))
	outside := filepath.Join(f.base, "outside.cert")
	if err := os.WriteFile(outside, tc, 0o644); err != nil {
		t.Fatal(err)
	}
	linkPlatform(t, st, "ingest-1.cert", outside)
	if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatalf("symbolic link over the logged ingest-1.cert: %v", err)
	}
	regularExport(t, st, out, "ingest-1.cert")
	if !bytes.Equal(mustReadFile(t, outside), tc) {
		t.Fatal("written through the link")
	}
	// A symbolic link as admin-1.pub, pointing outside to a foreign key.
	outPub := filepath.Join(f.base, "outside.pub")
	foreign := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(outPub, foreign, 0o644); err != nil {
		t.Fatal(err)
	}
	linkPlatform(t, st, "admin-1.pub", outPub)
	if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatalf("symbolic link as admin-1.pub: %v", err)
	}
	regularExport(t, st, out, "admin-1.pub")
	if !bytes.Equal(mustReadFile(t, outPub), foreign) {
		t.Fatal("written through the link")
	}
}

// TestPublishLinkToLoggedContent (backlog 54): a symbolic link under a
// logged name whose target outside data/platform/ holds the logged
// content is not taken for the export's file: the same publish run again
// replaces the link itself by a regular file, its target stays as it
// was, and the log does not change. A link as identity-1.pub, whose name
// is never free, is refused with a message naming the link, and nothing
// is written.
func TestPublishLinkToLoggedContent(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	before := lookupCert(t, st, f.res.Pin, "ingest-1.cert")
	targets := map[string]string{}
	for _, n := range []string{"admin-1.pub", "ingest-1.cert", "ingest-1.pub"} {
		targets[n] = filepath.Join(f.base, "outside-"+n)
		if err := os.WriteFile(targets[n], mustReadFile(t, filepath.Join(out, "platform", n)), 0o644); err != nil {
			t.Fatal(err)
		}
		linkPlatform(t, st, n, targets[n])
	}
	files := listDir(t, st.Path("platform"))
	if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatalf("links to the logged content: %v", err)
	}
	for n, target := range targets {
		regularExport(t, st, out, n)
		if !bytes.Equal(mustReadFile(t, target), mustReadFile(t, filepath.Join(out, "platform", n))) {
			t.Fatalf("target of %s changed", n)
		}
		if fi, err := os.Lstat(target); err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("target of %s: %v %v", n, fi, err)
		}
	}
	if fmt.Sprint(listDir(t, st.Path("platform"))) != fmt.Sprint(files) {
		t.Fatalf("files: %v", listDir(t, st.Path("platform")))
	}
	after := lookupCert(t, st, f.res.Pin, "ingest-1.cert")
	if len(after) != 1 || after[0].Index != before[0].Index || !bytes.Equal(after[0].Content, before[0].Content) {
		t.Fatalf("log changed: %+v", after)
	}

	// identity-1.pub as a link to the right key: never replaced, refused.
	target := filepath.Join(f.base, "outside-identity-1.pub")
	if err := os.WriteFile(target, mustReadFile(t, filepath.Join(out, "platform", "identity-1.pub")), 0o644); err != nil {
		t.Fatal(err)
	}
	p := linkPlatform(t, st, "identity-1.pub", target)
	files = listDir(t, st.Path("platform"))
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	if !errors.Is(err, store.ErrExists) || errors.Is(err, translog.ErrDuplicate) || !strings.Contains(err.Error(), p+" is a symbolic link") {
		t.Fatalf("identity-1.pub as a link: %v", err)
	}
	if !isLink(t, p) || fmt.Sprint(listDir(t, st.Path("platform"))) != fmt.Sprint(files) {
		t.Fatal("written")
	}
}

// TestPublishDanglingLink (backlog 55): a dangling symbolic link under a
// name of the export is replaced by the export's file when the name is
// free (the link itself: its target is not created), and refused with a
// message naming the link otherwise, before anything is written (not
// "written meanwhile" after other files of the export were written).
func TestPublishDanglingLink(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	// Free names: the logged ingest-1.cert and the public key of the
	// logged admin-1.cert.
	var targets []string
	for _, n := range []string{"admin-1.pub", "ingest-1.cert"} {
		target := filepath.Join(f.base, "missing-"+n)
		targets = append(targets, target)
		linkPlatform(t, st, n, target)
	}
	if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatalf("dangling links under free names: %v", err)
	}
	regularExport(t, st, out, "admin-1.pub", "ingest-1.cert")
	for _, target := range targets {
		if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("target %s written: %v", target, err)
		}
	}

	// Names that are not free, beside new files of the export that come
	// first in the order of writing (public keys before certificates).
	a2pub, a2 := f.cert(t, 1, keys.RoleAdmin, 2)
	idPub := mustReadFile(t, filepath.Join(out, "platform", "identity-1.pub"))
	// Another admin-1.cert of the same key than the logged one.
	id1, _ := f.platform(t).IdentityKey(1)
	aPub := mustReadFile(t, filepath.Join(out, "platform", "admin-1.pub"))
	ac, err := keys.NewPlatformCert(id1, 1, keys.RoleAdmin, 1, aPub, testNow.Add(time.Second).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	other, err := ac.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other, mustReadFile(t, filepath.Join(out, "platform", "admin-1.cert"))) {
		t.Fatal("the same certificate")
	}
	for _, c := range []struct {
		name, link string
		files      map[string][]byte
		dup        bool
		why        string
	}{
		{"identity-1.pub", "identity-1.pub", map[string][]byte{"identity-1.pub": idPub, "admin-2.pub": a2pub, "admin-2.cert": a2}, false, ""},
		{"admin-1.cert", "admin-1.cert", map[string][]byte{"admin-1.cert": other, "admin-1.pub": aPub, "admin-2.pub": a2pub, "admin-2.cert": a2}, true, "a valid entry is never replaced"},
	} {
		exp := writeExport(t, filepath.Join(f.base, "exp-"+c.name), c.files)
		saved := mustReadFile(t, st.Path("platform", c.link))
		p := linkPlatform(t, st, c.link, filepath.Join(f.base, "missing-"+c.name))
		files := listDir(t, st.Path("platform"))
		err := Publish(PublishOptions{From: exp, Data: st, Pin: f.res.Pin})
		if !errors.Is(err, store.ErrExists) || errors.Is(err, translog.ErrDuplicate) != c.dup ||
			!strings.Contains(err.Error(), p+" is a symbolic link") || !strings.Contains(err.Error(), c.why) ||
			strings.Contains(err.Error(), "written meanwhile") {
			t.Fatalf("%s: dangling link under a name that is not free: %v", c.name, err)
		}
		if !isLink(t, p) || fmt.Sprint(listDir(t, st.Path("platform"))) != fmt.Sprint(files) {
			t.Fatalf("%s: written: %v", c.name, listDir(t, st.Path("platform")))
		}
		if es := lookupCert(t, st, f.res.Pin, "admin-2.cert"); len(es) != 0 {
			t.Fatalf("%s: logged: %+v", c.name, es)
		}
		// The operator removes the link and puts the file back.
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := st.WritePlatformFile(c.link, saved); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPublishLinkedCertFreesPub (backlog 54): a symbolic link as an
// unlogged certificate is not the export's certificate, even when it
// points to the same content: the certificate is replaced, and with it
// a foreign public key beside it (freeName), and both are the export's
// afterwards; the target of the link stays.
func TestPublishLinkedCertFreesPub(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	a2pub, a2 := f.cert(t, 1, keys.RoleAdmin, 2)
	exp := writeExport(t, filepath.Join(f.base, "expA2"), map[string][]byte{"admin-2.pub": a2pub, "admin-2.cert": a2})
	target := filepath.Join(f.base, "outside-admin-2.cert")
	if err := os.WriteFile(target, a2, 0o644); err != nil {
		t.Fatal(err)
	}
	linkPlatform(t, st, "admin-2.cert", target)
	if err := st.WritePlatformFile("admin-2.pub", bytes.Repeat([]byte{5}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: exp, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatalf("linked certificate with a foreign public key: %v", err)
	}
	regularExport(t, st, exp, "admin-2.cert", "admin-2.pub")
	if !bytes.Equal(mustReadFile(t, target), a2) {
		t.Fatal("written through the link")
	}
	if es := lookupCert(t, st, f.res.Pin, "admin-2.cert"); len(es) != 1 || !bytes.Equal(es[0].Content, a2) {
		t.Fatalf("log: %+v", es)
	}
}
