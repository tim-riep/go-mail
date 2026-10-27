package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/shamir"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// screen is the Display of a test: it records every share line.
type screen struct {
	lines  int
	shares map[int][]string
}

func (s *screen) Write(p []byte) (int, error) {
	if s.shares == nil {
		s.shares = map[int][]string{}
	}
	line := strings.TrimSuffix(string(p), "\n")
	var i, n int
	head, rest, ok := strings.Cut(line, ": ")
	if _, err := fmt.Sscanf(head, "Anteil %d/%d", &i, &n); err != nil || !ok {
		return 0, fmt.Errorf("unexpected display line %q", line)
	}
	s.shares[i] = strings.Fields(rest)
	s.lines++
	return len(p), nil
}

// prompter answers AskShare(want) with the share shown on its screen,
// typed sloppily, and AskShare(0) from its queue.
type prompter struct {
	scr       *screen
	handovers []int
	asked     []int
	queue     [][]string
	answer    func(want int) ([]string, error)
	handErr   error
}

func (p *prompter) Handover(i, n int) error {
	p.handovers = append(p.handovers, i)
	return p.handErr
}

func (p *prompter) AskShare(want int) ([]string, error) {
	p.asked = append(p.asked, want)
	if p.answer != nil {
		return p.answer(want)
	}
	if want == 0 {
		if len(p.queue) == 0 {
			return nil, errors.New("no more shares")
		}
		ws := p.queue[0]
		p.queue = p.queue[1:]
		return sloppy(ws), nil
	}
	return sloppy(p.scr.shares[want]), nil
}

// sloppy types words as a holder might: upper case, tabs, line breaks.
func sloppy(ws []string) []string {
	if len(ws) < 10 {
		return ws
	}
	return []string{"  " + strings.ToUpper(strings.Join(ws[:10], " \t")), strings.Join(ws[10:], "\n") + "\r\n"}
}

// tamper returns a share with the same index and split but another
// value, with a valid checksum.
func tamper(t *testing.T, ws []string) []string {
	t.Helper()
	s, err := shamir.ShareFromWords(ws)
	if err != nil {
		t.Fatal(err)
	}
	s.Y[0] ^= 1
	return s.Words()
}

func witnessKey(t *testing.T, name string) witness.Key {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return witness.Key{Name: name, Pub: pub}
}

var testNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return testNow }

// fixture is a finished Init with a known root.
type fixture struct {
	base   string
	root   keys.Seed
	res    *Result
	scr    *screen
	shares map[int][]string
	w      []witness.Key
}

func (f *fixture) opts(out, keyDir string, p *prompter) InitOptions {
	return InitOptions{
		Out: out, KeyDir: keyDir, Shares: Shares{3, 5}, Origin: "go-mail.test/log",
		Witnesses: f.w, MinWitnesses: len(f.w)/2 + 1, Display: p.scr, Prompter: p, Now: fixedNow,
		Rand: io.MultiReader(bytes.NewReader(f.root[:]), rand.Reader),
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{base: t.TempDir()}
	if _, err := rand.Read(f.root[:]); err != nil {
		t.Fatal(err)
	}
	f.w = []witness.Key{witnessKey(t, "w1"), witnessKey(t, "w2"), witnessKey(t, "w3")}
	f.scr = &screen{}
	p := &prompter{scr: f.scr}
	res, err := Init(f.opts(filepath.Join(f.base, "out"), filepath.Join(f.base, "keys"), p))
	if err != nil {
		t.Fatal(err)
	}
	f.res = res
	f.shares = f.scr.shares
	if want := []int{1, 2, 3, 4, 5}; fmt.Sprint(p.handovers) != fmt.Sprint(want) || f.scr.lines != 5 {
		t.Fatalf("handovers %v, %d lines", p.handovers, f.scr.lines)
	}
	// The probe asked three distinct indices.
	if len(p.asked) != 3 {
		t.Fatalf("probe asked %v", p.asked)
	}
	seen := map[int]bool{}
	for _, i := range p.asked {
		if i < 1 || i > 5 || seen[i] {
			t.Fatalf("probe asked %v", p.asked)
		}
		seen[i] = true
	}
	return f
}

// unlockOpts returns UnlockOptions for identity 1 with the given shares
// in the queue.
func (f *fixture) unlock(idx ...int) (UnlockOptions, *prompter) {
	p := &prompter{scr: &screen{}}
	for _, i := range idx {
		p.queue = append(p.queue, f.shares[i])
	}
	return UnlockOptions{IdentityGen: 1, IdentityPub: f.res.IdentityPub, Prompter: p, Now: fixedNow}, p
}

func identityOf(t *testing.T, root []byte, gen uint32) ed25519.PublicKey {
	t.Helper()
	pub, err := identityPub(root, gen)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func parseShares(t *testing.T, m map[int][]string, idx ...int) []*shamir.Share {
	t.Helper()
	var ss []*shamir.Share
	for _, i := range idx {
		s, err := shamir.ShareFromWords(m[i])
		if err != nil {
			t.Fatal(err)
		}
		ss = append(ss, s)
	}
	return ss
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	var names []string
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			names = append(names, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(names)
	return names
}

// assertNothing checks that a failed ceremony left no file: out and
// keyDir are missing or empty, and no staging directory is left next to
// out.
func assertNothing(t *testing.T, out, keyDir string) {
	t.Helper()
	for _, d := range []string{out, keyDir} {
		if d == "" {
			continue
		}
		if n := listDir(t, d); len(n) != 0 {
			t.Fatalf("%s holds %v", d, n)
		}
	}
	ents, _ := os.ReadDir(filepath.Dir(out))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			t.Fatalf("staging directory %s left", e.Name())
		}
	}
}

func TestParseShares(t *testing.T) {
	for in, want := range map[string]Shares{"3-of-5": {3, 5}, "2-of-2": {2, 2}, "16-of-16": {16, 16}, "2-of-16": {2, 16}} {
		got, err := ParseShares(in)
		if err != nil || got != want || got.String() != in {
			t.Fatalf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "3of5", "3-of-", "-of-5", "03-of-5", "3-of-05", "+3-of-5", "3-of-+5", "1-of-5",
		"6-of-5", "3-of-17", "3-of-5x", "a-of-5", "1000-of-5", "3-of-5-of-5", " 3-of-5", "0-of-0"} {
		if _, err := ParseShares(in); !errors.Is(err, ErrShares) {
			t.Fatalf("%q accepted", in)
		}
	}
}

func TestInit(t *testing.T) {
	f := newFixture(t)
	out, kd := filepath.Join(f.base, "out"), filepath.Join(f.base, "keys")
	if want := identityOf(t, f.root[:], 1); !f.res.IdentityPub.Equal(want) {
		t.Fatal("identity not derived from the root")
	}
	want := []string{"identity-1.pin", "platform/admin-1.cert", "platform/admin-1.pub", "platform/identity-1.pub",
		"platform/ingest-1.cert", "platform/ingest-1.pub", "platform/witnesses.rec"}
	if got := listDir(t, out); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("export %v", got)
	}
	if got := listDir(t, kd); fmt.Sprint(got) != "[admin-1.key ingest-1.key]" {
		t.Fatalf("keys %v", got)
	}
	assertNoStaging(t, f.base)
	if fi, _ := os.Stat(kd); fi.Mode().Perm() != 0o700 {
		t.Fatalf("key directory mode %v", fi.Mode())
	}
	if f.res.Out != out || f.res.KeyDir != kd || len(f.res.Pin.Identities) != 1 || f.res.Pin.Identities[0].Gen != 1 ||
		!f.res.Pin.Identities[0].Pub.Equal(f.res.IdentityPub) {
		t.Fatal("result")
	}
	// The pin file holds fields 1 to 6 and 8, byte for byte the encoding
	// of store.PlatformPin (task 15b point 1).
	want1 := &store.PlatformPin{Gen: 1, Pub: f.res.IdentityPub, Origin: "go-mail.test/log", MinWitnesses: 2,
		Identities: []store.PlatformIdentity{{Gen: 1, Pub: f.res.IdentityPub}}}
	for _, w := range f.w {
		want1.Witnesses = append(want1.Witnesses, store.Witness{Name: w.Name, Pub: w.Pub})
	}
	if enc, err := want1.Encode(); err != nil || !bytes.Equal(enc, mustReadFile(t, filepath.Join(out, "identity-1.pin"))) {
		t.Fatalf("pin file is not the encoding of fields 1 to 6 and 8: %v", err)
	}

	// The certificates verify against identity-1.pub of the export, and
	// the keys in the key directory match them.
	idPub, _ := os.ReadFile(filepath.Join(out, "platform", "identity-1.pub"))
	if !ed25519.PublicKey(idPub).Equal(f.res.IdentityPub) {
		t.Fatal("identity-1.pub")
	}
	for _, c := range []struct {
		name string
		role keys.Role
		kr   uint8
	}{{"admin", keys.RoleAdmin, store.KeyRoleAdmin}, {"ingest", keys.RoleIngest, store.KeyRoleIngest}} {
		data, _ := os.ReadFile(filepath.Join(out, "platform", c.name+"-1.cert"))
		cert, err := keys.DecodePlatformCert(data)
		if err != nil || cert.Verify(idPub) != nil || cert.Role != c.role || cert.Gen != 1 || cert.IdentityGen != 1 ||
			cert.ValidFrom != testNow.UnixMilli() {
			t.Fatalf("%s certificate: %v", c.name, err)
		}
		pub, _ := os.ReadFile(filepath.Join(out, "platform", c.name+"-1.pub"))
		priv, gen, err := ReadKey(filepath.Join(kd, c.name+"-1.key"), c.kr)
		if err != nil || gen != 1 || !cert.Pub.Equal(priv.Public()) || !cert.Pub.Equal(ed25519.PublicKey(pub)) {
			t.Fatalf("%s key: %v", c.name, err)
		}
		if fi, _ := os.Stat(filepath.Join(kd, c.name+"-1.key")); fi.Mode().Perm() != 0o600 {
			t.Fatalf("key mode %v", fi.Mode())
		}
	}
	pin, err := ReadPin(filepath.Join(out, "identity-1.pin"))
	if err != nil || pin.Gen != 1 || pin.Dev || !pin.Pub.Equal(f.res.IdentityPub) {
		t.Fatalf("pin: %v", err)
	}
	wdata, _ := os.ReadFile(filepath.Join(out, "platform", "witnesses.rec"))
	ws, err := witness.DecodeWitnesses(wdata)
	if err != nil || ws.Min != 2 || len(ws.List) != 3 || ws.List[0].Name != "w1" {
		t.Fatalf("witnesses.rec: %v", err)
	}

	// All ten combinations of three of five shares rebuild the root.
	n := 0
	for a := 1; a <= 5; a++ {
		for b := a + 1; b <= 5; b++ {
			for c := b + 1; c <= 5; c++ {
				secret, err := shamir.Combine(parseShares(t, f.shares, a, b, c))
				if err != nil || !bytes.Equal(secret, f.root[:]) {
					t.Fatalf("%d %d %d: %v", a, b, c, err)
				}
				n++
			}
		}
	}
	if n != 10 {
		t.Fatal(n)
	}
	// Two shares are not enough.
	if _, err := shamir.Combine(parseShares(t, f.shares, 1, 2)); !errors.Is(err, shamir.ErrInsufficient) {
		t.Fatal("two shares")
	}
	// No secret in the export or in the key directory beyond the keys:
	// the root does not occur in any file.
	for _, dir := range []string{out, kd} {
		for _, name := range listDir(t, dir) {
			b, _ := os.ReadFile(filepath.Join(dir, name))
			if bytes.Contains(b, f.root[:]) {
				t.Fatalf("root in %s", name)
			}
			if dir == out {
				if _, _, _, err := store.DecodePlatformKey(b); err == nil {
					t.Fatalf("private key in the export: %s", name)
				}
			}
		}
	}
	// A second ceremony into the same key directory is refused before
	// anything is shown.
	f2 := &fixture{base: f.base, root: f.root, w: f.w}
	p := &prompter{scr: &screen{}}
	if _, err := Init(f2.opts(filepath.Join(f.base, "out2"), kd, p)); !errors.Is(err, ErrKeyDir) || len(p.handovers) != 0 {
		t.Fatalf("second ceremony: %v", err)
	}
	// And into the same export directory.
	if _, err := Init(f2.opts(out, filepath.Join(f.base, "keys2"), p)); !errors.Is(err, ErrOutDir) {
		t.Fatalf("export directory reused: %v", err)
	}
}

func assertNoStaging(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			t.Fatalf("staging directory %s left", e.Name())
		}
	}
}

func TestInitProbeFails(t *testing.T) {
	f := &fixture{base: t.TempDir(), w: []witness.Key{witnessKey(t, "w")}}
	rand.Read(f.root[:])
	other := &screen{}
	// Shares of another split with the same index, to mix in.
	otherShares, _ := shamir.Split(f.root[:], 3, 5, nil)
	for _, s := range otherShares {
		other.Write([]byte(fmt.Sprintf("Anteil %d/5: %s\n", s.Index, strings.Join(s.Words(), " "))))
	}
	for name, c := range map[string]struct {
		answer func(p *prompter, want int) ([]string, error)
		errs   []error
	}{
		"tampered share (other identity)": {func(p *prompter, want int) ([]string, error) {
			if len(p.asked) == 1 {
				return tamper(t, p.scr.shares[want]), nil
			}
			return p.scr.shares[want], nil
		}, []error{ErrProbe}},
		"wrong index": {func(p *prompter, want int) ([]string, error) {
			return p.scr.shares[want%5+1], nil
		}, []error{ErrProbe, ErrShares}},
		"other split": {func(p *prompter, want int) ([]string, error) {
			if len(p.asked) == 2 {
				return other.shares[want], nil
			}
			return p.scr.shares[want], nil
		}, []error{ErrProbe, ErrShares, shamir.ErrMismatch}},
		"checksum": {func(p *prompter, want int) ([]string, error) {
			ws := append([]string(nil), p.scr.shares[want]...)
			ws[0], ws[1] = ws[1], ws[0]
			if ws[0] == ws[1] {
				ws[2], ws[3] = ws[3], ws[2]
			}
			return ws, nil
		}, []error{ErrProbe, shamir.ErrChecksum}},
		"too few words": {func(p *prompter, want int) ([]string, error) {
			return p.scr.shares[want][:29], nil
		}, []error{ErrProbe, shamir.ErrWordCount}},
		"abbreviation": {func(p *prompter, want int) ([]string, error) {
			ws := append([]string(nil), p.scr.shares[want]...)
			if len(ws[4]) > 4 {
				ws[4] = ws[4][:4]
			} else {
				ws[4] = "zzzz"
			}
			return ws, nil
		}, []error{ErrProbe, shamir.ErrUnknownWord}},
		"prompter error": {func(p *prompter, want int) ([]string, error) {
			return nil, io.ErrUnexpectedEOF
		}, []error{ErrProbe, io.ErrUnexpectedEOF}},
	} {
		t.Run(name, func(t *testing.T) {
			p := &prompter{scr: &screen{}}
			p.answer = func(want int) ([]string, error) { return c.answer(p, want) }
			out, kd := filepath.Join(f.base, "out"), filepath.Join(f.base, "keys")
			_, err := Init(f.opts(out, kd, p))
			for _, e := range c.errs {
				if !errors.Is(err, e) {
					t.Fatalf("%v is not %v", err, e)
				}
			}
			if _, err := os.Lstat(out); err == nil {
				t.Fatal("export directory written")
			}
			if _, err := os.Lstat(kd); err == nil {
				t.Fatal("key directory written")
			}
			assertNoStaging(t, f.base)
			if strings.Contains(fmt.Sprint(err), p.scr.shares[1][0]+" ") {
				t.Fatal("share word in the error")
			}
		})
	}
	// A failing handover stops before any share is shown.
	p := &prompter{scr: &screen{}, handErr: io.EOF}
	if _, err := Init(f.opts(filepath.Join(f.base, "o"), filepath.Join(f.base, "k"), p)); !errors.Is(err, io.EOF) || p.scr.lines != 0 {
		t.Fatal("handover error")
	}
	// A display that fails.
	p = &prompter{scr: &screen{}}
	o := f.opts(filepath.Join(f.base, "o"), filepath.Join(f.base, "k"), p)
	o.Display = failWriter{}
	if _, err := Init(o); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("display error")
	}
	assertNothing(t, filepath.Join(f.base, "o"), filepath.Join(f.base, "k"))
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrShortWrite }

func TestInitOptions(t *testing.T) {
	base := t.TempDir()
	f := &fixture{base: base, w: []witness.Key{witnessKey(t, "a"), witnessKey(t, "b")}}
	p := &prompter{scr: &screen{}}
	out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	opts := func(mod func(*InitOptions)) error {
		o := f.opts(out, kd, p)
		o.MinWitnesses = 2
		mod(&o)
		_, err := Init(o)
		return err
	}
	// The quorum is checked before anything else, even before the
	// prompter.
	if err := opts(func(o *InitOptions) { o.MinWitnesses = 1; o.Prompter = nil }); !errors.Is(err, translog.ErrWitness) {
		t.Fatalf("quorum 1 of 2: %v", err)
	}
	if err := opts(func(o *InitOptions) { o.Witnesses = nil; o.MinWitnesses = 0 }); !errors.Is(err, translog.ErrWitness) {
		t.Fatal("no witness")
	}
	if err := opts(func(o *InitOptions) { o.Origin = "with space" }); !errors.Is(err, translog.ErrHead) {
		t.Fatal("origin")
	}
	if err := opts(func(o *InitOptions) { o.Witnesses = []witness.Key{f.w[0], f.w[0]} }); !errors.Is(err, witness.ErrWitnesses) {
		t.Fatal("duplicate witness")
	}
	if err := opts(func(o *InitOptions) { o.Shares = Shares{1, 5} }); !errors.Is(err, ErrShares) {
		t.Fatal("shares")
	}
	if err := opts(func(o *InitOptions) { o.Display = nil }); !errors.Is(err, ErrOptions) {
		t.Fatal("display")
	}
	if err := opts(func(o *InitOptions) { o.Prompter = nil }); !errors.Is(err, ErrOptions) {
		t.Fatal("prompter")
	}
	if err := opts(func(o *InitOptions) { o.KeyDir = "" }); !errors.Is(err, ErrKeyDir) {
		t.Fatal("no key directory")
	}
	if err := opts(func(o *InitOptions) { o.Out = "" }); !errors.Is(err, ErrOutDir) {
		t.Fatal("no export directory")
	}
	if err := opts(func(o *InitOptions) { o.KeyDir = filepath.Join(out, "keys") }); !errors.Is(err, ErrOutDir) {
		t.Fatal("key directory inside the export")
	}
	if err := opts(func(o *InitOptions) { o.Out = filepath.Join(kd, "out") }); !errors.Is(err, ErrOutDir) {
		t.Fatal("export inside the key directory")
	}
	// A symbolic link does not hide the overlap.
	os.MkdirAll(out, 0o700)
	os.Symlink(out, filepath.Join(base, "link"))
	if err := opts(func(o *InitOptions) { o.KeyDir = filepath.Join(base, "link", "keys") }); !errors.Is(err, ErrOutDir) {
		t.Fatal("key directory inside the export through a link")
	}
	os.WriteFile(filepath.Join(out, "x"), nil, 0o600)
	if err := opts(func(*InitOptions) {}); !errors.Is(err, ErrOutDir) {
		t.Fatal("export directory not empty")
	}
	os.WriteFile(filepath.Join(base, "file"), nil, 0o600)
	if err := opts(func(o *InitOptions) { o.Out = filepath.Join(base, "file") }); !errors.Is(err, ErrOutDir) {
		t.Fatal("export directory is a file")
	}
	if err := opts(func(o *InitOptions) { o.Out = filepath.Join(base, "o2"); o.KeyDir = filepath.Join(base, "file") }); !errors.Is(err, ErrKeyDir) {
		t.Fatal("key directory is a file")
	}
	os.MkdirAll(kd, 0o700)
	os.WriteFile(filepath.Join(kd, "ingest-1.key"), nil, 0o600)
	if err := opts(func(o *InitOptions) { o.Out = filepath.Join(base, "o2") }); !errors.Is(err, ErrKeyDir) {
		t.Fatal("key directory with keys")
	}
	if len(p.handovers) != 0 || len(p.asked) != 0 {
		t.Fatal("prompter used before the options were checked")
	}
	// A failing random source.
	if err := opts(func(o *InitOptions) {
		o.Out = filepath.Join(base, "o3")
		o.KeyDir = filepath.Join(base, "k3")
		o.Rand = bytes.NewReader(nil)
	}); err == nil {
		t.Fatal("no randomness")
	}
	// An empty existing export directory is fine.
	os.MkdirAll(filepath.Join(base, "o4"), 0o700)
	o := f.opts(filepath.Join(base, "o4"), filepath.Join(base, "k4"), &prompter{scr: &screen{}})
	o.MinWitnesses = 2
	o.Rand = nil
	o.Now = nil
	if _, err := Init(o); err != nil {
		t.Fatal(err)
	}
}

// TestInitCrash injects a failure at every write of Init: no half
// ceremony remains.
func TestInitCrash(t *testing.T) {
	f := &fixture{base: t.TempDir(), w: []witness.Key{witnessKey(t, "w")}}
	rand.Read(f.root[:])
	defer func() { crashHook = nil }()
	points := map[string]bool{}
	for n := 1; ; n++ {
		calls := 0
		crashHook = func(point string) error {
			calls++
			if calls == n {
				points[point] = true
				return errors.New("crash at " + point)
			}
			return nil
		}
		p := &prompter{scr: &screen{}}
		out, kd := filepath.Join(f.base, fmt.Sprint("out", n)), filepath.Join(f.base, fmt.Sprint("keys", n))
		o := f.opts(out, kd, p)
		o.MinWitnesses = 1
		_, err := Init(o)
		if calls < n {
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		if err == nil || !strings.Contains(err.Error(), "crash at") {
			t.Fatalf("crash %d: %v", n, err)
		}
		assertNothing(t, out, kd)
		if _, err := os.Lstat(kd); err == nil {
			t.Fatalf("crash %d: key directory created", n)
		}
	}
	for _, p := range []string{"commit", "export-file", "export", "root", "link", "key", "keys"} {
		if !points[p] {
			t.Fatalf("injection point %s not reached", p)
		}
	}
	// A key directory that existed before stays, without keys.
	kd := filepath.Join(f.base, "existing")
	os.Mkdir(kd, 0o700)
	crashHook = func(point string) error {
		if point == "keys" {
			return errors.New("crash")
		}
		return nil
	}
	o := f.opts(filepath.Join(f.base, "outX"), kd, &prompter{scr: &screen{}})
	o.MinWitnesses = 1
	if _, err := Init(o); err == nil {
		t.Fatal("no crash")
	}
	assertNothing(t, filepath.Join(f.base, "outX"), kd)
	if _, err := os.Stat(kd); err != nil {
		t.Fatal("existing key directory removed")
	}
}

func TestIngestRotate(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(f.base, "rot")
	kd := filepath.Join(f.base, "keys")
	u, p := f.unlock(5, 2, 4)
	validFrom := testNow.Add(48 * time.Hour)
	res, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: out, KeyDir: kd, Gen: 2, ValidFrom: validFrom})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(p.asked) != "[0 0 0]" || res.Gen != 2 {
		t.Fatalf("asked %v", p.asked)
	}
	if got := listDir(t, out); fmt.Sprint(got) != "[platform/ingest-2.cert platform/ingest-2.pub]" {
		t.Fatalf("export %v", got)
	}
	// The certificate verifies against identity-1.pub of the first
	// ceremony.
	idPub, _ := os.ReadFile(filepath.Join(f.base, "out", "platform", "identity-1.pub"))
	data, _ := os.ReadFile(filepath.Join(out, "platform", "ingest-2.cert"))
	cert, err := keys.DecodePlatformCert(data)
	if err != nil || cert.Verify(idPub) != nil || cert.Gen != 2 || cert.Role != keys.RoleIngest || cert.IdentityGen != 1 ||
		cert.ValidFrom != validFrom.UnixMilli() || !cert.Pub.Equal(res.Pub) {
		t.Fatalf("certificate: %v", err)
	}
	priv, gen, err := ReadKey(filepath.Join(kd, "ingest-2.key"), store.KeyRoleIngest)
	if err != nil || gen != 2 || !cert.Pub.Equal(priv.Public()) {
		t.Fatal("ingest key")
	}
	// The new key is not the old one.
	old, _, _ := ReadKey(filepath.Join(kd, "ingest-1.key"), store.KeyRoleIngest)
	if old.Equal(priv) {
		t.Fatal("same key")
	}
	// Without ValidFrom the certificate is valid from Now.
	u, _ = f.unlock(1, 3, 5)
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: filepath.Join(f.base, "rot3"), KeyDir: kd, Gen: 3}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(f.base, "rot3", "platform", "ingest-3.cert"))
	if c, _ := keys.DecodePlatformCert(data); c.ValidFrom != testNow.UnixMilli() {
		t.Fatal("valid_from")
	}

	rot := func(u UnlockOptions, gen uint32, out string) error {
		_, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: out, KeyDir: kd, Gen: gen})
		return err
	}
	fresh := filepath.Join(f.base, "fresh")
	u, p = f.unlock(1, 2, 3)
	if err := rot(u, 1, fresh); !errors.Is(err, keys.ErrGeneration) || len(p.asked) != 0 {
		t.Fatal("generation 1")
	}
	if err := rot(u, 2, fresh); !errors.Is(err, ErrKeyDir) || len(p.asked) != 0 {
		t.Fatal("existing ingest-2.key")
	}
	if err := rot(u, 4, filepath.Join(f.base, "out")); !errors.Is(err, ErrOutDir) {
		t.Fatal("used export directory")
	}
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: fresh, Gen: 4}); !errors.Is(err, ErrKeyDir) {
		t.Fatal("no key directory")
	}
	// Shares of the right split but a wrong identity.
	u, _ = f.unlock(1, 2, 3)
	u.IdentityPub = f.w[0].Pub
	if err := rot(u, 4, fresh); !errors.Is(err, ErrIdentity) {
		t.Fatalf("other identity: %v", err)
	}
	u, _ = f.unlock(1, 2, 3)
	u.IdentityGen = 2
	if err := rot(u, 4, fresh); !errors.Is(err, ErrIdentity) {
		t.Fatal("other identity generation")
	}
	// A tampered share yields another root.
	u, p = f.unlock(1, 2)
	p.queue = append(p.queue, tamper(t, f.shares[3]))
	if err := rot(u, 4, fresh); !errors.Is(err, ErrIdentity) {
		t.Fatalf("tampered share: %v", err)
	}
	// Shares of two splits, a share twice, too few shares.
	other, _ := shamir.Split(f.root[:], 3, 5, nil)
	u, p = f.unlock(1, 2)
	p.queue = append(p.queue[:1], other[1].Words())
	if err := rot(u, 4, fresh); !errors.Is(err, shamir.ErrMismatch) || !errors.Is(err, ErrShares) {
		t.Fatalf("mixed splits: %v", err)
	}
	u, _ = f.unlock(1, 1, 2)
	if err := rot(u, 4, fresh); !errors.Is(err, shamir.ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	u, _ = f.unlock(1, 2)
	if err := rot(u, 4, fresh); err == nil {
		t.Fatal("too few shares")
	}
	u, p = f.unlock()
	p.queue = [][]string{{"abandon"}}
	if err := rot(u, 4, fresh); !errors.Is(err, ErrShares) || !errors.Is(err, shamir.ErrWordCount) {
		t.Fatalf("malformed share: %v", err)
	}
	// A share of a split with a threshold above MaxShareCount.
	big, _ := shamir.Split(f.root[:], MaxShareCount+1, MaxShareCount+1, nil)
	u, p = f.unlock()
	p.queue = [][]string{big[0].Words()}
	if err := rot(u, 4, fresh); !errors.Is(err, ErrShares) {
		t.Fatalf("large threshold: %v", err)
	}
	if err := rot(UnlockOptions{IdentityGen: 1, IdentityPub: f.res.IdentityPub}, 4, fresh); !errors.Is(err, ErrOptions) {
		t.Fatal("no prompter")
	}
	if err := rot(UnlockOptions{IdentityGen: 1, Prompter: p}, 4, fresh); !errors.Is(err, ErrIdentity) {
		t.Fatal("no identity")
	}
	assertNothing(t, fresh, "")
	if got := listDir(t, kd); fmt.Sprint(got) != "[admin-1.key ingest-1.key ingest-2.key ingest-3.key]" {
		t.Fatalf("keys %v", got)
	}
}

// cycle repeats data forever.
type cycle struct {
	data []byte
	off  int
}

func (c *cycle) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.data[c.off%len(c.data)]
		c.off++
	}
	return len(p), nil
}

func TestReshare(t *testing.T) {
	f := newFixture(t)
	oldID := parseShares(t, f.shares, 1)[0].ID
	u, _ := f.unlock(2, 3, 5)
	scr := &screen{}
	u.Prompter.(*prompter).scr = scr
	// The first draw repeats the old identifier: Reshare draws again.
	prefix := append([]byte{byte(oldID >> 8), byte(oldID)}, make([]byte, 32)...)
	r := io.MultiReader(bytes.NewReader(prefix), rand.Reader)
	if err := Reshare(ReshareOptions{UnlockOptions: u, Shares: Shares{2, 3}, Display: scr, Rand: r}); err != nil {
		t.Fatal(err)
	}
	if len(scr.shares) != 3 || scr.lines != 3 {
		t.Fatalf("%d new shares", len(scr.shares))
	}
	newShares := parseShares(t, scr.shares, 1, 2, 3)
	if newShares[0].ID == oldID || newShares[0].Threshold != 2 {
		t.Fatal("new split identifier")
	}
	for _, pair := range [][2]int{{0, 1}, {0, 2}, {1, 2}} {
		secret, err := shamir.Combine([]*shamir.Share{newShares[pair[0]], newShares[pair[1]]})
		if err != nil || !bytes.Equal(secret, f.root[:]) {
			t.Fatal("new shares do not rebuild the root")
		}
	}
	// Old shares still rebuild the root (they cannot be recalled), but
	// do not mix with new ones.
	if secret, _ := shamir.Combine(parseShares(t, f.shares, 1, 2, 4)); !bytes.Equal(secret, f.root[:]) {
		t.Fatal("old shares")
	}
	if _, err := shamir.Combine([]*shamir.Share{parseShares(t, f.shares, 1)[0], newShares[0], newShares[1]}); !errors.Is(err, shamir.ErrMismatch) {
		t.Fatal("old and new mixed")
	}
	// An unlucky random source that always repeats the old identifier.
	u, _ = f.unlock(2, 3, 5)
	if err := Reshare(ReshareOptions{UnlockOptions: u, Shares: Shares{2, 3}, Display: &screen{}, Rand: &cycle{data: prefix}}); !errors.Is(err, ErrShares) {
		t.Fatalf("same identifier forever: %v", err)
	}
	u, _ = f.unlock(2, 3, 5)
	if err := Reshare(ReshareOptions{UnlockOptions: u, Shares: Shares{4, 3}, Display: &screen{}}); !errors.Is(err, ErrShares) {
		t.Fatal("shares")
	}
	if err := Reshare(ReshareOptions{UnlockOptions: u, Shares: Shares{2, 3}}); !errors.Is(err, ErrOptions) {
		t.Fatal("display")
	}
	u, _ = f.unlock(2, 3)
	if err := Reshare(ReshareOptions{UnlockOptions: u, Shares: Shares{2, 3}, Display: &screen{}}); err == nil {
		t.Fatal("too few shares")
	}
	// A wrong share in the probe of the new split.
	u, p := f.unlock(2, 3, 5)
	scr = &screen{}
	n := 0
	p.answer = func(want int) ([]string, error) {
		if want == 0 {
			ws := p.queue[0]
			p.queue = p.queue[1:]
			return ws, nil
		}
		if n++; n == 2 {
			return tamper(t, scr.shares[want]), nil
		}
		return scr.shares[want], nil
	}
	if err := Reshare(ReshareOptions{UnlockOptions: u, Shares: Shares{3, 4}, Display: scr}); !errors.Is(err, ErrProbe) {
		t.Fatalf("probe: %v", err)
	}
}

func TestSucceed(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(f.base, "succ")
	u, _ := f.unlock(1, 4, 5)
	opts := SucceedOptions{UnlockOptions: u, Out: out, Pin: f.res.Pin}
	res, err := Succeed(opts)
	if err != nil {
		t.Fatal(err)
	}
	if want := identityOf(t, f.root[:], 2); !res.IdentityPub.Equal(want) || res.IdentityPub.Equal(f.res.IdentityPub) {
		t.Fatal("identity 2")
	}
	if got := listDir(t, out); fmt.Sprint(got) != "[identity-2.pin platform/identity-2.pub platform/identity-2.succ]" {
		t.Fatalf("export %v", got)
	}
	data, _ := os.ReadFile(filepath.Join(out, "platform", "identity-2.succ"))
	s, err := keys.DecodePlatformSuccession(data)
	if err != nil || s.Verify(f.res.IdentityPub, 1) != nil || !s.Pub.Equal(res.IdentityPub) || s.ValidFrom != testNow.UnixMilli() {
		t.Fatalf("succession: %v", err)
	}
	pub, _ := os.ReadFile(filepath.Join(out, "platform", "identity-2.pub"))
	if !res.IdentityPub.Equal(ed25519.PublicKey(pub)) {
		t.Fatal("identity-2.pub")
	}
	// The pin carries both generations (the list of pin 1 plus the new
	// one) and origin, witnesses and quorum of pin 1, byte for byte the
	// encoding of store.PlatformPin.
	want := *f.res.Pin
	want.Gen, want.Pub = 2, res.IdentityPub
	want.Identities = append(append([]store.PlatformIdentity(nil), f.res.Pin.Identities...), store.PlatformIdentity{Gen: 2, Pub: res.IdentityPub})
	enc, err := want.Encode()
	if err != nil || !bytes.Equal(enc, mustReadFile(t, filepath.Join(out, "identity-2.pin"))) {
		t.Fatalf("pin 2 is not the encoding of fields 1 to 6 and 8: %v", err)
	}
	ids, err := PinIdentities(res.Pin)
	if err != nil || len(ids) != 2 || !ids[0].Pub.Equal(f.res.IdentityPub) || !ids[1].Pub.Equal(res.IdentityPub) {
		t.Fatalf("identity list: %v", err)
	}
	pin, err := ReadPin(filepath.Join(out, "identity-2.pin"))
	if err != nil || pin.Gen != 2 || pin.Dev || !pin.Pub.Equal(res.IdentityPub) {
		t.Fatalf("pin: %v", err)
	}

	// A compromise of generation 2 is locked (task 15f point 1, Q19):
	// ErrCompromised before any share is asked, nothing written.
	u, p := f.unlock(2, 3, 4)
	u.IdentityGen, u.IdentityPub = 2, res.IdentityPub
	locked := SucceedOptions{UnlockOptions: u, Out: filepath.Join(f.base, "succ3c"), Pin: res.Pin, Compromised: true,
		Origin: f.res.Pin.Origin, Witnesses: f.w[:1], MinWitnesses: 1}
	if _, err := Succeed(locked); !errors.Is(err, ErrCompromised) {
		t.Fatalf("compromise: %v", err)
	}
	if len(p.asked) != 0 || len(p.handovers) != 0 {
		t.Fatalf("compromise asked shares: %v", p.asked)
	}
	assertNothing(t, locked.Out, "")

	// From generation 2 on: the whole list goes into the next pin; here a
	// regular succession of generation 2 with the witnesses changed on
	// purpose.
	u, _ = f.unlock(2, 3, 4)
	u.IdentityGen, u.IdentityPub = 2, res.IdentityPub
	opts3 := SucceedOptions{UnlockOptions: u, Out: filepath.Join(f.base, "succ3"), Pin: res.Pin,
		Origin: f.res.Pin.Origin, Witnesses: f.w[:1], MinWitnesses: 1}
	res3, err := Succeed(opts3)
	if err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, opts3.Out); fmt.Sprint(got) != "[identity-3.pin platform/identity-3.pub platform/identity-3.succ]" {
		t.Fatalf("export 3 %v", got)
	}
	s3, err := keys.DecodePlatformSuccession(mustReadFile(t, filepath.Join(opts3.Out, "platform", "identity-3.succ")))
	if err != nil || s3.Verify(res.IdentityPub, 2) != nil || !s3.Pub.Equal(res3.IdentityPub) {
		t.Fatalf("succession 3: %v", err)
	}
	p3 := res3.Pin
	if len(p3.Identities) != 3 || !p3.Identities[2].Pub.Equal(identityOf(t, f.root[:], 3)) || !p3.Identities[1].Pub.Equal(res.IdentityPub) ||
		p3.MinWitnesses != 1 || len(p3.Witnesses) != 1 || p3.Witnesses[0].Name != "w1" || p3.Origin != f.res.Pin.Origin {
		t.Fatalf("pin 3 %+v", p3)
	}

	fail := func(mod func(*SucceedOptions)) error {
		u, _ := f.unlock(1, 2, 3)
		o := opts
		o.UnlockOptions, o.Out = u, filepath.Join(f.base, "bad")
		mod(&o)
		_, err := Succeed(o)
		return err
	}
	if err := fail(func(o *SucceedOptions) { o.MinWitnesses = 1 }); !errors.Is(err, translog.ErrWitness) {
		t.Fatal("quorum 1 of 3")
	}
	if err := fail(func(o *SucceedOptions) { o.Witnesses, o.MinWitnesses = f.w[:2], 1 }); !errors.Is(err, translog.ErrWitness) {
		t.Fatal("quorum 1 of 2")
	}
	if err := fail(func(o *SucceedOptions) { o.Origin = "another.test/log" }); !errors.Is(err, ErrOptions) {
		t.Fatal("origin changed")
	}
	if err := fail(func(o *SucceedOptions) { o.Pin = nil }); !errors.Is(err, ErrOptions) {
		t.Fatal("no pin")
	}
	if err := fail(func(o *SucceedOptions) { o.Pin = res.Pin }); !errors.Is(err, ErrIdentity) {
		t.Fatal("pin of another generation than the identity unlocked")
	}
	dev := *f.res.Pin
	dev.Dev = true
	if err := fail(func(o *SucceedOptions) { o.Pin = &dev }); !errors.Is(err, ErrIdentity) {
		t.Fatal("development pin")
	}
	if err := fail(func(o *SucceedOptions) { o.Out = out }); !errors.Is(err, ErrOutDir) {
		t.Fatal("used export directory")
	}
	if err := fail(func(o *SucceedOptions) { o.Prompter = nil }); !errors.Is(err, ErrOptions) {
		t.Fatal("prompter")
	}
	if err := fail(func(o *SucceedOptions) { o.IdentityGen = 0 }); !errors.Is(err, ErrIdentity) {
		t.Fatal("generation 0")
	}
	// A pin whose earlier generation does not derive from the root.
	u, _ = f.unlock(2, 3, 4)
	u.IdentityGen, u.IdentityPub = 2, res.IdentityPub
	forged := *res.Pin
	forged.Identities = []store.PlatformIdentity{{Gen: 1, Pub: f.w[0].Pub}, res.Pin.Identities[1]}
	if _, err := Succeed(SucceedOptions{UnlockOptions: u, Out: filepath.Join(f.base, "bad"), Pin: &forged}); !errors.Is(err, ErrIdentity) {
		t.Fatalf("forged list: %v", err)
	}
	if err := fail(func(o *SucceedOptions) { o.Prompter.(*prompter).queue = nil }); err == nil {
		t.Fatal("no shares")
	}
	assertNothing(t, filepath.Join(f.base, "bad"), "")
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
