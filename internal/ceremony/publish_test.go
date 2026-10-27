package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/translog/translogtest"
	"github.com/tim-riep/go-mail/internal/witness"
)

// recLog records the names of the platform entries appended.
type recLog struct {
	*translogtest.Unverified
	names []string
	fail  error
}

func (l *recLog) Append(k translog.Kind, content []byte) (int64, error) {
	key, err := translog.KeyOf(k, content)
	if err != nil {
		return 0, err
	}
	if k != translog.KindPlatform {
		return 0, fmt.Errorf("kind %v", k)
	}
	l.names = append(l.names, string(key.Subject))
	if l.fail != nil {
		return 0, l.fail
	}
	return translogtest.NoIndex, nil
}

func newLog(t *testing.T) *recLog {
	u, err := translogtest.NewUnverified(true)
	if err != nil {
		t.Fatal(err)
	}
	return &recLog{Unverified: u}
}

func newData(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// platform derives the platform keys of the fixture's root.
func (f *fixture) platform(t *testing.T) *keys.PlatformRoot {
	t.Helper()
	seed := f.root
	return keys.DerivePlatform(&seed)
}

// export writes an export directory with the given platform files.
func writeExport(t *testing.T, dir string, files map[string][]byte) string {
	t.Helper()
	os.MkdirAll(filepath.Join(dir, "platform"), 0o700)
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, "platform", n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func (f *fixture) cert(t *testing.T, idGen uint32, role keys.Role, gen uint32) (pub, cert []byte) {
	t.Helper()
	p := f.platform(t)
	id, _ := p.IdentityKey(idGen)
	var k ed25519.PrivateKey
	if role == keys.RoleAdmin {
		k, _ = p.AdminKey(gen)
	} else {
		k, _ = p.IngestKey(gen)
	}
	c, err := keys.NewPlatformCert(id, idGen, role, gen, pubOf(k), testNow.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	cd, _ := c.Encode()
	return pubOf(k), cd
}

func (f *fixture) succ(t *testing.T, gen uint32) (pub, succ []byte) {
	t.Helper()
	p := f.platform(t)
	prev, _ := p.IdentityKey(gen - 1)
	next, _ := p.IdentityKey(gen)
	s, err := keys.NewPlatformSuccession(prev, gen, pubOf(next), testNow.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	sd, _ := s.Encode()
	return pubOf(next), sd
}

func TestPublish(t *testing.T) {
	f := newFixture(t)
	st := newData(t, filepath.Join(f.base, "data"))
	log := newLog(t)
	out := filepath.Join(f.base, "out")
	opts := PublishOptions{From: out, Data: st, Log: log, Pin: f.res.Pin}
	if err := Publish(opts); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(log.names) != "[admin-1.cert ingest-1.cert]" {
		t.Fatalf("log %v", log.names)
	}
	for _, n := range listDir(t, filepath.Join(out, "platform")) {
		want, _ := os.ReadFile(filepath.Join(out, "platform", n))
		got, err := st.ReadPlatformFile(n)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: %v", n, err)
		}
	}
	if _, err := os.Stat(filepath.Join(st.Root, "platform", "identity-1.pin")); err == nil {
		t.Fatal("pin in the data directory")
	}
	for _, role := range []keys.Role{keys.RoleAdmin, keys.RoleIngest} {
		c, err := st.ReadPlatformCert(role, 1)
		if err != nil || c.Verify(f.res.IdentityPub) != nil {
			t.Fatal("certificate in the data directory")
		}
	}
	// Publishing again skips identical files and appends again
	// (idempotent).
	log.names = nil
	if err := Publish(opts); err != nil || len(log.names) != 2 {
		t.Fatalf("again: %v %v", err, log.names)
	}

	// Ingest rotation, then publish.
	u, _ := f.unlock(1, 2, 3)
	rot := filepath.Join(f.base, "rot")
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: rot, KeyDir: filepath.Join(f.base, "keys"), Gen: 2}); err != nil {
		t.Fatal(err)
	}
	log.names = nil
	if err := Publish(PublishOptions{From: rot, Data: st, Log: log, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(log.names) != "[ingest-2.cert]" {
		t.Fatalf("log %v", log.names)
	}
	// witnesses.rec is the server's working copy and is replaced.
	ws := &witness.Witnesses{List: f.w[:1], Min: 1}
	wrec, _ := ws.Encode()
	wdir := writeExport(t, filepath.Join(f.base, "w"), map[string][]byte{WitnessesFile: wrec})
	if err := Publish(PublishOptions{From: wdir, Data: st, Log: log, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.ReadPlatformFile(WitnessesFile); !bytes.Equal(got, wrec) {
		t.Fatal("witnesses.rec not replaced")
	}

	// Succession: published with the old pin, or with the new pin and
	// its identity list.
	u, _ = f.unlock(3, 4, 5)
	succ := filepath.Join(f.base, "succ")
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: succ, Identities: f.res.Identities, Origin: "o", Witnesses: f.w[:1], MinWitnesses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: succ, Data: st, Log: log, Pin: res2.Pin}); !errors.Is(err, ErrIdentity) {
		t.Fatalf("pin of generation 2 without identity list: %v", err)
	}
	log.names = nil
	if err := Publish(PublishOptions{From: succ, Data: st, Log: log, Pin: res2.Pin, Identities: res2.Identities}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(log.names) != "[identity-2.succ]" {
		t.Fatalf("log %v", log.names)
	}
	log.names = nil
	if err := Publish(PublishOptions{From: succ, Data: st, Log: log, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	// With the old pin, a certificate of generation 2 verifies through
	// the succession now in the data directory.
	pub, cd := f.cert(t, 2, keys.RoleAdmin, 2)
	dir := writeExport(t, filepath.Join(f.base, "a2"), map[string][]byte{"admin-2.pub": pub, "admin-2.cert": cd})
	log.names = nil
	if err := Publish(PublishOptions{From: dir, Data: st, Log: log, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(log.names) != "[admin-2.cert]" {
		t.Fatalf("log %v", log.names)
	}
}

// TestPublishOrder checks the order of the log entries: successions by
// generation, then certificates by role and generation.
func TestPublishOrder(t *testing.T) {
	f := newFixture(t)
	st := newData(t, filepath.Join(f.base, "data"))
	log := newLog(t)
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Log: log, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	add := func(name string, b []byte) { files[name] = b }
	for _, g := range []uint32{2, 3} {
		pub, s := f.succ(t, g)
		add(fmt.Sprintf("identity-%d.pub", g), pub)
		add(fmt.Sprintf("identity-%d.succ", g), s)
	}
	for _, c := range []struct {
		idGen uint32
		role  keys.Role
		name  string
		gen   uint32
	}{{3, keys.RoleIngest, "ingest", 3}, {2, keys.RoleIngest, "ingest", 2}, {3, keys.RoleAdmin, "admin", 2}} {
		pub, cd := f.cert(t, c.idGen, c.role, c.gen)
		add(fmt.Sprintf("%s-%d.pub", c.name, c.gen), pub)
		add(fmt.Sprintf("%s-%d.cert", c.name, c.gen), cd)
	}
	dir := writeExport(t, filepath.Join(f.base, "x"), files)
	log.names = nil
	if err := Publish(PublishOptions{From: dir, Data: st, Log: log, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(log.names); got != "[identity-2.succ identity-3.succ admin-2.cert ingest-2.cert ingest-3.cert]" {
		t.Fatalf("log order %s", got)
	}
	for n := range files {
		if got, _ := st.ReadPlatformFile(n); !bytes.Equal(got, files[n]) {
			t.Fatalf("%s not copied", n)
		}
	}
}

func TestPublishRefuses(t *testing.T) {
	f := newFixture(t)
	pin := f.res.Pin
	idPub := f.res.IdentityPub
	admin1Pub, _ := f.cert(t, 1, keys.RoleAdmin, 1)
	ingest2Pub, ingest2 := f.cert(t, 1, keys.RoleIngest, 2)
	ingest3Pub, ingest3 := f.cert(t, 1, keys.RoleIngest, 3)
	succ2Pub, succ2 := f.succ(t, 2)
	_, succ3 := f.succ(t, 3)
	cert3Pub, cert3 := f.cert(t, 3, keys.RoleAdmin, 1)
	// A certificate signed by a foreign key.
	_, foreign, _ := ed25519.GenerateKey(nil)
	fc, _ := keys.NewPlatformCert(foreign, 1, keys.RoleAdmin, 1, admin1Pub, 0)
	forgedCert, _ := fc.Encode()
	fs, _ := keys.NewPlatformSuccession(foreign, 2, succ2Pub, 0)
	forgedSucc, _ := fs.Encode()
	otherSucc, _ := keys.NewPlatformSuccession(foreign, 2, foreign.Public().(ed25519.PublicKey), 0)
	otherSuccData, _ := otherSucc.Encode()
	badW := []byte("not a record")

	n := 0
	for name, c := range map[string]struct {
		files map[string][]byte
		mod   func(*PublishOptions)
		errs  []error
	}{
		"forged certificate":        {map[string][]byte{"admin-1.pub": admin1Pub, "admin-1.cert": forgedCert}, nil, []error{translog.ErrOrder, keys.ErrSignature}},
		"forged succession":         {map[string][]byte{"identity-2.succ": forgedSucc}, nil, []error{translog.ErrOrder}},
		"succession against pin":    {map[string][]byte{"identity-2.succ": otherSuccData}, func(o *PublishOptions) { o.Pin, o.Identities = f.pin2(t) }, []error{translog.ErrMismatch}},
		"forged listed succession":  {map[string][]byte{"identity-2.succ": forgedSucc}, func(o *PublishOptions) { o.Pin, o.Identities = f.pin2(t) }, []error{translog.ErrOrder}},
		"gap in ingest generations": {map[string][]byte{"ingest-3.pub": ingest3Pub, "ingest-3.cert": ingest3}, nil, []error{translog.ErrPrerequisite}},
		"gap in successions":        {map[string][]byte{"identity-3.succ": succ3}, nil, []error{translog.ErrPrerequisite}},
		"unknown identity":          {map[string][]byte{"admin-1.pub": cert3Pub, "admin-1.cert": cert3}, nil, []error{translog.ErrPrerequisite}},
		"identity pub unknown":      {map[string][]byte{"identity-2.pub": succ2Pub}, nil, []error{translog.ErrPrerequisite}},
		"identity pub differs":      {map[string][]byte{"identity-1.pub": succ2Pub}, nil, []error{ErrIdentity}},
		"cert without pub":          {map[string][]byte{"ingest-2.cert": ingest2}, nil, []error{ErrOutDir}},
		"pub without cert":          {map[string][]byte{"ingest-2.pub": ingest2Pub}, nil, []error{ErrOutDir}},
		"pub of another key":        {map[string][]byte{"ingest-2.pub": admin1Pub, "ingest-2.cert": ingest2}, nil, []error{ErrOutDir}},
		"cert under wrong name":     {map[string][]byte{"ingest-3.pub": ingest2Pub, "ingest-3.cert": ingest2}, nil, []error{ErrOutDir}},
		"succession wrong name":     {map[string][]byte{"identity-3.succ": succ2}, nil, []error{ErrOutDir}},
		"malformed cert":            {map[string][]byte{"ingest-2.pub": ingest2Pub, "ingest-2.cert": []byte("x")}, nil, []error{keys.ErrCert}},
		"malformed succession":      {map[string][]byte{"identity-2.succ": []byte("x")}, nil, []error{keys.ErrCert}},
		"unknown file":              {map[string][]byte{"identity-1.pin": []byte("x")}, nil, []error{ErrOutDir}},
		"non-canonical name":        {map[string][]byte{"ingest-02.cert": ingest2}, nil, []error{ErrOutDir}},
		"bad witnesses.rec":         {map[string][]byte{WitnessesFile: badW}, nil, []error{witness.ErrWitnesses}},
		"no options":                {map[string][]byte{}, func(o *PublishOptions) { o.Log = nil }, []error{ErrOptions}},
		"development pin":           {map[string][]byte{}, func(o *PublishOptions) { o.Pin = &store.PlatformPin{Gen: 1, Pub: idPub, Dev: true} }, []error{ErrIdentity}},
		"development pin with list": {map[string][]byte{}, func(o *PublishOptions) {
			o.Pin = &store.PlatformPin{Gen: 1, Pub: idPub, Dev: true}
			o.Identities = f.res.Identities
		}, []error{ErrIdentity}},
		"list against pin": {map[string][]byte{}, func(o *PublishOptions) { _, o.Identities = f.pin2(t) }, []error{ErrIdentity, translog.ErrPin}},
		"invalid pin":      {map[string][]byte{}, func(o *PublishOptions) { o.Pin = &store.PlatformPin{Gen: 1} }, []error{ErrIdentity}},
		"log refuses":      {map[string][]byte{"ingest-2.pub": ingest2Pub, "ingest-2.cert": ingest2}, func(o *PublishOptions) { o.Log.(*recLog).fail = translog.ErrOrder }, []error{translog.ErrOrder}},
	} {
		t.Run(name, func(t *testing.T) {
			n++
			st := newData(t, filepath.Join(f.base, fmt.Sprint("data", n)))
			log := newLog(t)
			// The data directory holds generation 1 already.
			if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Log: log, Pin: pin}); err != nil {
				t.Fatal(err)
			}
			before := listDir(t, filepath.Join(st.Root, "platform"))
			log.names = nil
			dir := writeExport(t, filepath.Join(f.base, fmt.Sprint("x", n)), c.files)
			o := PublishOptions{From: dir, Data: st, Log: log, Pin: pin}
			if c.mod != nil {
				c.mod(&o)
			}
			err := Publish(o)
			for _, e := range c.errs {
				if !errors.Is(err, e) {
					t.Fatalf("%v is not %v", err, e)
				}
			}
			if name == "log refuses" {
				return // the files are written before the log entries
			}
			if after := listDir(t, filepath.Join(st.Root, "platform")); fmt.Sprint(after) != fmt.Sprint(before) || len(log.names) != 0 {
				t.Fatalf("written: %v, logged %v", after, log.names)
			}
		})
	}
}

// pin2 returns a pin of identity generation 2 with its identity list.
func (f *fixture) pin2(t *testing.T) (*store.PlatformPin, []translog.Identity) {
	pub2 := identityOf(t, f.root[:], 2)
	return &store.PlatformPin{Gen: 2, Pub: pub2}, []translog.Identity{f.res.Identities[0], {Gen: 2, Pub: pub2}}
}

func TestPublishExisting(t *testing.T) {
	f := newFixture(t)
	st := newData(t, filepath.Join(f.base, "data"))
	log := newLog(t)
	out := filepath.Join(f.base, "out")
	// A certificate of generation 1 with other content is already in the
	// data directory.
	_, other := f.cert(t, 1, keys.RoleIngest, 1)
	c, _ := keys.DecodePlatformCert(other)
	c2, _ := keys.NewPlatformCert(mustIdentity(t, f, 1), 1, keys.RoleIngest, 1, c.Pub, 1)
	other, _ = c2.Encode()
	if err := st.WritePlatformFile("ingest-1.cert", other); err != nil {
		t.Fatal(err)
	}
	err := Publish(PublishOptions{From: out, Data: st, Log: log, Pin: f.res.Pin})
	if !errors.Is(err, store.ErrExists) || !errors.Is(err, translog.ErrDuplicate) {
		t.Fatalf("existing certificate: %v", err)
	}
	if got := listDir(t, filepath.Join(st.Root, "platform")); fmt.Sprint(got) != "[ingest-1.cert]" || len(log.names) != 0 {
		t.Fatalf("written %v", got)
	}
	// A public key with other content.
	st2 := newData(t, filepath.Join(f.base, "data2"))
	st2.WritePlatformFile("identity-1.pub", make([]byte, 32))
	if err := Publish(PublishOptions{From: out, Data: st2, Log: log, Pin: f.res.Pin}); !errors.Is(err, store.ErrExists) || errors.Is(err, translog.ErrDuplicate) {
		t.Fatalf("existing key: %v", err)
	}
	// A file that appears while Publish writes: identical content is
	// fine, other content is refused.
	st3 := newData(t, filepath.Join(f.base, "data3"))
	defer func() { crashHook = nil }()
	crashHook = func(point string) error {
		if point == "publish-file" {
			crashHook = nil
			return st3.WritePlatformFile("ingest-1.cert", other)
		}
		return nil
	}
	if err := Publish(PublishOptions{From: out, Data: st3, Log: log, Pin: f.res.Pin}); !errors.Is(err, store.ErrExists) {
		t.Fatalf("racing writer: %v", err)
	}
	src, _ := os.ReadFile(filepath.Join(out, "platform", "ingest-1.cert"))
	st4 := newData(t, filepath.Join(f.base, "data4"))
	crashHook = func(point string) error {
		if point == "publish-file" {
			crashHook = nil
			return st4.WritePlatformFile("ingest-1.cert", src)
		}
		return nil
	}
	if err := Publish(PublishOptions{From: out, Data: st4, Log: log, Pin: f.res.Pin}); err != nil {
		t.Fatalf("racing writer with the same content: %v", err)
	}
}

func mustIdentity(t *testing.T, f *fixture, gen uint32) ed25519.PrivateKey {
	t.Helper()
	k, err := f.platform(t).IdentityKey(gen)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestPublishCrash interrupts Publish at every write; running it again
// completes it.
func TestPublishCrash(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(f.base, "out")
	defer func() { crashHook = nil }()
	for n := 1; ; n++ {
		st := newData(t, filepath.Join(f.base, fmt.Sprint("data", n)))
		log := newLog(t)
		calls := 0
		crashHook = func(point string) error {
			if calls++; calls == n {
				return errors.New("crash at " + point)
			}
			return nil
		}
		err := Publish(PublishOptions{From: out, Data: st, Log: log, Pin: f.res.Pin})
		crashHook = nil
		if calls < n {
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		if err == nil || !strings.Contains(err.Error(), "crash at") || len(log.names) != 0 {
			t.Fatalf("crash %d: %v %v", n, err, log.names)
		}
		if err := Publish(PublishOptions{From: out, Data: st, Log: log, Pin: f.res.Pin}); err != nil {
			t.Fatalf("after crash %d: %v", n, err)
		}
		if fmt.Sprint(log.names) != "[admin-1.cert ingest-1.cert]" {
			t.Fatalf("after crash %d: log %v", n, log.names)
		}
	}
	// A symbolic link in the export is refused.
	dir := filepath.Join(f.base, "link")
	os.MkdirAll(filepath.Join(dir, "platform"), 0o700)
	os.Symlink(filepath.Join(out, "platform", "identity-1.pub"), filepath.Join(dir, "platform", "identity-1.pub"))
	st := newData(t, filepath.Join(f.base, "dataL"))
	if err := Publish(PublishOptions{From: dir, Data: st, Log: newLog(t), Pin: f.res.Pin}); !errors.Is(err, ErrOutDir) {
		t.Fatalf("symbolic link: %v", err)
	}
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "missing"), Data: st, Log: newLog(t), Pin: f.res.Pin}); !errors.Is(err, ErrOutDir) {
		t.Fatal("missing export")
	}
	// Too many files.
	many := map[string][]byte{}
	for i := 1; i <= maxExportFiles+1; i++ {
		many[fmt.Sprintf("admin-%d.pub", i)] = []byte("x")
	}
	if err := Publish(PublishOptions{From: writeExport(t, filepath.Join(f.base, "many"), many), Data: st, Log: newLog(t), Pin: f.res.Pin}); !errors.Is(err, ErrOutDir) {
		t.Fatal("too many files")
	}
}

func TestParsePlatformName(t *testing.T) {
	for _, n := range []string{"identity-1.pub", "identity-2.succ", "admin-7.cert", "ingest-4294967295.pub"} {
		if _, ok := parsePlatformName(n); !ok {
			t.Fatalf("%s refused", n)
		}
	}
	for _, n := range []string{"identity-1.cert", "admin-1.succ", "admin-0.cert", "admin-01.cert", "admin-+1.cert", "admin-1",
		"admin.cert", "user-1.pub", "admin-1.cert.tmp", "ingest-4294967296.pub", "-1.pub", "admin--1.pub", "identity-1.pin"} {
		if _, ok := parsePlatformName(n); ok {
			t.Fatalf("%s accepted", n)
		}
	}
}
