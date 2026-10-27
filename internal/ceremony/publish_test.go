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
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/translog/translogtest"
	"github.com/tim-riep/go-mail/internal/witness"
)

// recLog records the names of the platform entries appended; Lookup
// finds the platform entries appended without failure (it judges no
// validity: every append counts).
type recLog struct {
	*translogtest.Unverified
	names  []string
	logged map[string][]byte
	fail   error
}

func (l *recLog) Lookup(kind translog.Kind, subject []byte) ([]translog.Entry, error) {
	c, ok := l.logged[string(subject)]
	if kind != translog.KindPlatform || !ok {
		return nil, nil
	}
	return []translog.Entry{{Key: translog.Key{Kind: kind, Subject: bytes.Clone(subject)}, Content: c}}, nil
}

func (l *recLog) AppendPlatform(name string, content []byte) error {
	key, err := translog.KeyOf(translog.KindPlatform, content)
	if err != nil {
		return err
	}
	if string(key.Subject) != name {
		return fmt.Errorf("%s logged as %s", key.Subject, name)
	}
	l.names = append(l.names, name)
	if l.fail != nil {
		return l.fail
	}
	if l.logged == nil {
		l.logged = map[string][]byte{}
	}
	if _, ok := l.logged[name]; !ok {
		l.logged[name] = bytes.Clone(content)
	}
	return nil
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

// pinN returns the pin of identity generation n of the fixture's root,
// with the identity list 1..n and origin, witnesses and quorum of pin 1.
func (f *fixture) pinN(t *testing.T, n uint32) *store.PlatformPin {
	t.Helper()
	p := *f.res.Pin
	p.Identities = nil
	for g := uint32(1); g <= n; g++ {
		p.Identities = append(p.Identities, store.PlatformIdentity{Gen: g, Pub: identityOf(t, f.root[:], g)})
	}
	p.Gen, p.Pub = n, p.Identities[n-1].Pub
	if _, err := p.Encode(); err != nil {
		t.Fatal(err)
	}
	return &p
}

// pin2 returns the pin of identity generation 2 with its identity list.
func (f *fixture) pin2(t *testing.T) *store.PlatformPin { return f.pinN(t, 2) }

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
	// witnesses.rec, the server's working copy, must be the pin's: the
	// same in the export goes through, another one is refused, in the
	// export as in the data directory, and never replaced silently.
	wrec, _ := (&witness.Witnesses{List: f.w, Min: 2}).Encode()
	wdir := writeExport(t, filepath.Join(f.base, "w"), map[string][]byte{WitnessesFile: wrec})
	if err := Publish(PublishOptions{From: wdir, Data: st, Log: log, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	other, _ := (&witness.Witnesses{List: f.w[:1], Min: 1}).Encode()
	odir := writeExport(t, filepath.Join(f.base, "wo"), map[string][]byte{WitnessesFile: other})
	if err := Publish(PublishOptions{From: odir, Data: st, Log: log, Pin: f.res.Pin}); !errors.Is(err, translog.ErrMismatch) {
		t.Fatalf("other witnesses in the export: %v", err)
	}
	otherPin := *f.res.Pin
	otherPin.Witnesses, otherPin.MinWitnesses = []store.Witness{{Name: f.w[0].Name, Pub: f.w[0].Pub}}, 1
	if err := Publish(PublishOptions{From: rot, Data: st, Log: log, Pin: &otherPin}); !errors.Is(err, translog.ErrMismatch) {
		t.Fatalf("pin with other witnesses than the data directory: %v", err)
	}
	if got, _ := st.ReadPlatformFile(WitnessesFile); !bytes.Equal(got, wrec) {
		t.Fatal("witnesses.rec replaced")
	}

	// Succession: refused with the old pin, which does not know
	// generation 2 (Q10 point 5); published with the new pin.
	u, _ = f.unlock(3, 4, 5)
	succ := filepath.Join(f.base, "succ")
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: succ, Pin: f.res.Pin})
	if err != nil {
		t.Fatal(err)
	}
	log.names = nil
	if err := Publish(PublishOptions{From: succ, Data: st, Log: log, Pin: f.res.Pin}); !errors.Is(err, translog.ErrMismatch) || len(log.names) != 0 {
		t.Fatalf("succession with the old pin: %v", err)
	}
	if err := Publish(PublishOptions{From: succ, Data: st, Log: log, Pin: res2.Pin}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(log.names) != "[identity-2.succ]" {
		t.Fatalf("log %v", log.names)
	}
	// From now on data/platform/ names generation 2: the old pin is
	// refused whatever the export.
	if err := Publish(PublishOptions{From: rot, Data: st, Log: log, Pin: f.res.Pin}); !errors.Is(err, translog.ErrMismatch) {
		t.Fatalf("old pin after the succession: %v", err)
	}
	// A certificate of identity generation 2 verifies with the new pin.
	pub, cd := f.cert(t, 2, keys.RoleAdmin, 2)
	dir := writeExport(t, filepath.Join(f.base, "a2"), map[string][]byte{"admin-2.pub": pub, "admin-2.cert": cd})
	log.names = nil
	if err := Publish(PublishOptions{From: dir, Data: st, Log: log, Pin: res2.Pin}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(log.names) != "[admin-2.cert]" {
		t.Fatalf("log %v", log.names)
	}

	// While a server runs (it holds locks/server), publish refuses
	// before it reads anything.
	release, err := st.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: dir, Data: st, Log: log, Pin: res2.Pin}); !errors.Is(err, ErrServer) || !errors.Is(err, store.ErrLocked) {
		t.Fatalf("beside a server: %v", err)
	}
	release()
	if err := Publish(PublishOptions{From: dir, Data: st, Log: log, Pin: res2.Pin}); err != nil {
		t.Fatalf("after the server: %v", err)
	}
}

// TestPublishLog: publish into the operator log of the data directory
// (PublishOptions.Log nil, OpenLog): the certificates and the succession
// are entries of kind platform, valid against the pin (CheckPlatform),
// and the server signs a head over them (Operator.SignHead with the
// ingest key). After the succession the log opens only with the new pin
// for publish, and the server signs with it.
func TestPublishLog(t *testing.T) {
	f := newFixture(t)
	st := newData(t, filepath.Join(f.base, "data"))
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	u, _ := f.unlock(3, 4, 5)
	succ := filepath.Join(f.base, "succ")
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: succ, Pin: f.res.Pin})
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: succ, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatal(err)
	}
	ingest, _, err := ReadKey(filepath.Join(f.base, "keys", "ingest-1.key"), store.KeyRoleIngest)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := translog.NewLogSigner(ingest)
	if err != nil {
		t.Fatal(err)
	}
	{
		pin := res2.Pin
		ids, err := PinIdentities(pin)
		if err != nil {
			t.Fatal(err)
		}
		wvs, err := (&witness.Witnesses{List: pinWitnesses(pin), Min: pin.MinWitnesses}).Verifiers()
		if err != nil {
			t.Fatal(err)
		}
		l, err := translog.Open(translog.Options{Store: st, Identities: ids, Origin: pin.Origin, Known: note.VerifierList(wvs...),
			Witnesses: wvs, MinWitnesses: pin.MinWitnesses})
		if err != nil {
			t.Fatal(err)
		}
		for i, name := range []string{"admin-1.cert", "ingest-1.cert", "identity-2.succ"} {
			e, err := l.Entry(int64(i))
			if err != nil || e.Key.Kind != translog.KindPlatform || string(e.Key.Subject) != name {
				t.Fatalf("entry %d: %v %+v", i, err, e)
			}
			raw, err := st.ReadPlatformFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.CheckPlatform(name, raw); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		h, err := l.(translog.Operator).SignHead(signer, testNow.Add(time.Minute))
		if err != nil || h.Size != 3 {
			t.Fatalf("head: %v %+v", err, h)
		}
	}
	// The log opens with the old pin for nobody: it does not know
	// generation 2 of platform/.
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: f.res.Pin}); !errors.Is(err, translog.ErrMismatch) {
		t.Fatalf("old pin: %v", err)
	}
	if _, err := OpenLog(st, &store.PlatformPin{Gen: 1, Pub: f.res.IdentityPub, Dev: true}); !errors.Is(err, ErrIdentity) {
		t.Fatalf("development pin: %v", err)
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
	if err := Publish(PublishOptions{From: dir, Data: st, Log: log, Pin: f.pinN(t, 3)}); err != nil {
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
	otherW, _ := (&witness.Witnesses{List: f.w[:1], Min: 1}).Encode()
	devPin := *pin
	devPin.Dev = true
	listPin := *pin
	listPin.Identities = f.pin2(t).Identities
	usePin2 := func(o *PublishOptions) { o.Pin = f.pin2(t) }

	n := 0
	for name, c := range map[string]struct {
		files map[string][]byte
		mod   func(*PublishOptions)
		errs  []error
	}{
		"forged certificate":         {map[string][]byte{"admin-1.pub": admin1Pub, "admin-1.cert": forgedCert}, nil, []error{translog.ErrOrder, keys.ErrSignature}},
		"succession above the pin":   {map[string][]byte{"identity-2.succ": succ2}, nil, []error{translog.ErrMismatch}},
		"forged succession":          {map[string][]byte{"identity-2.succ": forgedSucc}, nil, []error{translog.ErrMismatch}},
		"succession against pin":     {map[string][]byte{"identity-2.succ": otherSuccData}, usePin2, []error{translog.ErrMismatch}},
		"forged listed succession":   {map[string][]byte{"identity-2.succ": forgedSucc}, usePin2, []error{translog.ErrOrder}},
		"succession of generation 1": {map[string][]byte{"identity-1.succ": succ2}, nil, []error{ErrOutDir}},
		"gap in ingest generations":  {map[string][]byte{"ingest-3.pub": ingest3Pub, "ingest-3.cert": ingest3}, nil, []error{translog.ErrPrerequisite}},
		"successions above the pin":  {map[string][]byte{"identity-3.succ": succ3}, usePin2, []error{translog.ErrMismatch}},
		"unknown identity":           {map[string][]byte{"admin-1.pub": cert3Pub, "admin-1.cert": cert3}, nil, []error{translog.ErrMismatch}},
		"identity pub unknown":       {map[string][]byte{"identity-2.pub": succ2Pub}, nil, []error{translog.ErrMismatch}},
		"identity pub differs":       {map[string][]byte{"identity-1.pub": succ2Pub}, nil, []error{ErrIdentity}},
		"cert without pub":           {map[string][]byte{"ingest-2.cert": ingest2}, nil, []error{ErrOutDir}},
		"pub without cert":           {map[string][]byte{"ingest-2.pub": ingest2Pub}, nil, []error{ErrOutDir}},
		"pub of another key":         {map[string][]byte{"ingest-2.pub": admin1Pub, "ingest-2.cert": ingest2}, nil, []error{ErrOutDir}},
		"cert under wrong name":      {map[string][]byte{"ingest-3.pub": ingest2Pub, "ingest-3.cert": ingest2}, nil, []error{ErrOutDir}},
		"succession wrong name":      {map[string][]byte{"identity-3.succ": succ2}, f.withPin(t, 3), []error{ErrOutDir}},
		"malformed cert":             {map[string][]byte{"ingest-2.pub": ingest2Pub, "ingest-2.cert": []byte("x")}, nil, []error{keys.ErrCert}},
		"malformed succession":       {map[string][]byte{"identity-2.succ": []byte("x")}, usePin2, []error{keys.ErrCert}},
		"unknown file":               {map[string][]byte{"identity-1.pin": []byte("x")}, nil, []error{ErrOutDir}},
		"non-canonical name":         {map[string][]byte{"ingest-02.cert": ingest2}, nil, []error{ErrOutDir}},
		"bad witnesses.rec":          {map[string][]byte{WitnessesFile: badW}, nil, []error{witness.ErrWitnesses}},
		"other witnesses.rec":        {map[string][]byte{WitnessesFile: otherW}, nil, []error{translog.ErrMismatch}},
		"no options":                 {map[string][]byte{}, func(o *PublishOptions) { o.From = "" }, []error{ErrOptions}},
		"no pin":                     {map[string][]byte{}, func(o *PublishOptions) { o.Pin = nil }, []error{ErrOptions}},
		"development pin":            {map[string][]byte{}, func(o *PublishOptions) { o.Pin = &devPin }, []error{ErrIdentity}},
		"list against pin":           {map[string][]byte{}, func(o *PublishOptions) { o.Pin = &listPin }, []error{ErrIdentity, translog.ErrPin}},
		"invalid pin":                {map[string][]byte{}, func(o *PublishOptions) { o.Pin = &store.PlatformPin{Gen: 1} }, []error{ErrIdentity}},
		"short pin":                  {map[string][]byte{}, func(o *PublishOptions) { o.Pin = &store.PlatformPin{Gen: 1, Pub: idPub} }, []error{ErrIdentity}},
		"log refuses":                {map[string][]byte{"ingest-2.pub": ingest2Pub, "ingest-2.cert": ingest2}, func(o *PublishOptions) { o.Log.(*recLog).fail = translog.ErrOrder }, []error{translog.ErrOrder}},
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
	// A data directory that names a generation the pin does not know, or
	// contradicts its list, is refused before the export is read.
	for name, files := range map[string]map[string][]byte{
		"identity-2.pub":  {"identity-2.pub": succ2Pub},
		"identity-2.succ": {"identity-2.succ": succ2},
		"cert of 3":       {"admin-1.cert": cert3},
		"other pub of 1":  {"identity-1.pub": succ2Pub},
	} {
		n++
		st := newData(t, filepath.Join(f.base, fmt.Sprint("data", n)))
		for fn, b := range files {
			if err := st.WritePlatformFile(fn, b); err != nil {
				t.Fatal(err)
			}
		}
		if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Log: newLog(t), Pin: pin}); !errors.Is(err, translog.ErrMismatch) {
			t.Fatalf("%s in the data directory: %v", name, err)
		}
	}
}

// withPin returns a modifier that publishes with the pin of generation n.
func (f *fixture) withPin(t *testing.T, n uint32) func(*PublishOptions) {
	return func(o *PublishOptions) { o.Pin = f.pinN(t, n) }
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
	// A public key with other content; an identity key that is not the
	// pin's contradicts the pin (the start check of the server).
	st2 := newData(t, filepath.Join(f.base, "data2"))
	st2.WritePlatformFile("admin-1.pub", make([]byte, 32))
	if err := Publish(PublishOptions{From: out, Data: st2, Log: log, Pin: f.res.Pin}); !errors.Is(err, store.ErrExists) || errors.Is(err, translog.ErrDuplicate) {
		t.Fatalf("existing key: %v", err)
	}
	st2b := newData(t, filepath.Join(f.base, "data2b"))
	st2b.WritePlatformFile("identity-1.pub", make([]byte, 32))
	if err := Publish(PublishOptions{From: out, Data: st2b, Log: log, Pin: f.res.Pin}); !errors.Is(err, translog.ErrMismatch) {
		t.Fatalf("existing identity key: %v", err)
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
