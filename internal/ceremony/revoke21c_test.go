package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of task 21c (D93): succeed --compromised, revoke, admin-rotate
// and publish with pin field 7.

// headAt is the time of the heads the tests sign: after valid_from of
// the certificates of the fixture (testNow) and within the clock
// tolerance of the ceremony clock fixedNow.
var headAt = testNow.Add(time.Minute)

// witnessPair returns a witness key and its note signer.
func witnessPair(t *testing.T, name string) (witness.Key, note.Signer) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(vkey, "+", 3)
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 1+ed25519.PublicKeySize {
		t.Fatal("verifier key", err)
	}
	return witness.Key{Name: name, Pub: ed25519.PublicKey(raw[1:])}, signer
}

// signHead signs and publishes a head of the operator log of st at time
// at, with ingest generation ingest of the fixture's root as log key and
// the given witness signers, as the server and its witnesses would; the
// log is opened with pin.
func (f *fixture) signHead(t *testing.T, st *store.Store, pin *store.PlatformPin, ingest uint32, at time.Time, ws ...note.Signer) *translog.Head {
	t.Helper()
	l, err := OpenLog(st, pin)
	if err != nil {
		t.Fatal(err)
	}
	op := l.(translog.Operator)
	k, err := f.platform(t).IngestKey(ingest)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := translog.NewLogSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	h, err := op.SignHead(signer, at)
	if err != nil {
		t.Fatal(err)
	}
	text, err := h.Text()
	if err != nil {
		t.Fatal(err)
	}
	if h.Note, err = note.Sign(&note.Note{Text: string(text)}, append([]note.Signer{signer}, ws...)...); err != nil {
		t.Fatal(err)
	}
	if len(ws) < pin.MinWitnesses {
		// Below the quorum PublishHead refuses: written as a server
		// that does not check would write it.
		if err := store.WriteFileAtomic(filepath.Join(st.Root, filepath.FromSlash(translog.HeadPath(h.Size))), h.Note); err != nil {
			t.Fatal(err)
		}
		return h
	}
	if err := op.PublishHead(h); err != nil {
		t.Fatal(err)
	}
	return h
}

// published publishes the export of the fixture's Init into a new data
// directory and signs a head of size 2 at headAt, cosigned by every
// witness.
func (f *fixture) published(t *testing.T, name string) (*store.Store, *translog.Head) {
	t.Helper()
	st := newData(t, filepath.Join(f.base, name))
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	return st, f.signHead(t, st, f.res.Pin, 1, headAt, f.ws...)
}

// TestSucceedCompromised (D93 (4)): succeed with Compromised writes the
// pin of generation 2 with the identity list 1..2 and field 7 revoking
// identity 1 at the boundary, and identity-2.pub, but no succession; the
// boundary is required and checked before any share is asked; a regular
// succession later carries field 7 over.
func TestSucceedCompromised(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(f.base, "succ2")
	size, at := int64(2), headAt.UnixMilli()
	// Refused before any share is asked, nothing written.
	for _, c := range []struct {
		size, at int64
		want     []error
	}{
		{0, 0, []error{ErrCompromised, ErrRevocation}},
		{0, at, []error{ErrRevocation}},
		{-1, at, []error{ErrRevocation}},
		{translog.MaxTreeSize + 1, at, []error{ErrRevocation}},
		{size, 0, []error{ErrRevocation}},
		{size, -5, []error{ErrRevocation}},
		{size, testNow.Add(translog.MaxClockSkew + time.Millisecond).UnixMilli(), []error{ErrRevocation}},
	} {
		u, p := f.unlock(1, 2, 3)
		_, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out, Pin: f.res.Pin, Compromised: true, HeadSize: c.size, HeadTime: c.at})
		for _, w := range c.want {
			if !errors.Is(err, w) {
				t.Fatalf("%d/%d: %v, want %v", c.size, c.at, err, w)
			}
		}
		if len(p.asked) != 0 || len(p.handovers) != 0 {
			t.Fatalf("%d/%d: shares asked", c.size, c.at)
		}
		assertNothing(t, out, "")
	}
	// A boundary without Compromised.
	u, p := f.unlock(1, 2, 3)
	if _, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out, Pin: f.res.Pin, HeadSize: size, HeadTime: at}); !errors.Is(err, ErrOptions) || len(p.asked) != 0 {
		t.Fatalf("boundary without compromise: %v", err)
	}
	// The clock tolerance itself passes.
	u, _ = f.unlock(1, 2, 3)
	res, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out, Pin: f.res.Pin, Compromised: true,
		HeadSize: size, HeadTime: testNow.Add(translog.MaxClockSkew).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, out); fmt.Sprint(got) != "[identity-2.pin platform/identity-2.pub]" {
		t.Fatalf("export %v", got)
	}
	if !res.IdentityPub.Equal(identityOf(t, f.root[:], 2)) {
		t.Fatal("identity 2")
	}
	want := *f.res.Pin
	want.Gen, want.Pub = 2, res.IdentityPub
	want.Identities = append(append([]store.PlatformIdentity(nil), f.res.Pin.Identities...), store.PlatformIdentity{Gen: 2, Pub: res.IdentityPub})
	want.Revoked = []store.PlatformRevoked{{Role: store.KeyRoleIdentity, Gen: 1, AtSize: size, AtTime: testNow.Add(translog.MaxClockSkew).UnixMilli() + 1}}
	enc, err := want.Encode()
	if err != nil || !bytes.Equal(enc, mustReadFile(t, filepath.Join(out, "identity-2.pin"))) {
		t.Fatalf("pin 2 is not the encoding with field 7: %v", err)
	}
	pin2, err := ReadPin(filepath.Join(out, "identity-2.pin"))
	if err != nil || fmt.Sprint(pin2.Revoked) != fmt.Sprint(want.Revoked) {
		t.Fatalf("pin 2: %v %+v", err, pin2)
	}
	// Wrong shares: nothing written.
	u, p = f.unlock(1, 2)
	p.queue = append(p.queue, tamper(t, f.shares[3]))
	out2 := filepath.Join(f.base, "succ2b")
	if _, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out2, Pin: f.res.Pin, Compromised: true, HeadSize: size, HeadTime: at}); !errors.Is(err, ErrIdentity) {
		t.Fatalf("tampered share: %v", err)
	}
	assertNothing(t, out2, "")

	// A regular succession of generation 2 carries field 7 over; a second
	// compromise adds identity 2 after identity 1.
	u, _ = f.unlock(2, 4, 5)
	u.IdentityGen, u.IdentityPub = 2, res.IdentityPub
	res3, err := Succeed(SucceedOptions{UnlockOptions: u, Out: filepath.Join(f.base, "succ3"), Pin: pin2})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(res3.Pin.Revoked) != fmt.Sprint(want.Revoked) || len(res3.Pin.Identities) != 3 {
		t.Fatalf("field 7 not carried over: %+v", res3.Pin.Revoked)
	}
	if got := listDir(t, filepath.Join(f.base, "succ3")); fmt.Sprint(got) != "[identity-3.pin platform/identity-3.pub platform/identity-3.succ]" {
		t.Fatalf("export %v", got)
	}
	u, _ = f.unlock(1, 3, 5)
	u.IdentityGen, u.IdentityPub = 3, res3.IdentityPub
	res4, err := Succeed(SucceedOptions{UnlockOptions: u, Out: filepath.Join(f.base, "succ4"), Pin: res3.Pin, Compromised: true, HeadSize: 7, HeadTime: at})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(res4.Pin.Revoked); got != fmt.Sprintf("[{0 1 2 %d} {0 3 7 %d}]", testNow.Add(translog.MaxClockSkew).UnixMilli()+1, at+1) {
		t.Fatalf("field 7 of pin 4: %s", got)
	}
}

// TestRevoke (D93 (4)): revoke writes the pin of the same identity
// generation with one more element in field 7, in the canonical order;
// role, generation and boundary are checked and a generation revoked
// already is refused, all before any share is asked.
func TestRevoke(t *testing.T) {
	f := newFixture(t)
	at := headAt.UnixMilli()
	out := filepath.Join(f.base, "rev")
	u, p := f.unlock(4, 1, 2)
	res, err := Revoke(RevokeOptions{UnlockOptions: u, Out: out, Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 1, HeadSize: 2, HeadTime: at})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(p.asked) != "[0 0 0]" || len(p.handovers) != 0 || res.KeyDir != "" || !res.IdentityPub.Equal(f.res.IdentityPub) {
		t.Fatalf("asked %v", p.asked)
	}
	if got := listDir(t, out); fmt.Sprint(got) != "[identity-1.pin]" {
		t.Fatalf("export %v", got)
	}
	want := *f.res.Pin
	// revoked_at_time is the time of the head + 1 ms (D93 addendum).
	want.Revoked = []store.PlatformRevoked{{Role: store.KeyRoleIngest, Gen: 1, AtSize: 2, AtTime: at + 1}}
	enc, err := want.Encode()
	if err != nil || !bytes.Equal(enc, mustReadFile(t, filepath.Join(out, "identity-1.pin"))) {
		t.Fatalf("pin: %v", err)
	}
	// Admin 3 and admin 1 go before ingest 1, in order.
	u, _ = f.unlock(2, 3, 5)
	resA, err := Revoke(RevokeOptions{UnlockOptions: u, Out: filepath.Join(f.base, "revA"), Pin: res.Pin, Role: store.KeyRoleAdmin, Gen: 3, HeadSize: 9, HeadTime: at - 1})
	if err != nil {
		t.Fatal(err)
	}
	u, _ = f.unlock(2, 3, 5)
	resB, err := Revoke(RevokeOptions{UnlockOptions: u, Out: filepath.Join(f.base, "revB"), Pin: resA.Pin, Role: store.KeyRoleAdmin, Gen: 1, HeadSize: 1, HeadTime: minHeadTime})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(resB.Pin.Revoked); got != fmt.Sprintf("[{1 1 1 %d} {1 3 9 %d} {2 1 2 %d}]", minHeadTime+1, at, at+1) {
		t.Fatalf("field 7 %s", got)
	}
	// Refusals before any share is asked; nothing written.
	fresh := filepath.Join(f.base, "fresh")
	for _, c := range []struct {
		o    RevokeOptions
		want error
	}{
		{RevokeOptions{Pin: resB.Pin, Role: store.KeyRoleIngest, Gen: 1, HeadSize: 3, HeadTime: at}, ErrRevocation},
		{RevokeOptions{Pin: resB.Pin, Role: store.KeyRoleAdmin, Gen: 3, HeadSize: 9, HeadTime: at - 1}, ErrRevocation},
		{RevokeOptions{Pin: f.res.Pin, Role: store.KeyRoleIdentity, Gen: 1, HeadSize: 2, HeadTime: at}, ErrRevocation},
		{RevokeOptions{Pin: f.res.Pin, Role: 3, Gen: 1, HeadSize: 2, HeadTime: at}, ErrRevocation},
		{RevokeOptions{Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 0, HeadSize: 2, HeadTime: at}, ErrRevocation},
		{RevokeOptions{Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 1, HeadSize: 0, HeadTime: at}, ErrRevocation},
		{RevokeOptions{Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 1, HeadSize: 2, HeadTime: 0}, ErrRevocation},
		// A time in seconds (attack review 21c F2), and just below the
		// earliest head time.
		{RevokeOptions{Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 1, HeadSize: 2, HeadTime: at / 1000}, ErrRevocation},
		{RevokeOptions{Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 1, HeadSize: 2, HeadTime: minHeadTime - 1}, ErrRevocation},
		{RevokeOptions{Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 1, HeadSize: 2, HeadTime: testNow.Add(time.Hour).UnixMilli()}, ErrRevocation},
		{RevokeOptions{Role: store.KeyRoleIngest, Gen: 1, HeadSize: 2, HeadTime: at}, ErrOptions},
		{RevokeOptions{Pin: f.pin2(t), Role: store.KeyRoleIngest, Gen: 1, HeadSize: 2, HeadTime: at}, ErrIdentity},
		{RevokeOptions{Pin: f.res.Pin, Out: filepath.Join(f.base, "out"), Role: store.KeyRoleIngest, Gen: 1, HeadSize: 2, HeadTime: at}, ErrOutDir},
	} {
		u, p := f.unlock(1, 2, 3)
		c.o.UnlockOptions = u
		if c.o.Out == "" {
			c.o.Out = fresh
		}
		if _, err := Revoke(c.o); !errors.Is(err, c.want) {
			t.Fatalf("%+v: %v, want %v", c.o, err, c.want)
		}
		if len(p.asked) != 0 {
			t.Fatalf("%+v: shares asked", c.o)
		}
	}
	// A development pin, a forged identity list, shares of another root.
	dev := *f.res.Pin
	dev.Dev = true
	u, _ = f.unlock(1, 2, 3)
	if _, err := Revoke(RevokeOptions{UnlockOptions: u, Out: fresh, Pin: &dev, Role: store.KeyRoleIngest, Gen: 1, HeadSize: 2, HeadTime: at}); !errors.Is(err, ErrIdentity) {
		t.Fatalf("development pin: %v", err)
	}
	other := newFixture(t)
	u, _ = other.unlock(1, 2, 3)
	u.IdentityPub = f.res.IdentityPub
	if _, err := Revoke(RevokeOptions{UnlockOptions: u, Out: fresh, Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 1, HeadSize: 2, HeadTime: at}); !errors.Is(err, ErrIdentity) {
		t.Fatalf("other root: %v", err)
	}
	// The identity list of the pin must derive from the root as well.
	u, _ = f.unlock(1, 2, 3)
	u.IdentityGen, u.IdentityPub = 2, identityOf(t, f.root[:], 2)
	forged := f.pin2(t)
	forged.Identities[0].Pub = other.res.IdentityPub
	if _, err := Revoke(RevokeOptions{UnlockOptions: u, Out: fresh, Pin: forged, Role: store.KeyRoleIngest, Gen: 1, HeadSize: 2, HeadTime: at}); !errors.Is(err, ErrIdentity) {
		t.Fatalf("forged list: %v", err)
	}
	assertNothing(t, fresh, "")
	// Too many revoked generations.
	big := *f.res.Pin
	big.Revoked = nil
	for g := uint32(1); g <= store.MaxPinRevoked; g++ {
		big.Revoked = append(big.Revoked, store.PlatformRevoked{Role: store.KeyRoleIngest, Gen: g, AtSize: 1, AtTime: 1})
	}
	u, p = f.unlock(1, 2, 3)
	if _, err := Revoke(RevokeOptions{UnlockOptions: u, Out: fresh, Pin: &big, Role: store.KeyRoleAdmin, Gen: 1, HeadSize: 2, HeadTime: at}); !errors.Is(err, ErrRevocation) || len(p.asked) != 0 {
		t.Fatalf("too many: %v", err)
	}
	// RoleName.
	if RoleName(store.KeyRoleIdentity) != "identity" || RoleName(store.KeyRoleAdmin) != "admin" || RoleName(store.KeyRoleIngest) != "ingest" || RoleName(9) != "role-9" {
		t.Fatal("RoleName")
	}
}

// TestAdminRotate (D93 (3)): a new admin generation as IngestRotate makes
// an ingest generation.
func TestAdminRotate(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(f.base, "adm")
	kd := filepath.Join(f.base, "keys")
	u, p := f.unlock(3, 1, 5)
	validFrom := testNow.Add(24 * time.Hour)
	res, err := AdminRotate(RotateOptions{UnlockOptions: u, Out: out, KeyDir: kd, Gen: 2, ValidFrom: validFrom})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(p.asked) != "[0 0 0]" || res.Gen != 2 {
		t.Fatalf("asked %v", p.asked)
	}
	if got := listDir(t, out); fmt.Sprint(got) != "[platform/admin-2.cert platform/admin-2.pub]" {
		t.Fatalf("export %v", got)
	}
	cert, err := keys.DecodePlatformCert(mustReadFile(t, filepath.Join(out, "platform", "admin-2.cert")))
	if err != nil || cert.Verify(f.res.IdentityPub) != nil || cert.Role != keys.RoleAdmin || cert.Gen != 2 || cert.IdentityGen != 1 ||
		cert.ValidFrom != validFrom.UnixMilli() || !cert.Pub.Equal(res.Pub) {
		t.Fatalf("certificate: %v", err)
	}
	priv, gen, err := ReadKey(filepath.Join(kd, "admin-2.key"), store.KeyRoleAdmin)
	if err != nil || gen != 2 || !cert.Pub.Equal(priv.Public()) {
		t.Fatal("admin key")
	}
	if old, _, _ := ReadKey(filepath.Join(kd, "admin-1.key"), store.KeyRoleAdmin); old.Equal(priv) {
		t.Fatal("same key")
	}
	// Refusals before any share: generation 1, an existing key, a time in
	// the past, an unknown role (only through runRotate).
	fresh := filepath.Join(f.base, "fresh")
	u, p = f.unlock(1, 2, 3)
	if _, err := AdminRotate(RotateOptions{UnlockOptions: u, Out: fresh, KeyDir: kd, Gen: 1}); !errors.Is(err, keys.ErrGeneration) {
		t.Fatalf("generation 1: %v", err)
	}
	if _, err := AdminRotate(RotateOptions{UnlockOptions: u, Out: fresh, KeyDir: kd, Gen: 2}); !errors.Is(err, ErrKeyDir) {
		t.Fatalf("existing key: %v", err)
	}
	if _, err := AdminRotate(RotateOptions{UnlockOptions: u, Out: fresh, KeyDir: kd, Gen: 3, ValidFrom: testNow.Add(-time.Second)}); !errors.Is(err, ErrOptions) {
		t.Fatalf("past: %v", err)
	}
	if _, err := runRotate(RotateOptions{UnlockOptions: u, Out: fresh, KeyDir: kd, Gen: 3}, store.KeyRoleIdentity); !errors.Is(err, ErrOptions) {
		t.Fatalf("identity role: %v", err)
	}
	if len(p.asked) != 0 {
		t.Fatal("shares asked")
	}
	assertNothing(t, fresh, "")
	// Without ValidFrom: Now; published after admin-1.cert.
	u, _ = f.unlock(1, 2, 4)
	if _, err := AdminRotate(RotateOptions{UnlockOptions: u, Out: fresh, KeyDir: kd, Gen: 3}); err != nil {
		t.Fatal(err)
	}
	if c, _ := keys.DecodePlatformCert(mustReadFile(t, filepath.Join(fresh, "platform", "admin-3.cert"))); c.ValidFrom != testNow.UnixMilli() {
		t.Fatal("valid_from")
	}
	st := newData(t, filepath.Join(f.base, "data"))
	log := newLog(t)
	for _, from := range []string{filepath.Join(f.base, "out"), out, fresh} {
		if err := Publish(PublishOptions{From: from, Data: st, Log: log, Pin: f.res.Pin}); err != nil {
			t.Fatalf("publish %s: %v", from, err)
		}
	}
	if fmt.Sprint(log.names) != "[admin-1.cert ingest-1.cert admin-2.cert admin-3.cert]" {
		t.Fatalf("log %v", log.names)
	}
}

// TestPublishRevocations: publish with a pin that has field 7 checks it
// against the newest witness-confirmed head and data/platform/, refuses
// what a revocation makes invalid before anything is written, and takes
// what was logged before the boundary.
func TestPublishRevocations(t *testing.T) {
	f := newFixture(t)
	st, h := f.published(t, "data")
	if h.Size != 2 || h.Time != headAt.UnixMilli() {
		t.Fatalf("head %d %d", h.Size, h.Time)
	}
	at := h.Time
	revoke := func(pin *store.PlatformPin, out string, role uint8, gen uint32, size, at int64) *store.PlatformPin {
		t.Helper()
		u, _ := f.unlock(1, 2, 3)
		res, err := Revoke(RevokeOptions{UnlockOptions: u, Out: filepath.Join(f.base, out), Pin: pin, Role: role, Gen: gen, HeadSize: size, HeadTime: at})
		if err != nil {
			t.Fatal(err)
		}
		return res.Pin
	}
	// Ingest 1 revoked at the head (whose time is the boundary: the
	// operator log still opens the head signed by ingest 1 at that time).
	pinR := revoke(f.res.Pin, "rev", store.KeyRoleIngest, 1, h.Size, at)
	u, _ := f.unlock(1, 2, 3)
	rot := filepath.Join(f.base, "rot")
	// With the new pin: valid_from is revoked_at_time (the zero time).
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: rot, KeyDir: filepath.Join(f.base, "keys"), Gen: 2, Revoked: pinR.Revoked}); err != nil {
		t.Fatal(err)
	}
	var checked *translog.Head
	if err := Publish(PublishOptions{From: rot, Data: st, Pin: pinR, RevocationsChecked: func(h *translog.Head) { checked = h }}); err != nil {
		t.Fatal(err)
	}
	if checked == nil || checked.Size != 2 {
		t.Fatal("RevocationsChecked")
	}
	// The init export again: logged before the boundary, Append is
	// idempotent, nothing refused.
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: pinR}); err != nil {
		t.Fatalf("again: %v", err)
	}
	l, err := OpenLog(st, pinR)
	if err != nil {
		t.Fatal(err)
	}
	if es, _ := l.Lookup(translog.KindPlatform, []byte("ingest-2.cert")); len(es) != 1 {
		t.Fatal("ingest-2.cert not logged")
	}

	// Refused before anything is written: a boundary beyond the head (size
	// or time), a revoked generation that data/platform/ does not hold,
	// no head, a head without the witness quorum.
	adm := filepath.Join(f.base, "adm")
	u, _ = f.unlock(1, 2, 3)
	if _, err := AdminRotate(RotateOptions{UnlockOptions: u, Out: adm, KeyDir: filepath.Join(f.base, "keys"), Gen: 2}); err != nil {
		t.Fatal(err)
	}
	for i, pin := range []*store.PlatformPin{
		revoke(f.res.Pin, "r1", store.KeyRoleAdmin, 1, h.Size+1, at),
		revoke(f.res.Pin, "r2", store.KeyRoleAdmin, 1, h.Size, at+1),
		revoke(f.res.Pin, "r3", store.KeyRoleAdmin, 5, h.Size, at),
		revoke(f.res.Pin, "r4", store.KeyRoleIngest, 3, 1, at),
	} {
		before := listDir(t, st.Root)
		err := Publish(PublishOptions{From: adm, Data: st, Pin: pin})
		if !errors.Is(err, ErrRevocation) {
			t.Fatalf("pin %d: %v", i, err)
		}
		if after := listDir(t, st.Root); fmt.Sprint(after) != fmt.Sprint(before) {
			t.Fatalf("pin %d: written", i)
		}
	}
	stN := newData(t, filepath.Join(f.base, "noHead"))
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: stN, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	pinN := revoke(f.res.Pin, "rN", store.KeyRoleAdmin, 1, 2, headAt.UnixMilli())
	if err := Publish(PublishOptions{From: adm, Data: stN, Pin: pinN}); !errors.Is(err, ErrRevocation) || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("no head: %v", err)
	}
	f.signHead(t, stN, f.res.Pin, 1, headAt, f.ws[0]) // one of the two witness signatures
	if err := Publish(PublishOptions{From: adm, Data: stN, Pin: pinN}); !errors.Is(err, ErrRevocation) || !strings.Contains(err.Error(), "1 of the 2 witness signatures") {
		t.Fatalf("head without quorum: %v", err)
	}
	if _, err := stN.ReadPlatformFile("admin-2.cert"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("written")
	}

	// A pin that revokes an admin generation whose certificate is not a
	// valid entry of the log below the boundary (here: in data/platform/
	// only, a crash before its log entry) would lock the role for good:
	// refused before anything is written.
	stC, _ := f.published(t, "dataC")
	a2pub, a2 := f.cert(t, 1, keys.RoleAdmin, 2)
	if err := stC.WritePlatformFile("admin-2.cert", a2); err != nil {
		t.Fatal(err)
	}
	if err := stC.WritePlatformFile("admin-2.pub", a2pub); err != nil {
		t.Fatal(err)
	}
	pinA2 := revoke(f.res.Pin, "rA2", store.KeyRoleAdmin, 2, 2, at)
	exp := writeExport(t, filepath.Join(f.base, "expA2"), map[string][]byte{"admin-2.pub": a2pub, "admin-2.cert": a2})
	if err := Publish(PublishOptions{From: exp, Data: stC, Pin: pinA2}); !errors.Is(err, ErrRevocation) || !strings.Contains(err.Error(), "locks the role") {
		t.Fatalf("revoked admin generation without logged certificate: %v", err)
	}
	lC, err := OpenLog(stC, f.res.Pin)
	if err != nil {
		t.Fatal(err)
	}
	if es, _ := lC.Lookup(translog.KindPlatform, []byte("admin-2.cert")); len(es) != 0 {
		t.Fatal("admin-2.cert logged")
	}
	// Without the revocation it goes through; logged at index 2, the
	// boundary 2 does not cover it, 3 does.
	if err := Publish(PublishOptions{From: exp, Data: stC, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: exp, Data: stC, Pin: pinA2}); !errors.Is(err, ErrRevocation) {
		t.Fatalf("certificate at the boundary: %v", err)
	}
	f.signHead(t, stC, f.res.Pin, 1, headAt.Add(time.Second), f.ws...)
	if err := Publish(PublishOptions{From: exp, Data: stC, Pin: revoke(f.res.Pin, "rA3", store.KeyRoleAdmin, 2, 3, at)}); err != nil {
		t.Fatalf("certificate below the boundary: %v", err)
	}
	// A certificate the pin's revoked identity issues: translog.ErrRevoked
	// before anything is written (TestCompromiseChain for the rest).
}

// TestCompromiseChain: after succeed --compromised of identity 1 the
// export of generation 2 (identity-2.pub without succession), a new admin
// and a new ingest generation under identity 2 are published with pin 2;
// a forged succession of identity 1 is refused; a regular succession of
// generation 2 to 3 needs no identity-2.succ; field 7 stays in pin 3,
// and publish with it refuses what identity 1 issues.
func TestCompromiseChain(t *testing.T) {
	f := newFixture(t)
	st, h := f.published(t, "data")
	u, _ := f.unlock(1, 2, 3)
	out2 := filepath.Join(f.base, "succ2")
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out2, Pin: f.res.Pin, Compromised: true, HeadSize: h.Size, HeadTime: h.Time})
	if err != nil {
		t.Fatal(err)
	}
	// The old pin does not know generation 2.
	if err := Publish(PublishOptions{From: out2, Data: st, Pin: f.res.Pin}); !errors.Is(err, translog.ErrMismatch) {
		t.Fatalf("old pin: %v", err)
	}
	if err := Publish(PublishOptions{From: out2, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatalf("identity-2.pub without succession: %v", err)
	}
	kd := filepath.Join(f.base, "keys")
	u, _ = f.unlock(2, 3, 4)
	u.IdentityGen, u.IdentityPub = 2, res2.IdentityPub
	adm := filepath.Join(f.base, "adm")
	if _, err := AdminRotate(RotateOptions{UnlockOptions: u, Out: adm, KeyDir: kd, Gen: 2, ValidFrom: headAt.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	u, _ = f.unlock(2, 3, 4)
	u.IdentityGen, u.IdentityPub = 2, res2.IdentityPub
	rot := filepath.Join(f.base, "rot")
	// A successor of ingest 1 (certified by identity 1, revoked at the
	// boundary by the cascade) valid after the boundary: refused by
	// Publish (D93 addendum); valid from the boundary on (in the past is
	// allowed with pin 2): taken.
	late := filepath.Join(f.base, "late")
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: late, KeyDir: filepath.Join(f.base, "k3"), Gen: 2, ValidFrom: headAt.Add(time.Hour), Revoked: res2.Pin.Revoked}); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: late, Data: st, Pin: res2.Pin}); !errors.Is(err, ErrRevocation) || !strings.Contains(err.Error(), "no ingest generation would sign heads") {
		t.Fatalf("late successor: %v", err)
	}
	u, _ = f.unlock(2, 3, 4)
	u.IdentityGen, u.IdentityPub = 2, res2.IdentityPub
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: rot, KeyDir: kd, Gen: 2, ValidFrom: time.UnixMilli(h.Time - 1), Revoked: res2.Pin.Revoked}); !errors.Is(err, ErrOptions) {
		t.Fatalf("before the boundary: %v", err)
	}
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: rot, KeyDir: kd, Gen: 2, ValidFrom: time.UnixMilli(h.Time + 1), Revoked: res2.Pin.Revoked}); err != nil {
		t.Fatal(err)
	}
	for _, from := range []string{adm, rot} {
		if err := Publish(PublishOptions{From: from, Data: st, Pin: res2.Pin}); err != nil {
			t.Fatalf("publish %s: %v", from, err)
		}
	}
	// A succession to generation 2 signed with the stolen key of identity
	// 1 (it names the pin's key of generation 2): revoked.
	_, s2 := f.succ(t, 2)
	forged := writeExport(t, filepath.Join(f.base, "forged"), map[string][]byte{"identity-2.succ": s2})
	if err := Publish(PublishOptions{From: forged, Data: st, Pin: res2.Pin}); !errors.Is(err, translog.ErrRevoked) {
		t.Fatalf("forged succession: %v", err)
	}
	if _, err := st.ReadPlatformFile("identity-2.succ"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("forged succession written")
	}
	// A regular succession of generation 2 to 3, with pin 3.
	u, _ = f.unlock(5, 3, 1)
	u.IdentityGen, u.IdentityPub = 2, res2.IdentityPub
	out3 := filepath.Join(f.base, "succ3")
	res3, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out3, Pin: res2.Pin})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(res3.Pin.Revoked) != fmt.Sprint(res2.Pin.Revoked) {
		t.Fatal("field 7 not carried over")
	}
	if err := Publish(PublishOptions{From: out3, Data: st, Pin: res3.Pin}); err != nil {
		t.Fatalf("succession 2 to 3: %v", err)
	}
	names := logNames(t, st, res3.Pin)
	if fmt.Sprint(names) != "[admin-1.cert ingest-1.cert admin-2.cert ingest-2.cert identity-3.succ]" {
		t.Fatalf("log %v", names)
	}
	// Identity 1 issues nothing with pin 3 either.
	i3pub, i3 := f.cert(t, 1, keys.RoleIngest, 3)
	dir := writeExport(t, filepath.Join(f.base, "attack"), map[string][]byte{"ingest-3.pub": i3pub, "ingest-3.cert": i3})
	if err := Publish(PublishOptions{From: dir, Data: st, Pin: res3.Pin}); !errors.Is(err, translog.ErrRevoked) {
		t.Fatalf("issued by identity 1 with pin 3: %v", err)
	}
	// What identity 3 issues goes through.
	u, _ = f.unlock(2, 4, 5)
	u.IdentityGen, u.IdentityPub = 3, res3.IdentityPub
	rot3 := filepath.Join(f.base, "rot3")
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: rot3, KeyDir: kd, Gen: 3, ValidFrom: headAt.Add(2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: rot3, Data: st, Pin: res3.Pin}); err != nil {
		t.Fatalf("ingest 3 under identity 3: %v", err)
	}
}

// logNames returns the subjects of the entries of the operator log of
// st, in log order.
func logNames(t *testing.T, st *store.Store, pin *store.PlatformPin) []string {
	t.Helper()
	l, err := OpenLog(st, pin)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for i := int64(0); ; i++ {
		e, err := l.Entry(i)
		if errors.Is(err, translog.ErrNotInLog) {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, string(e.Key.Subject))
	}
}

// TestAddRevoked: the canonical order and the refusals of addRevoked.
func TestAddRevoked(t *testing.T) {
	var list []store.PlatformRevoked
	var err error
	for _, r := range []store.PlatformRevoked{{Role: 2, Gen: 3, AtSize: 1, AtTime: 1}, {Role: 0, Gen: 1, AtSize: 1, AtTime: 1}, {Role: 2, Gen: 1, AtSize: 1, AtTime: 1}, {Role: 1, Gen: 7, AtSize: 1, AtTime: 1}, {Role: 2, Gen: 9, AtSize: 1, AtTime: 1}} {
		if list, err = addRevoked(list, r); err != nil {
			t.Fatal(err)
		}
	}
	if got := fmt.Sprint(list); got != "[{0 1 1 1} {1 7 1 1} {2 1 1 1} {2 3 1 1} {2 9 1 1}]" {
		t.Fatal(got)
	}
	if err := store.CheckPinRevoked(list, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := addRevoked(list, store.PlatformRevoked{Role: 2, Gen: 3, AtSize: 5, AtTime: 5}); !errors.Is(err, ErrRevocation) {
		t.Fatal("duplicate")
	}
	// newPin refuses a list translog would refuse (an identity generation
	// not below the pin's).
	ids := []translog.Identity{{Gen: 1, Pub: make([]byte, 32)}}
	ws := []witness.Key{{Name: "w", Pub: make([]byte, 32)}}
	if _, _, err := newPin(&pinData{Identities: ids, Origin: "o", Witnesses: ws, MinWitnesses: 1,
		Revoked: []store.PlatformRevoked{{Role: store.KeyRoleIdentity, Gen: 1, AtSize: 1, AtTime: 1}}}); !errors.Is(err, ErrRevocation) {
		t.Fatalf("newPin: %v", err)
	}
}
