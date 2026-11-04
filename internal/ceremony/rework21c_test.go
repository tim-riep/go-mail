package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of the rework of task 21c after review.

// thiefCert returns a certificate for role/gen over a key the thief made
// himself, signed with the stolen identity key of generation idGen.
func (f *fixture) thiefCert(t *testing.T, idGen uint32, role keys.Role, gen uint32, validFrom time.Time) (pub, cert []byte) {
	t.Helper()
	id, err := f.platform(t).IdentityKey(idGen)
	if err != nil {
		t.Fatal(err)
	}
	kpub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := keys.NewPlatformCert(id, idGen, role, gen, kpub, validFrom.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	cd, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return kpub, cd
}

// TestPublishReissueAfterThief (attack review 21c F1): the thief logged
// ingest-2.cert (his own key, signed with the stolen identity 1) at an
// index the boundary of succeed --compromised makes invalid. The
// reissue under identity 2 with the same name (translog doc.go "Reading
// for the operator") goes through publish: the thief's files in
// data/platform/ are replaced, the reissued certificate is logged and
// valid, and the server signs with it. A detour to generation 3 is
// refused before any file is written; a valid entry is never replaced;
// a crash between the replaced public key and the replaced certificate
// is repaired by running publish again.
func TestPublishReissueAfterThief(t *testing.T) {
	f := newFixture(t)
	st, h := f.published(t, "data") // admin-1.cert @0, ingest-1.cert @1, head size 2
	tp, tc := f.thiefCert(t, 1, keys.RoleIngest, 2, headAt.Add(time.Hour))
	thief := writeExport(t, filepath.Join(f.base, "thief"), map[string][]byte{"ingest-2.cert": tc, "ingest-2.pub": tp})
	if err := Publish(PublishOptions{From: thief, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatalf("thief before the revocation: %v", err)
	}
	u, _ := f.unlock(1, 2, 3)
	out2 := filepath.Join(f.base, "succ2")
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out2, Pin: f.res.Pin, Compromised: true, HeadSize: h.Size, HeadTime: h.Time})
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: out2, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatalf("pin 2: %v", err)
	}
	lookup := func() []translog.Entry {
		t.Helper()
		l, err := OpenLog(st, res2.Pin)
		if err != nil {
			t.Fatal(err)
		}
		es, err := l.Lookup(translog.KindPlatform, []byte("ingest-2.cert"))
		if err != nil {
			t.Fatal(err)
		}
		return es
	}
	if es := lookup(); len(es) != 0 {
		t.Fatalf("thief's certificate valid under pin 2: %+v", es)
	}
	rotate := func(gen uint32, out, kd string) {
		t.Helper()
		u, _ := f.unlock(2, 3, 4)
		u.IdentityGen, u.IdentityPub = 2, res2.IdentityPub
		if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: out, KeyDir: kd, Gen: gen, ValidFrom: time.UnixMilli(h.Time + 1), Revoked: res2.Pin.Revoked}); err != nil {
			t.Fatal(err)
		}
	}

	// The detour to generation 3: its predecessor ingest-2.cert is no
	// valid entry of the log; refused before anything is written.
	rot3 := filepath.Join(f.base, "rot3")
	rotate(3, rot3, filepath.Join(f.base, "k3"))
	before := listDir(t, st.Path("platform"))
	err = Publish(PublishOptions{From: rot3, Data: st, Pin: res2.Pin})
	if !errors.Is(err, translog.ErrPrerequisite) || !strings.Contains(err.Error(), "ingest-3.cert needs ingest-2.cert, which is neither in the export nor a valid entry of the log") {
		t.Fatalf("generation 3 past the invalid generation 2: %v", err)
	}
	if after := listDir(t, st.Path("platform")); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("written: %v", after)
	}

	// The reissue under the same name; a crash after the public key was
	// replaced, before the certificate: publish again repairs it.
	rot := filepath.Join(f.base, "rot2")
	rotate(2, rot, filepath.Join(f.base, "k2"))
	defer func() { crashHook = nil }()
	crashHook = func(point string) error {
		if point == "publish-file" {
			crashHook = nil
			return errors.New("crash")
		}
		return nil
	}
	if err := Publish(PublishOptions{From: rot, Data: st, Pin: res2.Pin}); err == nil || err.Error() != "crash" {
		t.Fatalf("crash: %v", err)
	}
	newPub := mustReadFile(t, filepath.Join(rot, "platform", "ingest-2.pub"))
	newCert := mustReadFile(t, filepath.Join(rot, "platform", "ingest-2.cert"))
	if !bytes.Equal(mustReadFile(t, st.Path("platform", "ingest-2.pub")), newPub) || !bytes.Equal(mustReadFile(t, st.Path("platform", "ingest-2.cert")), tc) {
		t.Fatal("public key first")
	}
	if err := Publish(PublishOptions{From: rot, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatalf("reissue under the same name: %v", err)
	}
	if !bytes.Equal(mustReadFile(t, st.Path("platform", "ingest-2.cert")), newCert) || !bytes.Equal(mustReadFile(t, st.Path("platform", "ingest-2.pub")), newPub) {
		t.Fatal("not replaced")
	}
	if es := lookup(); len(es) != 1 || !bytes.Equal(es[0].Content, newCert) {
		t.Fatalf("reissued certificate not valid: %+v", es)
	}
	if fmt.Sprint(listDir(t, st.Path("platform"))) != fmt.Sprint(before) {
		t.Fatalf("files: %v", listDir(t, st.Path("platform")))
	}
	// Idempotent.
	if err := Publish(PublishOptions{From: rot, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatalf("again: %v", err)
	}
	// The server signs with the reissued generation (alert for the
	// thief's entry, translog TestRevokedThiefHeadRecovery).
	l, err := OpenLog(st, res2.Pin)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := f.platform(t).IngestKey(2)
	signer, err := translog.NewLogSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	var inv *translog.InvalidEntriesError
	if hs, err := l.(translog.Operator).SignHead(signer, headAt.Add(2*time.Minute)); hs == nil || !errors.As(err, &inv) {
		t.Fatalf("SignHead with the reissued generation: %v", err)
	}
	// Generation 3 now has its predecessor.
	if err := Publish(PublishOptions{From: rot3, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatalf("generation 3 after the reissue: %v", err)
	}

	// A valid entry is never replaced: another certificate of the same
	// name (identity 2, other valid_from) is refused, naming both files.
	id2, _ := f.platform(t).IdentityKey(2)
	c, err := keys.NewPlatformCert(id2, 2, keys.RoleIngest, 2, ed25519.PublicKey(newPub), h.Time)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := c.Encode()
	otherExp := writeExport(t, filepath.Join(f.base, "other"), map[string][]byte{"ingest-2.cert": other, "ingest-2.pub": newPub})
	before = listDir(t, st.Path("platform"))
	err = Publish(PublishOptions{From: otherExp, Data: st, Pin: res2.Pin})
	if !errors.Is(err, store.ErrExists) || !errors.Is(err, translog.ErrDuplicate) || !strings.Contains(err.Error(), st.Path("platform", "ingest-2.cert")) ||
		!strings.Contains(err.Error(), filepath.Join(otherExp, "platform", "ingest-2.cert")) || !strings.Contains(err.Error(), "valid entry of the log") {
		t.Fatalf("other certificate over a valid entry: %v", err)
	}
	if !bytes.Equal(mustReadFile(t, st.Path("platform", "ingest-2.cert")), newCert) || fmt.Sprint(listDir(t, st.Path("platform"))) != fmt.Sprint(before) {
		t.Fatal("replaced")
	}
	// Nor under the old pin, where the thief's certificate is the valid
	// entry: the honest certificate of the same name is refused.
	st2, _ := f.published(t, "data2")
	if err := Publish(PublishOptions{From: thief, Data: st2, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	hp, hc := f.cert(t, 1, keys.RoleIngest, 2)
	honest := writeExport(t, filepath.Join(f.base, "honest"), map[string][]byte{"ingest-2.cert": hc, "ingest-2.pub": hp})
	err = Publish(PublishOptions{From: honest, Data: st2, Pin: f.res.Pin})
	if !errors.Is(err, translog.ErrDuplicate) || !strings.Contains(err.Error(), "valid entry of the log") {
		t.Fatalf("the thief's certificate is valid under this pin: %v", err)
	}
	if !bytes.Equal(mustReadFile(t, st2.Path("platform", "ingest-2.cert")), tc) {
		t.Fatal("replaced")
	}
}

// TestPublishRevokedHead (attack review 21c F3): publish reports a
// newest head that the log key of a generation revoked at its time
// signed (here: the head of the boundary signed again later by ingest 1,
// whose identity the pin revokes), and none for the confirmed head
// itself.
func TestPublishRevokedHead(t *testing.T) {
	f := newFixture(t)
	st, h := f.published(t, "data")
	u, _ := f.unlock(1, 2, 3)
	out2 := filepath.Join(f.base, "succ2")
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out2, Pin: f.res.Pin, Compromised: true, HeadSize: h.Size, HeadTime: h.Time})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	report := func(hh *translog.Head, gen uint32, at int64) {
		got = append(got, fmt.Sprint(hh.Size, hh.Time, gen, at))
	}
	if err := Publish(PublishOptions{From: out2, Data: st, Pin: res2.Pin, RevokedHead: report}); err != nil || len(got) != 0 {
		t.Fatalf("confirmed head: %v %v", err, got)
	}
	h2 := f.signHead(t, st, f.res.Pin, 1, headAt.Add(time.Minute), f.ws...)
	if h2.Size != h.Size {
		t.Fatalf("size %d", h2.Size)
	}
	if err := Publish(PublishOptions{From: out2, Data: st, Pin: res2.Pin, RevokedHead: report}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprintf("[%d %d 1 %d]", h.Size, h2.Time, h.Time+1) {
		t.Fatalf("reported %v", got)
	}
	// A test's log is not looked at.
	got = nil
	if err := Publish(PublishOptions{From: writeExport(t, filepath.Join(f.base, "e"), nil), Data: st, Pin: res2.Pin, RevokedHead: report, Log: revokedHeadLog{mustOpenLog(t, st, res2.Pin)}}); err != nil || len(got) != 0 {
		t.Fatalf("plain log: %v %v", err, got)
	}
}

// revokedHeadLog hides the Operator methods of a log.
type revokedHeadLog struct{ translog.Log }

func mustOpenLog(t *testing.T, st *store.Store, pin *store.PlatformPin) translog.Log {
	t.Helper()
	l, err := OpenLog(st, pin)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestRevocationTimes (attack review 21c F2): a revocation time in
// seconds is refused by the ceremony (checkBoundary, TestRevoke) and by
// publish for every element of field 7; an ingest element whose
// revoked_at_time is not after valid_from of the generation's
// certificate is refused when the generation was valid at the newest
// head, and taken when it was not valid yet (revoked before it acts);
// for an admin element only the lower bound applies (task 22 point 2).
func TestRevocationTimes(t *testing.T) {
	f := newFixture(t)
	st, h := f.published(t, "data")
	// The scenario of the review: ingest 2 rotated and in use, ingest 1
	// revoked with the time typed in seconds.
	kd := filepath.Join(f.base, "k")
	u, _ := f.unlock(1, 2, 3)
	rot := filepath.Join(f.base, "rot")
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: rot, KeyDir: kd, Gen: 2, ValidFrom: headAt.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: rot, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	h3 := f.signHead(t, st, f.res.Pin, 2, headAt.Add(2*time.Minute), f.ws...)
	u, p := f.unlock(1, 2, 3)
	if _, err := Revoke(RevokeOptions{UnlockOptions: u, Out: filepath.Join(f.base, "rv"), Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 1, HeadSize: h3.Size, HeadTime: h.Time / 1000}); !errors.Is(err, ErrRevocation) ||
		!strings.Contains(err.Error(), "not in seconds") || len(p.asked) != 0 {
		t.Fatalf("seconds: %v", err)
	}
	empty := writeExport(t, filepath.Join(f.base, "e"), nil)
	with := func(r ...store.PlatformRevoked) *store.PlatformPin {
		pin := *f.res.Pin
		pin.Revoked = r
		return &pin
	}
	for i, c := range []struct {
		pin  *store.PlatformPin
		want string
	}{
		// Pins not made by this ceremony: a time in seconds.
		{with(store.PlatformRevoked{Role: store.KeyRoleIngest, Gen: 1, AtSize: h3.Size, AtTime: h.Time/1000 + 1}), "seconds instead of milliseconds"},
		{with(store.PlatformRevoked{Role: store.KeyRoleAdmin, Gen: 1, AtSize: h3.Size, AtTime: minHeadTime}), "seconds instead of milliseconds"},
		// valid_from of ingest-1.cert is testNow, valid at the head.
		{with(store.PlatformRevoked{Role: store.KeyRoleIngest, Gen: 1, AtSize: h3.Size, AtTime: testNow.UnixMilli()}), "would never have been valid"},
	} {
		before := listDir(t, st.Root)
		err := Publish(PublishOptions{From: empty, Data: st, Pin: c.pin})
		if !errors.Is(err, ErrRevocation) || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%d: %v", i, err)
		}
		if fmt.Sprint(listDir(t, st.Root)) != fmt.Sprint(before) {
			t.Fatalf("%d: written", i)
		}
	}
	// An admin element: revoked_at_time has no meaning for it (D93 (2)),
	// only the lower bound applies (spec review of 21c, task 22 point 2):
	// a boundary of a head older than the admin generation (valid at the
	// newest head) is taken, as a repair with an older head needs it.
	adm1 := mustReadFile(t, st.Path("platform", "admin-1.cert"))
	if c, err := keys.DecodePlatformCert(adm1); err != nil || c.ValidFrom <= minHeadTime || c.ValidFrom > h3.Time {
		t.Fatalf("admin-1.cert: %v", err)
	}
	if err := Publish(PublishOptions{From: empty, Data: st, Pin: with(store.PlatformRevoked{Role: store.KeyRoleAdmin, Gen: 1, AtSize: h3.Size, AtTime: minHeadTime + 1})}); err != nil {
		t.Fatalf("admin before valid_from: %v", err)
	}
	// One millisecond after valid_from: taken.
	if err := Publish(PublishOptions{From: empty, Data: st, Pin: with(store.PlatformRevoked{Role: store.KeyRoleIngest, Gen: 1, AtSize: h3.Size, AtTime: testNow.UnixMilli() + 1})}); err != nil {
		t.Fatalf("after valid_from: %v", err)
	}
	// A generation not valid yet at the newest head (admin 2 valid from
	// an hour after it) is revoked before it acts.
	adm := filepath.Join(f.base, "adm")
	u, _ = f.unlock(1, 2, 3)
	if _, err := AdminRotate(RotateOptions{UnlockOptions: u, Out: adm, KeyDir: filepath.Join(f.base, "ka"), Gen: 2, ValidFrom: headAt.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: adm, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	h4 := f.signHead(t, st, f.res.Pin, 2, headAt.Add(3*time.Minute), f.ws...)
	u, _ = f.unlock(1, 2, 3)
	r, err := Revoke(RevokeOptions{UnlockOptions: u, Out: filepath.Join(f.base, "rvA"), Pin: f.res.Pin, Role: store.KeyRoleAdmin, Gen: 2, HeadSize: h4.Size, HeadTime: h4.Time})
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: empty, Data: st, Pin: r.Pin}); err != nil {
		t.Fatalf("admin 2 revoked before its valid_from: %v", err)
	}
}

// TestRotateBothRevoked (spec review 21c Low-2): with a pin that revokes
// the predecessor ingest generation and the identity generation before
// the current one, the earlier time applies when that identity
// certified the predecessor, else the predecessor's own; with the
// identity's time earlier the ceremony takes exactly one of the two,
// given explicitly, and refuses anything else naming both (before any
// share is asked); with the identity's time not earlier the own one,
// as for the predecessor alone.
func TestRotateBothRevoked(t *testing.T) {
	f := newFixture(t)
	A := testNow.Add(-2 * time.Hour).UnixMilli() // identity 1
	B := testNow.Add(-time.Hour).UnixMilli()     // ingest 2
	both := []store.PlatformRevoked{
		{Role: store.KeyRoleIdentity, Gen: 1, AtSize: 2, AtTime: A},
		{Role: store.KeyRoleIngest, Gen: 2, AtSize: 3, AtTime: B},
	}
	kd := filepath.Join(f.base, "keys")
	fresh := filepath.Join(f.base, "fresh")
	run := func(rev []store.PlatformRevoked, valid time.Time, out string) error {
		u, p := f.unlock(1, 2, 3)
		u.IdentityGen, u.IdentityPub = 2, identityOf(t, f.root[:], 2)
		_, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: out, KeyDir: filepath.Join(kd, filepath.Base(out)), Gen: 3, ValidFrom: valid, Revoked: rev})
		if err != nil && len(p.asked) != 0 {
			t.Fatalf("shares asked: %v", err)
		}
		return err
	}
	for i, v := range []time.Time{{}, time.UnixMilli(A - 1), time.UnixMilli(A + 1), time.UnixMilli(B + 1), testNow.Add(time.Hour)} {
		err := run(both, v, fresh)
		if !errors.Is(err, ErrRevocation) || !strings.Contains(err.Error(), rfc3339(A)) || !strings.Contains(err.Error(), rfc3339(B)) {
			t.Fatalf("%d %v: %v", i, v, err)
		}
	}
	assertNothing(t, fresh, "")
	for i, v := range []int64{A, B} {
		out := filepath.Join(f.base, fmt.Sprint("both", i))
		if err := run(both, time.UnixMilli(v), out); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		c, err := keys.DecodePlatformCert(mustReadFile(t, filepath.Join(out, "platform", "ingest-3.cert")))
		if err != nil || c.ValidFrom != v {
			t.Fatalf("%d: valid_from %v", i, err)
		}
	}
	// The identity's time not earlier: the own one, the zero time means it.
	later := []store.PlatformRevoked{
		{Role: store.KeyRoleIdentity, Gen: 1, AtSize: 2, AtTime: B + 5},
		{Role: store.KeyRoleIngest, Gen: 2, AtSize: 3, AtTime: B},
	}
	if err := run(later, time.UnixMilli(B+5), fresh); !errors.Is(err, ErrRevocation) {
		t.Fatalf("identity time: %v", err)
	}
	out := filepath.Join(f.base, "later")
	if err := run(later, time.Time{}, out); err != nil {
		t.Fatal(err)
	}
	if c, err := keys.DecodePlatformCert(mustReadFile(t, filepath.Join(out, "platform", "ingest-3.cert"))); err != nil || c.ValidFrom != B {
		t.Fatalf("valid_from %v", err)
	}
}
