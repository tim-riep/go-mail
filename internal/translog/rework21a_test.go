package translog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of the rework of task 21a after review: the cascade from a
// revoked identity generation to the admin and ingest generations it
// certified (D93 addendum), the recovery from heads that do not belong
// to the log under the new pin (ErrRevokedHead, RepairTree), and the
// scenarios of the reviews as regular tests.

// certFor returns <role>-<gen>.cert for pub, issued by identity idGen
// of p.
func certFor(t testing.TB, p *tplat, role keys.Role, gen, idGen uint32, pub ed25519.PublicKey, validFrom int64) []byte {
	t.Helper()
	c, err := keys.NewPlatformCert(p.identity(t, idGen), idGen, role, gen, pub, validFrom)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// addrSigned returns an address assignment of adminGen signed with priv.
func addrSigned(t testing.TB, priv ed25519.PrivateKey, a string, mbx store.ID, validFrom int64, adminGen uint32) []byte {
	t.Helper()
	as := &store.AddressAssignment{Address: a, MailboxID: mbx, ValidFrom: validFrom, AdminGen: adminGen}
	if err := as.Sign(priv); err != nil {
		t.Fatal(err)
	}
	b, err := as.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeRaw appends data as the next entry past Append (as someone with
// write access to log/ would).
func writeRaw(t *testing.T, e *tenv, kind Kind, data []byte) int64 {
	t.Helper()
	en, err := NewEntry(kind, data)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := en.Encode()
	if err != nil {
		t.Fatal(err)
	}
	n := e.tree().Size
	if _, err := (&fileLog{f: &files{root: e.st.Root}}).write(e.tree(), en.Key, enc); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestRevokedCertQueries: RevokedCertAtIndex and RevokedCertAtTime
// answer for the generation's own element and for that of its issuing
// identity generation, with the boundaries N-1/N and T-1/T; revokedSince
// takes the earlier time.
func TestRevokedCertQueries(t *testing.T) {
	list := []Revoked{
		{Role: roleID, Gen: 1, AtSize: 100, AtTime: t0},
		{Role: roleIngest, Gen: 3, AtSize: 50, AtTime: t0 - hour},
		{Role: roleIngest, Gen: 4, AtSize: 50, AtTime: t0 + hour},
	}
	for _, role := range []uint8{roleAdmin, roleIngest} {
		if RevokedCertAtIndex(list, role, 7, 1, 99) || !RevokedCertAtIndex(list, role, 7, 1, 100) || RevokedCertAtIndex(list, role, 7, 2, 1<<40) {
			t.Fatalf("role %d: index boundary of the issuer", role)
		}
		if RevokedCertAtTime(list, role, 7, 1, t0-1) || !RevokedCertAtTime(list, role, 7, 1, t0) || RevokedCertAtTime(list, role, 7, 2, 1<<62) {
			t.Fatalf("role %d: time boundary of the issuer", role)
		}
	}
	if RevokedCertAtIndex(list, roleIngest, 3, 2, 49) || !RevokedCertAtIndex(list, roleIngest, 3, 2, 50) {
		t.Fatal("own index boundary")
	}
	if RevokedCertAtTime(list, roleIngest, 3, 2, t0-hour-1) || !RevokedCertAtTime(list, roleIngest, 3, 2, t0-hour) {
		t.Fatal("own time boundary")
	}
	for _, c := range []struct {
		gen, issuer uint32
		ok          bool
		at          int64
	}{
		{3, 1, true, t0 - hour}, // own element earlier
		{4, 1, true, t0},        // issuer earlier
		{4, 2, true, t0 + hour}, // own only
		{5, 1, true, t0},        // issuer only
		{5, 2, false, 0},
	} {
		if ok, at := revokedSince(list, roleIngest, c.gen, c.issuer); ok != c.ok || at != c.at {
			t.Errorf("revokedSince(%d, %d) = %v %d", c.gen, c.issuer, ok, at)
		}
	}
	v := &Verifier{Revoked: list}
	if !v.RevokedCertAtTime(roleIngest, 5, 1, t0) || v.RevokedCertAtTime(roleIngest, 5, 1, t0-1) {
		t.Fatal("Verifier.RevokedCertAtTime")
	}
	// Without LogKeys the Verifier knows no issuer: only the own element.
	if v.RevokedAtTime(roleIngest, 5, t0) || !v.RevokedAtTime(roleIngest, 4, t0+hour) {
		t.Fatal("Verifier.RevokedAtTime without LogKeys")
	}
	// With a logged key of generation 5 issued by identity 1 it knows.
	v.LogKeys = []LogKey{{Gen: 5, IdentityGen: 1, Logged: true}, {Gen: 6, IdentityGen: 1}}
	if !v.RevokedAtTime(roleIngest, 5, t0) || v.RevokedAtTime(roleIngest, 5, t0-1) || v.RevokedAtTime(roleAdmin, 5, t0) {
		t.Fatal("Verifier.RevokedAtTime with LogKeys")
	}
	if v.RevokedAtTime(roleIngest, 6, t0) {
		t.Fatal("an unlogged key decides nothing")
	}
}

// TestRevokedCascadeHeads: revoking identity 1 at time T ends ingest 1,
// which it certified, for heads from T on (time T-1 valid, T not), for
// SignHead, PublishHead, the client's Refresh and CheckHead and the
// metadata query; a head at T written past PublishHead is ErrRevokedHead
// for the server until the repair moves it aside; ingest 2, reissued
// under identity 2, takes over at T.
func TestRevokedCascadeHeads(t *testing.T) {
	e := newEnv(t, 1, 1)
	T := t0 + hour
	e.idGen = 2
	e.rev = []Revoked{{Role: roleID, Gen: 1, AtSize: e.tree().Size, AtTime: T}}
	srv := e.openServer()
	g1 := e.logSigner(1)
	h, err := srv.SignHead(g1, time.UnixMilli(T-1))
	if err != nil {
		t.Fatalf("time T-1: %v", err)
	}
	if _, err := srv.SignHead(g1, time.UnixMilli(T)); !errors.Is(err, ErrHead) {
		t.Fatalf("time T: %v", err)
	}
	if err := srv.PublishHead(e.cosigned(h, e.ws...)); err != nil {
		t.Fatal(err)
	}
	e.now = time.UnixMilli(T - 1)
	cl, v := e.client()
	if _, err := cl.Refresh(e.now); err != nil {
		t.Fatalf("client, time T-1: %v", err)
	}
	if len(v.LogKeys) != 1 || !v.LogKeys[0].Revoked || v.LogKeys[0].RevokedAt != T || v.LogKeys[0].IdentityGen != 1 {
		t.Fatalf("log keys %+v", v.LogKeys)
	}
	if v.RevokedAtTime(roleIngest, 1, T-1) || !v.RevokedAtTime(roleIngest, 1, T) ||
		v.RevokedCertAtTime(roleIngest, 1, 1, T-1) || !v.RevokedCertAtTime(roleIngest, 1, 1, T) {
		t.Fatal("metadata query")
	}
	if keys, err := srv.LogKeys(); err != nil || len(keys) != 1 || !keys[0].Revoked || keys[0].RevokedAt != T || keys[0].IdentityGen != 1 {
		t.Fatalf("operator log keys %+v %v", keys, err)
	}
	// A head at T: refused by PublishHead and the client.
	e.now = time.UnixMilli(T)
	hT := e.headOf(T)
	if err := srv.PublishHead(e.cosigned(hT, e.ws...)); !errors.Is(err, ErrHead) {
		t.Fatalf("PublishHead at T: %v", err)
	}
	// CheckHead checks the issuer's revocation also for a LogKey built
	// without Revoked.
	vc := e.verifier()
	k := v.LogKeys[0]
	k.Revoked, k.RevokedAt = false, 0
	vc.LogKeys = []LogKey{k}
	for _, c := range []struct {
		at   int64
		want bool
	}{{T - 1, true}, {T, false}} {
		hn := e.headOf(c.at)
		hn.Note = sign(t, hn, e.all()...)
		vc.Last = nil
		if err := vc.CheckHead(hn, nil); (err == nil) != c.want || err != nil && !errors.Is(err, ErrHead) {
			t.Fatalf("CheckHead at %d: %v", c.at-T, err)
		}
	}
	// Written past PublishHead: the client refuses it, the server names
	// it until the repair.
	e.publish(hT, e.all()...)
	if _, err := cl.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("client, time T: %v", err)
	}
	cert2 := e.p.cert(t, keys.RoleIngest, 2, 2, T)
	if err := e.st.WritePlatformFile("ingest-2.cert", cert2); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Append(KindPlatform, cert2); err != nil {
		t.Fatal(err)
	}
	e.signer = e.logSigner(2)
	if _, err := srv.SignHead(e.signer, e.now); !errors.Is(err, ErrRevokedHead) {
		t.Fatalf("SignHead over the head at T: %v", err)
	}
	hp := e.headOf(T)
	if err := srv.PublishHead(e.cosigned(hp, e.ws...)); !errors.Is(err, ErrRevokedHead) {
		t.Fatalf("PublishHead over the head at T: %v", err)
	}
	if err := RepairTree(e.serverOptions()); err != nil {
		t.Fatal(err)
	}
	h2, err := srv.SignHead(e.signer, e.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.PublishHead(e.cosigned(h2, e.ws...)); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Refresh(e.now); err != nil {
		t.Fatalf("client after the reissue: %v", err)
	}
	if v.RevokedAtTime(roleIngest, 2, T) || !v.RevokedAtTime(roleIngest, 1, T) {
		t.Fatal("metadata query after the reissue")
	}
}

// TestRevokedForeignAdminBeforeBoundary (attack review F1): the thief
// logs admin-2.cert with his own key, issued by the stolen identity 1,
// before the confirmed head. The new pin revokes identity 1 at N; the
// thief's admin 2 can no longer assign at or after N, also not backdated
// below the honest successor's valid_from: Append refuses, the audit
// marks it "revoked", CheckAddress keeps the old owner. Its certificate
// and what it logged before N stay valid.
func TestRevokedForeignAdminBeforeBoundary(t *testing.T) {
	e := newEnv(t, 1, 1)
	thiefAdmin := newPlat(t).admin(t, 2)
	mOld, mEvil := newMbx(t), newMbx(t)
	// Before the valid_from of the thief's admin-2.cert: not superseded
	// (TestAdminSupersessionBackdatedCert).
	e.mustAppend(KindAddress, e.addr(t, "victim@example.org", mOld, t0-hour, 1))
	fc := certFor(t, e.p, keys.RoleAdmin, 2, 1, thiefAdmin.Public().(ed25519.PublicKey), t0)
	e.mustAppend(KindPlatform, fc)
	before := e.mustAppend(KindAddress, addrSigned(t, thiefAdmin, "early@example.org", mEvil, t0, 2))
	h := e.head()
	N := h.Size
	S := t0 + hour
	e.idGen = 2
	e.rev = []Revoked{{Role: roleID, Gen: 1, AtSize: N, AtTime: h.Time}}
	srv := e.openServer()
	e.op = srv
	e.mustAppend(KindPlatform, e.p.cert(t, keys.RoleAdmin, 3, 2, S))
	evil := addrSigned(t, thiefAdmin, "victim@example.org", mEvil, S-1, 2)
	if _, err := srv.Append(KindAddress, evil); !errors.Is(err, ErrRevoked) || !errors.Is(err, ErrOrder) {
		t.Fatalf("thief's assignment at N: %v", err)
	}
	if err := srv.CheckAddress("victim@example.org", mOld, S+day); err != nil {
		t.Fatalf("victim: %v", err)
	}
	// Written past Append: invalid for the server and every client.
	i := writeRaw(t, e, KindAddress, evil)
	if err := srv.CheckAddress("victim@example.org", mOld, S+day); err != nil {
		t.Fatalf("victim after the raw entry: %v", err)
	}
	if err := srv.CheckPlatform("admin-2.cert", fc); err != nil {
		t.Fatalf("the certificate logged before N: %v", err)
	}
	if err := srv.CheckAddress("early@example.org", mEvil, t0); err != nil {
		t.Fatalf("assignment at %d before N: %v", before, err)
	}
	e.signer = e.logSigner(2)
	if err := e.st.WritePlatformFile("ingest-2.cert", e.p.cert(t, keys.RoleIngest, 2, 2, h.Time+1)); err != nil {
		t.Fatal(err)
	}
	// Ingest 1, certified by identity 1, signs nothing from T on: the
	// confirmed head (time T) no longer belongs to the log and the
	// repair moves it aside; ingest 2 under identity 2 takes over.
	data, _ := e.st.ReadPlatformFile("ingest-2.cert")
	if _, err := srv.Append(KindPlatform, data); err != nil {
		t.Fatal(err)
	}
	if err := RepairTree(e.serverOptions()); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Minute)
	hs, err := srv.SignHead(e.signer, e.now)
	var inv *InvalidEntriesError
	if !errors.As(err, &inv) || len(inv.Entries) != 1 || inv.Entries[0] != (InvalidEntry{Index: i, Class: "revoked"}) {
		t.Fatalf("SignHead: %v", err)
	}
	if err := srv.PublishHead(e.cosigned(hs, e.ws...)); err != nil {
		t.Fatal(err)
	}
	cl, _ := e.client()
	if _, err := cl.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if got := cl.Invalid(); len(got) != 1 || got[0] != (InvalidEntry{Index: i, Class: "revoked"}) {
		t.Fatalf("client audit %v", got)
	}
	if err := cl.CheckAddress("victim@example.org", mOld, S+day); err != nil {
		t.Fatalf("client: victim: %v", err)
	}
}

// TestRevokedThiefHeadRecovery (spec review M1): the thief logs
// ingest-2.cert with his own key, issued by the stolen identity 1 at
// index N, and publishes a head signed by it. Under the new pin the
// certificate is invalid; SignHead and PublishHead name the head
// (ErrRevokedHead), the client refuses it, RepairTree moves it to
// heads-revoked/ byte for byte, and the server signs and publishes
// again with ingest 2 reissued under identity 2 under the same name.
// The repair depends on the pin's field 7 (spec review L1): the key file
// of ingest-2.cert names the reissue, not the thief's entry.
func TestRevokedThiefHeadRecovery(t *testing.T) {
	e := newEnv(t, 1, 1)
	h := e.head()
	N := h.Size
	thiefKey := newPlat(t).ingest(t, 2)
	thief := certFor(t, e.p, keys.RoleIngest, 2, 1, thiefKey.Public().(ed25519.PublicKey), t0+1)
	if err := e.st.WritePlatformFile("ingest-2.cert", thief); err != nil {
		t.Fatal(err)
	}
	if i := e.mustAppend(KindPlatform, thief); i != N {
		t.Fatalf("thief at %d", i)
	}
	e.now = time.UnixMilli(t0 + hour)
	old := e.openServer()
	ts, err := NewLogSigner(thiefKey)
	if err != nil {
		t.Fatal(err)
	}
	e.signer = ts
	th, err := old.SignHead(ts, e.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.PublishHead(e.cosigned(th, e.ws...)); err != nil {
		t.Fatal(err)
	}
	thiefFile, err := os.ReadFile(e.path(HeadPath(th.Size)))
	if err != nil {
		t.Fatal(err)
	}

	// The new pin revokes identity 1 at N; revoked_at_time one
	// millisecond after the confirmed head keeps that head valid
	// (TestRevokedCompromise takes the head's own time).
	T := h.Time + 1
	e.idGen = 2
	e.rev = []Revoked{{Role: roleID, Gen: 1, AtSize: N, AtTime: T}}
	srv := e.openServer()
	e.now = e.now.Add(time.Minute)
	name := strings.TrimPrefix(HeadPath(th.Size), Dir+"/")
	if _, err := srv.SignHead(e.logSigner(1), e.now); !errors.Is(err, ErrRevokedHead) || !errors.Is(err, ErrConsistency) ||
		!strings.Contains(err.Error(), name) {
		t.Fatalf("SignHead: %v", err)
	}
	if err := srv.PublishHead(e.cosigned(th, e.ws...)); !errors.Is(err, ErrRevokedHead) {
		t.Fatalf("PublishHead: %v", err)
	}
	cl, v := e.client()
	if _, err := cl.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("client with the new pin: %v", err)
	}
	// Reissue ingest-2.cert under identity 2 (the thief's entry occupies
	// no key) and repair.
	reissue := e.p.cert(t, keys.RoleIngest, 2, 2, T)
	if err := store.WriteFileAtomic(e.path("platform/ingest-2.cert"), reissue); err != nil {
		t.Fatal(err)
	}
	ri, err := srv.Append(KindPlatform, reissue)
	if err != nil {
		t.Fatal(err)
	}
	e.signer = e.logSigner(2)
	if _, err := srv.SignHead(e.signer, e.now); !errors.Is(err, ErrRevokedHead) {
		t.Fatalf("SignHead after the reissue: %v", err)
	}
	if err := os.RemoveAll(e.path(KeysDir)); err != nil {
		t.Fatal(err)
	}
	res, err := RepairTreeResult(e.serverOptions())
	if err != nil {
		t.Fatal(err)
	}
	to := RevokedHeadPath(th.Size, sha256.Sum256(thiefFile))
	if len(res.RevokedHeads) != 1 || res.RevokedHeads[0] != (MovedHead{From: HeadPath(th.Size), To: to}) {
		t.Fatalf("moved %+v", res.RevokedHeads)
	}
	if got, err := os.ReadFile(e.path(to)); err != nil || !bytes.Equal(got, thiefFile) {
		t.Fatalf("moved head: %v", err)
	}
	if _, err := os.Stat(e.path(HeadPath(th.Size))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("head left in heads/: %v", err)
	}
	if _, err := os.Stat(e.path(HeadPath(N))); err != nil {
		t.Fatalf("the confirmed head: %v", err)
	}
	k, err := os.ReadFile(e.path(KeyPath(Key{Kind: KindPlatform, Subject: []byte("ingest-2.cert")})))
	if err != nil || string(k) != strconv.FormatInt(ri, 10) {
		t.Fatalf("key file of ingest-2.cert: %q %v (reissue at %d)", k, err, ri)
	}
	// Repeated: nothing more to move.
	if res, err := RepairTreeResult(e.serverOptions()); err != nil || len(res.RevokedHeads) != 0 {
		t.Fatalf("second repair: %+v %v", res, err)
	}
	hs, err := srv.SignHead(e.signer, e.now)
	var inv *InvalidEntriesError
	if !errors.As(err, &inv) || len(inv.Entries) != 1 || inv.Entries[0] != (InvalidEntry{Index: N, Class: "revoked"}) {
		t.Fatalf("SignHead after the repair: %v", err)
	}
	if err := srv.PublishHead(e.cosigned(hs, e.ws...)); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Refresh(e.now); err != nil {
		t.Fatalf("client after the repair: %v", err)
	}
	if v.Last.Size != hs.Size || len(cl.Invalid()) != 1 || cl.Invalid()[0] != (InvalidEntry{Index: N, Class: "revoked"}) {
		t.Fatalf("client: %+v %v", v.Last, cl.Invalid())
	}
	if err := cl.CheckPlatform("ingest-2.cert", reissue); err != nil {
		t.Fatal(err)
	}
	if err := cl.CheckPlatform("ingest-2.cert", thief); !errors.Is(err, ErrMismatch) {
		t.Fatalf("thief's certificate: %v", err)
	}
}

// TestRevokedHeadOnlyByField7: RepairTree moves only heads that field 7
// makes foreign. A head signed by a key the log does not know at all, or
// by the key of an ingest certificate that is invalid for another
// reason than field 7 (class "prerequisite"), is ErrConsistency as
// before and stays in heads/. moveHeadAside refuses a file that changed
// since the repair judged it.
func TestRevokedHeadOnlyByField7(t *testing.T) {
	for _, c := range []string{"unknown key", "invalid certificate"} {
		t.Run(c, func(t *testing.T) {
			e := newEnv(t, 1, 1)
			e.head()
			key := newPlat(t).ingest(t, 3)
			if c == "invalid certificate" {
				// ingest-3.cert without ingest-2.cert, written past Append.
				writeRaw(t, e, KindPlatform, certFor(t, e.p, keys.RoleIngest, 3, 1, key.Public().(ed25519.PublicKey), t0))
			}
			signer, err := NewLogSigner(key)
			if err != nil {
				t.Fatal(err)
			}
			e.addresses(1)
			hu := e.headOf(t0 + 1)
			e.publish(hu, append([]note.Signer{signer}, e.all()[1:]...)...)
			if err := RepairTree(e.serverOptions()); !errors.Is(err, ErrConsistency) || errors.Is(err, ErrRevokedHead) {
				t.Fatalf("repair: %v", err)
			}
			if _, err := e.openServer().SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) || errors.Is(err, ErrRevokedHead) {
				t.Fatalf("SignHead: %v", err)
			}
			if _, err := os.Stat(e.path(HeadPath(hu.Size))); err != nil {
				t.Fatalf("head removed: %v", err)
			}
			f := &files{root: e.st.Root}
			if _, err := f.moveHeadAside(hu.Size, [32]byte{1}); !errors.Is(err, ErrConsistency) {
				t.Fatalf("moveHeadAside of a changed file: %v", err)
			}
			if _, err := os.Stat(e.path(HeadPath(hu.Size))); err != nil {
				t.Fatalf("head moved: %v", err)
			}
		})
	}
}

// TestRevokedLoggedIssuer: the issuer that counts for the cascade is that
// of the valid entry. platform/ holds the thief's ingest-2.cert (identity
// 1, revoked) with the same key and valid_from as the reissue under
// identity 2 that the log holds; the client takes the issuer from the
// log and accepts heads of generation 2 after revoked_at_time.
func TestRevokedLoggedIssuer(t *testing.T) {
	e := newEnv(t, 1, 1)
	h := e.head()
	N := h.Size
	T := h.Time + 1
	pub := e.p.ingest(t, 2).Public().(ed25519.PublicKey)
	thief := certFor(t, e.p, keys.RoleIngest, 2, 1, pub, T)
	if i := e.mustAppend(KindPlatform, thief); i != N {
		t.Fatalf("thief at %d", i)
	}
	if err := e.st.WritePlatformFile("ingest-2.cert", thief); err != nil {
		t.Fatal(err)
	}
	e.idGen = 2
	e.rev = []Revoked{{Role: roleID, Gen: 1, AtSize: N, AtTime: T}}
	srv := e.openServer()
	if _, err := srv.Append(KindPlatform, certFor(t, e.p, keys.RoleIngest, 2, 2, pub, T)); err != nil {
		t.Fatal(err)
	}
	e.now = time.UnixMilli(T + hour)
	e.signer = e.logSigner(2)
	hs, err := srv.SignHead(e.signer, e.now)
	if hs == nil {
		t.Fatalf("SignHead: %v", err)
	}
	if err := srv.PublishHead(e.cosigned(hs, e.ws...)); err != nil {
		t.Fatal(err)
	}
	cl, v := e.client()
	if _, err := cl.Refresh(e.now); err != nil {
		t.Fatalf("client: %v", err)
	}
	for _, k := range v.LogKeys {
		if k.Gen == 2 && (!k.Logged || k.IdentityGen != 2 || k.Revoked) {
			t.Fatalf("log key %+v", k)
		}
	}
	if v.RevokedAtTime(roleIngest, 2, e.now.UnixMilli()) {
		t.Fatal("metadata query")
	}
}

// TestRevokedPrerequisiteLockout (spec review L3): listing in field 7
// a generation whose certificate is not a valid entry below its
// revoked_at_size (here the thief's ingest-2.cert at N) locks the role:
// no ingest-2.cert can be valid at or after N any more (ErrRevoked), and
// ingest-3.cert lacks its prerequisite (ErrPrerequisite). Revoking
// identity 1 alone already invalidates the thief's certificate, and the
// reissue under the same name works (TestRevokedThiefHeadRecovery).
func TestRevokedPrerequisiteLockout(t *testing.T) {
	e := newEnv(t, 1, 1)
	h := e.head()
	N := h.Size
	e.mustAppend(KindPlatform, e.p.cert(t, keys.RoleIngest, 2, 1, t0+1))
	e.idGen = 2
	e.rev = []Revoked{{Role: roleID, Gen: 1, AtSize: N, AtTime: h.Time}, {Role: roleIngest, Gen: 2, AtSize: N, AtTime: h.Time}}
	srv := e.openServer()
	if _, err := srv.Append(KindPlatform, e.p.cert(t, keys.RoleIngest, 3, 2, t0+hour)); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("ingest-3.cert: %v", err)
	}
	if _, err := srv.Append(KindPlatform, e.p.cert(t, keys.RoleIngest, 2, 2, t0+hour)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("ingest-2.cert: %v", err)
	}
	e.rev = e.rev[:1]
	srv = e.openServer()
	if _, err := srv.Append(KindPlatform, e.p.cert(t, keys.RoleIngest, 2, 2, t0+hour)); err != nil {
		t.Fatalf("reissue without the lockout: %v", err)
	}
}

// TestAdminSupersessionBackdatedCert (spec review L2): CheckAddress
// applies the admin supersession retroactively and fails closed: a
// backdated admin-2.cert (valid_from 0) logged before N makes the
// assignment of admin 1 in force fail (ErrOrder) for every time; neither
// revoking admin 2 nor identity 1 restores it, since the certificate
// was logged before N. The successor assigns again; reads from its
// valid_from on succeed, earlier reads keep failing.
func TestAdminSupersessionBackdatedCert(t *testing.T) {
	e := newEnv(t, 1, 1)
	m := newMbx(t)
	e.mustAppend(KindAddress, e.addr(t, "a@example.org", m, t0-hour, 1))
	if err := e.op.CheckAddress("a@example.org", m, t0); err != nil {
		t.Fatal(err)
	}
	h := e.head()
	e.mustAppend(KindPlatform, e.p.cert(t, keys.RoleAdmin, 2, 1, 0))
	if err := e.op.CheckAddress("a@example.org", m, t0); !errors.Is(err, ErrOrder) {
		t.Fatalf("after the backdated admin-2.cert: %v", err)
	}
	N := e.tree().Size
	e.idGen = 2
	e.rev = []Revoked{{Role: roleID, Gen: 1, AtSize: N, AtTime: h.Time}, {Role: roleAdmin, Gen: 2, AtSize: N, AtTime: h.Time}}
	srv := e.openServer()
	if _, err := srv.Append(KindPlatform, e.p.cert(t, keys.RoleAdmin, 3, 2, t0+hour)); err != nil {
		t.Fatal(err)
	}
	if err := srv.CheckAddress("a@example.org", m, t0); !errors.Is(err, ErrOrder) {
		t.Fatalf("after the revocation: %v", err)
	}
	if _, err := srv.Append(KindAddress, e.addr(t, "a@example.org", m, t0+hour, 3)); err != nil {
		t.Fatal(err)
	}
	if err := srv.CheckAddress("a@example.org", m, t0); !errors.Is(err, ErrOrder) {
		t.Fatalf("historic read: %v", err)
	}
	if err := srv.CheckAddress("a@example.org", m, t0+hour); err != nil {
		t.Fatalf("read after the reassignment: %v", err)
	}
}

// TestAdminRotateDoesNotRevoke (attack review F2): after admin-2.cert,
// the superseded admin 1 still assigns with a valid_from below its
// successor's (the rotation ends only later dates); listing admin 1 in
// field 7 stops it from revoked_at_size on.
func TestAdminRotateDoesNotRevoke(t *testing.T) {
	e := newEnv(t, 1, 1)
	S := t0 + hour
	mOld, mEvil := newMbx(t), newMbx(t)
	e.mustAppend(KindAddress, e.addr(t, "victim@example.org", mOld, t0, 1))
	e.mustAppend(KindPlatform, e.p.cert(t, keys.RoleAdmin, 2, 1, S))
	h := e.head()
	evil := e.addr(t, "victim@example.org", mEvil, S-1, 1)
	// Rotation only: the backdated assignment is valid.
	probe := e.openOp()
	if _, err := probe.Append(KindAddress, e.addr(t, "probe@example.org", mEvil, S-1, 1)); err != nil {
		t.Fatalf("rotation alone: %v", err)
	}
	// With admin 1 in field 7 at N (after the probe) it is refused.
	e.rev = []Revoked{{Role: roleAdmin, Gen: 1, AtSize: e.tree().Size, AtTime: h.Time}}
	srv := e.openServer()
	if _, err := srv.Append(KindAddress, evil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked admin 1: %v", err)
	}
	if err := srv.CheckAddress("victim@example.org", mOld, S+day); err != nil {
		t.Fatal(err)
	}
}

// TestRevokedFarFutureFreeze (attack review F3): a stolen admin key
// logs, before the confirmed head, an assignment with a far-future
// valid_from. It stays valid: the successor cannot reassign the address
// (valid_from must increase), and CheckAddress fails closed from that
// time on. The repair is a revoked_at_size at the thief's entry.
func TestRevokedFarFutureFreeze(t *testing.T) {
	e := newEnv(t, 1, 1)
	S := t0 + hour
	far := t0 + 100*365*day
	mOld, mNew := newMbx(t), newMbx(t)
	e.mustAppend(KindAddress, e.addr(t, "victim@example.org", mOld, t0, 1))
	i := e.mustAppend(KindAddress, e.addr(t, "victim@example.org", mOld, far, 1))
	e.addresses(1)
	h := e.head()
	N := h.Size
	e.mustAppend(KindPlatform, e.p.cert(t, keys.RoleAdmin, 2, 1, S))
	e.rev = []Revoked{{Role: roleAdmin, Gen: 1, AtSize: N, AtTime: h.Time}}
	srv := e.openServer()
	if _, err := srv.Append(KindAddress, e.addr(t, "victim@example.org", mNew, S, 2)); !errors.Is(err, ErrOrder) {
		t.Fatalf("reassignment over the frozen address: %v", err)
	}
	if err := srv.CheckAddress("victim@example.org", mOld, far+1); !errors.Is(err, ErrOrder) {
		t.Fatalf("at the far-future time: %v", err)
	}
	e.rev = []Revoked{{Role: roleAdmin, Gen: 1, AtSize: i, AtTime: h.Time}}
	srv = e.openServer()
	if _, err := srv.Append(KindAddress, e.addr(t, "victim@example.org", mNew, S, 2)); err != nil {
		t.Fatalf("repair with revoked_at_size at the thief's entry: %v", err)
	}
	if err := srv.CheckAddress("victim@example.org", mNew, far+1); err != nil {
		t.Fatal(err)
	}
}
