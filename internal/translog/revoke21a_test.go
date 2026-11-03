package translog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of task 21a (D93): the revocation of platform generations by pin
// field 7 and the admin supersession.

const (
	roleID     = store.KeyRoleIdentity
	roleAdmin  = store.KeyRoleAdmin
	roleIngest = store.KeyRoleIngest
)

// TestCheckRevoked: the rules of field 7 (CheckRevoked) and their
// agreement with store.CheckPinRevoked, the queries and AnchorFromPin.
func TestCheckRevoked(t *testing.T) {
	ok := []Revoked{
		{Role: roleID, Gen: 1, AtSize: 1, AtTime: 0},
		{Role: roleID, Gen: 2, AtSize: MaxTreeSize, AtTime: 5},
		{Role: roleAdmin, Gen: 1, AtSize: 10, AtTime: 7},
		{Role: roleAdmin, Gen: 7, AtSize: 10, AtTime: 7},
		{Role: roleIngest, Gen: 1<<32 - 1, AtSize: 10, AtTime: 1 << 62},
	}
	toStore := func(l []Revoked) []store.PlatformRevoked {
		var out []store.PlatformRevoked
		for _, r := range l {
			out = append(out, store.PlatformRevoked{Role: r.Role, Gen: r.Gen, AtSize: r.AtSize, AtTime: r.AtTime})
		}
		return out
	}
	if CheckRevoked(ok, 3) != nil || store.CheckPinRevoked(toStore(ok), 3) != nil {
		t.Fatal("valid list refused")
	}
	if CheckRevoked(nil, 1) != nil || store.CheckPinRevoked(nil, 1) != nil {
		t.Fatal("empty list refused")
	}
	long := make([]Revoked, MaxRevoked+1)
	for i := range long {
		long[i] = Revoked{Role: roleIngest, Gen: uint32(i + 1), AtSize: 1}
	}
	if !errors.Is(CheckRevoked(long, 1), ErrPin) || !errors.Is(store.CheckPinRevoked(toStore(long), 1), store.ErrRecord) {
		t.Fatal("too many")
	}
	if CheckRevoked(long[:MaxRevoked], 1) != nil {
		t.Fatal("MaxRevoked elements refused")
	}
	for name, f := range map[string]func(l []Revoked) []Revoked{
		"unknown role":      func(l []Revoked) []Revoked { l[4].Role = 3; return l },
		"gen 0":             func(l []Revoked) []Revoked { l[2].Gen = 0; return l },
		"own identity":      func(l []Revoked) []Revoked { l[1].Gen = 3; return l },
		"later identity":    func(l []Revoked) []Revoked { l[1].Gen = 4; return l },
		"size 0":            func(l []Revoked) []Revoked { l[0].AtSize = 0; return l },
		"size negative":     func(l []Revoked) []Revoked { l[0].AtSize = -1; return l },
		"size above max":    func(l []Revoked) []Revoked { l[0].AtSize = MaxTreeSize + 1; return l },
		"time negative":     func(l []Revoked) []Revoked { l[3].AtTime = -1; return l },
		"duplicate":         func(l []Revoked) []Revoked { l[3].Gen = 1; return l },
		"gens descending":   func(l []Revoked) []Revoked { l[2], l[3] = l[3], l[2]; return l },
		"roles descending":  func(l []Revoked) []Revoked { l[3], l[4] = l[4], l[3]; return l },
		"same, other times": func(l []Revoked) []Revoked { return append(l, Revoked{Role: roleIngest, Gen: 1<<32 - 1, AtSize: 3}) },
	} {
		l := f(append([]Revoked(nil), ok...))
		if err := CheckRevoked(l, 3); !errors.Is(err, ErrPin) {
			t.Errorf("%s: %v", name, err)
		}
		if err := store.CheckPinRevoked(toStore(l), 3); !errors.Is(err, store.ErrRecord) {
			t.Errorf("store %s: %v", name, err)
		}
	}

	// Boundaries: index N-1 valid, N not; time T-1 valid, T not.
	list := []Revoked{{Role: roleIngest, Gen: 2, AtSize: 100, AtTime: t0}}
	if RevokedAtIndex(list, roleIngest, 2, 99) || !RevokedAtIndex(list, roleIngest, 2, 100) || !RevokedAtIndex(list, roleIngest, 2, 101) {
		t.Fatal("RevokedAtIndex boundary")
	}
	if RevokedAtTime(list, roleIngest, 2, t0-1) || !RevokedAtTime(list, roleIngest, 2, t0) {
		t.Fatal("RevokedAtTime boundary")
	}
	if RevokedAtIndex(list, roleIngest, 1, 1<<40) || RevokedAtIndex(list, roleAdmin, 2, 1<<40) || RevokedAtTime(list, roleIngest, 3, 1<<62) {
		t.Fatal("other generation or role revoked")
	}
	v := &Verifier{Revoked: list}
	if !v.IsRevoked(roleIngest, 2) || v.IsRevoked(roleAdmin, 2) || v.RevokedAtTime(roleIngest, 2, t0-1) || !v.RevokedAtTime(roleIngest, 2, t0) {
		t.Fatal("Verifier queries")
	}
	if r, ok := FindRevoked(list, roleIngest, 2); !ok || r != list[0] {
		t.Fatal("FindRevoked")
	}
	if _, ok := FindRevoked(list, roleIngest, 1); ok {
		t.Fatal("FindRevoked found another generation")
	}

	// AnchorFromPin copies fields 8 and 7.
	p := newPlat(t)
	ids := p.ids(t, 2)
	pin := &store.PlatformPin{Gen: 2, Pub: ids[1].Pub, Origin: testOrigin,
		Witnesses: []store.Witness{{Name: "w", Pub: ids[0].Pub}}, MinWitnesses: 1,
		Identities: []store.PlatformIdentity{{Gen: 1, Pub: ids[0].Pub}, {Gen: 2, Pub: ids[1].Pub}},
		Revoked:    []store.PlatformRevoked{{Role: roleID, Gen: 1, AtSize: 4, AtTime: 5}, {Role: roleIngest, Gen: 1, AtSize: 6, AtTime: 7}}}
	gotIDs, gotRev := AnchorFromPin(pin)
	if len(gotIDs) != 2 || gotIDs[1].Gen != 2 || !gotIDs[1].Pub.Equal(ids[1].Pub) ||
		len(gotRev) != 2 || gotRev[1] != (Revoked{Role: roleIngest, Gen: 1, AtSize: 6, AtTime: 7}) {
		t.Fatalf("AnchorFromPin: %v %v", gotIDs, gotRev)
	}
	gotIDs[0].Pub[0] ^= 1
	if pin.Identities[0].Pub[0] == gotIDs[0].Pub[0] {
		t.Fatal("AnchorFromPin shares the keys")
	}
	pin.Revoked = nil
	if _, rev := AnchorFromPin(pin); rev != nil {
		t.Fatal("revocations from a pin without field 7")
	}
	if MaxRevoked != store.MaxPinRevoked {
		t.Fatal("MaxRevoked differs from store")
	}
}

// TestRevokedAnchorRefused: a revocation list that fails CheckRevoked
// is ErrPin for an operator log, RepairTree and a client log.
func TestRevokedAnchorRefused(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.rev = []Revoked{{Role: roleID, Gen: 1, AtSize: 1}} // identity 1 is the pin's own
	if _, err := Open(e.serverOptions()); !errors.Is(err, ErrPin) {
		t.Fatalf("operator: %v", err)
	}
	if err := RepairTree(e.serverOptions()); !errors.Is(err, ErrPin) {
		t.Fatalf("RepairTree: %v", err)
	}
	if _, err := Open(Options{Store: e.st, Verifier: e.verifier(), IndexFile: filepath.Join(t.TempDir(), "i.json")}); !errors.Is(err, ErrPin) {
		t.Fatalf("client: %v", err)
	}
	v := e.verifier()
	if err := v.CheckHead(e.headOf(t0), nil); !errors.Is(err, ErrPin) {
		t.Fatalf("CheckHead: %v", err)
	}
}

// revCase is an entry that a revocation makes invalid from its
// boundary on.
type revCase struct {
	name  string
	idGen uint32
	rev   Revoked // AtSize is set by the test
	// prep appends the prerequisites with the operator log of a pin
	// without field 7 and returns the entry under test.
	prep func(t *testing.T, e *tenv) (Kind, []byte)
}

func revCases() []revCase {
	return []revCase{
		{"certificate issued by a revoked identity", 2, Revoked{Role: roleID, Gen: 1},
			func(t *testing.T, e *tenv) (Kind, []byte) {
				return KindPlatform, e.p.cert(t, keys.RoleIngest, 2, 1, t0+day)
			}},
		{"succession issued by a revoked identity", 2, Revoked{Role: roleID, Gen: 1},
			func(t *testing.T, e *tenv) (Kind, []byte) { return KindPlatform, e.p.succ(t, 2, t0) }},
		{"succession to a revoked identity", 3, Revoked{Role: roleID, Gen: 2},
			func(t *testing.T, e *tenv) (Kind, []byte) { return KindPlatform, e.p.succ(t, 2, t0) }},
		{"certificate of a revoked admin generation", 1, Revoked{Role: roleAdmin, Gen: 2},
			func(t *testing.T, e *tenv) (Kind, []byte) {
				return KindPlatform, e.p.cert(t, keys.RoleAdmin, 2, 1, t0+day)
			}},
		{"certificate of a revoked ingest generation", 1, Revoked{Role: roleIngest, Gen: 2},
			func(t *testing.T, e *tenv) (Kind, []byte) {
				return KindPlatform, e.p.cert(t, keys.RoleIngest, 2, 1, t0+day)
			}},
		{"address of a revoked admin generation", 1, Revoked{Role: roleAdmin, Gen: 1},
			func(t *testing.T, e *tenv) (Kind, []byte) {
				return KindAddress, e.addr(t, "rev@example.org", newMbx(t), t0, 1)
			}},
		{"address of a revoked admin generation 2", 1, Revoked{Role: roleAdmin, Gen: 2},
			func(t *testing.T, e *tenv) (Kind, []byte) {
				e.mustAppend(KindPlatform, e.p.cert(t, keys.RoleAdmin, 2, 1, t0+day))
				return KindAddress, e.addr(t, "rev@example.org", newMbx(t), t0+day, 2)
			}},
		// D93 addendum (task 21a rework): revoking identity 1 ends the
		// admin generations it certified from revoked_at_size on.
		{"address of an admin generation certified by a revoked identity", 2, Revoked{Role: roleID, Gen: 1},
			func(t *testing.T, e *tenv) (Kind, []byte) {
				return KindAddress, e.addr(t, "rev@example.org", newMbx(t), t0, 1)
			}},
		{"address of admin generation 2 certified by a revoked identity", 2, Revoked{Role: roleID, Gen: 1},
			func(t *testing.T, e *tenv) (Kind, []byte) {
				e.mustAppend(KindPlatform, e.p.cert(t, keys.RoleAdmin, 2, 1, t0+day))
				return KindAddress, e.addr(t, "rev@example.org", newMbx(t), t0+day, 2)
			}},
	}
}

// TestRevokedAppendBoundary: Append accepts the entry at index
// revoked_at_size-1 and refuses it at revoked_at_size (ErrRevoked, an
// ErrOrder), for every role; the entries before the boundary that the
// revoked generation issued stay valid.
func TestRevokedAppendBoundary(t *testing.T) {
	for _, c := range revCases() {
		t.Run(c.name, func(t *testing.T) {
			for _, valid := range []bool{true, false} {
				e := newEnv(t, 1, 1)
				kind, data := c.prep(t, e)
				n := e.tree().Size // the index of the entry under test
				e.idGen = c.idGen
				r := c.rev
				r.AtSize, r.AtTime = n+1, t0 // index N-1 = n
				if !valid {
					r.AtSize = n // index N = n
				}
				e.rev = []Revoked{r}
				e.op = e.openOp()
				i, err := e.op.Append(kind, data)
				if valid {
					if err != nil || i != n {
						t.Fatalf("index N-1: %d %v", i, err)
					}
				} else if !errors.Is(err, ErrRevoked) || !errors.Is(err, ErrOrder) {
					t.Fatalf("index N: %v", err)
				}
				// admin-1.cert and ingest-1.cert (identity 1, indices 0
				// and 1) were logged before every boundary.
				if err := e.op.CheckPlatform("admin-1.cert", e.p.cert(t, keys.RoleAdmin, 1, 1, t0-day)); err != nil {
					t.Fatalf("history: %v", err)
				}
			}
		})
	}
}

// TestRevokedAudit: an entry written past Append (by an operator whose
// pin has no field 7) at or after the boundary is invalid in the audit
// of a client with the new pin (class "revoked") and in SignHead of an
// operator with it (InvalidEntriesError, ErrRevoked); before the
// boundary it is valid for both.
func TestRevokedAudit(t *testing.T) {
	for _, c := range revCases() {
		t.Run(c.name, func(t *testing.T) {
			for _, valid := range []bool{true, false} {
				e := newEnv(t, 1, 1)
				kind, data := c.prep(t, e)
				n := e.tree().Size
				e.mustAppend(kind, data)                     // pin without field 7: accepted
				e.mustAppend(KindUser, newUser(t).rec(t, 1)) // a valid entry after it
				e.idGen = c.idGen
				r := c.rev
				// revoked_at_time after the heads of this test: a revoked
				// identity generation also ends the ingest generation it
				// certified from then on (TestRevokedCascade).
				r.AtSize, r.AtTime = n+1, t0+day
				if !valid {
					r.AtSize = n
				}
				e.rev = []Revoked{r}
				srv := e.openServer()
				h, err := srv.SignHead(e.signer, e.now)
				var inv *InvalidEntriesError
				switch {
				case h == nil:
					t.Fatalf("SignHead: %v", err)
				case valid && err != nil:
					t.Fatalf("SignHead before the boundary: %v", err)
				case !valid && (!errors.As(err, &inv) || !errors.Is(err, ErrRevoked) || len(inv.Entries) != 1 ||
					inv.Entries[0] != InvalidEntry{Index: n, Class: "revoked"}):
					t.Fatalf("SignHead after the boundary: %v", err)
				}
				if err := srv.PublishHead(e.cosigned(h, e.ws...)); err != nil {
					t.Fatal(err)
				}
				cl, _ := e.client()
				if _, err := cl.Refresh(e.now); err != nil {
					t.Fatal(err)
				}
				got := cl.Invalid()
				if valid != (len(got) == 0) || !valid && got[0] != (InvalidEntry{Index: n, Class: "revoked"}) {
					t.Fatalf("client audit: %v", got)
				}
				// The operator of the same pin judges alike.
				if kind == KindPlatform {
					name := recName(t, data)
					cerr, serr := cl.CheckPlatform(name, data), srv.CheckPlatform(name, data)
					if valid != (cerr == nil) || valid != (serr == nil) {
						t.Fatalf("CheckPlatform: client %v, server %v", cerr, serr)
					}
					if !valid && (!errors.Is(cerr, ErrNotInLog) || !cl.v.IsRevoked(c.rev.Role, c.rev.Gen)) {
						t.Fatalf("CheckPlatform of a revoked entry: %v", cerr)
					}
				}
			}
		})
	}
}

// recName returns the file name of a platform record.
func recName(t *testing.T, data []byte) string {
	t.Helper()
	e, err := NewEntry(KindPlatform, data)
	if err != nil {
		t.Fatal(err)
	}
	return string(e.Subject)
}

// TestRevokedIngestHeads: a revoked ingest generation signs heads with
// a time before revoked_at_time validly and none at or after it, for
// the client (Refresh, CheckHead), SignHead and PublishHead; its
// certificate, logged before revoked_at_size, stays valid.
func TestRevokedIngestHeads(t *testing.T) {
	e := newEnv(t, 1, 1)
	T := t0 + hour
	e.rev = []Revoked{{Role: roleIngest, Gen: 1, AtSize: e.tree().Size, AtTime: T}}
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
	if len(v.LogKeys) != 1 || !v.LogKeys[0].Revoked || v.LogKeys[0].RevokedAt != T {
		t.Fatalf("log keys %+v", v.LogKeys)
	}
	// A re-signature of the same size at time T is refused by the
	// server and, published anyway, by the client.
	e.now = time.UnixMilli(T)
	hT := e.headOf(T)
	if err := srv.PublishHead(e.cosigned(hT, e.ws...)); !errors.Is(err, ErrHead) {
		t.Fatalf("PublishHead at T: %v", err)
	}
	e.publish(hT, e.all()...)
	if _, err := cl.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("client, time T: %v", err)
	}
	if v.Last.Time != T-1 {
		t.Fatal("refused head taken over")
	}
	// CheckHead checks Verifier.Revoked also for a LogKey built without
	// Revoked.
	vc := e.verifier()
	k := v.LogKeys[0]
	k.Revoked, k.RevokedAt = false, 0
	vc.LogKeys = []LogKey{k}
	hn := e.headOf(T)
	hn.Note = sign(t, hn, e.all()...)
	if err := vc.CheckHead(hn, nil); !errors.Is(err, ErrHead) {
		t.Fatalf("CheckHead at T: %v", err)
	}
	vc.Last = nil
	hp := e.headOf(T - 1)
	hp.Note = sign(t, hp, e.all()...)
	if err := vc.CheckHead(hp, nil); err != nil {
		t.Fatalf("CheckHead at T-1: %v", err)
	}
	// After the rotation to generation 2 (valid from T) the server signs
	// at T again, and the client accepts it.
	cert2 := e.p.cert(t, keys.RoleIngest, 2, 1, T)
	if err := e.st.WritePlatformFile("ingest-2.cert", cert2); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Append(KindPlatform, cert2); err != nil {
		t.Fatal(err)
	}
	// heads/2.sig, written at T past PublishHead, does not belong to
	// the log under the pin: SignHead names it, the repair moves it
	// aside.
	e.signer = e.logSigner(2)
	if _, err := srv.SignHead(e.signer, e.now); !errors.Is(err, ErrRevokedHead) || !errors.Is(err, ErrConsistency) ||
		!strings.Contains(err.Error(), "heads/2.sig") {
		t.Fatalf("SignHead over a revoked head: %v", err)
	}
	res, err := RepairTreeResult(e.serverOptions())
	if err != nil || len(res.RevokedHeads) != 1 || res.RevokedHeads[0].From != HeadPath(2) {
		t.Fatalf("repair: %+v %v", res, err)
	}
	h2, err := srv.SignHead(e.signer, e.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.PublishHead(e.cosigned(h2, e.ws...)); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Refresh(e.now); err != nil {
		t.Fatalf("client after the rotation: %v", err)
	}
	// The ingest certificate of generation 1 (index 1 < revoked_at_size)
	// stays valid; metadata is judged with RevokedAtTime.
	c1, _ := e.st.ReadPlatformFile("ingest-1.cert")
	if err := cl.CheckPlatform("ingest-1.cert", c1); err != nil {
		t.Fatal(err)
	}
	if v.RevokedAtTime(roleIngest, 1, T-1) || !v.RevokedAtTime(roleIngest, 1, T) || v.RevokedAtTime(roleIngest, 2, T) {
		t.Fatal("receipt time query")
	}
}

// TestLogKeyCoversRevoked: the revocation bound of LogKey.Covers.
func TestLogKeyCoversRevoked(t *testing.T) {
	k := LogKey{Logged: true, ValidFrom: 10, Revoked: true, RevokedAt: 20}
	for tm, want := range map[int64]bool{9: false, 10: true, 19: true, 20: false, 21: false} {
		if k.Covers(tm) != want {
			t.Errorf("Covers(%d) = %v", tm, !want)
		}
	}
	k.Until = 15
	if k.Covers(15) || !k.Covers(14) {
		t.Fatal("Until before RevokedAt")
	}
	k.Revoked = false
	if !k.Covers(14) || k.Covers(25) {
		t.Fatal("RevokedAt without Revoked")
	}
}

// TestAdminSupersession: admin generation g assigns only until
// valid_from of admin-<g+1>.cert (D93 (3)): at append and audit for an
// assignment logged after that certificate, in CheckAddress for the
// assignment in force; assignments before it stay valid.
func TestAdminSupersession(t *testing.T) {
	e := newEnv(t, 1, 1)
	S := t0 + hour
	mOld, mNew := newMbx(t), newMbx(t)
	// Logged before the rotation: one dated before S, one after it.
	e.mustAppend(KindAddress, e.addr(t, "old@example.org", mOld, t0, 1))
	e.mustAppend(KindAddress, e.addr(t, "future@example.org", mOld, S+5, 1))
	e.mustAppend(KindPlatform, e.p.cert(t, keys.RoleAdmin, 2, 1, S))
	// Logged after it: admin 1 only before S.
	e.mustAppend(KindAddress, e.addr(t, "late@example.org", mOld, S-1, 1))
	_, err := e.op.Append(KindAddress, e.addr(t, "late2@example.org", mOld, S, 1))
	if !errors.Is(err, ErrOrder) || errors.Is(err, ErrRevoked) {
		t.Fatalf("admin 1 at S: %v", err)
	}
	e.mustAppend(KindAddress, e.addr(t, "late2@example.org", mNew, S, 2))
	check := func(name string, l Log) {
		t.Helper()
		for _, c := range []struct {
			addr string
			mbx  store.ID
			at   int64
			want error
		}{
			{"old@example.org", mOld, S + day, nil}, // history stays in force
			{"late@example.org", mOld, S + day, nil},
			{"late2@example.org", mNew, S, nil},
			{"future@example.org", mOld, S + 5, ErrOrder},
			{"future@example.org", mOld, S + 4, ErrNotInLog},
		} {
			if err := l.CheckAddress(c.addr, c.mbx, c.at); (c.want == nil) != (err == nil) || c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("%s: CheckAddress(%s, %d): %v, want %v", name, c.addr, c.at, err, c.want)
			}
		}
	}
	check("operator", e.op)
	if adminSuperseded(newState(nil, nil, nil), 1<<32-1, 0) {
		t.Fatal("the last admin generation has no successor")
	}
	// The same assignment written past Append is invalid in the audit
	// (class "order").
	n := e.tree().Size
	en, _ := NewEntry(KindAddress, e.addr(t, "raw@example.org", mOld, S+1, 1))
	enc, _ := en.Encode()
	if _, err := (&fileLog{f: &files{root: e.st.Root}}).write(e.tree(), en.Key, enc); err != nil {
		t.Fatal(err)
	}
	e.head()
	cl, _ := e.client()
	if _, err := cl.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if got := cl.Invalid(); len(got) != 1 || got[0] != (InvalidEntry{Index: n, Class: "order"}) {
		t.Fatalf("audit %v", got)
	}
	check("client", cl)
	if err := cl.CheckAddress("raw@example.org", mOld, S+2); !errors.Is(err, ErrNotInLog) {
		t.Fatalf("raw assignment: %v", err)
	}
}

// TestRevokedCompromise follows D93 (4) through one tree: identity 1 is
// compromised; the new pin (identity 2) revokes it at the size N and
// time T of a confirmed head. The thief logs a certificate with identity
// 1 after N (through an operator with the old pin); the reissue under
// identity 2 takes the same name; what identity 1 issued before N stays
// valid. Admin 1 and ingest 1, certified by identity 1, act no more from
// N and T on (D93 addendum): the operator reissues ingest under identity
// 2, and the repair moves the confirmed head (time T, signed by ingest
// 1) out of heads/.
func TestRevokedCompromise(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.addresses(2)
	h := e.head() // the confirmed head: size N
	N := h.Size
	thief := e.p.cert(t, keys.RoleAdmin, 2, 1, t0)
	if i := e.mustAppend(KindPlatform, thief); i != N {
		t.Fatalf("thief at %d", i)
	}
	// The client update: pin 2 revokes identity 1 at N.
	e.idGen = 2
	e.rev = []Revoked{{Role: roleID, Gen: 1, AtSize: N, AtTime: h.Time}}
	srv := e.openServer()
	if err := srv.CheckPlatform("admin-2.cert", thief); !errors.Is(err, ErrNotInLog) {
		t.Fatalf("thief's certificate: %v", err)
	}
	// Reissue under identity 2 with the name the thief used.
	reissue := e.p.cert(t, keys.RoleAdmin, 2, 2, t0+hour)
	i, err := srv.Append(KindPlatform, reissue)
	if err != nil {
		t.Fatalf("reissue: %v", err)
	}
	if err := srv.CheckPlatform("admin-2.cert", reissue); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Append(KindAddress, e.addr(t, "new@example.org", newMbx(t), t0+hour, 2)); err != nil {
		t.Fatal(err)
	}
	// Admin 1 (certified by identity 1 before N) assigns nothing from N
	// on, whatever the valid_from.
	for _, vf := range []int64{t0 + 10, t0 + hour} {
		if _, err := srv.Append(KindAddress, e.addr(t, "x@example.org", newMbx(t), vf, 1)); !errors.Is(err, ErrRevoked) {
			t.Fatalf("admin 1 certified by identity 1: %v", err)
		}
	}
	// Ingest 1 (certified by identity 1) signs no head from T on; the
	// reissue under identity 2 takes over at T.
	e.now = e.now.Add(time.Minute)
	if _, err := srv.SignHead(e.signer, e.now); !errors.Is(err, ErrHead) && !errors.Is(err, ErrRevokedHead) {
		t.Fatalf("ingest 1 after T: %v", err)
	}
	in2 := e.p.cert(t, keys.RoleIngest, 2, 2, h.Time)
	if err := e.st.WritePlatformFile("ingest-2.cert", in2); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Append(KindPlatform, in2); err != nil {
		t.Fatal(err)
	}
	e.signer = e.logSigner(2)
	if _, err := srv.SignHead(e.signer, e.now); !errors.Is(err, ErrRevokedHead) || !strings.Contains(err.Error(), HeadPath(N)[len(Dir)+1:]) {
		t.Fatalf("the confirmed head under the new pin: %v", err)
	}
	res, err := RepairTreeResult(e.serverOptions())
	if err != nil || len(res.RevokedHeads) != 1 || res.RevokedHeads[0].From != HeadPath(N) {
		t.Fatalf("repair: %+v %v", res, err)
	}
	hs, err := srv.SignHead(e.signer, e.now)
	var inv *InvalidEntriesError
	if !errors.As(err, &inv) || len(inv.Entries) != 1 || inv.Entries[0].Index != N {
		t.Fatalf("SignHead: %v", err)
	}
	if err := srv.PublishHead(e.cosigned(hs, e.ws...)); err != nil {
		t.Fatal(err)
	}
	cl, _ := e.client()
	if _, err := cl.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if got := cl.Invalid(); len(got) != 1 || got[0] != (InvalidEntry{Index: N, Class: "revoked"}) {
		t.Fatalf("audit %v", got)
	}
	ents, err := cl.Lookup(KindPlatform, []byte("admin-2.cert"))
	if err != nil || len(ents) != 1 || ents[0].Index != i {
		t.Fatalf("lookup %v %v", ents, err)
	}
	for _, name := range []string{"admin-1.cert", "ingest-1.cert"} {
		data, _ := e.st.ReadPlatformFile(name)
		if err := cl.CheckPlatform(name, data); err != nil {
			t.Fatalf("%s before N: %v", name, err)
		}
	}
	// Metadata: ingest 1 until T-1, ingest 2 from T.
	v := cl.v
	if v.RevokedAtTime(roleIngest, 1, h.Time-1) || !v.RevokedAtTime(roleIngest, 1, h.Time) || v.RevokedAtTime(roleIngest, 2, h.Time) {
		t.Fatal("receipt time query")
	}
}

// TestRevokedIndexAnchor: a pin without field 7 keeps the anchor hash
// of the audit index (the identity list alone, as before D93); a pin
// with field 7 has another one, so the client rebuilds its index when
// field 7 changes.
func TestRevokedIndexAnchor(t *testing.T) {
	p := newPlat(t)
	ids := p.ids(t, 2)
	// The formula from before D93.
	h := sha256.New()
	h.Write([]byte("gomail/v1/translog-anchor\x00"))
	for _, id := range ids {
		h.Write(binary.BigEndian.AppendUint32(nil, id.Gen))
		h.Write(id.Pub)
	}
	var old [32]byte
	copy(old[:], h.Sum(nil))
	if anchorHash(ids, nil) != old || anchorHash(ids, []Revoked{}) != old {
		t.Fatal("anchor of a pin without field 7 changed")
	}
	r1 := []Revoked{{Role: roleID, Gen: 1, AtSize: 5, AtTime: 6}}
	r2 := []Revoked{{Role: roleID, Gen: 1, AtSize: 5, AtTime: 7}}
	if anchorHash(ids, r1) == old || anchorHash(ids, r1) == anchorHash(ids, r2) {
		t.Fatal("anchor ignores field 7")
	}

	e := newEnv(t, 1, 1)
	e.head()
	idx := filepath.Join(t.TempDir(), "index.json")
	open := func() *fileLog {
		t.Helper()
		l, err := Open(Options{Store: e.st, Verifier: e.verifier(), IndexFile: idx})
		if err != nil {
			t.Fatal(err)
		}
		fl := l.(*fileLog)
		if _, err := fl.Refresh(e.now); err != nil {
			t.Fatal(err)
		}
		return fl
	}
	anchor := func() tlog.Hash {
		t.Helper()
		data, err := os.ReadFile(idx)
		if err != nil {
			t.Fatal(err)
		}
		var s struct{ Anchor tlog.Hash }
		if err := json.Unmarshal(data, &s); err != nil {
			t.Fatal(err)
		}
		return s.Anchor
	}
	open()
	a0 := anchor()
	if a0 != anchorHash(e.p.ids(t, 1), nil) {
		t.Fatal("index anchor")
	}
	e.rev = []Revoked{{Role: roleIngest, Gen: 5, AtSize: 1, AtTime: 0}}
	l := open()
	if anchor() == a0 || l.ref.Anchor != anchorHash(e.p.ids(t, 1), e.rev) {
		t.Fatal("index not rebuilt for field 7")
	}
	e.rev = nil
	open()
	if anchor() != a0 {
		t.Fatal("index not rebuilt for a pin without field 7")
	}
}

// TestInvalidEntriesErrorRevoked: the class "revoked" unwraps to
// ErrRevoked, which is an ErrOrder.
func TestInvalidEntriesErrorRevoked(t *testing.T) {
	err := &InvalidEntriesError{Entries: []InvalidEntry{{Index: 3, Class: "revoked"}}}
	if !errors.Is(err, ErrRevoked) || !errors.Is(err, ErrOrder) {
		t.Fatal(err)
	}
	if errClass(ErrRevoked) != "revoked" || errClass(ErrOrder) != "order" {
		t.Fatal("errClass")
	}
}

// TestPinSizeWithRevoked measures the largest pin with field 7 through
// store.PlatformPin (TestPinSize measures the proposal's schema): with
// MaxIdentities generations, MaxWitnesses witnesses, an origin of
// MaxOrigin bytes and MaxRevoked revocations it stays below MaxPinFile
// and decodes again byte for byte.
func TestPinSizeWithRevoked(t *testing.T) {
	list := testIdentities(t, MaxIdentities)
	last := list[len(list)-1]
	sp := &store.PlatformPin{Gen: last.Gen, Pub: last.Pub, Origin: strings.Repeat("o", MaxOrigin), MinWitnesses: MaxWitnesses}
	for i := 0; i < MaxWitnesses; i++ {
		sp.Witnesses = append(sp.Witnesses, store.Witness{Name: strings.Repeat(string(rune('a'+i)), 64), Pub: list[i].Pub})
	}
	for _, id := range list {
		sp.Identities = append(sp.Identities, store.PlatformIdentity{Gen: id.Gen, Pub: id.Pub})
	}
	for i := 0; i < MaxRevoked; i++ {
		role := []uint8{roleID, roleAdmin, roleIngest}[i*3/MaxRevoked]
		gen := uint32(1<<32-1) - uint32(MaxRevoked-i)
		if role == roleID {
			gen = uint32(i + 1)
		}
		sp.Revoked = append(sp.Revoked, store.PlatformRevoked{Role: role, Gen: gen, AtSize: MaxTreeSize, AtTime: 1 << 62})
	}
	enc, err := sp.Encode()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("largest pin with field 7: %d bytes; read limit %d", len(enc), MaxPinFile)
	if len(enc) > MaxPinFile {
		t.Fatalf("pin of %d bytes exceeds MaxPinFile", len(enc))
	}
	d, err := store.DecodePlatformPin(enc)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := d.Encode()
	if !bytes.Equal(again, enc) {
		t.Fatal("round trip")
	}
	ids, rev := AnchorFromPin(d)
	if CheckIdentities(ids, ids[len(ids)-1]) != nil || CheckRevoked(rev, d.Gen) != nil || len(rev) != MaxRevoked {
		t.Fatal("anchor of the largest pin")
	}
}
