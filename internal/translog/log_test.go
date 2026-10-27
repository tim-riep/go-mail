package translog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// TestLogEndToEnd appends one record of every kind, signs a head and
// checks every Check method of the operator and of a client.
func TestLogEndToEnd(t *testing.T) {
	e := newEnv(t, 1, 1)
	u := newUser(t)
	mbx := newMbx(t)
	u1 := u.rec(t, 1)
	iu := e.mustAppend(KindUser, u1)
	ep1 := mkEpoch(t, mbx, 1, nil, u, 1, []store.Member{member(u, 1)}, t0)
	ie := e.mustAppend(KindEpoch, ep1)
	ad := e.addr(t, "info@example.org", mbx, t0, 1)
	if err := e.op.AppendAddress(ad); err != nil {
		t.Fatal(err)
	}
	if iu != 2 || ie != 3 {
		t.Fatalf("indices %d %d", iu, ie)
	}

	// Operator: checks against the committed tree.
	for _, l := range []Log{e.op} {
		if !l.Verified() {
			t.Fatal("Verified")
		}
		if err := l.CheckUser(u.id, u1); err != nil {
			t.Fatal(err)
		}
		if err := l.CheckGeneration(u.id, 1); err != nil {
			t.Fatal(err)
		}
		if err := l.CheckEpoch(mbx, 1, ep1); err != nil {
			t.Fatal(err)
		}
		if err := l.CheckAddress("info@example.org", mbx, t0); err != nil {
			t.Fatal(err)
		}
		if err := l.CheckFresh(e.now); err != nil {
			t.Fatal(err)
		}
	}

	// Client: nothing before the first head.
	c, v := e.client()
	if err := c.CheckUser(u.id, u1); !errors.Is(err, ErrPending) {
		t.Fatalf("before the first head: %v", err)
	}
	if err := c.CheckFresh(e.now); !errors.Is(err, ErrStale) {
		t.Fatalf("fresh before the first head: %v", err)
	}
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrStale) {
		t.Fatalf("refresh without a head: %v", err)
	}
	h := e.head()
	got, err := c.Refresh(e.now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != h.Size || got.Hash != h.Hash || v.Last == nil || v.Last.Size != 5 {
		t.Fatal("reference head")
	}
	if err := c.CheckFresh(e.now); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckUser(u.id, u1); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckGeneration(u.id, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckGeneration(u.id, 2); !errors.Is(err, ErrNotInLog) {
		t.Fatal(err)
	}
	if err := c.CheckGeneration(u.id, 0); !errors.Is(err, ErrNotInLog) {
		t.Fatal(err)
	}
	if err := c.CheckEpoch(mbx, 1, ep1); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckEpoch(mbx, 2, ep1); !errors.Is(err, ErrEntry) {
		t.Fatal("epoch under another number")
	}
	if err := c.CheckPlatform("ingest-1.cert", e.p.cert(t, keys.RoleIngest, 1, 1, t0-day)); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckPlatform("ingest-2.cert", e.p.cert(t, keys.RoleIngest, 1, 1, t0-day)); !errors.Is(err, ErrEntry) {
		t.Fatal("platform under another name")
	}
	if err := c.CheckPlatform("ingest-2.cert", e.p.cert(t, keys.RoleIngest, 2, 1, t0)); !errors.Is(err, ErrNotInLog) {
		t.Fatal(err)
	}
	if err := c.CheckPlatform("ingest-1.cert", e.p.cert(t, keys.RoleIngest, 1, 1, t0)); !errors.Is(err, ErrMismatch) {
		t.Fatalf("other certificate under a logged name: %v", err)
	}
	if err := c.CheckRevokedSignature(u.id, 1, ep1); err != nil {
		t.Fatal(err)
	}
	es, err := c.Lookup(KindEpoch, mbx[:])
	if err != nil || len(es) != 1 || !bytes.Equal(es[0].Content, ep1) || es[0].Index != 3 {
		t.Fatalf("Lookup %v", err)
	}
	if es, err := c.Lookup(KindUser, mbx[:]); err != nil || len(es) != 0 {
		t.Fatal("Lookup of nothing")
	}
	en, err := c.Entry(2)
	if err != nil || !bytes.Equal(en.Content, u1) {
		t.Fatal(err)
	}
	if _, err := c.Entry(5); !errors.Is(err, ErrNotInLog) || errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	if _, err := c.Entry(-1); !errors.Is(err, ErrNotInLog) {
		t.Fatal(err)
	}
	if en, err := e.op.Entry(3); err != nil || !bytes.Equal(en.Content, ep1) {
		t.Fatal(err)
	}
	if _, err := e.op.Entry(5); !errors.Is(err, ErrNotInLog) {
		t.Fatal(err)
	}
	hh, err := c.Head()
	if err != nil || hh.Size != 5 {
		t.Fatal(err)
	}
	if hh, err := e.op.Head(); err != nil || hh.Size != 5 {
		t.Fatal(err)
	}
	if hh, err := e.op.Refresh(e.now); err != nil || hh.Size != 5 {
		t.Fatal(err)
	}
	if len(c.Invalid()) != 0 || len(e.op.(*operatorLog).Invalid()) != 0 {
		t.Fatal("invalid entries")
	}

	// Proofs of the operator verify with the Verifier.
	p, err := e.op.InclusionProof(2, 5)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := (&Entry{Key: Key{Kind: KindUser, Subject: u.id[:], Seq: 1}, Content: u1}).Encode()
	if err := v.CheckInclusion(2, enc, p); err != nil {
		t.Fatal(err)
	}
	tp, err := e.op.ConsistencyProof(2, 5)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := tlog.TreeHash(2, e.hashReader())
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckTreeProof(tp, 5, h.Hash, 2, h2); err != nil {
		t.Fatal(err)
	}
	for _, f := range []func() error{
		func() error { _, err := e.op.InclusionProof(5, 5); return err },
		func() error { _, err := e.op.InclusionProof(-1, 5); return err },
		func() error { _, err := e.op.ConsistencyProof(0, 5); return err },
		func() error { _, err := e.op.ConsistencyProof(3, 2); return err },
		func() error { _, err := e.op.ConsistencyProof(1, MaxTreeSize+1); return err },
	} {
		if err := f(); !errors.Is(err, ErrConsistency) {
			t.Fatal(err)
		}
	}
	if _, err := e.op.InclusionProof(1, 6); !errors.Is(err, ErrNotInLog) {
		t.Fatal(err)
	}
	if _, err := e.op.ConsistencyProof(1, 6); !errors.Is(err, ErrNotInLog) {
		t.Fatal(err)
	}

	// A second client reopens with the same audit index; a third with a
	// damaged index rebuilds it.
	idx := c.opts.IndexFile
	l2, err := Open(Options{Store: e.st, Verifier: &Verifier{Origin: v.Origin, Witnesses: v.Witnesses, MinWitnesses: 1,
		Identity: v.Identity, Identities: v.Identities, Last: v.Last, Now: v.Now}, IndexFile: idx})
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.CheckEpoch(mbx, 1, ep1); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idx, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	l3, err := Open(Options{Store: e.st, Verifier: &Verifier{Origin: v.Origin, Witnesses: v.Witnesses, MinWitnesses: 1,
		Identity: v.Identity, Identities: v.Identities, Last: v.Last, Now: v.Now}, IndexFile: idx})
	if err != nil {
		t.Fatal(err)
	}
	if err := l3.CheckAddress("info@example.org", mbx, t0+1); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(idx); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("audit index mode")
	}
}

// TestOpenRules covers the refusals of Open.
func TestOpenRules(t *testing.T) {
	e := newEnv(t, 1, 1)
	v := e.verifier()
	if _, err := Open(Options{Store: e.st}); !errors.Is(err, ErrPin) {
		t.Fatal("operator without identity list")
	}
	if _, err := Open(Options{Store: e.st, Identities: []Identity{{Gen: 2, Pub: v.Identity.Pub}}}); !errors.Is(err, ErrPin) {
		t.Fatal("operator with a broken identity list")
	}
	if _, err := Open(Options{Store: e.st, Verifier: v}); !errors.Is(err, ErrConsistency) {
		t.Fatal("client without audit index")
	}
	if _, err := Open(Options{Store: e.st, Verifier: v, IndexFile: filepath.Join(e.st.Root, "log", "index.json")}); !errors.Is(err, ErrIO) {
		t.Fatal("audit index in the data directory")
	}
	idx := filepath.Join(t.TempDir(), "i.json")
	noClock := e.verifier()
	noClock.Now = nil
	if _, err := Open(Options{Store: e.st, Verifier: noClock, IndexFile: idx}); !errors.Is(err, ErrStale) {
		t.Fatal("client without clock")
	}
	bad := e.verifier()
	bad.MinWitnesses = 2
	if _, err := Open(Options{Store: e.st, Verifier: bad, IndexFile: idx}); !errors.Is(err, ErrWitness) {
		t.Fatal("client with an inadmissible quorum")
	}
	bad = e.verifier()
	bad.Last = &Head{Size: MaxTreeSize + 1}
	if _, err := Open(Options{Store: e.st, Verifier: bad, IndexFile: idx}); !errors.Is(err, ErrHead) {
		t.Fatal("client with a Last beyond MaxTreeSize")
	}
	// A Last whose tree is not in the data directory.
	bad = e.verifier()
	bad.Last = &Head{Origin: testOrigin, Size: 7, Time: t0}
	if _, err := Open(Options{Store: e.st, Verifier: bad, IndexFile: idx}); !errors.Is(err, ErrConsistency) {
		t.Fatal("client with a Last beyond the log")
	}
	// tree.rec missing beside entries.
	if err := os.Remove(e.path(TreeFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Store: e.st, Identities: e.p.ids(t, 1)}); !errors.Is(err, ErrConsistency) {
		t.Fatal("entries without tree.rec")
	}
}

// TestDuplicateAndIdempotent: a second entry with a taken key is
// ErrDuplicate, the same content returns the same index.
func TestDuplicateAndIdempotent(t *testing.T) {
	e := newEnv(t, 1, 1)
	u := newUser(t)
	u1 := u.rec(t, 1)
	i := e.mustAppend(KindUser, u1)
	if j := e.mustAppend(KindUser, u1); j != i {
		t.Fatalf("idempotent append: %d != %d", j, i)
	}
	if err := e.op.AppendUser(u.id, u1); err != nil {
		t.Fatal(err)
	}
	// Another user.rec with the same ID and one generation (another
	// root): the key is taken.
	other := newUser(t)
	other.id = u.id
	if _, err := e.op.Append(KindUser, other.rec(t, 1)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	// The AppendX wrappers check the subject.
	if err := e.op.AppendUser(newMbx(t), u1); !errors.Is(err, ErrEntry) {
		t.Fatal("AppendUser with another ID")
	}
	mbx := newMbx(t)
	ep := mkEpoch(t, mbx, 1, nil, u, 1, []store.Member{member(u, 1)}, t0)
	if err := e.op.AppendEpoch(mbx, 2, ep); !errors.Is(err, ErrEntry) {
		t.Fatal("AppendEpoch with another number")
	}
	if err := e.op.AppendEpoch(mbx, 1, ep); err != nil {
		t.Fatal(err)
	}
	if err := e.op.AppendPlatform("admin-2.cert", e.p.cert(t, keys.RoleAdmin, 2, 1, t0)); err != nil {
		t.Fatal(err)
	}
	if err := e.op.AppendPlatform("admin-4.cert", e.p.cert(t, keys.RoleAdmin, 3, 1, t0)); !errors.Is(err, ErrEntry) {
		t.Fatal("AppendPlatform with another name")
	}
	if _, err := e.op.Append(KindUser, []byte("x")); !errors.Is(err, ErrEntry) {
		t.Fatal("garbage")
	}
	// A client's idempotent append of an uncovered entry is pending.
	c, v := e.client()
	if j, err := c.Append(KindUser, u1); err != nil || j != i {
		t.Fatal(err)
	}
	if len(v.Pending) != 1 || v.Pending[0].Index != i {
		t.Fatal("pending")
	}
	if j, err := c.Append(KindUser, u1); err != nil || j != i || len(v.Pending) != 1 {
		t.Fatal("pending twice")
	}
}

// TestUserRules covers the user rules of doc.go "Validity rules".
func TestUserRules(t *testing.T) {
	e := newEnv(t, 1, 1)
	u := newUser(t)
	u1, u2, u3 := u.rec(t, 1), u.rec(t, 2), u.rec(t, 3)
	if _, err := e.op.Append(KindUser, u2); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("generation 2 first: %v", err)
	}
	e.mustAppend(KindUser, u1)
	// Same ID, other root: never loggable.
	other := newUser(t)
	other.id = u.id
	other.rec(t, 1)
	if _, err := e.op.Append(KindUser, other.rec(t, 2)); !errors.Is(err, ErrOrder) {
		t.Fatalf("other root: %v", err)
	}
	e.mustAppend(KindUser, u2)
	if _, err := e.op.Append(KindUser, u1); !errors.Is(err, ErrDuplicate) && err != nil {
		t.Fatal(err)
	}
	e.mustAppend(KindUser, u3)
	e.head()
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckUser(u.id, u2); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("rolled back user.rec: %v", err)
	}
	if err := c.CheckUser(u.id, u3); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckUser(newMbx(t), u3); !errors.Is(err, ErrEntry) {
		t.Fatal("CheckUser with another ID")
	}
	if err := c.CheckUser(other.id, other.rec(t, 1)); !errors.Is(err, ErrMismatch) {
		t.Fatalf("other content: %v", err)
	}
	if err := e.op.CheckUser(u.id, u2); !errors.Is(err, ErrSuperseded) {
		t.Fatal("operator: rolled back user.rec")
	}
}

// TestEpochRules covers the epoch rules: foreign epoch numbers, unlogged
// signers, revoked signers and the chain.
func TestEpochRules(t *testing.T) {
	e := newEnv(t, 1, 1)
	alice, mallory := newUser(t), newUser(t)
	mbx := newMbx(t)
	ep1 := mkEpoch(t, mbx, 1, nil, alice, 1, []store.Member{member(alice, 1)}, t0)
	// The signer's user entry is missing.
	if _, err := e.op.Append(KindEpoch, ep1); !errors.Is(err, ErrUnloggedSigner) || !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("unlogged signer: %v", err)
	}
	e.mustAppend(KindUser, alice.rec(t, 1))
	e.mustAppend(KindUser, mallory.rec(t, 1))
	// Epoch 2 before epoch 1.
	ep2 := mkEpoch(t, mbx, 2, ep1, alice, 1, []store.Member{member(alice, 1)}, t0+1)
	if _, err := e.op.Append(KindEpoch, ep2); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("epoch 2 first: %v", err)
	}
	e.mustAppend(KindEpoch, ep1)
	// A foreign epoch number: mallory is no member of epoch 1.
	foreign := mkEpoch(t, mbx, 2, ep1, mallory, 1, []store.Member{member(mallory, 1), member(alice, 1)}, t0+1)
	if _, err := e.op.Append(KindEpoch, foreign); !errors.Is(err, ErrOrder) {
		t.Fatalf("foreign epoch: %v", err)
	}
	// Signature that does not verify with the logged identity key.
	fake := &tuser{root: mallory.root, id: alice.id}
	forged := mkEpoch(t, mbx, 2, ep1, fake, 1, []store.Member{member(alice, 1)}, t0+1)
	if _, err := e.op.Append(KindEpoch, forged); !errors.Is(err, ErrOrder) {
		t.Fatalf("forged signature: %v", err)
	}
	// Wrong prev_hash.
	wrong := mkEpoch(t, mbx, 2, []byte("other"), alice, 1, []store.Member{member(alice, 1)}, t0+1)
	if _, err := e.op.Append(KindEpoch, wrong); !errors.Is(err, ErrOrder) {
		t.Fatalf("wrong prev_hash: %v", err)
	}
	// The key (mbx, 2) is not taken: alice appends her epoch 2.
	i2 := e.mustAppend(KindEpoch, ep2)
	// Alice revokes generation 1; an epoch signed by it afterwards is
	// never loggable.
	e.mustAppend(KindUser, alice.rec(t, 2))
	ep3 := mkEpoch(t, mbx, 3, ep2, alice, 1, []store.Member{member(alice, 1)}, t0+2)
	if _, err := e.op.Append(KindEpoch, ep3); !errors.Is(err, ErrOrder) {
		t.Fatalf("revoked signer: %v", err)
	}
	// Signer generation above the logged one.
	ep3b := mkEpoch(t, mbx, 3, ep2, alice, 3, []store.Member{member(alice, 3)}, t0+2)
	if _, err := e.op.Append(KindEpoch, ep3b); !errors.Is(err, ErrUnloggedSigner) {
		t.Fatalf("unlogged generation: %v", err)
	}
	e.head()
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	// Revoked generation: the epoch logged before the revocation counts.
	if err := c.CheckRevokedSignature(alice.id, 1, ep2); err != nil {
		t.Fatal(err)
	}
	// Index comparison: a record logged after the revocation of gen.
	if err := c.CheckRevokedSignature(mallory.id, 0, ep2); !errors.Is(err, ErrNotInLog) {
		t.Fatal(err)
	}
	ep1m := mkEpoch(t, newMbx(t), 1, nil, mallory, 1, []store.Member{member(mallory, 1)}, t0)
	if _, err := c.Append(KindEpoch, ep1m); err != nil {
		t.Fatal(err)
	}
	e.head()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRevokedSignature(alice.id, 1, ep1m); !errors.Is(err, ErrOrder) {
		t.Fatalf("logged after the revocation: %v", err)
	}
	if err := c.CheckRevokedSignature(alice.id, 1, ep3); !errors.Is(err, ErrNotInLog) {
		t.Fatalf("never logged: %v", err)
	}
	if err := c.CheckRevokedSignature(alice.id, 1, []byte("x")); !errors.Is(err, ErrEntry) {
		t.Fatal("not a record")
	}
	if err := c.CheckRevokedSignature(alice.id, 1<<32-1, ep2); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckEpoch(mbx, 2, foreign); !errors.Is(err, ErrMismatch) {
		t.Fatalf("foreign epoch in store: %v", err)
	}
	if i2 != 5 {
		t.Fatalf("index of epoch 2: %d", i2)
	}
}

// TestAddressRules: order of valid_from, admin certificate, signature,
// and CheckAddress without and with a contradicting assignment.
func TestAddressRules(t *testing.T) {
	e := newEnv(t, 1, 1)
	m1, m2 := newMbx(t), newMbx(t)
	const a = "info@example.org"
	if _, err := e.op.Append(KindAddress, e.addr(t, a, m1, t0, 2)); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("admin 2 not logged: %v", err)
	}
	if _, err := e.op.Append(KindAddress, e.addr(t, a, m1, t0-2*day, 1)); !errors.Is(err, ErrOrder) {
		t.Fatalf("before the admin certificate: %v", err)
	}
	e.mustAppend(KindAddress, e.addr(t, a, m1, t0, 1))
	if _, err := e.op.Append(KindAddress, e.addr(t, a, m2, t0-1, 1)); !errors.Is(err, ErrOrder) {
		t.Fatalf("backdated: %v", err)
	}
	if _, err := e.op.Append(KindAddress, e.addr(t, a, m2, t0, 1)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("same valid_from: %v", err)
	}
	// Signed by another key than admin-1.
	as := &store.AddressAssignment{Address: a, MailboxID: m2, ValidFrom: t0 + day, AdminGen: 1}
	if err := as.Sign(e.p.admin(t, 2)); err != nil {
		t.Fatal(err)
	}
	forged, _ := as.Encode()
	if _, err := e.op.Append(KindAddress, forged); !errors.Is(err, ErrOrder) {
		t.Fatalf("forged admin signature: %v", err)
	}
	e.mustAppend(KindAddress, e.addr(t, a, m2, t0+day, 1))
	e.head()
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAddress(a, m1, t0-1); !errors.Is(err, ErrNotInLog) {
		t.Fatalf("before the first assignment: %v", err)
	}
	if err := c.CheckAddress("other@example.org", m1, t0); !errors.Is(err, ErrNotInLog) {
		t.Fatalf("address without assignment: %v", err)
	}
	if err := c.CheckAddress(a, m1, t0+day-1); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAddress(a, m2, t0+day-1); !errors.Is(err, ErrMismatch) {
		t.Fatalf("contradicting assignment: %v", err)
	}
	if err := c.CheckAddress(a, m2, t0+2*day); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAddress("Info@Example.org", m2, t0+2*day); !errors.Is(err, ErrEntry) {
		t.Fatal("not normalized")
	}
	if es, err := c.Lookup(KindAddress, []byte(a)); err != nil || len(es) != 2 {
		t.Fatal("Lookup of the address")
	}
}

// TestPlatformRules: generations, successions and the identity list.
func TestPlatformRules(t *testing.T) {
	e := newEnv(t, 1, 1)
	if _, err := e.op.Append(KindPlatform, e.p.cert(t, keys.RoleIngest, 3, 1, t0)); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("generation 3 before 2: %v", err)
	}
	if _, err := e.op.Append(KindPlatform, e.p.cert(t, keys.RoleIngest, 2, 2, t0)); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("identity 2 unknown: %v", err)
	}
	// A certificate signed by another key than its identity_gen.
	c2, err := keys.NewPlatformCert(e.p.identity(t, 2), 1, keys.RoleIngest, 2, e.p.ingest(t, 2).Public().(ed25519PublicKey), t0)
	if err != nil {
		t.Fatal(err)
	}
	bad, _ := c2.Encode()
	if _, err := e.op.Append(KindPlatform, bad); !errors.Is(err, ErrOrder) {
		t.Fatalf("wrong identity signature: %v", err)
	}
	if _, err := e.op.Append(KindPlatform, e.p.succ(t, 3, t0)); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("succession 3 before 2: %v", err)
	}
	e.mustAppend(KindPlatform, e.p.succ(t, 2, t0))
	e.mustAppend(KindPlatform, e.p.succ(t, 3, t0))
	e.mustAppend(KindPlatform, e.p.cert(t, keys.RoleAdmin, 2, 3, t0))
	// A succession signed by a key that is not generation g-1.
	other := newPlat(t)
	s4, err := keys.NewPlatformSuccession(other.identity(t, 3), 4, other.identity(t, 4).Public().(ed25519PublicKey), t0)
	if err != nil {
		t.Fatal(err)
	}
	bad, _ = s4.Encode()
	if _, err := e.op.Append(KindPlatform, bad); !errors.Is(err, ErrOrder) {
		t.Fatalf("succession by a foreign key: %v", err)
	}
	e.head()

	// A client with a pin of generation 3 (list 1..3) audits the log.
	e.idGen = 3
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckPlatform("identity-3.succ", e.p.succ(t, 3, t0)); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckPlatform("admin-2.cert", e.p.cert(t, keys.RoleAdmin, 2, 3, t0)); err != nil {
		t.Fatal(err)
	}
	// A succession whose generation is in the list but names another
	// key contradicts the pin.
	s3, _ := keys.NewPlatformSuccession(e.p.identity(t, 2), 3, other.identity(t, 3).Public().(ed25519PublicKey), t0)
	b3, _ := s3.Encode()
	if err := c.CheckPlatform("identity-3.succ", b3); !errors.Is(err, ErrMismatch) {
		t.Fatalf("succession against the pin: %v", err)
	}
	// An operator with that pin refuses such an entry.
	e2 := newEnvWith(t, e.p, e.ws, 1)
	e2.idGen = 3
	op2 := e2.openOp()
	if _, err := op2.Append(KindPlatform, e.p.succ(t, 2, t0)); err != nil {
		t.Fatal(err)
	}
	if _, err := op2.Append(KindPlatform, b3); !errors.Is(err, ErrMismatch) {
		t.Fatalf("operator: succession against the pin: %v", err)
	}
	// Generations of the list need no logged succession.
	if _, err := op2.Append(KindPlatform, e.p.cert(t, keys.RoleIngest, 2, 3, t0)); err != nil {
		t.Fatalf("certificate by a listed generation: %v", err)
	}
}

// TestTamper: an entry removed or changed below a verified head, a
// changed tile, a rolled back tree.rec.
func TestTamper(t *testing.T) {
	e := newEnv(t, 1, 1)
	u := newUser(t)
	u1 := u.rec(t, 1)
	e.mustAppend(KindUser, u1)
	e.head()
	c, v := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(e.path(EntryPath(2)))
	if err != nil {
		t.Fatal(err)
	}
	// Changed: another valid entry of the same key.
	other := newUser(t)
	other.id = u.id
	changed, _ := (&Entry{Key: Key{Kind: KindUser, Subject: u.id[:], Seq: 1}, Content: other.rec(t, 1)}).Encode()
	if err := os.WriteFile(e.path(EntryPath(2)), changed, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckUser(u.id, u1); !errors.Is(err, ErrConsistency) {
		t.Fatalf("changed entry: %v", err)
	}
	p, err := e.op.InclusionProof(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.CheckInclusion(2, changed, p); !errors.Is(err, ErrConsistency) {
		t.Fatal("inclusion proof of a changed entry")
	}
	if _, err := e.op.Entry(2); !errors.Is(err, ErrConsistency) {
		t.Fatal("operator Entry of a changed entry")
	}
	if _, err := c.Entry(2); !errors.Is(err, ErrConsistency) {
		t.Fatal("client Entry of a changed entry")
	}
	// A new device rebuilds its index and fails.
	if _, err := Open(Options{Store: e.st, Verifier: &Verifier{Origin: v.Origin, Witnesses: v.Witnesses, MinWitnesses: 1,
		Identity: v.Identity, Identities: v.Identities, Last: v.Last, Now: v.Now}, IndexFile: filepath.Join(t.TempDir(), "i")}); !errors.Is(err, ErrConsistency) {
		t.Fatalf("rebuild over a changed entry: %v", err)
	}
	// Removed.
	if err := os.Remove(e.path(EntryPath(2))); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckUser(u.id, u1); !errors.Is(err, ErrConsistency) {
		t.Fatalf("removed entry: %v", err)
	}
	if err := os.WriteFile(e.path(EntryPath(2)), orig, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckUser(u.id, u1); err != nil {
		t.Fatal(err)
	}
	// A changed tile: Open refuses, the client's proofs fail.
	tile := e.path(TilePath(tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}))
	tdata, err := os.ReadFile(tile)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), tdata...)
	bad[0] ^= 1
	if err := os.WriteFile(tile, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Store: e.st, Identities: e.p.ids(t, 1)}); !errors.Is(err, ErrConsistency) {
		t.Fatal("Open over a changed tile")
	}
	if err := c.CheckUser(u.id, u1); !errors.Is(err, ErrConsistency) {
		t.Fatalf("proof over a changed tile: %v", err)
	}
	if err := os.WriteFile(tile, tdata, 0o644); err != nil {
		t.Fatal(err)
	}
	// tree.rec damaged.
	if err := os.WriteFile(e.path(TreeFile), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.op.Append(KindUser, newUser(t).rec(t, 1)); !errors.Is(err, ErrConsistency) {
		t.Fatal("append over a damaged tree.rec")
	}
}

// TestRollback: tree.rec rolled back; Append refuses and deletes
// nothing (task 03d finding 3).
func TestRollback(t *testing.T) {
	e := newEnv(t, 1, 1)
	u := newUser(t)
	e.mustAppend(KindUser, u.rec(t, 1))
	e.mustAppend(KindUser, u.rec(t, 2))
	// Roll back by two entries: entries/<n+1>.rec exists.
	h2, err := tlog.TreeHash(2, e.hashReader())
	if err != nil {
		t.Fatal(err)
	}
	full := e.tree()
	f := &files{root: e.st.Root}
	if err := f.writeTree(treeState{Size: 2, Hash: h2}); err != nil {
		t.Fatal(err)
	}
	op := e.openOp()
	if _, err := op.Append(KindUser, newUser(t).rec(t, 1)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("rolled back by two: %v", err)
	}
	for i := int64(0); i < 4; i++ {
		if _, err := os.Stat(e.path(EntryPath(i))); err != nil {
			t.Fatalf("entry %d deleted", i)
		}
	}
	// Roll back by one below a published head: refused as well.
	if err := f.writeTree(full); err != nil {
		t.Fatal(err)
	}
	e.head()
	h3, err := tlog.TreeHash(3, e.hashReader())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.writeTree(treeState{Size: 3, Hash: h3}); err != nil {
		t.Fatal(err)
	}
	if _, err := op.Append(KindUser, newUser(t).rec(t, 1)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("rolled back below a head: %v", err)
	}
	if _, err := os.Stat(e.path(EntryPath(3))); err != nil {
		t.Fatal("entry 3 deleted")
	}
	// Repaired: appends continue.
	if err := f.writeTree(full); err != nil {
		t.Fatal(err)
	}
	if _, err := e.openOp().Append(KindUser, newUser(t).rec(t, 1)); err != nil {
		t.Fatal(err)
	}
	// A client whose head is beyond tree.rec refuses to append.
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if err := f.writeTree(treeState{Size: 3, Hash: h3}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.path(HeadPath(4))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.path(EntryPath(4))); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(KindUser, newUser(t).rec(t, 1)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("client behind tree.rec: %v", err)
	}
}

// TestCrash interrupts Append after each of its writes; Open and a new
// Append heal the log.
func TestCrash(t *testing.T) {
	e := newEnv(t, 1, 1)
	errCrash := errors.New("crash")
	for _, step := range []string{"entry", "tiles", "key", "tree"} {
		u := newUser(t)
		data := u.rec(t, 1)
		size := e.tree().Size
		crashHook = func(s string) error {
			if s == step {
				return errCrash
			}
			return nil
		}
		_, err := e.op.Append(KindUser, data)
		crashHook = nil
		if !errors.Is(err, errCrash) {
			t.Fatalf("%s: %v", step, err)
		}
		e.op = e.openOp()
		i, err := e.op.Append(KindUser, data)
		if err != nil || i != size {
			t.Fatalf("after a crash at %s: %d %v", step, i, err)
		}
		if err := e.op.CheckUser(u.id, data); err != nil {
			t.Fatal(err)
		}
		if _, err := e.op.Append(KindUser, newUser(t).rec(t, 1)); err != nil {
			t.Fatal(err)
		}
	}
	e.head()
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if n := len(c.Invalid()); n != 0 {
		t.Fatalf("%d invalid entries", n)
	}
}

// TestManyEntries crosses a tile boundary (256 entries).
func TestManyEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	e := newEnv(t, 1, 1)
	mbx := newMbx(t)
	c, _ := e.client()
	var first *Head
	for i := 0; i < 260; i++ {
		e.mustAppend(KindAddress, e.addr(t, "a@example.org", mbx, t0+int64(i), 1))
		if i == 100 {
			first = e.head()
			e.now = e.now.Add(time.Minute)
			if _, err := c.Refresh(e.now); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The client's Append brings its state from 103 to 262 entries,
	// across the tile boundary at 256, one tile per read (task 07b
	// finding 1).
	if i, err := c.Append(KindUser, newUser(t).rec(t, 1)); err != nil || i != 262 {
		t.Fatalf("client append across a tile boundary: %d %v", i, err)
	}
	e.head()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAddress("a@example.org", mbx, t0+259); err != nil {
		t.Fatal(err)
	}
	if _, err := e.op.ConsistencyProof(first.Size, 262); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Store: e.st, Identities: e.p.ids(t, 1)}); err != nil {
		t.Fatal(err)
	}
}

// TestHeadRules: a head without witness signature, with too few, too
// old, no continuation, in the future, with another origin, beyond
// MaxTreeSize.
func TestHeadRules(t *testing.T) {
	e := newEnv(t, 3, 2)
	c, v := e.client()
	h := e.headOf(e.now.UnixMilli())
	// Without witness signature.
	e.publish(h, e.signer)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrWitness) {
		t.Fatalf("no witness: %v", err)
	}
	// Too few witnesses.
	e.publish(h, e.signer, e.ws[0].signer)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrWitness) {
		t.Fatalf("one of two witnesses: %v", err)
	}
	// Without log signature.
	e.publish(h, e.ws[0].signer, e.ws[1].signer)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("no log signature: %v", err)
	}
	// Another origin.
	o := *h
	o.Origin = "other"
	e.publish(&o, e.all()...)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("other origin: %v", err)
	}
	// In the future.
	f := *h
	f.Time = e.now.Add(MaxClockSkew + time.Second).UnixMilli()
	e.publish(&f, e.all()...)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("future head: %v", err)
	}
	// Quorum reached.
	e.publish(h, e.signer, e.ws[0].signer, e.ws[2].signer)
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if v.Last.Size != 2 {
		t.Fatal("size")
	}
	// Older than 24 hours.
	if err := c.CheckFresh(e.now.Add(24*time.Hour + time.Millisecond)); !errors.Is(err, ErrStale) || errors.Is(err, ErrWithheld) {
		t.Fatalf("stale: %v", err)
	}
	if err := c.CheckFresh(e.now.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Earlier time for the same size.
	early := *h
	early.Time--
	e.publish(&early, e.all()...)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("earlier time: %v", err)
	}
	// Same size, another hash: a split view.
	split := *h
	split.Hash[0] ^= 1
	split.Time++
	e.publish(&split, e.all()...)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("same size, other hash: %v", err)
	}
	// Same size, later time: a re-signature.
	e.now = e.now.Add(time.Hour)
	e.head()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	// A larger head that does not extend the last one.
	e.mustAppend(KindUser, newUser(t).rec(t, 1))
	nc := e.headOf(e.now.UnixMilli())
	nc.Hash[0] ^= 1
	e.publish(nc, e.all()...)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("no continuation: %v", err)
	}
	// A smaller head after heads/ lost the newer ones.
	for _, n := range []int64{2, 3} {
		if err := os.Remove(e.path(HeadPath(n))); err != nil {
			t.Fatal(err)
		}
	}
	// Task 14b point 2: an older view of the same log only warns
	// (ErrOlderHead) and is never taken over; a smaller head that
	// contradicts the reference head, or one signed after it, is
	// ErrConsistency; one without the quorum keeps ErrWitness.
	h1 := &Head{Origin: testOrigin, Size: 1, Time: e.now.UnixMilli()}
	h1.Hash, _ = tlog.TreeHash(1, e.hashReader())
	ref := *v.Last
	e.publish(h1, e.all()...)
	if got, err := c.Refresh(e.now); !errors.Is(err, ErrOlderHead) || got.Size != ref.Size || v.Last.Size != ref.Size {
		t.Fatalf("smaller head: %v", err)
	}
	if err := c.CheckFresh(e.now); err != nil {
		t.Fatalf("CheckFresh with an older head published: %v", err)
	}
	later := *h1
	later.Time = ref.Time + 1
	e.publish(&later, e.all()...)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("smaller head signed later: %v", err)
	}
	other := *h1
	other.Hash[0] ^= 1
	e.publish(&other, e.all()...)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("smaller head of another tree: %v", err)
	}
	e.publish(h1, e.signer)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrWitness) {
		t.Fatalf("smaller head without the quorum: %v", err)
	}
	e.publish(h1, e.all()...)
	if v.Last.Size != ref.Size || v.Last.Hash != ref.Hash {
		t.Fatal("reference head changed")
	}
	// A head file with an invalid witness line does not open.
	good := sign(t, e.headOf(e.now.UnixMilli()), e.all()...)
	if err := store.WriteFileAtomic(e.path(HeadPath(3)), bytes.Replace(good, []byte("— witness-0 "), []byte("— witness-0 A"), 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("poisoned head: %v", err)
	}
	// Beyond MaxTreeSize: CheckHead refuses before any proof.
	big := &Head{Origin: testOrigin, Size: MaxTreeSize + 1, Time: e.now.UnixMilli()}
	if err := v.CheckHead(big, nil); !errors.Is(err, ErrHead) {
		t.Fatal("head beyond MaxTreeSize")
	}
	if _, err := ParseHeadText([]byte("gomail-test\n1099511627777\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\ntime 1\n")); !errors.Is(err, ErrHead) {
		t.Fatal("parse beyond MaxTreeSize")
	}
	// A file named beyond MaxTreeSize is ignored.
	if err := os.WriteFile(e.path(HeadsDir+"/1099511627777.sig"), good, 0o644); err != nil {
		t.Fatal(err)
	}
	if n, _ := (&files{root: e.st.Root}).newestHeadSize(); n != 3 {
		t.Fatal("head beyond MaxTreeSize listed")
	}
}

// TestWithheld: an own entry withheld by the server (ErrWithheld)
// against an outage (ErrStale).
func TestWithheld(t *testing.T) {
	for _, withheld := range []bool{true, false} {
		e := newEnv(t, 1, 1)
		e.head()
		c, v := e.client()
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatal(err)
		}
		u := newUser(t)
		i, err := c.Append(KindUser, u.rec(t, 1))
		if err != nil || len(v.Pending) != 1 || v.Pending[0].Index != i {
			t.Fatal("pending", err)
		}
		if withheld {
			// The server re-signs the old size more than HeadInterval
			// after the append.
			e.now = e.now.Add(HeadInterval + time.Minute)
			h := &Head{Origin: testOrigin, Size: 2, Hash: v.Last.Hash, Time: e.now.UnixMilli()}
			e.publish(h, e.all()...)
			if _, err := c.Refresh(e.now); !errors.Is(err, ErrWithheld) || !errors.Is(err, ErrStale) {
				t.Fatalf("withheld: %v", err)
			}
			if err := c.CheckFresh(e.now); !errors.Is(err, ErrWithheld) {
				t.Fatal("Fresh with a withheld entry")
			}
			continue
		}
		// Outage: no new head; the entry stays pending.
		e.now = e.now.Add(MaxPendingHeadAge)
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatalf("outage within the limit: %v", err)
		}
		if err := c.CheckUser(u.id, u.rec(t, 1)); !errors.Is(err, ErrPending) {
			t.Fatalf("own entry: %v", err)
		}
		e.now = e.now.Add(time.Millisecond)
		if _, err := c.Refresh(e.now); !errors.Is(err, ErrStale) || errors.Is(err, ErrWithheld) {
			t.Fatalf("outage beyond MaxPendingHeadAge: %v", err)
		}
		// A covering head ends it.
		e.head()
		if _, err := c.Refresh(e.now); err != nil || len(v.Pending) != 0 {
			t.Fatalf("covered: %v", err)
		}
	}
}

// TestPendingLeaf: a head covering the own index with another entry is
// ErrConsistency.
func TestPendingLeaf(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.head()
	c, v := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(KindUser, newUser(t).rec(t, 1)); err != nil {
		t.Fatal(err)
	}
	v.Pending[0].Leaf[0] ^= 1
	e.head()
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("own entry replaced: %v", err)
	}
}

// TestIngestRotation: the first head of a new ingest generation, signed
// by it alone in the tree that logs its certificate, is accepted; the
// old generation signs no head from the switch time on.
func TestIngestRotation(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.head()
	c, v := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	sw := e.now.Add(time.Hour).UnixMilli()
	cert2 := e.p.cert(t, keys.RoleIngest, 2, 1, sw)
	if err := e.st.WritePlatformFile("ingest-2.cert", cert2); err != nil {
		t.Fatal(err)
	}
	e.mustAppend(KindPlatform, cert2)
	e.now = time.UnixMilli(sw)
	// Signed by generation 1 at the switch time: refused.
	e.head()
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("old generation after the switch: %v", err)
	}
	// Signed by generation 2 before its valid_from: refused.
	e.signer = e.logSigner(2)
	h := e.headOf(sw - 1)
	e.publish(h, e.all()...)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("new generation before valid_from: %v", err)
	}
	// Signed by generation 2 from the switch on: accepted, although the
	// certificate became a logged entry only in this very head.
	e.head()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	var g2 *LogKey
	for i := range v.LogKeys {
		if v.LogKeys[i].Gen == 2 {
			g2 = &v.LogKeys[i]
		}
	}
	if g2 == nil || !g2.Logged || g2.ValidFrom != sw {
		t.Fatal("log key of generation 2")
	}
	// A new device accepts it too.
	c2, _ := e.client()
	if _, err := c2.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	// An unlogged certificate in platform/ opens heads but signs none.
	cert3 := e.p.cert(t, keys.RoleIngest, 3, 1, sw+1)
	if err := e.st.WritePlatformFile("ingest-3.cert", cert3); err != nil {
		t.Fatal(err)
	}
	e.signer = e.logSigner(3)
	e.now = e.now.Add(time.Minute)
	e.head()
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("unlogged generation: %v", err)
	}
}

// TestSuccessionAbovePin: a client with an older pin (generation 1)
// follows a logged succession to generation 2 and accepts an ingest
// certificate signed by it, from platform/ before the head and from the
// log afterwards.
func TestSuccessionAbovePin(t *testing.T) {
	e := newEnv(t, 1, 1)
	c, _ := e.client()
	s2 := e.p.succ(t, 2, t0)
	if err := e.st.WritePlatformFile("identity-2.succ", s2); err != nil {
		t.Fatal(err)
	}
	e.mustAppend(KindPlatform, s2)
	sw := e.now.Add(time.Minute).UnixMilli()
	cert2 := e.p.cert(t, keys.RoleIngest, 2, 2, sw)
	if err := e.st.WritePlatformFile("ingest-2.cert", cert2); err != nil {
		t.Fatal(err)
	}
	e.mustAppend(KindPlatform, cert2)
	e.now = time.UnixMilli(sw)
	e.signer = e.logSigner(2)
	e.head()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckPlatform("ingest-2.cert", cert2); err != nil {
		t.Fatal(err)
	}
	// platform/ loses the files: the logged entries still yield the key.
	for _, n := range []string{"identity-2.succ", "ingest-2.cert"} {
		if err := os.Remove(e.path("platform/" + n)); err != nil {
			t.Fatal(err)
		}
	}
	e.now = e.now.Add(time.Minute)
	e.head()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
}

// TestNewPin: an audit index built for another identity list is
// rebuilt from entry 0.
func TestNewPin(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.mustAppend(KindPlatform, e.p.succ(t, 2, t0))
	e.head()
	c, v := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	idx := c.opts.IndexFile
	e.idGen = 2
	nv := e.verifier()
	nv.Last = v.Last
	l, err := Open(Options{Store: e.st, Verifier: nv, IndexFile: idx})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.CheckPlatform("identity-2.succ", e.p.succ(t, 2, t0)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	s, err := unmarshalState(data, nil, nil)
	if err != nil || s.Anchor != anchorHash(e.p.ids(t, 2)) {
		t.Fatal("index not rebuilt for the new pin")
	}
}

// TestInvalidEntries: entries written past Append are skipped by the
// audit, occupy no key and are reported.
func TestInvalidEntries(t *testing.T) {
	e := newEnv(t, 1, 1)
	u := newUser(t)
	mbx := newMbx(t)
	ep1 := mkEpoch(t, mbx, 1, nil, u, 1, []store.Member{member(u, 1)}, t0)
	f := &files{root: e.st.Root}
	// Write entries without the validity rules: the epoch before its
	// signer, garbage, then the real records.
	raw := func(kind Kind, content []byte) {
		t.Helper()
		var enc []byte
		if content == nil {
			enc = []byte("garbage")
		} else {
			en, err := NewEntry(kind, content)
			if err != nil {
				t.Fatal(err)
			}
			if enc, err = en.Encode(); err != nil {
				t.Fatal(err)
			}
		}
		tr := e.tree()
		if _, err := (&fileLog{f: f}).write(tr, Key{Kind: kind, Subject: []byte("x")}, enc); err != nil {
			t.Fatal(err)
		}
	}
	raw(KindEpoch, ep1)
	raw(KindUser, nil)
	e.op = e.openOp()
	if got := e.op.(*operatorLog).Invalid(); len(got) != 2 || got[0].Class != "unlogged-signer" || got[1].Class != "entry" {
		t.Fatalf("invalid entries %v", got)
	}
	e.mustAppend(KindUser, u.rec(t, 1))
	i := e.mustAppend(KindEpoch, ep1)
	if i != 5 {
		t.Fatalf("epoch index %d", i)
	}
	raw(KindEpoch, ep1)
	e.head()
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	inv := c.Invalid()
	if len(inv) != 3 || inv[2].Index != 6 || inv[2].Class != "duplicate" {
		t.Fatalf("client invalid entries %v", inv)
	}
	if es, err := c.Lookup(KindEpoch, mbx[:]); err != nil || len(es) != 1 || es[0].Index != 5 {
		t.Fatal("Lookup returns an invalid entry")
	}
}

// TestSplitView: two clients shown different heads of one size get a
// quorum for both only when at least 2*min - n witnesses collude
// (doc.go "Witness quorum"), tested with 1 of 1 and 3 of 3.
func TestSplitView(t *testing.T) {
	for _, q := range []struct{ n, min int }{{1, 1}, {3, 3}} {
		for colluding := 0; colluding <= q.n; colluding++ {
			p := newPlat(t)
			ws := newWitnesses(t, q.n)
			a := newEnvWith(t, p, ws, q.min)
			b := newEnvWith(t, p, ws, q.min)
			a.mustAppend(KindUser, newUser(t).rec(t, 1))
			b.mustAppend(KindUser, newUser(t).rec(t, 1))
			ha, hb := a.headOf(t0), b.headOf(t0)
			if ha.Size != hb.Size || ha.Hash == hb.Hash {
				t.Fatal("fork")
			}
			// Each witness cosigns at most one head per size unless it
			// colludes with the server.
			seen := make([]map[int64]tlog.Hash, q.n)
			cosign := func(h *Head) []noteSigner {
				var out []noteSigner
				for i, w := range ws {
					if seen[i] == nil {
						seen[i] = map[int64]tlog.Hash{}
					}
					if prev, ok := seen[i][h.Size]; ok && prev != h.Hash && i >= colluding {
						continue
					}
					seen[i][h.Size] = h.Hash
					out = append(out, w.signer)
				}
				return out
			}
			a.publish(ha, append([]noteSigner{a.signer}, cosign(ha)...)...)
			b.publish(hb, append([]noteSigner{b.signer}, cosign(hb)...)...)
			ca, _ := a.client()
			cb, _ := b.client()
			_, errA := ca.Refresh(a.now)
			_, errB := cb.Refresh(b.now)
			both := errA == nil && errB == nil
			if both != (colluding >= 2*q.min-q.n) {
				t.Fatalf("%d of %d with %d colluding: %v / %v", q.min, q.n, colluding, errA, errB)
			}
			if !both && (errA != nil || !errors.Is(errB, ErrWitness)) {
				t.Fatalf("%d of %d with %d colluding: %v / %v", q.min, q.n, colluding, errA, errB)
			}
		}
	}
}

// TestQuorumInPin: an inadmissible quorum is refused by the pin and by
// the Verifier.
func TestQuorumInPin(t *testing.T) {
	e := newEnv(t, 2, 2)
	ids := e.p.ids(t, 1)
	pin := &store.PlatformPin{Gen: 1, Pub: ids[0].Pub, Origin: testOrigin, MinWitnesses: 1,
		Witnesses:  []store.Witness{{Name: "a", Pub: e.ws[0].pub}, {Name: "b", Pub: e.ws[1].pub}},
		Identities: []store.PlatformIdentity{{Gen: 1, Pub: ids[0].Pub}}}
	if _, err := pin.Encode(); err == nil {
		t.Fatal("pin with 1 of 2")
	}
	v := e.verifier()
	v.MinWitnesses = 1
	e.head()
	if err := v.CheckHead(e.headOf(t0), nil); !errors.Is(err, ErrWitness) {
		t.Fatal("verifier with 1 of 2")
	}
}

// TestCheckpoint covers Verifier.CheckCheckpoint.
func TestCheckpoint(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.head()
	small := e.headOf(t0)
	e.mustAppend(KindUser, newUser(t).rec(t, 1))
	e.now = e.now.Add(time.Minute)
	e.head()
	c, v := e.client()
	if err := v.CheckCheckpoint(testOrigin, 2, small.Hash, t0, nil); !errors.Is(err, ErrStale) {
		t.Fatal("no reference head")
	}
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	last := v.Last
	proof, err := e.op.ConsistencyProof(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		origin string
		size   int64
		hash   tlog.Hash
		time   int64
		proof  tlog.TreeProof
		want   error
	}{
		{testOrigin, 3, last.Hash, last.Time, nil, nil},
		{testOrigin, 3, last.Hash, last.Time + 1, nil, nil},
		{testOrigin, 3, last.Hash, 0, nil, nil},
		{testOrigin, 3, small.Hash, last.Time, nil, ErrConsistency},
		{testOrigin, 2, small.Hash, t0, proof, nil},
		{testOrigin, 2, small.Hash, last.Time, proof, nil},
		{testOrigin, 2, small.Hash, last.Time + 1, proof, ErrConsistency},
		{testOrigin, 2, last.Hash, t0, proof, ErrConsistency},
		{testOrigin, 4, last.Hash, last.Time, nil, ErrPending},
		{"other", 3, last.Hash, last.Time, nil, ErrHead},
		{testOrigin, 0, last.Hash, last.Time, nil, ErrHead},
		{testOrigin, MaxTreeSize + 1, last.Hash, last.Time, nil, ErrHead},
		{testOrigin, 3, last.Hash, -1, nil, ErrHead},
	} {
		err := v.CheckCheckpoint(x.origin, x.size, x.hash, x.time, x.proof)
		if (x.want == nil) != (err == nil) || (x.want != nil && !errors.Is(err, x.want)) {
			t.Fatalf("%+v: %v", x, err)
		}
	}
}

// TestRewrittenLog: an entry below a verified head is changed and the
// whole tree recomputed (tiles, tree.rec): the consistency proof of the
// next head fails.
func TestRewrittenLog(t *testing.T) {
	p, ws := newPlat(t), newWitnesses(t, 1)
	a := newEnvWith(t, p, ws, 1)
	b := newEnvWith(t, p, ws, 1)
	a.mustAppend(KindUser, newUser(t).rec(t, 1))
	b.mustAppend(KindUser, newUser(t).rec(t, 1))
	b.mustAppend(KindUser, newUser(t).rec(t, 1))
	a.head()
	c, _ := a.client()
	if _, err := c.Refresh(a.now); err != nil {
		t.Fatal(err)
	}
	// The attacker replaces log/ of a by the rewritten log b.
	if err := os.RemoveAll(a.path(Dir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(b.path(Dir), a.path(Dir)); err != nil {
		t.Fatal(err)
	}
	a.now = a.now.Add(time.Minute)
	a.head()
	if _, err := c.Refresh(a.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("rewritten log: %v", err)
	}
}
