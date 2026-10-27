package client_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of tasks 06e and 06f: wraps are issued again (device lost, Sync)
// only for the members the signed epoch.rec names and for readers of past
// periods whose template a valid generation signed, and only after the
// old wrap checked as the template.

// plantWrap writes epochs/<n>/members/<victim>.wrap of mbx: a parseable
// wrap for recipient victim with generation gen, with garbage keys, whose
// trailer names signer (ID, signerGen) and carries a signature by key, or
// by a random key if key is nil. It is what a writer of the data
// directory can plant, with a key of the signer if he has one (a thief
// with the key store of a lost device). It returns the file.
func plantWrap(t *testing.T, env *testenv.Env, mbx store.ID, n uint32, victim store.ID, gen uint32, signer store.ID, signerGen uint32, key ed25519.PrivateKey) []byte {
	t.Helper()
	priv, err := ecdhGen()
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := envelope.Seal(
		envelope.Header{Kind: envelope.KindWrap, MailboxID: mbx, Epoch: n, FileID: victim, Created: env.Clock.Now().UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientUserUnwrap, ID: victim, Gen: gen, PublicKey: priv.PublicKey()}},
		[]byte("garbage"), &envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerUser, ID: signer, Gen: signerGen, Key: key}})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Store.WriteWrap(mbx, n, victim, data); err != nil {
		t.Fatal(err)
	}
	return data
}

// plantOwnWrapWithKeys writes members/<u>.wrap of epoch n of mbx, sealed
// for generation gen of u (unwrap key derived from the seed words, as the
// thief of a device has it) and signed by generation gen of u, holding
// well-formed epoch keys that are not those of epoch.rec: unlike plantWrap
// the wrap opens and its keys decode, only Matches tells them apart. It
// returns the file.
func plantOwnWrapWithKeys(t *testing.T, env *testenv.Env, mbx store.ID, n uint32, u *testenv.User, gen uint32) []byte {
	t.Helper()
	seed, err := keys.SeedFromWords(u.Words)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	d := keys.DeriveUser(seed)
	defer d.Zero()
	identity, err := d.IdentityKey(gen)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe(identity)
	unwrap, err := d.UnwrapKey(gen)
	if err != nil {
		t.Fatal(err)
	}
	content, err := ecdhGen()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := ecdhGen()
	if err != nil {
		t.Fatal(err)
	}
	k := &store.EpochKeys{MailboxID: mbx, Epoch: n, Content: content, Meta: meta}
	plain, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe(plain)
	data, err := envelope.Seal(
		envelope.Header{Kind: envelope.KindWrap, MailboxID: mbx, Epoch: n, FileID: u.ID, Created: env.Clock.Now().UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientUserUnwrap, ID: u.ID, Gen: gen, PublicKey: unwrap.PublicKey()}},
		plain, &envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerUser, ID: u.ID, Gen: gen, Key: identity}})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Store.WriteWrap(mbx, n, u.ID, data); err != nil {
		t.Fatal(err)
	}
	return data
}

// acceptAs writes members/<u>.accept of epoch n over wrap, signed by the
// current generation of u: what u (colluding with a writer of the data
// directory) can always write.
func acceptAs(t *testing.T, env *testenv.Env, u *testenv.User, mbx store.ID, n uint32, wrap []byte) {
	t.Helper()
	ks := env.Keystore(u)
	defer ks.Zero()
	a := &store.WrapAccept{MailboxID: mbx, Epoch: n, UserID: u.ID, WrapHash: sha256Sum(wrap), UserGen: ks.Generation}
	if err := a.Sign(ks.Identity); err != nil {
		t.Fatal(err)
	}
	if err := env.Store.WriteAccept(a); err != nil {
		t.Fatal(err)
	}
}

// identityOf derives the identity key of generation gen from seed words.
func identityOf(t *testing.T, words []string, gen uint32) ed25519.PrivateKey {
	t.Helper()
	seed, err := keys.SeedFromWords(words)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	d := keys.DeriveUser(seed)
	defer d.Zero()
	id, err := d.IdentityKey(gen)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// cannotRead fails if u reads mail id of mbx.
func cannotRead(t *testing.T, env *testenv.Env, u *testenv.User, mbx, id store.ID) {
	t.Helper()
	if _, _, err := env.Reopen(u).Read(mbx, id); err == nil {
		t.Fatalf("%s reads the mail", u.ID)
	}
}

// notReissued checks that the warnings name id as not issued again and
// hold IDs and numbers only (no error text), and that each planted file
// is unchanged.
func notReissued(t *testing.T, env *testenv.Env, id store.ID, planted map[uint32][]byte, mbx store.ID) {
	t.Helper()
	found := false
	for _, w := range env.Warnings.Take() {
		if !strings.Contains(w, id.String()) {
			continue
		}
		if !strings.Contains(w, "wird nicht neu ausgestellt") {
			t.Fatalf("warning about %s: %s", id, w)
		}
		for _, bad := range []string{"client:", "envelope:", "store:", "garbage"} {
			if strings.Contains(w, bad) {
				t.Fatalf("warning holds more than IDs: %s", w)
			}
		}
		found = true
	}
	if !found {
		t.Fatalf("no warning names %s", id)
	}
	for n, data := range planted {
		if got := mustRead(t, env.Store.WrapFile(mbx, n, id)); string(got) != string(data) {
			t.Fatalf("wrap of epoch %d for %s was issued again", n, id)
		}
	}
}

// TestPlantedWrapSync: mallory is a registered user, never a member of
// alice's mailbox, and moves to generation 2. A writer of the data
// directory plants mallory.wrap (recipient generation 1) in every epoch,
// first signed in the name of mallory, then in the name of alice's valid
// generation 1, both with a random key. Alice's Sync issues nothing for
// mallory: she is in no member list and the wrap is no checked template
// (checkTemplate: signer not a member, signature); the warning names IDs
// only.
func TestPlantedWrapSync(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	mallory := f.env.NewUser("mallory")
	f.env.Rotate(mallory)
	for _, signer := range []*testenv.User{mallory, f.u} {
		gen := uint32(1)
		if signer == mallory {
			gen = 2
		}
		planted := map[uint32][]byte{}
		for _, e := range chainOf(t, f.env, f.mbx) {
			planted[e.Number] = plantWrap(t, f.env, f.mbx, e.Number, mallory.ID, 1, signer.ID, gen, nil)
		}
		f.env.Clock.Advance(time.Minute)
		f.env.Warnings.Take()
		if err := f.env.Reopen(f.u).Sync(); err != nil {
			t.Fatal(err)
		}
		notReissued(t, f.env, mallory.ID, planted, f.mbx)
		cannotRead(t, f.env, mallory, f.mbx, old.ID)
	}
	readBody(t, f.env, f.env.Reopen(f.u), f.mbx, old.ID, "secret")
}

// TestPlantedWrapDeviceLost: the planted mallory.wrap names alice's
// generation 1 as signer with a random key, and mallory countersigns it
// with her own generation (she colludes). Alice's device lost issues
// nothing for mallory: the signature does not check with the old key
// store, and a wrap-accept alone never counts.
func TestPlantedWrapDeviceLost(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	mallory := f.env.NewUser("mallory")
	planted := map[uint32][]byte{}
	for _, e := range chainOf(t, f.env, f.mbx) {
		planted[e.Number] = plantWrap(t, f.env, f.mbx, e.Number, mallory.ID, 1, f.u.ID, 1, nil)
		acceptAs(t, f.env, mallory, f.mbx, e.Number, planted[e.Number])
	}
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	notReissued(t, f.env, mallory.ID, planted, f.mbx)
	cannotRead(t, f.env, mallory, f.mbx, old.ID)
	readBody(t, f.env, f.u.Client, f.mbx, old.ID, "secret")
}

// TestNonMemberRevokedSignerDeviceLost: the thief of alice's device
// signs mallory.wrap with alice's real generation 1. Mallory is in no
// member list, so it is a wrap of a reader of a past period; signed by the
// generation that device lost revokes and without mallory's wrap-accept,
// it is not issued again.
func TestNonMemberRevokedSignerDeviceLost(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	mallory := f.env.NewUser("mallory")
	id1 := identityOf(t, f.u.Words, 1)
	defer keys.Wipe(id1)
	planted := map[uint32][]byte{}
	for _, e := range chainOf(t, f.env, f.mbx) {
		planted[e.Number] = plantWrap(t, f.env, f.mbx, e.Number, mallory.ID, 1, f.u.ID, 1, id1)
	}
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	notReissued(t, f.env, mallory.ID, planted, f.mbx)
	cannotRead(t, f.env, mallory, f.mbx, old.ID)
}

// TestNonMemberRevokedSignerSync: after alice's device lost, the thief
// plants mallory.wrap in every epoch signed with alice's revoked
// generation 1, for mallory's generation 1 (she moved to 2). Alice's Sync
// issues none of them again. Epoch 1: mallory is in no member list and
// has no wrap-accept. The epochs after the revocation list alice with
// generation 2, so a signature of generation 1 is no template there, even
// though mallory countersigns those wraps (she colludes): she never gets
// a key the thief does not have.
func TestNonMemberRevokedSignerSync(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	mallory := f.env.NewUser("mallory")
	f.env.Clock.Advance(time.Minute)
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	fresh := f.deliver(t, "fresh", "after the loss")
	f.env.Rotate(mallory)
	id1 := identityOf(t, f.u.Words, 1)
	defer keys.Wipe(id1)
	planted := map[uint32][]byte{}
	chain := chainOf(t, f.env, f.mbx)
	discarded := discardedOf(chain)
	after := 0
	for _, e := range chain {
		if discarded[e.Number] {
			continue
		}
		planted[e.Number] = plantWrap(t, f.env, f.mbx, e.Number, mallory.ID, 1, f.u.ID, 1, id1)
		if memberGen(e, f.u.ID) == 2 {
			acceptAs(t, f.env, mallory, f.mbx, e.Number, planted[e.Number])
			after++
		}
	}
	if after == 0 || len(planted) == after {
		t.Fatal("no epochs before and after the revocation")
	}
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	if err := f.env.Reopen(f.u).Sync(); err != nil {
		t.Fatal(err)
	}
	notReissued(t, f.env, mallory.ID, planted, f.mbx)
	cannotRead(t, f.env, mallory, f.mbx, old.ID)
	cannotRead(t, f.env, mallory, f.mbx, fresh.ID)
}

// pastPeriod moves the clock to the next month (epoch 2 in force) and
// lets alice share epoch 1 with each reader as a past period.
func pastPeriod(t *testing.T, f *fixture, readers ...*testenv.User) {
	t.Helper()
	f.env.Clock.Set(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC))
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	for _, r := range readers {
		if wrapped := f.env.Share(f.u, f.mbx, r, client.ShareOptions{From: 1, To: 1}); len(wrapped) != 1 {
			t.Fatalf("wrapped %v", wrapped)
		}
	}
}

// pastReaderWarned checks that the warnings name each reader as a reader
// of a past period not issued again, with the remedy Revoke, then Share.
func pastReaderWarned(t *testing.T, w string, readers ...*testenv.User) {
	t.Helper()
	for _, r := range readers {
		i := strings.Index(w, r.ID.String()+" (Leser eines vergangenen Zeitraums) wird nicht neu ausgestellt")
		if i < 0 || !strings.Contains(w[i:], "(Revoke, dann Share)") {
			t.Fatalf("no warning for %s: %s", r.ID, w)
		}
	}
}

// TestPastReaderDeviceLost: carol and dave read epoch 1 as a past period
// (Share with To). Carol has read it (her wrap-accept names her wrap),
// dave has not. After alice's device lost neither wrap is issued again:
// both templates are signed by alice's generation 1, which device lost
// revokes, and a wrap-accept is no proof (task 06f, TODO(Q15)); the
// warnings name both with the remedy Revoke, then Share. Carol still
// reads with her wrap-accept (S13), dave does not until alice shares anew.
func TestPastReaderDeviceLost(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "october")
	carol := f.env.NewUser("carol")
	dave := f.env.NewUser("dave")
	pastPeriod(t, f, carol, dave)
	readBody(t, f.env, carol.Client, f.mbx, old.ID, "october")
	f.env.Warnings.Take()
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	pastReaderWarned(t, strings.Join(f.env.Warnings.Take(), "\n"), carol, dave)
	for _, r := range []*testenv.User{carol, dave} {
		if tr := wrapOf(t, f.env, f.mbx, 1, r.ID).Trailer; tr.Signer.Gen != 1 {
			t.Fatalf("wrap of %s issued again", r.ID)
		}
	}
	readBody(t, f.env, f.env.Reopen(carol), f.mbx, old.ID, "october")
	if _, _, err := f.env.Reopen(dave).Read(f.mbx, old.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("dave without a new wrap: %v", err)
	}
	if err := f.u.Client.Revoke(f.mbx, dave.ID); err != nil {
		t.Fatal(err)
	}
	f.env.Share(f.u, f.mbx, dave, client.ShareOptions{From: 1, To: 1})
	readBody(t, f.env, f.env.Reopen(dave), f.mbx, old.ID, "october")
}

// TestPastReaderSync: carol reads epoch 1 as a past period and loses her
// device. On alice's Sync her wrap, signed by alice's valid generation 1,
// is issued for carol's generation 2.
func TestPastReaderSync(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "october")
	carol := f.env.NewUser("carol")
	pastPeriod(t, f, carol)
	readBody(t, f.env, carol.Client, f.mbx, old.ID, "october")
	if gen := f.env.DeviceLost(carol); gen != 2 {
		t.Fatal(gen)
	}
	if _, _, err := carol.Client.Read(f.mbx, old.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("carol before alice's Sync: %v", err)
	}
	f.env.Warnings.Take()
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(f.env.Warnings.Take(), "\n"); !strings.Contains(w, "für "+carol.ID.String()+" auf Generation 2 neu ausgestellt") {
		t.Fatalf("warnings: %s", w)
	}
	readBody(t, f.env, f.env.Reopen(carol), f.mbx, old.ID, "october")
}

// TestPastReaderSyncRevokedSigner: bob is a member from epoch 5 on;
// carol and dave read epoch 5 as a past period, with wraps alice signed
// with generation 1. Alice moves to generation 2 (testenv.Rotate), so
// those signatures are revoked. Carol loses her device: device lost
// countersigns her wrap with her generation 2 while it still checks; dave
// moves to generation 2 without device lost. On bob's Sync neither wrap is
// issued again (task 06f, TODO(Q15)): the template is signed by a revoked
// generation, and carol's wrap-accept is no proof (whoever holds alice's
// old key store can make such a template, and carol can countersign any
// file). Both are named with the remedy Revoke, then Share; after bob
// shares anew carol reads.
func TestPastReaderSyncRevokedSigner(t *testing.T) {
	f := newFixture(t)
	alice := f.u
	bob := f.env.NewUser("bob")
	carol := f.env.NewUser("carol")
	dave := f.env.NewUser("dave")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(alice, f.mbx, bob, client.ShareOptions{})
	shared := chainOf(t, f.env, f.mbx)[4]
	if shared.Number != 5 || shared.Reason != store.ReasonMemberAdded {
		t.Fatal("no member-added epoch 5")
	}
	m := f.deliver(t, "five", "epoch five")
	readBody(t, f.env, bob.Client, f.mbx, m.ID, "epoch five")
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Set(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC))
	for _, r := range []*testenv.User{carol, dave} {
		if wrapped := f.env.Share(alice, f.mbx, r, client.ShareOptions{From: 5, To: 5}); len(wrapped) != 1 {
			t.Fatalf("wrapped %v", wrapped)
		}
		readBody(t, f.env, r.Client, f.mbx, m.ID, "epoch five")
	}
	f.env.Rotate(alice)
	if gen := f.env.DeviceLost(carol); gen != 2 {
		t.Fatal(gen)
	}
	f.env.Rotate(dave)
	f.env.Warnings.Take()
	if err := f.env.Reopen(bob).Sync(); err != nil {
		t.Fatal(err)
	}
	w := strings.Join(f.env.Warnings.Take(), "\n")
	if strings.Contains(w, "für "+carol.ID.String()+" auf Generation 2 neu ausgestellt") {
		t.Fatalf("carol's wrap issued again: %s", w)
	}
	pastReaderWarned(t, w, carol, dave)
	for _, r := range []*testenv.User{carol, dave} {
		if tr := wrapOf(t, f.env, f.mbx, 5, r.ID).Trailer; store.ID(tr.Signer.ID) != alice.ID || tr.Signer.Gen != 1 {
			t.Fatalf("wrap of %s issued again", r.ID)
		}
		if _, _, err := f.env.Reopen(r).Read(f.mbx, m.ID); !errors.Is(err, client.ErrWrap) {
			t.Fatalf("%s: %v", r.ID, err)
		}
	}
	readBody(t, f.env, f.env.Reopen(alice), f.mbx, m.ID, "epoch five")
	bc := f.env.Reopen(bob)
	if err := bc.Revoke(f.mbx, carol.ID); err != nil {
		t.Fatal(err)
	}
	f.env.Share(bob, f.mbx, carol, client.ShareOptions{From: 5, To: 5})
	readBody(t, f.env, f.env.Reopen(carol), f.mbx, m.ID, "epoch five")
}

// TestAcceptOfOwnRevokedGeneration: a wrap for bob's generation 2,
// signed by alice's revoked generation 1, with an acceptance signed by
// bob's own revoked generation 1 is rejected (checkAccept); with an
// acceptance of bob's current generation 2 it is accepted.
func TestAcceptOfOwnRevokedGeneration(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 1})
	readBody(t, f.env, bob.Client, f.mbx, a.ID, "x")
	plain := ownEpochKeys(t, f.env, bob, f.mbx, 1)
	bobKs1 := f.env.Keystore(bob)
	defer bobKs1.Zero()
	f.env.Rotate(bob)
	f.env.Rotate(f.u)
	bobUser, _, err := f.env.Store.ReadUser(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	aliceID1 := identityOf(t, f.u.Words, 1)
	defer keys.Wipe(aliceID1)
	w2, err := envelope.Seal(
		envelope.Header{Kind: envelope.KindWrap, MailboxID: f.mbx, Epoch: 1, FileID: bob.ID, Created: f.env.Clock.Now().UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientUserUnwrap, ID: bob.ID, Gen: 2, PublicKey: bobUser.Current().UnwrapPub}},
		plain, &envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerUser, ID: f.u.ID, Gen: 1, Key: aliceID1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.env.Store.WriteWrap(f.mbx, 1, bob.ID, w2); err != nil {
		t.Fatal(err)
	}
	accept := func(ks *keys.Keystore) {
		acc := &store.WrapAccept{MailboxID: f.mbx, Epoch: 1, UserID: bob.ID, WrapHash: sha256Sum(w2), UserGen: ks.Generation}
		if err := acc.Sign(ks.Identity); err != nil {
			t.Fatal(err)
		}
		if err := f.env.Store.WriteAccept(acc); err != nil {
			t.Fatal(err)
		}
	}
	accept(bobKs1)
	bc := f.env.Reopen(bob)
	f.env.Warnings.Take()
	if _, _, err := bc.Read(f.mbx, a.ID); !errors.Is(err, client.ErrWrap) || !strings.Contains(err.Error(), "wrap-accept of epoch 1 is signed by generation 1") {
		t.Fatalf("acceptance by bob's revoked generation 1: %v", err)
	}
	bobKs2 := f.env.Keystore(bob)
	defer bobKs2.Zero()
	accept(bobKs2)
	readBody(t, f.env, f.env.Reopen(bob), f.mbx, a.ID, "x")
}

// TestPlantedOwnWrapDuringDeviceLost: after step 2 of device lost
// checked alice's own wrap of epoch 1, a writer of the data directory
// replaces it by a file that claims her new generation 2. Step 4 opens it
// with the new key store, rejects it with a warning and seals the wrap
// again from the keys checked in step 2: alice keeps the access.
func TestPlantedOwnWrapDuringDeviceLost(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	f.env.Clock.Advance(time.Minute)
	var planted []byte
	client.SetCrashHook(t, func(p string) bool {
		if p == "devicelost-prepared" {
			planted = plantWrap(t, f.env, f.mbx, 1, f.u.ID, 2, f.u.ID, 1, nil)
		}
		return false
	})
	f.env.Warnings.Take()
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	client.SetCrashHook(t, nil)
	if planted == nil {
		t.Fatal("not planted")
	}
	if w := strings.Join(f.env.Warnings.Take(), "\n"); !strings.Contains(w, "eigene Verpackung der Epoche 1") {
		t.Fatalf("warnings: %s", w)
	}
	if w := wrapOf(t, f.env, f.mbx, 1, f.u.ID); w.Recipients[0].Gen != 2 || w.Trailer.Signer.Gen != 2 || string(w.Bytes()) == string(planted) {
		t.Fatal("own wrap of epoch 1 not sealed again")
	}
	readBody(t, f.env, f.u.Client, f.mbx, old.ID, "secret")
}

// TestWordInputLimits: RecoverRead normalizes its words like device lost
// and Restore (case, white space); input with more than 512 words or an
// overlong word is rejected before it is normalized, with an error that
// does not name the input.
func TestWordInputLimits(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "before")
	pub, words := recoveryKey(t)
	f.env.Clock.Advance(time.Hour)
	if err := f.u.Client.SetRecovery(f.mbx, pub, yes); err != nil {
		t.Fatal(err)
	}
	rc, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, mess(words))
	if err != nil {
		t.Fatalf("recover read with case and white space: %v", err)
	}
	readBody(t, f.env, rc, f.mbx, old.ID, "before")
	rc.Close()

	junk := make([]string, 200000)
	for i := range junk {
		junk[i] = "zzzz"
	}
	long := []string{strings.Repeat("y", 40000)}
	many := []string{strings.Repeat("abc ", 513)}
	cfg := f.env.ClientConfig(f.u.Dir)
	f.u.Client.Close()
	for name, in := range map[string][]string{"elements": junk, "word": long, "words": many} {
		check := func(what string, err error) {
			t.Helper()
			if !errors.Is(err, client.ErrArgument) || strings.Contains(err.Error(), "zzzz") || strings.Contains(err.Error(), "yyy") || strings.Contains(err.Error(), "abc") {
				t.Fatalf("%s, %s: %v", what, name, err)
			}
		}
		_, err := client.DeviceLost(cfg, testenv.Passphrase, in)
		check("device lost", err)
		_, err = client.Restore(f.env.ClientConfig(t.TempDir()), client.RestoreOptions{Words: in}, testenv.Passphrase)
		check("restore", err)
		_, err = client.Restore(f.env.ClientConfig(t.TempDir()), client.RestoreOptions{Shares: [][]string{in, in}}, testenv.Passphrase)
		check("restore shares", err)
		_, err = client.RecoverRead(f.env.ClientConfig(""), f.mbx, in)
		check("recover read", err)
	}
}
