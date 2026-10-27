package client_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests that pin single rules of the reader and of the chain (task 06d):
// each test is built so that exactly one check of the client rejects the
// file, and each checks the warning or error of that check.

// ownEpochKeys opens the wrap of epoch n of u with u's current key store,
// without checking its signature, and returns the plaintext epoch keys.
func ownEpochKeys(t *testing.T, env *testenv.Env, u *testenv.User, mbx store.ID, n uint32) []byte {
	t.Helper()
	ks := env.Keystore(u)
	defer ks.Zero()
	data, err := env.Store.ReadWrap(mbx, n, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := parse(t, data).Decrypt(envelope.RecipientKey{Type: envelope.RecipientUserUnwrap, ID: u.ID, Gen: ks.Generation, PrivateKey: ks.Unwrap})
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

// sealWrap seals the epoch keys plain as a wrap for the current
// generation of user to, signed by the current generation of signer, with
// the given header (kind wrap).
func sealWrap(t *testing.T, env *testenv.Env, signer, to *testenv.User, h envelope.Header, plain []byte) []byte {
	t.Helper()
	sks := env.Keystore(signer)
	defer sks.Zero()
	u, _, err := env.Store.ReadUser(to.ID)
	if err != nil {
		t.Fatal(err)
	}
	h.Kind, h.Created = envelope.KindWrap, env.Clock.Now().UnixMilli()
	data, err := envelope.Seal(h,
		[]envelope.Recipient{{Type: envelope.RecipientUserUnwrap, ID: to.ID, Gen: u.Current().Gen, PublicKey: u.Current().UnwrapPub}},
		plain, &envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerUser, ID: signer.ID, Gen: sks.Generation, Key: sks.Identity}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// wrapHeader is the header of the wrap of epoch n of mbx for u.
func wrapHeader(mbx store.ID, n uint32, u *testenv.User) envelope.Header {
	return envelope.Header{MailboxID: mbx, Epoch: n, FileID: u.ID}
}

// readWith places wrap as u's wrap of epoch n, opens u's client again and
// reads mail id; it returns the error and the warnings of the attempt.
func readWith(t *testing.T, f *fixture, u *testenv.User, n uint32, wrap []byte, id store.ID) (string, error) {
	t.Helper()
	if err := f.env.Store.WriteWrap(f.mbx, n, u.ID, wrap); err != nil {
		t.Fatal(err)
	}
	c := f.env.Reopen(u)
	f.env.Warnings.Take()
	_, _, err := c.Read(f.mbx, id)
	return strings.Join(f.env.Warnings.Take(), "\n"), err
}

// TestWrapSignedByUserMemberOnly: a wrap with the right keys, for the
// right recipient and with the right header, is accepted only if a user
// member (kind 1) of its epoch signed it (D61): a registered user who is
// no member and a delegate (kind 3) of the epoch are rejected.
func TestWrapSignedByUserMemberOnly(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	bob := f.env.NewUser("bob")
	plain1 := ownEpochKeys(t, f.env, f.u, f.mbx, 1)
	// Control: the same wrap sealed again and signed by alice is valid.
	if w, err := readWith(t, f, f.u, 1, sealWrap(t, f.env, f.u, f.u, wrapHeader(f.mbx, 1, f.u), plain1), a.ID); err != nil {
		t.Fatalf("wrap signed by alice: %v (%s)", err, w)
	}
	// Signed by bob, registered but no member of epoch 1.
	w, err := readWith(t, f, f.u, 1, sealWrap(t, f.env, bob, f.u, wrapHeader(f.mbx, 1, f.u), plain1), a.ID)
	if !errors.Is(err, client.ErrWrap) || !strings.Contains(w, "non-member") {
		t.Fatalf("wrap signed by a non-member: %v (%s)", err, w)
	}

	// Bob becomes a delegate of the epochs from now on (epoch 5).
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{Delegate: true})
	f.env.Clock.Advance(time.Minute)
	m5 := f.deliver(t, "five", "y")
	e5, _, err := f.env.Store.ReadEpoch(f.mbx, 5)
	if err != nil || m5.Epoch != 5 || kindOf(e5, bob.ID) != store.MemberDelegate {
		t.Fatalf("epoch 5: %v", err)
	}
	plain5 := ownEpochKeys(t, f.env, f.u, f.mbx, 5)
	if w, err := readWith(t, f, f.u, 5, sealWrap(t, f.env, f.u, f.u, wrapHeader(f.mbx, 5, f.u), plain5), m5.ID); err != nil {
		t.Fatalf("wrap of epoch 5 signed by alice: %v (%s)", err, w)
	}
	w, err = readWith(t, f, f.u, 5, sealWrap(t, f.env, bob, f.u, wrapHeader(f.mbx, 5, f.u), plain5), m5.ID)
	if !errors.Is(err, client.ErrWrap) || !strings.Contains(w, "non-member") {
		t.Fatalf("wrap signed by a delegate: %v (%s)", err, w)
	}
	// The delegate's own wrap, signed by alice, stays valid for him.
	if _, _, err := bob.Client.Read(f.mbx, m5.ID); err != nil {
		t.Fatal(err)
	}
}

// TestWrapHeaderMustMatch: a wrap with the right keys, for the right
// recipient and signed by a user member, whose header names another
// epoch, another mailbox or another file ID than its location is
// rejected (ErrMismatch). The keys match epoch.rec, so only the header
// check rejects it.
func TestWrapHeaderMustMatch(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	bob := f.env.NewUser("bob")
	other, _ := store.NewID(nil)
	plain1 := ownEpochKeys(t, f.env, f.u, f.mbx, 1)
	for name, h := range map[string]envelope.Header{
		"epoch 2":         wrapHeader(f.mbx, 2, f.u),
		"another mailbox": wrapHeader(other, 1, f.u),
		"file ID of bob":  wrapHeader(f.mbx, 1, bob),
	} {
		w, err := readWith(t, f, f.u, 1, sealWrap(t, f.env, f.u, f.u, h, plain1), a.ID)
		if !errors.Is(err, client.ErrMismatch) {
			t.Errorf("wrap header with %s: %v (%s)", name, err, w)
		}
	}
	if w, err := readWith(t, f, f.u, 1, sealWrap(t, f.env, f.u, f.u, wrapHeader(f.mbx, 1, f.u), plain1), a.ID); err != nil {
		t.Fatalf("control: %v (%s)", err, w)
	}
}

// TestWrapKeysMustMatchEpoch: a wrap for the right recipient, with the
// right header and signed by a user member of its epoch, whose keys are
// not the keys of the signed epoch.rec, is rejected (store.EpochKeys.
// Matches, D61): the real keys of epoch 2 relabelled as epoch 1, and the
// real keys of epoch 1 labelled with another epoch number.
func TestWrapKeysMustMatchEpoch(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	plain1 := ownEpochKeys(t, f.env, f.u, f.mbx, 1)
	k2, err := store.DecodeEpochKeys(ownEpochKeys(t, f.env, f.u, f.mbx, 2))
	if err != nil {
		t.Fatal(err)
	}
	k2.Epoch = 1
	foreign, err := k2.Encode()
	if err != nil {
		t.Fatal(err)
	}
	k1, err := store.DecodeEpochKeys(plain1)
	if err != nil {
		t.Fatal(err)
	}
	k1.Epoch = 2
	relabelled, err := k1.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for name, plain := range map[string][]byte{"keys of epoch 2": foreign, "keys labelled epoch 2": relabelled} {
		w, err := readWith(t, f, f.u, 1, sealWrap(t, f.env, f.u, f.u, wrapHeader(f.mbx, 1, f.u), plain), a.ID)
		if !errors.Is(err, client.ErrWrap) || !strings.Contains(w, "passen nicht zur signierten Epoche") {
			t.Errorf("wrap with %s: %v (%s)", name, err, w)
		}
	}
	if w, err := readWith(t, f, f.u, 1, sealWrap(t, f.env, f.u, f.u, wrapHeader(f.mbx, 1, f.u), plain1), a.ID); err != nil {
		t.Fatalf("control: %v (%s)", err, w)
	}
}

// TestWrapOfRevokedSignerGeneration: bob's wraps were signed by alice's
// generation 1. After alice moved to generation 2, bob's client no longer
// accepts them: a wrap is never logged, so a revoked generation does not
// count for it (2.2 rule 4, SPEC-ISSUES S13, strictest reading); no
// .accept file (wrap-accept, task 06b) exists. The epochs, which are
// logged, stay valid.
func TestWrapOfRevokedSignerGeneration(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 1})
	if _, _, err := bob.Client.Read(f.mbx, a.ID); err != nil {
		t.Fatalf("bob before the revocation: %v", err)
	}
	if w := parse(t, mustRead(t, f.env.Store.WrapFile(f.mbx, 1, bob.ID))); w.Trailer == nil || w.Trailer.Signer.Gen != 1 {
		t.Fatal("bob's wrap is not signed by generation 1")
	}
	if gen := f.env.Rotate(f.u); gen != 2 {
		t.Fatalf("generation %d", gen)
	}
	bc := f.env.Reopen(bob)
	f.env.Warnings.Take()
	if _, _, err := bc.Read(f.mbx, a.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("wrap signed by a revoked generation: %v", err)
	}
	if w := strings.Join(f.env.Warnings.Take(), "\n"); !strings.Contains(w, "generation 1 is revoked") {
		t.Fatalf("warnings: %s", w)
	}
	if _, err := bc.MailboxName(f.mbx); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("folders through a wrap of a revoked generation: %v", err)
	}
	// The chain itself, signed by generation 1 and logged, verifies.
	if err := bc.Sync(); err != nil {
		t.Fatal(err)
	}
}

// TestReaderIgnoresEpochBeyondHead: the head of the chain is mailbox.rec
// for the reader as for the server. After a crash between epoch.rec 5
// and mailbox.rec (still 4), the server encrypts mails for epoch 4 even
// after the begin of epoch 5; the reader accepts such a mail, because
// epoch 5 does not count for it, and does not read the folders of epoch
// 5 (ErrEpoch).
func TestReaderIgnoresEpochBeyondHead(t *testing.T) {
	f := newFixture(t)
	f.env.Clock.Set(time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC))
	client.SetCrashHook(t, func(p string) bool { return p == "epoch-written" })
	if err := f.u.Client.Sync(); !errors.Is(err, client.ErrCrashed) {
		t.Fatal(err)
	}
	client.SetCrashHook(t, nil)
	e4, _, err := f.env.Store.ReadEpoch(f.mbx, 4)
	if err != nil {
		t.Fatal(err)
	}
	e5, _, err := f.env.Store.ReadEpoch(f.mbx, 5)
	if err != nil {
		t.Fatal("epoch 5 not written")
	}
	if m, _ := f.env.Store.ReadMailbox(f.mbx); m.Epoch != 4 {
		t.Fatal("mailbox.rec moved")
	}
	c := f.env.Reopen(f.u)
	late := time.UnixMilli(e5.Begin).Add(time.Hour)
	id := f.forge(t, e4, late, "for epoch 4 after the begin of 5", 1, f.env.IngestKey, 1)
	f.env.Warnings.Take()
	if _, body, err := c.Read(f.mbx, id); err != nil || string(body) != "for epoch 4 after the begin of 5" {
		t.Fatalf("mail for the head epoch 4: %v (%q)", err, f.env.Warnings.Take())
	}
	if _, err := c.FoldersOfEpoch(f.mbx, 5); !errors.Is(err, client.ErrEpoch) {
		t.Fatalf("folders of the epoch beyond the head: %v", err)
	}
	if _, err := c.FoldersOfEpoch(f.mbx, 4); err != nil {
		t.Fatal(err)
	}
}

// forgeImmediate appends to the chain of f an epoch with immediate effect
// beginning now, signed by its member alice, that discards exactly the
// given epochs, and points mailbox.rec to it.
func forgeImmediate(t *testing.T, f *fixture, discards []uint32) *store.Epoch {
	t.Helper()
	h := chainOf(t, f.env, f.mbx)
	head := h[len(h)-1]
	_, headData, err := f.env.Store.ReadEpoch(f.mbx, head.Number)
	if err != nil {
		t.Fatal(err)
	}
	ks := f.env.Keystore(f.u)
	defer ks.Zero()
	e := *head
	e.Number, e.PrevHash = head.Number+1, store.EpochHash(headData)
	e.Reason, e.Begin = store.ReasonMemberRemoved, f.env.Clock.Now().UnixMilli()
	e.Discards = discards
	e.SignerID, e.SignerGen = f.u.ID, ks.Generation
	if err := e.Sign(ks.Identity); err != nil {
		t.Fatal(err)
	}
	data, err := f.env.Store.WriteEpoch(&e)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.env.Log.AppendEpoch(f.mbx, e.Number, data); err != nil {
		t.Fatal(err)
	}
	m, err := f.env.Store.ReadMailbox(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	m.Epoch = e.Number
	if err := f.env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	return &e
}

// TestIncompleteDiscards: an epoch with immediate effect must discard
// every later epoch that is not discarded (2.4 rule 1, store.Chain rule
// 6). Epoch 5, begun now after epoch 1, that discards 2 and 3 but not 4
// breaks the chain (store.ErrChain); the valid prefix stays readable. The
// same epoch with complete discards is accepted.
func TestIncompleteDiscards(t *testing.T) {
	t.Run("complete", func(t *testing.T) {
		f := newFixture(t)
		a := f.deliver(t, "a", "x")
		f.env.Clock.Advance(time.Hour)
		forgeImmediate(t, f, []uint32{2, 3, 4})
		// Epoch 5 is part of the chain: epoch 4 is discarded. (The
		// forged epoch has no wraps, so its folders are not read.)
		c := f.env.Reopen(f.u)
		if _, err := c.FoldersOfEpoch(f.mbx, 4); !errors.Is(err, client.ErrDiscardedEpoch) {
			t.Fatalf("complete discards: %v", err)
		}
		if _, _, err := c.Read(f.mbx, a.ID); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("incomplete", func(t *testing.T) {
		f := newFixture(t)
		a := f.deliver(t, "a", "x")
		f.env.Clock.Advance(time.Hour)
		forgeImmediate(t, f, []uint32{2, 3})
		f.env.Warnings.Take()
		if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
			t.Fatalf("incomplete discards: %v", err)
		}
		if w := strings.Join(f.env.Warnings.Take(), "\n"); !strings.Contains(w, "does not discard epoch 4") {
			t.Fatalf("warnings: %s", w)
		}
		c := f.env.Reopen(f.u)
		if _, body, err := c.Read(f.mbx, a.ID); err != nil || !strings.Contains(string(body), "x") {
			t.Fatalf("mail of the valid prefix: %v", err)
		}
		if _, err := c.FoldersOfEpoch(f.mbx, 4); err != nil {
			t.Fatalf("folders of the valid prefix: %v", err)
		}
		if _, err := c.FoldersOfEpoch(f.mbx, 5); !errors.Is(err, client.ErrEpoch) {
			t.Fatalf("folders of the invalid epoch: %v", err)
		}
		bob := f.env.NewUser("bob")
		if _, err := c.Share(f.mbx, bob.ID, client.ShareOptions{}); !errors.Is(err, store.ErrChain) {
			t.Fatalf("share on the broken chain: %v", err)
		}
	})
}
