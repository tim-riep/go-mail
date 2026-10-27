package client_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 06g: a template signed by a revoked generation heals only
// recipients the head of the chain still names; own wraps are proven by
// the seed during device lost; a mailbox missing from the data directory
// leaves no mark; ForceNewGeneration; recovery.wrap is checked before the
// record; device lost covers every membership.

// reissueMark returns the mark of an incomplete device lost of mailbox
// mbx in the state of the client directory dir (0: none).
func reissueMark(t *testing.T, dir string, mbx store.ID) uint32 {
	t.Helper()
	var st struct {
		Mailboxes map[string]*struct {
			Reissue uint32 `json:"reissue"`
		} `json:"mailboxes"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "state.json")), &st); err != nil {
		t.Fatal(err)
	}
	if ms := st.Mailboxes[mbx.String()]; ms != nil {
		return ms.Reissue
	}
	return 0
}

// knows reports whether the state of the client directory dir names
// mailbox mbx.
func knows(t *testing.T, dir string, mbx store.ID) bool {
	t.Helper()
	var st struct {
		Mailboxes map[string]json.RawMessage `json:"mailboxes"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "state.json")), &st); err != nil {
		t.Fatal(err)
	}
	_, ok := st.Mailboxes[mbx.String()]
	return ok
}

// warningWith fails unless a warning holds every part, and if any warning
// holds an error text.
func warningWith(t *testing.T, warnings []string, parts ...string) {
	t.Helper()
	onlyIDs(t, warnings)
	for _, w := range warnings {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(w, p)
		}
		if ok {
			return
		}
	}
	t.Fatalf("no warning with %q in:\n%s", parts, strings.Join(warnings, "\n"))
}

// ownWrapsFor fails unless every own wrap of u in an epoch of the chain
// that is not discarded is made for generation gen and signed by u's
// generation gen (u's own mailbox).
func ownWrapsFor(t *testing.T, f *fixture, u *testenv.User, gen uint32) {
	t.Helper()
	chain := chainOf(t, f.env, f.mbx)
	discarded := discardedOf(chain)
	for _, e := range chain {
		if discarded[e.Number] || !wrapExists(f.env, f.mbx, e.Number, u.ID) {
			continue
		}
		w := wrapOf(t, f.env, f.mbx, e.Number, u.ID)
		if w.Recipients[0].Gen != gen || store.ID(w.Trailer.Signer.ID) != u.ID || w.Trailer.Signer.Gen != gen {
			t.Fatalf("own wrap of epoch %d: for generation %d, signed by %d", e.Number, w.Recipients[0].Gen, w.Trailer.Signer.Gen)
		}
	}
}

// removedMember sets up finding 1 of task 06g: alice shares her mailbox
// with bob and then mallory (both members from their immediate epochs on),
// mallory reads mail m, alice revokes mallory (her wraps are deleted) and
// bob countersigns his wraps. It returns m, bob, mallory and the first
// epoch whose member list names mallory.
func removedMember(t *testing.T, f *fixture) (*client.Mail, *testenv.User, *testenv.User, *store.Epoch) {
	t.Helper()
	bob := f.env.NewUser("bob")
	mallory := f.env.NewUser("mallory")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	f.env.Share(f.u, f.mbx, mallory, client.ShareOptions{})
	m := f.deliver(t, "m", "for all three")
	readBody(t, f.env, mallory.Client, f.mbx, m.ID, "for all three")
	readBody(t, f.env, bob.Client, f.mbx, m.ID, "for all three")
	var shared *store.Epoch
	for _, e := range chainOf(t, f.env, f.mbx) {
		if _, ok := e.Member(mallory.ID); ok && shared == nil {
			shared = e
		}
	}
	if shared == nil {
		t.Fatal("mallory is in no member list")
	}
	f.env.Clock.Advance(time.Minute)
	if err := f.u.Client.Revoke(f.mbx, mallory.ID); err != nil {
		t.Fatal(err)
	}
	if wrapExists(f.env, f.mbx, shared.Number, mallory.ID) {
		t.Fatal("mallory's wrap not deleted")
	}
	cannotRead(t, f.env, mallory, f.mbx, m.ID)
	if err := f.env.Reopen(bob).Sync(); err != nil {
		t.Fatal(err)
	}
	return m, bob, mallory, shared
}

// TestRevokedMemberTemplateSync: mallory was a member from epoch e on and
// was revoked; e still lists her. Alice moves to generation 2, and the
// thief with her generation 1 plants mallory.wrap of e signed by it. Bob's
// Sync heals the wraps of members the head names, but not mallory's: the
// template is signed by a revoked generation and the head does not name
// her (task 06g finding 1). The warning names IDs only.
func TestRevokedMemberTemplateSync(t *testing.T) {
	f := newFixture(t)
	m, bob, mallory, shared := removedMember(t, f)
	f.env.Rotate(f.u)
	id1 := identityOf(t, f.u.Words, 1)
	defer keys.Wipe(id1)
	planted := map[uint32][]byte{shared.Number: plantWrap(t, f.env, f.mbx, shared.Number, mallory.ID, 1, f.u.ID, 1, id1)}
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	if err := f.env.Reopen(bob).Sync(); err != nil {
		t.Fatal(err)
	}
	w := f.env.Warnings.Take()
	warningWith(t, w, mallory.ID.String(), "Kopf der Kette nennt den Empfänger nicht mehr")
	for _, s := range w {
		f.env.Warnings.Add(s)
	}
	notReissued(t, f.env, mallory.ID, planted, f.mbx)
	cannotRead(t, f.env, mallory, f.mbx, m.ID)
	// Bob, whom the head names, is healed and reads.
	if tr := wrapOf(t, f.env, f.mbx, shared.Number, bob.ID).Trailer; store.ID(tr.Signer.ID) == f.u.ID && tr.Signer.Gen == 1 {
		t.Fatal("bob's wrap is still signed by the revoked generation")
	}
	readBody(t, f.env, f.env.Reopen(bob), f.mbx, m.ID, "for all three")
}

// TestRevokedMemberTemplateDeviceLost: the same template, planted by the
// thief before alice runs device lost (her generation 1 signs it), is not
// issued again by her device lost (reissueWraps), while bob's wraps are.
func TestRevokedMemberTemplateDeviceLost(t *testing.T) {
	f := newFixture(t)
	m, bob, mallory, shared := removedMember(t, f)
	id1 := identityOf(t, f.u.Words, 1)
	defer keys.Wipe(id1)
	planted := map[uint32][]byte{shared.Number: plantWrap(t, f.env, f.mbx, shared.Number, mallory.ID, 1, f.u.ID, 1, id1)}
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	w := f.env.Warnings.Take()
	warningWith(t, w, mallory.ID.String(), "Kopf der Kette nennt den Empfänger nicht mehr")
	for _, s := range w {
		f.env.Warnings.Add(s)
	}
	notReissued(t, f.env, mallory.ID, planted, f.mbx)
	cannotRead(t, f.env, mallory, f.mbx, m.ID)
	if tr := wrapOf(t, f.env, f.mbx, shared.Number, bob.ID).Trailer; store.ID(tr.Signer.ID) != f.u.ID || tr.Signer.Gen != 2 {
		t.Fatalf("bob's wrap signed by %s generation %d", store.ID(tr.Signer.ID), tr.Signer.Gen)
	}
	readBody(t, f.env, f.env.Reopen(bob), f.mbx, m.ID, "for all three")
}

// TestStep2SkippedMissing: mailbox.rec is gone during step 2 of device
// lost (hidden when the translog warning of the start is shown, back at
// the crash point after step 2), so step 2 cannot countersign the own
// wraps with generation 2. Step 2 warns and does not mark it (mailbox.rec
// not found); step 4 opens the own wraps of generation 1 with the old key
// store, which the seed proves, and seals them for generation 2 (task 06g
// finding 2a): alice keeps her access.
func TestStep2SkippedMissing(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	mrec := f.env.Store.MailboxFile(f.mbx)
	hidden := mrec + ".hidden"
	cfg.Warn = func(s string) {
		f.env.Warnings.Add(s)
		if s == translog.Warning {
			if err := os.Rename(mrec, hidden); err != nil {
				t.Fatal(err)
			}
		}
	}
	client.SetCrashHook(t, func(p string) bool {
		if p == "devicelost-prepared" {
			if err := os.Rename(hidden, mrec); err != nil {
				t.Fatal(err)
			}
		}
		return false
	})
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
	if gen != 2 || err != nil {
		t.Fatalf("device lost: generation %d, %v", gen, err)
	}
	client.SetCrashHook(t, nil)
	warningWith(t, f.env.Warnings.Take(), f.mbx.String(), "nicht vorbereitet", "mailbox.rec fehlt")
	ownWrapsFor(t, f, f.u, 2)
	c := f.env.Reopen(f.u)
	readBody(t, f.env, c, f.mbx, old.ID, "secret")
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	readBody(t, f.env, f.env.Reopen(f.u), f.mbx, old.ID, "secret")
}

// TestStep2InvalidContinuation: mailbox.rec is invalid during the whole
// device lost. Step 2 warns with a fixed cause and marks the mailbox
// (finding 2b), step 4 fails (ErrPartial). Once mailbox.rec is back, device
// lost run again continues without a new generation and seals the own
// wraps of generation 1, which no wrap-accept of generation 2 names, for
// generation 2: the seed proves them; alice reads.
func TestStep2InvalidContinuation(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	mrec := f.env.Store.MailboxFile(f.mbx)
	good := mustRead(t, mrec)
	if err := store.WriteFileAtomic(mrec, []byte("not a mailbox record")); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
	if gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("device lost: generation %d, %v", gen, err)
	}
	warningWith(t, f.env.Warnings.Take(), f.mbx.String(), "nicht vorbereitet", "mailbox.rec ist ungültig")
	if m := reissueMark(t, f.u.Dir, f.mbx); m != 2 {
		t.Fatalf("mark %d", m)
	}
	if err := store.WriteFileAtomic(mrec, good); err != nil {
		t.Fatal(err)
	}
	gen, err = client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
	if gen != 2 || err != nil {
		t.Fatalf("continuation: generation %d, %v", gen, err)
	}
	if n := generations(t, f, f.u); n != 2 {
		t.Fatalf("%d generations", n)
	}
	if m := reissueMark(t, f.u.Dir, f.mbx); m != 0 {
		t.Fatalf("mark %d", m)
	}
	ownWrapsFor(t, f, f.u, 2)
	if g := headGen(t, f, f.u); g != 2 {
		t.Fatalf("head names generation %d", g)
	}
	readBody(t, f.env, f.env.Reopen(f.u), f.mbx, old.ID, "secret")
}

// TestStep2MarkBeforeCrash: the mark of step 2 is saved before anything
// else: a crash right after step 2 leaves the mailbox marked; device lost
// run again with mailbox.rec back completes it.
func TestStep2MarkBeforeCrash(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	mrec := f.env.Store.MailboxFile(f.mbx)
	good := mustRead(t, mrec)
	if err := store.WriteFileAtomic(mrec, []byte("not a mailbox record")); err != nil {
		t.Fatal(err)
	}
	client.SetCrashHook(t, func(p string) bool { return p == "devicelost-prepared" })
	if _, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); err == nil {
		t.Fatal("no crash")
	}
	client.SetCrashHook(t, nil)
	if m := reissueMark(t, f.u.Dir, f.mbx); m != 2 {
		t.Fatalf("mark %d", m)
	}
	if err := store.WriteFileAtomic(mrec, good); err != nil {
		t.Fatal(err)
	}
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 2 || err != nil {
		t.Fatalf("device lost again: generation %d, %v", gen, err)
	}
	if m := reissueMark(t, f.u.Dir, f.mbx); m != 0 {
		t.Fatalf("mark %d", m)
	}
	ownWrapsFor(t, f, f.u, 2)
	readBody(t, f.env, f.env.Reopen(f.u), f.mbx, old.ID, "secret")
}

// TestSeedProofNeedsMatchingKeys: the thief plants alice's own wrap of
// epoch 1, made for and signed by her generation 1 but with other keys,
// while mailbox.rec is invalid during step 2 (no cached keys). The seed
// proves the signature, but the keys do not match epoch.rec: the wrap is
// not sealed again for generation 2 (a warning names the epoch) and
// gives no access.
func TestSeedProofNeedsMatchingKeys(t *testing.T) {
	f := newFixture(t)
	f.deliver(t, "old", "secret")
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	id1 := identityOf(t, f.u.Words, 1)
	defer keys.Wipe(id1)
	planted := plantWrap(t, f.env, f.mbx, 1, f.u.ID, 1, f.u.ID, 1, id1)
	mrec := f.env.Store.MailboxFile(f.mbx)
	good := mustRead(t, mrec)
	if err := store.WriteFileAtomic(mrec, []byte("not a mailbox record")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); !errors.Is(err, client.ErrPartial) {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(mrec, good); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 2 || err != nil {
		t.Fatalf("continuation with a planted own wrap: generation %d, %v", gen, err)
	}
	warningWith(t, f.env.Warnings.Take(), "eigene Verpackung der Epoche 1 von "+f.mbx.String(), "wird nicht neu ausgestellt")
	if got := mustRead(t, f.env.Store.WrapFile(f.mbx, 1, f.u.ID)); string(got) != string(planted) {
		t.Fatal("the planted own wrap was sealed again")
	}
	if _, err := f.env.Reopen(f.u).FoldersOfEpoch(f.mbx, 1); err == nil {
		t.Fatal("epoch 1 opens with the planted wrap")
	}
}

// TestMissingMailboxNoMark: a mailbox of the local state no longer exists
// in the data directory. Device lost warns and marks nothing (task 06g
// finding 3), so a second device lost creates generation 3; the local
// state of the mailbox stays (task 06h finding 1).
func TestMissingMailboxNoMark(t *testing.T) {
	f := newFixture(t)
	second := f.env.Mailbox(f.u, "B", "b@example.org")
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	if err := os.RemoveAll(f.env.Store.MailboxDir(second)); err != nil {
		t.Fatal(err)
	}
	cfg := f.env.ClientConfig(f.u.Dir)
	f.env.Warnings.Take()
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 2 || err != nil {
		t.Fatalf("device lost: generation %d, %v", gen, err)
	}
	warningWith(t, f.env.Warnings.Take(), second.String(), "fehlt im Datenverzeichnis", "nichts wird vorgemerkt", "bleibt erhalten")
	if !knows(t, f.u.Dir, second) || reissueMark(t, f.u.Dir, second) != 0 {
		t.Fatal("the missing mailbox left the state or is marked")
	}
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 3 || err != nil {
		t.Fatalf("second device lost: generation %d, %v", gen, err)
	}
	if n := generations(t, f, f.u); n != 3 {
		t.Fatalf("%d generations", n)
	}
}

// TestForceNewGeneration: a mailbox stays marked (mailbox.rec invalid).
// Device lost without options only continues (generation 2 stays); with
// ForceNewGeneration it creates generation 3 (the device with generation 2
// may be lost as well), and the marked mailbox is completed with it: its
// own wraps of generation 1 are opened with the key store derived from
// the seed and sealed for generation 3.
func TestForceNewGeneration(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	mrec := f.env.Store.MailboxFile(f.mbx)
	good := mustRead(t, mrec)
	if err := store.WriteFileAtomic(mrec, []byte("not a mailbox record")); err != nil {
		t.Fatal(err)
	}
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("device lost: generation %d, %v", gen, err)
	}
	f.env.Warnings.Take()
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("continuation: generation %d, %v", gen, err)
	}
	warningWith(t, f.env.Warnings.Take(), "setzt die Neuausstellung", "ForceNewGeneration")
	if n := generations(t, f, f.u); n != 2 {
		t.Fatalf("%d generations", n)
	}
	if err := store.WriteFileAtomic(mrec, good); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	gen, err := client.DeviceLostWithOptions(cfg, testenv.Passphrase, f.u.Words, client.DeviceLostOptions{ForceNewGeneration: true})
	if gen != 3 || err != nil {
		t.Fatalf("forced: generation %d, %v", gen, err)
	}
	warningWith(t, f.env.Warnings.Take(), "ForceNewGeneration")
	if n := generations(t, f, f.u); n != 3 {
		t.Fatalf("%d generations", n)
	}
	if m := reissueMark(t, f.u.Dir, f.mbx); m != 0 {
		t.Fatalf("mark %d", m)
	}
	ownWrapsFor(t, f, f.u, 3)
	if g := headGen(t, f, f.u); g != 3 {
		t.Fatalf("head names generation %d", g)
	}
	readBody(t, f.env, f.env.Reopen(f.u), f.mbx, old.ID, "secret")
}

// plantRecoveryWrap writes recovery.wrap of epoch n of mbx for recovery
// recipient rid with garbage keys, whose trailer names signer (ID, gen)
// with a signature by a random key: what a writer of the data directory
// can plant without any key.
func plantRecoveryWrap(t *testing.T, env *testenv.Env, mbx store.ID, n uint32, rid, signer store.ID, gen uint32) []byte {
	t.Helper()
	priv, err := ecdhGen()
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := envelope.Seal(
		envelope.Header{Kind: envelope.KindWrap, MailboxID: mbx, Epoch: n, FileID: rid, Created: env.Clock.Now().UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientRecovery, ID: rid, Gen: store.RecoveryGen, PublicKey: priv.PublicKey()}},
		[]byte("garbage"), &envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerUser, ID: signer, Gen: gen, Key: key}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(env.Store.RecoveryWrapFile(mbx, n), data); err != nil {
		t.Fatal(err)
	}
	return data
}

// TestPlantedRecoveryWrapNotLeft: bob, who has not confirmed the recovery
// recipient, ran device lost (ErrPartial, marked); alice's Sync created
// the epoch for his generation 2. A recovery.wrap planted in the name of
// bob's revoked generation 1 does not check as a template: bob's Sync
// warns and does not count it as left (task 06g finding 4), so his mark is
// cleared and he is not told to confirm the record for it.
func TestPlantedRecoveryWrapNotLeft(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 1})
	readBody(t, f.env, bob.Client, f.mbx, old.ID, "secret")
	pub, _ := recoveryKey(t)
	f.env.Clock.Advance(time.Hour)
	if err := f.u.Client.SetRecovery(f.mbx, pub, yes); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Hour)
	bob.Client.Close()
	if gen, err := client.DeviceLost(f.env.ClientConfig(bob.Dir), testenv.Passphrase, bob.Words); gen != 2 || !errors.Is(err, client.ErrRecovery) {
		t.Fatalf("bob's device lost: generation %d, %v", gen, err)
	}
	if m := reissueMark(t, bob.Dir, f.mbx); m != 2 {
		t.Fatalf("mark %d", m)
	}
	if err := f.env.Reopen(f.u).Sync(); err != nil {
		t.Fatal(err)
	}
	if g := headGen(t, f, bob); g != 2 {
		t.Fatalf("head names bob with generation %d", g)
	}
	chain := chainOf(t, f.env, f.mbx)
	head := chain[len(chain)-1]
	rid := recoveryWrapFor(t, f.env, f.mbx, head.Number)
	plantRecoveryWrap(t, f.env, f.mbx, head.Number, rid, bob.ID, 1)
	f.env.Warnings.Take()
	if err := f.env.Reopen(bob).Sync(); err != nil {
		t.Fatal(err)
	}
	w := f.env.Warnings.Take()
	warningWith(t, w, "recovery.wrap der Epoche", "keine geprüfte Verpackung")
	for _, s := range w {
		if strings.Contains(s, "recovery.wrap") && strings.Contains(s, "nicht bestätigt") {
			t.Fatalf("the planted recovery.wrap counts as left: %s", s)
		}
	}
	if m := reissueMark(t, bob.Dir, f.mbx); m != 0 {
		t.Fatalf("mark %d after Sync", m)
	}
}

// TestDeviceLostUnopenedMembership: bob is a member of alice's mailbox but
// never opened it on his device (it is not in his state). His device lost
// finds it in the data directory (task 06g finding 6): it countersigns and
// seals his own wraps for generation 2 and creates the epoch
// generation-revoked; after alice's Sync he reads.
func TestDeviceLostUnopenedMembership(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 1})
	if len(bob.Client.Mailboxes()) != 0 {
		t.Fatal("bob knows the mailbox")
	}
	f.env.Clock.Advance(time.Hour)
	before := chainOf(t, f.env, f.mbx)
	f.env.Warnings.Take()
	now := f.env.Clock.Now()
	if gen := f.env.DeviceLost(bob); gen != 2 {
		t.Fatal(gen)
	}
	warningWith(t, f.env.Warnings.Take(), f.mbx.String(), "noch nicht geöffnet")
	e := checkImmediate(t, before, chainOf(t, f.env, f.mbx), now, store.ReasonGenerationRevoked)
	if memberGen(e, bob.ID) != 2 || e.SignerID != bob.ID || e.SignerGen != 2 {
		t.Fatalf("epoch %d: bob generation %d, signed by %s generation %d", e.Number, memberGen(e, bob.ID), e.SignerID, e.SignerGen)
	}
	if err := f.env.Reopen(f.u).Sync(); err != nil {
		t.Fatal(err)
	}
	readBody(t, f.env, f.env.Reopen(bob), f.mbx, old.ID, "secret")
}

// TestWarnCause: a warning names a fixed cause for an error, never its
// text (task 06g finding 5): no file name, no error chain.
func TestWarnCause(t *testing.T) {
	notFound := fmt.Errorf("%w: abc.accept", store.ErrNotFound)
	for _, c := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: %w: generation 1", client.ErrSigner, client.ErrRevoked), "widerrufenen Generation"},
		{fmt.Errorf("%w: epoch 3", client.ErrDiscardedEpoch), "verworfen"},
		{fmt.Errorf("%w: x", client.ErrStaleEpoch), "neueren"},
		{fmt.Errorf("%w: x", client.ErrEpoch), "außerhalb der geprüften Kette"},
		{fmt.Errorf("%w: x", client.ErrReplay), "ältere Version"},
		{fmt.Errorf("%w: x", client.ErrMailHash), "Metadaten"},
		{fmt.Errorf("%w: x", client.ErrMismatch), "Ort"},
		{fmt.Errorf("%w: x", client.ErrPlatform), "Plattformzertifikat"},
		{fmt.Errorf("%w: x", envelope.ErrSignature), "Signatur"},
		{fmt.Errorf("%w: %v", client.ErrWrap, notFound), "Epochenschlüssel"},
		{envelope.ErrDecrypt, "Entschlüsselung"},
		{envelope.ErrSuite, "Algorithmensatz"},
		{fmt.Errorf("%w: x", translog.ErrNotInLog), "Transparenzlog"},
		{fmt.Errorf("%w: epoch 2", store.ErrChain), "Epochenkette"},
		{notFound, "Datei fehlt"},
		{fmt.Errorf("%w: x", envelope.ErrTruncated), "Format"},
		{errors.New("abc.accept: something"), "Prüfung fehlgeschlagen"},
		{nil, "ohne Angabe"},
	} {
		got := client.WarnCause(c.err)
		if !strings.Contains(got, c.want) || strings.Contains(got, "accept") || strings.Contains(got, ":") {
			t.Errorf("%v: %q", c.err, got)
		}
	}
}
