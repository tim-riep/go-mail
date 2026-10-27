package client_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 06f: a reader of a past period gets a new wrap only from a
// template signed by a valid generation; device lost issues the files
// outside the log again independently of the immediate epoch, continues
// an incomplete run without a further generation, and Sync heals what a
// revoked generation signed; folders.gml is taken over once.

// onlyIDs fails if a warning holds the text of an error.
func onlyIDs(t *testing.T, warnings []string) {
	t.Helper()
	for _, w := range warnings {
		for _, bad := range []string{"client:", "envelope:", "store:", "keys:"} {
			if strings.Contains(w, bad) {
				t.Fatalf("warning holds an error text: %s", w)
			}
		}
	}
}

// TestStrawmanSelfAcceptDeviceLost: the thief of alice's device signs
// mallory.wrap of epoch 1 with alice's generation 1, and mallory, never a
// member, countersigns it with her current generation. Alice's device
// lost issues nothing for mallory: the template is signed by the revoked
// generation, and a wrap-accept is no proof (TODO(Q15)).
func TestStrawmanSelfAcceptDeviceLost(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	mallory := f.env.NewUser("mallory")
	id1 := identityOf(t, f.u.Words, 1)
	defer keys.Wipe(id1)
	planted := map[uint32][]byte{1: plantWrap(t, f.env, f.mbx, 1, mallory.ID, 1, f.u.ID, 1, id1)}
	acceptAs(t, f.env, mallory, f.mbx, 1, planted[1])
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	notReissued(t, f.env, mallory.ID, planted, f.mbx)
	cannotRead(t, f.env, mallory, f.mbx, old.ID)
}

// TestStrawmanSelfAcceptSync: the same template, planted after alice's
// device lost for mallory's old generation 1 (she moved to 2) and
// countersigned by her generation 2, is not issued again on alice's Sync.
func TestStrawmanSelfAcceptSync(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	mallory := f.env.NewUser("mallory")
	f.env.Clock.Advance(time.Minute)
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	f.env.Rotate(mallory)
	id1 := identityOf(t, f.u.Words, 1)
	defer keys.Wipe(id1)
	planted := map[uint32][]byte{1: plantWrap(t, f.env, f.mbx, 1, mallory.ID, 1, f.u.ID, 1, id1)}
	acceptAs(t, f.env, mallory, f.mbx, 1, planted[1])
	f.env.Warnings.Take()
	if err := f.env.Reopen(f.u).Sync(); err != nil {
		t.Fatal(err)
	}
	notReissued(t, f.env, mallory.ID, planted, f.mbx)
	cannotRead(t, f.env, mallory, f.mbx, old.ID)
}

// TestColludingPastReaderDeviceLost: the thief signs mallory.wrap of every
// epoch with alice's real generation 1 and mallory countersigns each. No
// wrap is issued again by device lost, mallory reads nothing.
func TestColludingPastReaderDeviceLost(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	mallory := f.env.NewUser("mallory")
	id1 := identityOf(t, f.u.Words, 1)
	defer keys.Wipe(id1)
	planted := map[uint32][]byte{}
	for _, e := range chainOf(t, f.env, f.mbx) {
		planted[e.Number] = plantWrap(t, f.env, f.mbx, e.Number, mallory.ID, 1, f.u.ID, 1, id1)
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

// TestNonMemberValidSelfSignedSync: mallory, registered but never a
// member, signs mallory.wrap (recipient generation 1) of every epoch with
// her real, valid generation 2. The signature checks with her user.rec;
// only the membership of the signer (checkTemplate) keeps alice's Sync
// from issuing it again.
func TestNonMemberValidSelfSignedSync(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	mallory := f.env.NewUser("mallory")
	f.env.Rotate(mallory)
	ks2 := f.env.Keystore(mallory)
	defer ks2.Zero()
	planted := map[uint32][]byte{}
	for _, e := range chainOf(t, f.env, f.mbx) {
		planted[e.Number] = plantWrap(t, f.env, f.mbx, e.Number, mallory.ID, 1, mallory.ID, 2, ks2.Identity)
	}
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	if err := f.env.Reopen(f.u).Sync(); err != nil {
		t.Fatal(err)
	}
	notReissued(t, f.env, mallory.ID, planted, f.mbx)
	cannotRead(t, f.env, mallory, f.mbx, old.ID)
}

// TestNonMemberRevokedSelfSignedWithAcceptSync: as above, signed with
// mallory's generation 1, revoked afterwards, and countersigned by her
// generation 2.
func TestNonMemberRevokedSelfSignedWithAcceptSync(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	mallory := f.env.NewUser("mallory")
	ks1 := f.env.Keystore(mallory)
	planted := map[uint32][]byte{}
	for _, e := range chainOf(t, f.env, f.mbx) {
		planted[e.Number] = plantWrap(t, f.env, f.mbx, e.Number, mallory.ID, 1, mallory.ID, 1, ks1.Identity)
	}
	ks1.Zero()
	f.env.Rotate(mallory)
	for n, d := range planted {
		acceptAs(t, f.env, mallory, f.mbx, n, d)
	}
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	if err := f.env.Reopen(f.u).Sync(); err != nil {
		t.Fatal(err)
	}
	notReissued(t, f.env, mallory.ID, planted, f.mbx)
	cannotRead(t, f.env, mallory, f.mbx, old.ID)
}

// restoredRecovery sets up the state of finding 2 of task 06f: alice
// shares her mailbox with bob (a member from epoch 5, epochs 1 to 4 a
// past period for him, which he reads), enters a recovery recipient that
// she and bob confirm, loses her device and restores the client from the
// seed on a new device, which has not confirmed the recovery record. It
// returns the old mail, bob, and the recovery words; alice's client is
// closed.
func restoredRecovery(t *testing.T, f *fixture) (*client.Mail, *testenv.User, []string) {
	t.Helper()
	old := f.deliver(t, "old", "before the loss")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 1})
	readBody(t, f.env, bob.Client, f.mbx, old.ID, "before the loss")
	pub, words := recoveryKey(t)
	f.env.Clock.Advance(time.Hour)
	if err := f.u.Client.SetRecovery(f.mbx, pub, yes); err != nil {
		t.Fatal(err)
	}
	if err := bob.Client.ConfirmRecovery(f.mbx, yes); err != nil {
		t.Fatal(err)
	}
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	rc, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, words)
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, f.env, rc, f.mbx, old.ID, "before the loss")
	rc.Close()
	f.env.Clock.Advance(time.Hour)
	f.u.Client.Close()
	dir := t.TempDir()
	if _, err := client.Restore(f.env.ClientConfig(dir), client.RestoreOptions{Words: f.u.Words}, testenv.Passphrase); err != nil {
		t.Fatal(err)
	}
	f.u.Dir = dir
	return old, bob, words
}

// deviceLostPartial runs device lost for alice on the restored device and
// expects ErrPartial with ErrRecovery and generation gen, warnings with
// IDs and the remedy only.
func deviceLostPartial(t *testing.T, f *fixture, gen uint32) []string {
	t.Helper()
	f.env.Warnings.Take()
	got, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
	if got != gen || !errors.Is(err, client.ErrPartial) || !errors.Is(err, client.ErrRecovery) || !strings.Contains(err.Error(), "ConfirmRecovery") {
		t.Fatalf("device lost: generation %d, %v", got, err)
	}
	w := f.env.Warnings.Take()
	onlyIDs(t, w)
	if s := strings.Join(w, "\n"); !strings.Contains(s, "Abhilfe: ConfirmRecovery, dann Sync") {
		t.Fatalf("warnings: %s", s)
	}
	return w
}

// generations returns the number of generations of u's user.rec in the
// data directory.
func generations(t *testing.T, f *fixture, u *testenv.User) int {
	t.Helper()
	user, _, err := f.env.Store.ReadUser(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return len(user.Generations)
}

// recoveryWrapsSignedBy fails unless recovery.wrap of every epoch that is
// not discarded and has one is signed by generation gen of u.
func recoveryWrapsSignedBy(t *testing.T, f *fixture, u *testenv.User, gen uint32) {
	t.Helper()
	chain := chainOf(t, f.env, f.mbx)
	discarded := discardedOf(chain)
	n := 0
	for _, e := range chain {
		data, err := f.env.Store.ReadRecoveryWrap(f.mbx, e.Number)
		if discarded[e.Number] || err != nil {
			continue
		}
		if tr := parse(t, data).Trailer; store.ID(tr.Signer.ID) != u.ID || tr.Signer.Gen != gen {
			t.Fatalf("recovery.wrap of epoch %d signed by %s generation %d", e.Number, store.ID(tr.Signer.ID), tr.Signer.Gen)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no recovery.wrap")
	}
}

// headGen returns the generation of u in the head of the chain.
func headGen(t *testing.T, f *fixture, u *testenv.User) uint32 {
	t.Helper()
	chain := chainOf(t, f.env, f.mbx)
	return memberGen(chain[len(chain)-1], u.ID)
}

// TestRecoveryAfterRestoreDeviceLost: alice restores her client from the
// seed on a new device, which has not confirmed the recovery record, and
// runs device lost. The immediate epoch cannot be created (the recovery
// recipient needs the confirmed record), but the files outside the log
// are issued again regardless: bob's wraps of the epochs he is a member of
// and folders.gml (task 06f finding 2a); recovery.wrap waits for the
// record, and the error is ErrPartial with ErrRecovery naming the remedy.
// After ConfirmRecovery alice's Sync issues recovery.wrap again (signed by
// her revoked generation, 2b) and creates the epoch generation-revoked
// for her own entry; the recovery recipient reads epoch 1, bob reads old
// and new mails, and since nothing is left, a later device lost creates
// generation 3.
func TestRecoveryAfterRestoreDeviceLost(t *testing.T) {
	f := newFixture(t)
	old, bob, words := restoredRecovery(t, f)
	before := chainOf(t, f.env, f.mbx)
	deviceLostPartial(t, f, 2)
	after := chainOf(t, f.env, f.mbx)
	if len(after) != len(before) || headGen(t, f, f.u) != 1 {
		t.Fatal("an epoch was created without the confirmed recovery record")
	}
	bobWraps := 0
	discarded := discardedOf(after)
	for _, e := range after {
		if discarded[e.Number] {
			continue
		}
		if _, listed := e.Member(bob.ID); listed {
			if tr := wrapOf(t, f.env, f.mbx, e.Number, bob.ID).Trailer; store.ID(tr.Signer.ID) == f.u.ID {
				if tr.Signer.Gen != 2 {
					t.Fatalf("bob's wrap of epoch %d signed by generation %d", e.Number, tr.Signer.Gen)
				}
				bobWraps++
			}
		}
		if tr := parse(t, mustRead(t, f.env.Store.FoldersFile(f.mbx, e.Number))).Trailer; store.ID(tr.Signer.ID) == f.u.ID && tr.Signer.Gen != 2 {
			t.Fatalf("folders.gml of epoch %d signed by generation %d", e.Number, tr.Signer.Gen)
		}
	}
	if bobWraps == 0 {
		t.Fatal("no wrap of bob issued again")
	}
	if data, err := f.env.Store.ReadRecoveryWrap(f.mbx, 1); err != nil || parse(t, data).Trailer.Signer.Gen != 1 {
		t.Fatalf("recovery.wrap of epoch 1 changed without the confirmed record: %v", err)
	}

	ac := f.env.Reopen(f.u)
	if err := ac.ConfirmRecovery(f.mbx, yes); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if err := ac.Sync(); err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(f.env.Warnings.Take(), "\n"); !strings.Contains(w, "recovery.wrap der Epoche 1 von "+f.mbx.String()+" neu ausgestellt") {
		t.Fatalf("warnings: %s", w)
	}
	recoveryWrapsSignedBy(t, f, f.u, 2)
	if headGen(t, f, f.u) != 2 {
		t.Fatal("Sync did not create the epoch for alice's generation 2")
	}
	rc, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, words)
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, f.env, rc, f.mbx, old.ID, "before the loss")
	rc.Close()
	fresh := f.deliver(t, "new", "after the loss")
	bc := f.env.Reopen(bob)
	if err := bc.Sync(); err != nil {
		t.Fatal(err)
	}
	readBody(t, f.env, bc, f.mbx, old.ID, "before the loss")
	readBody(t, f.env, bc, f.mbx, fresh.ID, "after the loss")
	readBody(t, f.env, ac, f.mbx, old.ID, "before the loss")
	// Sync cleared the mark: device lost creates the next generation.
	if gen := f.env.DeviceLost(f.u); gen != 3 || generations(t, f, f.u) != 3 {
		t.Fatalf("device lost after the healing Sync: generation %d", gen)
	}
}

// TestDeviceLostContinuesAfterPartial: after device lost ended with
// ErrPartial, running it again continues step 4 with generation 2 and
// generation 1 derived from the seed, and creates no generation 3 (task
// 06f finding 2c), as long as something is left; once the recovery
// record is confirmed, it completes: recovery.wrap and the epoch
// generation-revoked, read by the recovery recipient. Only then does
// device lost create generation 3 again. The words of another seed are
// refused (ErrSeed) and change nothing.
func TestDeviceLostContinuesAfterPartial(t *testing.T) {
	f := newFixture(t)
	old, _, words := restoredRecovery(t, f)
	deviceLostPartial(t, f, 2)
	w := deviceLostPartial(t, f, 2)
	if !strings.Contains(strings.Join(w, "\n"), "setzt die Neuausstellung der Dateien der Generation 1 fort") || generations(t, f, f.u) != 2 {
		t.Fatalf("device lost again created a generation: %d (%q)", generations(t, f, f.u), w)
	}
	other := testenv.New(t).NewUser("other")
	if _, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, other.Words); !errors.Is(err, client.ErrSeed) {
		t.Fatalf("other seed: %v", err)
	}
	ac := f.env.Reopen(f.u)
	if err := ac.ConfirmRecovery(f.mbx, yes); err != nil {
		t.Fatal(err)
	}
	ac.Close()
	f.env.Warnings.Take()
	if gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words); gen != 2 || err != nil {
		t.Fatalf("device lost after ConfirmRecovery: %d, %v", gen, err)
	}
	onlyIDs(t, f.env.Warnings.Take())
	if generations(t, f, f.u) != 2 {
		t.Fatal("a generation was created")
	}
	recoveryWrapsSignedBy(t, f, f.u, 2)
	if headGen(t, f, f.u) != 2 {
		t.Fatal("no epoch for alice's generation 2")
	}
	rc, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, words)
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, f.env, rc, f.mbx, old.ID, "before the loss")
	rc.Close()
	f.env.Reopen(f.u)
	if gen := f.env.DeviceLost(f.u); gen != 3 {
		t.Fatalf("device lost after the completed run: generation %d", gen)
	}
}

// TestDeviceLostFoldersTakeoverOnce: bob changes the folders, so
// folders.gml of epoch 5 on is signed by his generation 1; alice checks it
// (check record) and bob moves to generation 2. Alice's device lost takes
// the file over once, signed by her generation 2 with the version one
// above (task 06f finding 5): step 2 only checks it.
func TestDeviceLostFoldersTakeoverOnce(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	list, err := bob.Client.Folders(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.NewID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.Client.SetFolders(f.mbx, append(list, store.Folder{ID: id, Name: "Archiv"})); err != nil {
		t.Fatal(err)
	}
	data := mustRead(t, f.env.Store.FoldersFile(f.mbx, 5))
	h := parse(t, data)
	if store.ID(h.Trailer.Signer.ID) != bob.ID || h.Trailer.Signer.Gen != 1 {
		t.Fatal("folders.gml of epoch 5 not signed by bob")
	}
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	f.env.Rotate(bob)
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	g := parse(t, mustRead(t, f.env.Store.FoldersFile(f.mbx, 5)))
	if store.ID(g.Trailer.Signer.ID) != f.u.ID || g.Trailer.Signer.Gen != 2 || g.Header.Version != h.Header.Version+1 {
		t.Fatalf("folders.gml of epoch 5: signed by %s generation %d, version %d (was %d)", store.ID(g.Trailer.Signer.ID), g.Trailer.Signer.Gen, g.Header.Version, h.Header.Version)
	}
	if n := strings.Count(strings.Join(f.env.Warnings.Take(), "\n"), "folders.gml der Epoche 5 von "+f.mbx.String()+" war von einer widerrufenen Generation signiert"); n != 1 {
		t.Fatalf("taken over %d times", n)
	}
	l, err := f.u.Client.FoldersOfEpoch(f.mbx, 5)
	if err != nil || len(l.Folders) != len(list)+1 {
		t.Fatalf("folders after the takeover: %v", err)
	}
}

// TestSyncHealsRevokedSigner: bob and carol are members; their wraps of
// the epochs since they joined are signed by alice's generation 1, which
// is revoked (testenv.Rotate, without device lost). On bob's Sync, carol's
// wraps of the epochs that list her are issued again by bob, although
// they are for her current generation (task 06f finding 2b), and bob's own
// wraps, which he took with his wrap-accept, are sealed again by himself.
// Carol then reads without any wrap-accept.
func TestSyncHealsRevokedSigner(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	carol := f.env.NewUser("carol")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	f.env.Share(f.u, f.mbx, carol, client.ShareOptions{})
	m := f.deliver(t, "both", "for bob and carol")
	readBody(t, f.env, bob.Client, f.mbx, m.ID, "for bob and carol")
	// Bob countersigns his wraps while alice's generation 1 is valid.
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	cur := chainOf(t, f.env, f.mbx)
	var shared *store.Epoch
	for _, e := range cur {
		if _, ok := e.Member(carol.ID); ok && shared == nil {
			shared = e
		}
	}
	if tr := wrapOf(t, f.env, f.mbx, shared.Number, carol.ID).Trailer; store.ID(tr.Signer.ID) != f.u.ID || tr.Signer.Gen != 1 {
		t.Fatal("carol's wrap not signed by alice's generation 1")
	}
	f.env.Rotate(f.u)
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	if err := f.env.Reopen(bob).Sync(); err != nil {
		t.Fatal(err)
	}
	w := strings.Join(f.env.Warnings.Take(), "\n")
	onlyIDs(t, strings.Split(w, "\n"))
	if !strings.Contains(w, "für "+carol.ID.String()+" auf Generation 1 neu ausgestellt") || !strings.Contains(w, "eigene Verpackung der Epoche") {
		t.Fatalf("warnings: %s", w)
	}
	for _, u := range []*testenv.User{bob, carol} {
		if tr := wrapOf(t, f.env, f.mbx, shared.Number, u.ID).Trailer; store.ID(tr.Signer.ID) != bob.ID {
			t.Fatalf("wrap of %s of epoch %d not issued again by bob", u.ID, shared.Number)
		}
	}
	for _, e := range chainOf(t, f.env, f.mbx) {
		if err := os.Remove(f.env.Store.AcceptFile(f.mbx, e.Number, carol.ID)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	readBody(t, f.env, f.env.Reopen(carol), f.mbx, m.ID, "for bob and carol")
	readBody(t, f.env, f.env.Reopen(bob), f.mbx, m.ID, "for bob and carol")
}

// TestWordErrorsNameNoInput: unknown words or a wrong number of words
// give an error that does not name the input; NFKD width characters and
// upper case are normalized like every word input.
func TestWordErrorsNameNoInput(t *testing.T) {
	f := newFixture(t)
	cfg := f.env.ClientConfig(f.u.Dir)
	f.u.Client.Close()
	bad := append([]string(nil), f.u.Words...)
	bad[3] = "Zebraxyz"
	for name, in := range map[string][]string{"unknown": bad, "few": f.u.Words[:5], "nfkd": {"① " + strings.Join(f.u.Words, "　")}} {
		_, err := client.DeviceLost(cfg, testenv.Passphrase, in)
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if s := err.Error(); strings.Contains(strings.ToLower(s), "zebraxyz") || strings.Contains(s, f.u.Words[0]) {
			t.Fatalf("%s: error names the input: %v", name, err)
		}
	}
	fancy := []string{strings.ToUpper(strings.Join(f.u.Words, "　"))}
	if _, err := client.Restore(f.env.ClientConfig(t.TempDir()), client.RestoreOptions{Words: fancy}, testenv.Passphrase); err != nil {
		t.Fatalf("restore with NFKD ideographic space and upper case: %v", err)
	}
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, fancy); err != nil || gen != 2 {
		t.Fatalf("device lost with NFKD ideographic space and upper case: %d, %v", gen, err)
	}
}
