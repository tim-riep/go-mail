package client_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 06b: device lost, wrap-accept and takeover (S13).

// memberGen returns the generation of id in e (0 if not listed).
func memberGen(e *store.Epoch, id store.ID) uint32 {
	for _, m := range e.Members {
		if m.ID == id {
			return m.Gen
		}
	}
	return 0
}

// discardedOf returns the epochs discarded by an epoch of es.
func discardedOf(es []*store.Epoch) map[uint32]bool {
	out := map[uint32]bool{}
	for _, e := range es {
		for _, n := range e.Discards {
			out[n] = true
		}
	}
	return out
}

// wrapOf parses the wrap of epoch n of mbx for user.
func wrapOf(t *testing.T, env *testenv.Env, mbx store.ID, n uint32, user store.ID) *envelope.File {
	t.Helper()
	data, err := env.Store.ReadWrap(mbx, n, user)
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, data)
}

// copyClientDir copies the files of a client directory (key store,
// user.rec, state.json) to dst: the thief's copy of a device.
func copyClientDir(t *testing.T, src, dst string) string {
	t.Helper()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"keystore", "user.rec", "state.json"} {
		if err := os.WriteFile(filepath.Join(dst, name), mustRead(t, filepath.Join(src, name)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// readBody reads mail id of mbx with c and checks that it holds text.
func readBody(t *testing.T, env *testenv.Env, c *client.Client, mbx, id store.ID, text string) {
	t.Helper()
	_, body, err := c.Read(mbx, id)
	if err != nil || !strings.Contains(string(body), text) {
		t.Fatalf("mail %q: %v (%q)", text, err, env.Warnings.Take())
	}
}

// TestDeviceLostTwoMembers: alice loses her device. With her seed she
// creates generation 2: user.rec names it, the key store holds it, an
// epoch generation-revoked signed by generation 2 discards the supply,
// every wrap of a listed member and folders.gml she signed with
// generation 1 is issued again, and her own wraps are sealed for
// generation 2. Bob's wraps of epochs 1 to 4, from before he became a
// member (a past period for him), are not issued again (their template is
// signed by the revoked generation, task 06f); bob reads them with his
// wrap-accept. Alice reads old and new mails, so does bob after his Sync. The thief with the old key
// store cannot open the client, cannot open any new wrap, and an epoch
// he signs with generation 1 breaks the chain for every member (ErrChain)
// and is replaced by the next change.
func TestDeviceLostTwoMembers(t *testing.T) {
	f := newFixture(t)
	alice := f.u
	old := f.deliver(t, "old", "before the loss")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(alice, f.mbx, bob, client.ShareOptions{From: 1})
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	readBody(t, f.env, bob.Client, f.mbx, old.ID, "before the loss")
	thief := copyClientDir(t, alice.Dir, filepath.Join(f.env.Base, "thief"))
	oldKs := f.env.Keystore(alice)
	defer oldKs.Zero()
	before := chainOf(t, f.env, f.mbx)
	f.env.Clock.Advance(time.Hour)
	now := f.env.Clock.Now()
	if gen := f.env.DeviceLost(alice); gen != 2 {
		t.Fatalf("generation %d", gen)
	}
	u, raw, err := f.env.Store.ReadUser(alice.ID)
	if err != nil || u.Current().Gen != 2 || u.Current().Revokes != 1 {
		t.Fatalf("user.rec: %v", err)
	}
	if !bytes.Equal(raw, mustRead(t, filepath.Join(alice.Dir, "user.rec"))) {
		t.Fatal("user.rec of the client directory differs")
	}
	if ks := f.env.Keystore(alice); ks.Generation != 2 {
		t.Fatalf("key store holds generation %d", ks.Generation)
	}
	after := chainOf(t, f.env, f.mbx)
	e := checkImmediate(t, before, after, now, store.ReasonGenerationRevoked)
	if e.SignerID != alice.ID || e.SignerGen != 2 || memberGen(e, alice.ID) != 2 || memberGen(e, bob.ID) != 1 {
		t.Fatalf("epoch %d: signer %s/%d, members %v", e.Number, e.SignerID, e.SignerGen, e.Members)
	}
	discarded := discardedOf(after)
	for _, x := range after {
		if discarded[x.Number] {
			continue
		}
		if _, ok := x.Member(alice.ID); !ok {
			continue
		}
		if w := wrapOf(t, f.env, f.mbx, x.Number, alice.ID); w.Recipients[0].Gen != 2 || w.Trailer.Signer.Gen != 2 {
			t.Fatalf("own wrap of epoch %d not issued for generation 2", x.Number)
		}
		// The wraps issued again are countersigned; those of the new
		// epochs are countersigned once they are read.
		a, err := f.env.Store.ReadAccept(f.mbx, x.Number, alice.ID)
		if x.Number < e.Number && (err != nil || a.UserGen != 2 || a.WrapHash != sha256Sum(mustRead(t, f.env.Store.WrapFile(f.mbx, x.Number, alice.ID)))) {
			t.Fatalf("own wrap of epoch %d not countersigned by generation 2: %v", x.Number, err)
		}
		_, bobListed := x.Member(bob.ID)
		for _, p := range []string{f.env.Store.WrapFile(f.mbx, x.Number, bob.ID), f.env.Store.FoldersFile(f.mbx, x.Number)} {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			old := false
			if tr := parse(t, data).Trailer; tr.Signer.ID == alice.ID && tr.Signer.Gen == 1 {
				old = true
			}
			if past := !bobListed && p != f.env.Store.FoldersFile(f.mbx, x.Number); old != past {
				t.Fatalf("%s of epoch %d: signed by generation 1 %v, past period %v", filepath.Base(p), x.Number, old, past)
			}
		}
	}
	fresh := f.deliver(t, "new", "after the loss")
	readBody(t, f.env, alice.Client, f.mbx, old.ID, "before the loss")
	readBody(t, f.env, alice.Client, f.mbx, fresh.ID, "after the loss")
	bc := f.env.Reopen(bob)
	if err := bc.Sync(); err != nil {
		t.Fatal(err)
	}
	if n := len(chainOf(t, f.env, f.mbx)); n != len(after) {
		t.Fatalf("bob's Sync created %d epochs", n-len(after))
	}
	readBody(t, f.env, bc, f.mbx, old.ID, "before the loss")
	readBody(t, f.env, bc, f.mbx, fresh.ID, "after the loss")

	// The thief: no client, no new wrap.
	f.env.Warnings.Take()
	if _, err := client.Open(f.env.ClientConfig(thief), testenv.Passphrase); !errors.Is(err, client.ErrDeviceLostPending) {
		t.Fatalf("client with the old key store: %v", err)
	}
	for _, x := range after[len(before):] {
		if discarded[x.Number] {
			continue
		}
		w := wrapOf(t, f.env, f.mbx, x.Number, alice.ID)
		for _, gen := range []uint32{1, 2} {
			if _, err := w.Decrypt(envelope.RecipientKey{Type: envelope.RecipientUserUnwrap, ID: alice.ID, Gen: gen, PrivateKey: oldKs.Unwrap}); err == nil {
				t.Fatalf("the old unwrap key opens the wrap of epoch %d", x.Number)
			}
		}
	}
	// An epoch signed with the old key store breaks the chain.
	m, err := f.env.Store.ReadMailbox(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	head := after[len(after)-1]
	forged := f.env.ForgeEpoch(&testenv.User{Dir: thief, ID: alice.ID}, f.mbx, f.env.Clock.Now(), store.ReasonMemberAdded, head.Members, "A")
	if forged.SignerGen != 1 {
		t.Fatal("not forged with generation 1")
	}
	f.env.Warnings.Take()
	err = f.env.Reopen(bob).Sync()
	if !errors.Is(err, store.ErrChain) || !strings.Contains(err.Error(), "signed by a revoked generation") || !strings.Contains(err.Error(), "names a newer generation") {
		t.Fatalf("bob accepts an epoch of the revoked generation: %v", err)
	}
	// The warning names the epoch and a fixed cause, not the error text.
	w := f.env.Warnings.Take()
	onlyIDs(t, w)
	if s := strings.Join(w, "\n"); !strings.Contains(s, "bricht bei Epoche") || !strings.Contains(s, "widerrufenen Generation") {
		t.Fatalf("warnings: %s", s)
	}
	if err := f.env.Reopen(alice).Sync(); !errors.Is(err, store.ErrChain) {
		t.Fatalf("alice accepts an epoch of her revoked generation: %v", err)
	}
	// Beyond the head (the server ignores it), it is invalid for good and
	// the next change replaces it.
	if err := f.env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	if err := alice.Client.Revoke(f.mbx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if e, _, err := f.env.Store.ReadEpoch(f.mbx, forged.Number); err != nil || e.SignerGen != 2 || e.Reason != store.ReasonMemberRemoved {
		t.Fatalf("forged epoch not replaced: %v", err)
	}
}

// TestDeviceLostWrongSeed: the words of another seed, unknown words or a
// wrong passphrase change nothing; errors name positions, never words.
func TestDeviceLostWrongSeed(t *testing.T) {
	env := testenv.New(t)
	alice := env.NewUser("alice")
	mallory := env.NewUser("mallory")
	alice.Client.Close()
	cfg := env.ClientConfig(alice.Dir)
	ks := mustRead(t, filepath.Join(alice.Dir, "keystore"))
	_, user, _ := env.Store.ReadUser(alice.ID)
	if _, err := client.DeviceLost(cfg, testenv.Passphrase, mallory.Words); !errors.Is(err, client.ErrSeed) {
		t.Fatalf("seed of another user: %v", err)
	}
	words := append([]string(nil), alice.Words...)
	words[4] = "notaword"
	if _, err := client.DeviceLost(cfg, testenv.Passphrase, words); !errors.Is(err, keys.ErrUnknownWord) || strings.Contains(err.Error(), "notaword") || !strings.Contains(err.Error(), "word 5") {
		t.Fatalf("unknown word: %v", err)
	}
	words[4] = alice.Words[5]
	if _, err := client.DeviceLost(cfg, testenv.Passphrase, words); !errors.Is(err, keys.ErrChecksum) {
		t.Fatalf("wrong word: %v", err)
	}
	if _, err := client.DeviceLost(cfg, []byte("wrong"), alice.Words); !errors.Is(err, keys.ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := client.DeviceLost(cfg, nil, alice.Words); err == nil {
		t.Fatal("empty passphrase")
	}
	if _, err := client.DeviceLost(env.ClientConfig(filepath.Join(env.Base, "nobody")), testenv.Passphrase, alice.Words); !errors.Is(err, client.ErrNotRegistered) {
		t.Fatalf("no client directory: %v", err)
	}
	_, after, _ := env.Store.ReadUser(alice.ID)
	if !bytes.Equal(after, user) || !bytes.Equal(ks, mustRead(t, filepath.Join(alice.Dir, "keystore"))) {
		t.Fatal("changed by a failed device lost")
	}
	// While the client runs, its directory is locked.
	c := env.Reopen(alice)
	if _, err := client.DeviceLost(cfg, testenv.Passphrase, alice.Words); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("device lost while the client runs: %v", err)
	}
	c.Close()
	// Interrupted after the client directory got user.rec with generation
	// 2: a data directory rolled back to generation 1 is refused.
	client.SetCrashHook(t, func(p string) bool { return p == "devicelost-local" })
	if _, err := client.DeviceLost(cfg, testenv.Passphrase, alice.Words); !errors.Is(err, client.ErrCrashed) {
		t.Fatal(err)
	}
	client.SetCrashHook(t, nil)
	if err := store.WriteFileAtomic(env.Store.UserFile(alice.ID), user); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeviceLost(cfg, testenv.Passphrase, alice.Words); !errors.Is(err, client.ErrUserRecord) {
		t.Fatalf("rolled back user.rec: %v", err)
	}
	if _, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrUserRecord) {
		t.Fatalf("open with a rolled back user.rec: %v", err)
	}
	// Completed, and a second device lost moves on to generation 3.
	if err := store.WritePrivateFileAtomic(filepath.Join(alice.Dir, "user.rec"), user); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeviceLost(cfg, testenv.Passphrase, alice.Words); err != nil {
		t.Fatal(err)
	}
	env.Reopen(alice)
	if gen := env.DeviceLost(alice); gen != 3 {
		t.Fatal(gen)
	}
}

// TestDeviceLostCrash: a crash at every step of DeviceLost loses no
// access. The old key store stays until the last step; the client then
// opens as before or reports ErrDeviceLostPending, and running DeviceLost
// again completes it: alice and bob read the old and new mails. Bob reads
// the old mail before: epoch 1 is a past period for him (he became a
// member after it), its wrap signed by the revoked generation is not
// issued again (task 06f, reissueTarget), and he reads it with his
// wrap-accept (S13).
func TestDeviceLostCrash(t *testing.T) {
	points := []string{
		"devicelost-prepared", "devicelost-user", "devicelost-logged", "devicelost-wrap",
		"epoch-wraps", "epoch-folders", "epoch-written", "immediate", "supply", "mailbox",
		"devicelost-foreign", "folders-resigned", "devicelost-local",
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			alice := f.u
			old := f.deliver(t, "old", "before the loss")
			bob := f.env.NewUser("bob")
			f.env.Clock.Advance(time.Hour)
			f.env.Share(alice, f.mbx, bob, client.ShareOptions{From: 1})
			readBody(t, f.env, bob.Client, f.mbx, old.ID, "before the loss")
			if err := bob.Client.Sync(); err != nil {
				t.Fatal(err)
			}
			if err := alice.Client.Sync(); err != nil {
				t.Fatal(err)
			}
			f.env.Clock.Advance(time.Hour)
			ks := mustRead(t, filepath.Join(alice.Dir, "keystore"))
			alice.Client.Close()
			hits := 0
			client.SetCrashHook(t, func(p string) bool {
				if p == point {
					hits++
					return hits == 1
				}
				return false
			})
			cfg := f.env.ClientConfig(alice.Dir)
			if _, err := client.DeviceLost(cfg, testenv.Passphrase, alice.Words); !errors.Is(err, client.ErrCrashed) {
				t.Fatalf("no crash at %s: %v", point, err)
			}
			client.SetCrashHook(t, nil)
			if !bytes.Equal(ks, mustRead(t, filepath.Join(alice.Dir, "keystore"))) {
				t.Fatal("the old key store was replaced before the last step")
			}
			if c, err := client.Open(cfg, testenv.Passphrase); err == nil {
				// Before user.rec named generation 2: alice works as before.
				readBody(t, f.env, c, f.mbx, old.ID, "before the loss")
				c.Close()
			} else if !errors.Is(err, client.ErrDeviceLostPending) {
				t.Fatalf("open after the crash: %v", err)
			}
			gen, err := client.DeviceLost(cfg, testenv.Passphrase, alice.Words)
			if err != nil || gen != 2 {
				t.Fatalf("device lost again: %d, %v", gen, err)
			}
			f.env.Reopen(alice)
			fresh := f.deliver(t, "new", "after the loss")
			readBody(t, f.env, alice.Client, f.mbx, old.ID, "before the loss")
			readBody(t, f.env, alice.Client, f.mbx, fresh.ID, "after the loss")
			bc := f.env.Reopen(bob)
			if err := bc.Sync(); err != nil {
				t.Fatal(err)
			}
			readBody(t, f.env, bc, f.mbx, old.ID, "before the loss")
			readBody(t, f.env, bc, f.mbx, fresh.ID, "after the loss")
			head := chainOf(t, f.env, f.mbx)
			revoked := 0
			for _, e := range head {
				if e.Reason == store.ReasonGenerationRevoked {
					revoked++
				}
			}
			if revoked != 1 {
				t.Fatalf("%d epochs generation-revoked", revoked)
			}
		})
	}
}

// TestSyncWrapsForNewGeneration: alice moves to generation 2 without
// device lost doing anything in the mailbox (testenv.Rotate). On his
// Sync bob, a user member, wraps the epochs he is a member of for her
// generation 2, replacing the wraps of the revoked one (2.2 point 5), and
// because the head still names generation 1, begins an epoch
// generation-revoked that discards the supply (K1 point 4). Alice reads
// the mails of those epochs; her wrap of epoch 1, which bob is not a
// member of, stays as it was (device lost issues it again).
func TestSyncWrapsForNewGeneration(t *testing.T) {
	f := newFixture(t)
	alice := f.u
	old := f.deliver(t, "old", "epoch one")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(alice, f.mbx, bob, client.ShareOptions{From: 1})
	mid := f.deliver(t, "mid", "member added")
	readBody(t, f.env, bob.Client, f.mbx, mid.ID, "member added")
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	before := chainOf(t, f.env, f.mbx)
	shared := before[len(before)-4]
	if shared.Reason != store.ReasonMemberAdded {
		t.Fatal("no member-added epoch")
	}
	f.env.Rotate(alice)
	f.env.Clock.Advance(time.Minute)
	now := f.env.Clock.Now()
	f.env.Warnings.Take()
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	after := chainOf(t, f.env, f.mbx)
	e := checkImmediate(t, before, after, now, store.ReasonGenerationRevoked)
	if e.SignerID != bob.ID || memberGen(e, alice.ID) != 2 {
		t.Fatalf("epoch %d signed by %s, alice with generation %d", e.Number, e.SignerID, memberGen(e, alice.ID))
	}
	if w := wrapOf(t, f.env, f.mbx, shared.Number, alice.ID); w.Recipients[0].Gen != 2 || store.ID(w.Trailer.Signer.ID) != bob.ID {
		t.Fatal("bob did not wrap the member-added epoch for generation 2")
	}
	if w := wrapOf(t, f.env, f.mbx, 1, alice.ID); w.Recipients[0].Gen != 1 {
		t.Fatal("epoch 1, which bob is no member of, was changed")
	}
	if w := strings.Join(f.env.Warnings.Take(), "\n"); !strings.Contains(w, "Generation 2 neu ausgestellt") {
		t.Fatalf("warnings: %s", w)
	}
	fresh := f.deliver(t, "new", "generation revoked")
	readBody(t, f.env, alice.Client, f.mbx, mid.ID, "member added")
	readBody(t, f.env, alice.Client, f.mbx, fresh.ID, "generation revoked")
	if _, _, err := alice.Client.Read(f.mbx, old.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("epoch 1 with the wrap of generation 1: %v", err)
	}
	// Nothing more to do on the next Sync.
	if err := f.env.Reopen(bob).Sync(); err != nil {
		t.Fatal(err)
	}
	if len(chainOf(t, f.env, f.mbx)) != len(after) {
		t.Fatal("a second epoch generation-revoked")
	}
}

// TestDelegateDeviceLost: a delegate never creates epochs. After its
// device lost its own wraps stay for its old generation, and on the next
// Sync a user member wraps the epochs for its new generation and begins
// the epoch generation-revoked (K1 point 4).
func TestDelegateDeviceLost(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "before the loss")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 1, Delegate: true})
	readBody(t, f.env, bob.Client, f.mbx, old.ID, "before the loss")
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	before := chainOf(t, f.env, f.mbx)
	f.env.Warnings.Take()
	if gen := f.env.DeviceLost(bob); gen != 2 {
		t.Fatal(gen)
	}
	if w := strings.Join(f.env.Warnings.Take(), "\n"); !strings.Contains(w, "kein Mitglied") {
		t.Fatalf("warnings: %s", w)
	}
	if len(chainOf(t, f.env, f.mbx)) != len(before) {
		t.Fatal("a delegate created an epoch")
	}
	if _, _, err := bob.Client.Read(f.mbx, old.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("delegate before the member's Sync: %v", err)
	}
	f.env.Clock.Advance(time.Minute)
	now := f.env.Clock.Now()
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	e := checkImmediate(t, before, chainOf(t, f.env, f.mbx), now, store.ReasonGenerationRevoked)
	if memberGen(e, bob.ID) != 2 || kindOf(e, bob.ID) != store.MemberDelegate {
		t.Fatal("delegate not in the new epoch with generation 2")
	}
	readBody(t, f.env, f.env.Reopen(bob), f.mbx, old.ID, "before the loss")
}

// TestFoldersTakeover: folders.gml of epoch 5 is signed by alice's
// generation 1. After she moved to generation 2 (testenv.Rotate), carol,
// who never checked it, rejects it with a warning; bob, who checked it
// before (Sync), takes it over: he signs it again with his identity as
// version 2, and then carol accepts it as well.
func TestFoldersTakeover(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	carol := f.env.NewUser("carol")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	shared := chainOf(t, f.env, f.mbx)[4]
	if shared.Number != 5 || shared.Reason != store.ReasonMemberAdded {
		t.Fatal("no member-added epoch 5")
	}
	if _, err := bob.Client.MailboxName(f.mbx); err != nil {
		t.Fatal(err)
	}
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	if wrapped := f.env.Share(bob, f.mbx, carol, client.ShareOptions{From: 5}); len(wrapped) != 1 {
		t.Fatalf("wrapped %v", wrapped)
	}
	data := mustRead(t, f.env.Store.FoldersFile(f.mbx, 5))
	if tr := parse(t, data).Trailer; store.ID(tr.Signer.ID) != f.u.ID || tr.Signer.Gen != 1 {
		t.Fatal("folders.gml of epoch 5 not signed by alice's generation 1")
	}
	f.env.Rotate(f.u)
	cc := f.env.Reopen(carol)
	f.env.Warnings.Take()
	if _, err := cc.FoldersOfEpoch(f.mbx, 5); !errors.Is(err, client.ErrSigner) {
		t.Fatalf("carol, without a check record: %v", err)
	}
	if w := strings.Join(f.env.Warnings.Take(), "\n"); !strings.Contains(w, "vorher nicht geprüft") {
		t.Fatalf("warnings: %s", w)
	}
	if !bytes.Equal(data, mustRead(t, f.env.Store.FoldersFile(f.mbx, 5))) {
		t.Fatal("carol changed folders.gml")
	}
	bc := f.env.Reopen(bob)
	l, err := bc.FoldersOfEpoch(f.mbx, 5)
	if err != nil || l.Name != "A" {
		t.Fatalf("bob, with a check record: %v", err)
	}
	h := parse(t, mustRead(t, f.env.Store.FoldersFile(f.mbx, 5))).Header
	if tr := parse(t, mustRead(t, f.env.Store.FoldersFile(f.mbx, 5))).Trailer; store.ID(tr.Signer.ID) != bob.ID || h.Version != 2 {
		t.Fatalf("folders.gml not signed again by bob (version %d)", h.Version)
	}
	if w := strings.Join(f.env.Warnings.Take(), "\n"); !strings.Contains(w, "übernommen und neu signiert") {
		t.Fatalf("warnings: %s", w)
	}
	if l, err := f.env.Reopen(carol).FoldersOfEpoch(f.mbx, 5); err != nil || l.Name != "A" {
		t.Fatalf("carol after the takeover: %v", err)
	}
	// The file alice signed is never accepted again, not even by bob: a
	// takeover is one way, and the check record now names bob's file.
	if err := f.env.Store.WriteFolders(f.mbx, 5, data); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Reopen(bob).FoldersOfEpoch(f.mbx, 5); err == nil {
		t.Fatal("bob took over the old file again")
	}
}

// genCert certifies generation gen derived by d, signed by signer.
func genCert(t *testing.T, d *keys.UserRoot, signer ed25519.PrivateKey, gen uint32) *keys.GenerationCert {
	return genCertAt(t, d, signer, gen, 7)
}

func genCertAt(t *testing.T, d *keys.UserRoot, signer ed25519.PrivateKey, gen uint32, created int64) *keys.GenerationCert {
	t.Helper()
	id, err := d.IdentityKey(gen)
	if err != nil {
		t.Fatal(err)
	}
	uw, err := d.UnwrapKey(gen)
	if err != nil {
		t.Fatal(err)
	}
	c, err := keys.NewGenerationCert(signer, gen, id.Public().(ed25519.PublicKey), uw.PublicKey(), created)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// encodeUser encodes a user.rec with the given generations and a valid
// root signature, without the checks of store.User.
func encodeUser(t *testing.T, id store.ID, rootPub ed25519.PublicKey, root ed25519.PrivateKey, gens []*keys.GenerationCert) []byte {
	t.Helper()
	var list []*rec.Record
	for _, g := range gens {
		b, err := g.Encode()
		if err != nil {
			t.Fatal(err)
		}
		r, err := rec.Decode(keys.GenerationCertSchema, b)
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, r)
	}
	r := rec.New(store.UserSchema).SetBytes(1, id[:]).SetBytes(2, rootPub).SetList(3, list)
	tbs, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := keys.Sign(root, keys.DomainUser, tbs)
	if err != nil {
		t.Fatal(err)
	}
	data, err := r.SetBytes(4, sig).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestGenerationRecords: user.rec with a generation jump (1, 3) or with a
// generation not signed by the root is rejected wherever it is read; the
// data directory only takes an extension by exactly one generation
// (store.ReplaceUser).
func TestGenerationRecords(t *testing.T) {
	f := newFixture(t)
	alice := f.u
	seed, err := keys.SeedFromWords(alice.Words)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Zero()
	d := keys.DeriveUser(seed)
	defer d.Zero()
	root, _ := d.RootKey()
	user, raw, err := f.env.Store.ReadUser(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	alice.Client.Close()
	gens := func(extra ...*keys.GenerationCert) []*keys.GenerationCert {
		return append(append([]*keys.GenerationCert(nil), user.Generations...), extra...)
	}
	jump := &store.User{ID: alice.ID, RootPub: user.RootPub, Generations: gens(genCert(t, d, root, 3))}
	if err := jump.Sign(root); !errors.Is(err, store.ErrRecord) || !strings.Contains(err.Error(), "expected generation 2") {
		t.Fatalf("jump signed: %v", err)
	}
	if _, err := f.env.Store.ReplaceUser(jump); err == nil {
		t.Fatal("jump replaced")
	}
	other, _ := d.IdentityKey(9)
	unsigned := &store.User{ID: alice.ID, RootPub: user.RootPub, Generations: gens(genCert(t, d, other, 2))}
	if err := unsigned.Sign(root); !errors.Is(err, store.ErrRecord) || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("generation without root signature: %v", err)
	}
	// Written behind the back of the checks, both records are rejected
	// on reading.
	for name, bad := range map[string][]byte{
		"jump":         encodeUser(t, alice.ID, user.RootPub, root, gens(genCert(t, d, root, 3))),
		"not the root": encodeUser(t, alice.ID, user.RootPub, root, gens(genCert(t, d, other, 2))),
	} {
		if _, err := store.DecodeUser(bad); err == nil {
			t.Fatalf("%s: decoded", name)
		}
		if err := store.WriteFileAtomic(f.env.Store.UserFile(alice.ID), bad); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Open(f.env.ClientConfig(alice.Dir), testenv.Passphrase); !errors.Is(err, client.ErrUserRecord) {
			t.Fatalf("%s: open: %v", name, err)
		}
	}
	if err := store.WriteFileAtomic(f.env.Store.UserFile(alice.ID), raw); err != nil {
		t.Fatal(err)
	}
	// ReplaceUser: exactly one more generation, the earlier ones unchanged.
	next := &store.User{ID: alice.ID, RootPub: user.RootPub, Generations: gens(genCert(t, d, root, 2))}
	if err := next.Sign(root); err != nil {
		t.Fatal(err)
	}
	same := &store.User{ID: alice.ID, RootPub: user.RootPub, Generations: user.Generations, Signature: user.Signature}
	if _, err := f.env.Store.ReplaceUser(same); err != nil {
		t.Fatalf("identical record: %v", err)
	}
	if _, err := f.env.Store.ReplaceUser(next); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Store.ReplaceUser(next); err != nil {
		t.Fatalf("again: %v", err)
	}
	if _, err := f.env.Store.ReplaceUser(same); !errors.Is(err, store.ErrExists) {
		t.Fatalf("back to one generation: %v", err)
	}
	other2 := &store.User{ID: alice.ID, RootPub: user.RootPub, Generations: gens(genCertAt(t, d, root, 2, 99))}
	if err := other2.Sign(root); err != nil {
		t.Fatal(err)
	}
	third := &store.User{ID: alice.ID, RootPub: user.RootPub, Generations: append(append([]*keys.GenerationCert(nil), other2.Generations...), genCert(t, d, root, 3))}
	if err := third.Sign(root); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Store.ReplaceUser(third); !errors.Is(err, store.ErrExists) {
		t.Fatalf("other generation 2: %v", err)
	}
	nobody, _ := store.NewID(nil)
	lost := &store.User{ID: nobody, RootPub: user.RootPub, Generations: next.Generations}
	if err := lost.Sign(root); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Store.ReplaceUser(lost); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	// The key store of generation 1 no longer opens the client.
	if _, err := client.Open(f.env.ClientConfig(alice.Dir), testenv.Passphrase); !errors.Is(err, client.ErrDeviceLostPending) {
		t.Fatalf("open: %v", err)
	}
}

// TestDeviceLostRecoveryWrap: the recovery.wrap files alice made with
// generation 1 are issued again with generation 2, so the recovery
// recipient still reads after her device lost.
func TestDeviceLostRecoveryWrap(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "before the loss")
	pub, words := recoveryKey(t)
	f.env.Clock.Advance(time.Hour)
	if err := f.u.Client.SetRecovery(f.mbx, pub, yes); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Hour)
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	chain := chainOf(t, f.env, f.mbx)
	discarded := discardedOf(chain)
	for _, e := range chain {
		data, err := f.env.Store.ReadRecoveryWrap(f.mbx, e.Number)
		if discarded[e.Number] || err != nil {
			continue
		}
		if tr := parse(t, data).Trailer; tr.Signer.Gen != 2 {
			t.Fatalf("recovery.wrap of epoch %d signed by generation %d", e.Number, tr.Signer.Gen)
		}
	}
	rc, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, words)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	readBody(t, f.env, rc, f.mbx, old.ID, "before the loss")
}
