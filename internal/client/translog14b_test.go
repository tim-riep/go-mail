package client_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// More tests of task 14: the first entries (translog doc.go "Who
// writes"), the protocol for unlogged epochs, a rollback of the log by
// one, the platform generations, and the checks of task 06h that go with
// it (D84, mandatory points of task 14).

// newMailboxCopies returns the IDs of the first-entry copies in the client
// directory dir.
func newMailboxCopies(t *testing.T, dir string) []store.ID {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, "new-mailboxes"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []store.ID
	for _, e := range ents {
		id, err := store.ParseID(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

// TestLogCreateMailboxFirstEntry: epoch 1 is logged before the mailbox
// appears in the data directory (translog doc.go "Who writes", findings
// 03c-1, 03d-4, 03d-5). A crash after the copy, after the log entry or
// after mailbox.rec is completed by the next Open; a copy without
// epoch.rec is removed; an ID that somebody else logged first gives the
// mailbox a new ID.
func TestLogCreateMailboxFirstEntry(t *testing.T) {
	f := newFixture(t)
	for _, point := range []string{"mailbox-copy", "mailbox-logged", "mailbox-written"} {
		client.SetCrashHook(t, func(p string) bool { return p == point })
		if _, err := f.u.Client.CreateMailbox("C " + point); !errors.Is(err, client.ErrCrashed) {
			t.Fatalf("%s: %v", point, err)
		}
		client.SetCrashHook(t, nil)
		copies := newMailboxCopies(t, f.u.Dir)
		if len(copies) != 1 {
			t.Fatalf("%s: copies %v", point, copies)
		}
		id := copies[0]
		if point != "mailbox-written" {
			if _, err := os.Stat(f.env.Store.MailboxDir(id)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s: the mailbox is in the data directory before step 3: %v", point, err)
			}
		}
		f.env.Warnings.Take()
		c := f.env.Reopen(f.u)
		warningWith(t, f.env.Warnings.Take(), id.String(), "fertiggestellt")
		if copies := newMailboxCopies(t, f.u.Dir); len(copies) != 0 {
			t.Fatalf("%s: copy left: %v", point, copies)
		}
		if err := c.Sync(); err != nil {
			t.Fatalf("%s: %v", point, err)
		}
		if name, err := c.MailboxName(id); err != nil || name != "C "+point {
			t.Fatalf("%s: %q %v", point, name, err)
		}
		logMatchesStore(t, f.env, id)
	}
	// A leftover from before step 2 (no epoch.rec) is removed.
	left, _ := store.NewID(nil)
	ld := filepath.Join(f.u.Dir, "new-mailboxes", left.String())
	if err := os.MkdirAll(ld, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ld, "wrap"), []byte("w"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.env.Reopen(f.u)
	if _, err := os.Stat(ld); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leftover without epoch.rec: %v", err)
	}
	// Somebody logs an epoch 1 with the chosen ID first (K2 rule 4).
	bob := f.env.NewUser("bob")
	bks := f.env.Keystore(bob)
	defer bks.Zero()
	var taken store.ID
	client.SetCrashHook(t, func(p string) bool {
		if p == "mailbox-copy" && taken.IsZero() {
			taken = newMailboxCopies(t, f.u.Dir)[0]
			if _, err := f.env.LogOperator().Append(translog.KindEpoch, epochOne(t, f.env, taken, bob, bks)); err != nil {
				t.Fatal(err)
			}
		}
		return false
	})
	f.env.Warnings.Take()
	id, err := f.u.Client.CreateMailbox("D")
	client.SetCrashHook(t, nil)
	if err != nil || id == taken || taken.IsZero() {
		t.Fatalf("taken ID: %s %s %v", id, taken, err)
	}
	warningWith(t, f.env.Warnings.Take(), "bereits vergeben")
	if _, err := os.Stat(f.env.Store.MailboxDir(taken)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the taken ID was written to the data directory")
	}
	if len(newMailboxCopies(t, f.u.Dir)) != 0 {
		t.Fatal("copy of the taken ID left")
	}
	logMatchesStore(t, f.env, id)
	// A copy whose ID somebody logged first is dropped on resuming.
	client.SetCrashHook(t, func(p string) bool { return p == "mailbox-copy" })
	if _, err := f.u.Client.CreateMailbox("E"); !errors.Is(err, client.ErrCrashed) {
		t.Fatal(err)
	}
	client.SetCrashHook(t, nil)
	lost := newMailboxCopies(t, f.u.Dir)[0]
	if _, err := f.env.LogOperator().Append(translog.KindEpoch, epochOne(t, f.env, lost, bob, bks)); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	f.env.Reopen(f.u)
	warningWith(t, f.env.Warnings.Take(), lost.String(), "bereits vergeben")
	if len(newMailboxCopies(t, f.u.Dir)) != 0 {
		t.Fatal("copy of a taken ID kept")
	}
}

// epochOne returns an epoch 1 of mailbox id signed by u, with u as its
// only member.
func epochOne(t *testing.T, env *testenv.Env, id store.ID, u *testenv.User, ks *keys.Keystore) []byte {
	t.Helper()
	content, _ := ecdh.X25519().GenerateKey(rand.Reader)
	meta, _ := ecdh.X25519().GenerateKey(rand.Reader)
	e := &store.Epoch{MailboxID: id, Number: 1, Begin: env.Clock.Now().UnixMilli(), Reason: store.ReasonRegular, Suite: envelope.Suite1,
		ContentPub: content.PublicKey(), MetaPub: meta.PublicKey(),
		Members:  []store.Member{{Kind: store.MemberUser, ID: u.ID, Gen: ks.Generation}},
		SignerID: u.ID, SignerGen: ks.Generation}
	if err := e.Sign(ks.Identity); err != nil {
		t.Fatal(err)
	}
	data, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestLogRegisterFirstEntry: Register consumes the invitation, notes it
// (InviteUsed), appends the user entry and only then writes user.rec to
// the data directory. A crash at either point is completed by running
// Register again (the used invitation is not consumed again); a user ID
// that somebody logged first stops Register before the data directory.
func TestLogRegisterFirstEntry(t *testing.T) {
	env := testenv.New(t)
	dir := filepath.Join(env.Base, "clients", "carol")
	cfg := env.ClientConfig(dir)
	id, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
	if err != nil {
		t.Fatal(err)
	}
	code, err := env.Store.CreateInvite(env.Clock.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	logged := func() int {
		ents, err := env.LogOperator().Lookup(translog.KindUser, id[:])
		if err != nil {
			t.Fatal(err)
		}
		return len(ents)
	}
	client.SetCrashHook(t, func(p string) bool { return p == "register-invite" })
	if _, err := client.Register(cfg, code); !errors.Is(err, client.ErrCrashed) {
		t.Fatal(err)
	}
	if _, _, err := env.Store.ReadUser(id); !errors.Is(err, store.ErrNotFound) || logged() != 0 {
		t.Fatalf("after the invitation: %v, %d entries", err, logged())
	}
	client.SetCrashHook(t, func(p string) bool { return p == "register-logged" })
	if _, err := client.Register(cfg, code); !errors.Is(err, client.ErrCrashed) {
		t.Fatal(err)
	}
	if _, _, err := env.Store.ReadUser(id); !errors.Is(err, store.ErrNotFound) || logged() != 1 {
		t.Fatalf("after the log entry: %v, %d entries", err, logged())
	}
	client.SetCrashHook(t, nil)
	if got, err := client.Register(cfg, code); err != nil || got != id {
		t.Fatalf("resumed: %s %v", got, err)
	}
	c, err := client.Open(cfg, testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// Somebody else logs a user with dave's ID first.
	ddir := filepath.Join(env.Base, "clients", "dave")
	dcfg := env.ClientConfig(ddir)
	did, err := client.Keygen(dcfg, testenv.Passphrase, &testenv.Echo{})
	if err != nil {
		t.Fatal(err)
	}
	seed := keys.Seed{9}
	d := keys.DeriveUser(&seed)
	defer d.Zero()
	root, err := d.RootKey()
	if err != nil {
		t.Fatal(err)
	}
	other := encodeUser(t, did, root.Public().(ed25519.PublicKey), root, []*keys.GenerationCert{genCert(t, d, root, 1)})
	if _, err := env.LogOperator().Append(translog.KindUser, other); err != nil {
		t.Fatal(err)
	}
	code2, _ := env.Store.CreateInvite(env.Clock.Now().UnixMilli())
	_, err = client.Register(dcfg, code2)
	if !errors.Is(err, translog.ErrDuplicate) || !strings.Contains(err.Error(), "keygen") {
		t.Fatalf("taken user ID: %v", err)
	}
	if _, _, err := env.Store.ReadUser(did); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("user.rec written for a taken ID")
	}
}

// TestLogUnloggedSignerAppended: bob signs epoch head+1 with a generation
// whose user.rec is in the data directory but not in the log (a crash of
// his device lost between user.rec and its entry). Alice's change finds
// the epoch unlogged, appends it, gets ErrUnloggedSigner, appends bob's
// user.rec from the data directory and the epoch again (translog doc.go
// "Unlogged epoch.rec" steps 1 and 2), adopts it and changes on top of it.
func TestLogUnloggedSignerAppended(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	carol := f.env.NewUser("carol")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	seed, err := keys.SeedFromWords(bob.Words)
	if err != nil {
		t.Fatal(err)
	}
	d := keys.DeriveUser(seed)
	seed.Zero()
	defer d.Zero()
	root, err := d.RootKey()
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := f.env.Store.ReadUser(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	gens := append(append([]*keys.GenerationCert(nil), u.Generations...), genCert(t, d, root, 2))
	user2 := encodeUser(t, bob.ID, root.Public().(ed25519.PublicKey), root, gens)
	if err := store.WriteFileAtomic(f.env.Store.UserFile(bob.ID), user2); err != nil {
		t.Fatal(err)
	}
	id2, err := d.IdentityKey(2)
	if err != nil {
		t.Fatal(err)
	}
	epoch := beyondEpoch(t, f, func(e *store.Epoch) {
		e.SignerID, e.SignerGen = bob.ID, 2
		for i := range e.Members {
			if e.Members[i].ID == bob.ID {
				e.Members[i].Gen = 2
			}
		}
	}, id2)
	n := headOf(t, f.env, f.mbx) + 1
	store.MkdirAll(f.env.Store.EpochDir(f.mbx, n))
	if err := store.WriteFileAtomic(f.env.Store.EpochFile(f.mbx, n), epoch); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.LogOperator().Append(translog.KindEpoch, epoch); !errors.Is(err, translog.ErrUnloggedSigner) {
		t.Fatalf("epoch of an unlogged generation: %v", err)
	}
	// mailbox.rec names it (bob's change was interrupted before its log
	// entry): alice's client appends it while it verifies the chain.
	m, err := f.env.Store.ReadMailbox(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	m.Epoch = n
	if err := f.env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	if _, err := f.u.Client.FoldersOfEpoch(f.mbx, 1); err != nil {
		t.Fatal(err)
	}
	if err := f.env.LogOperator().CheckUser(bob.ID, user2); err != nil {
		t.Fatalf("bob's user.rec not appended: %v", err)
	}
	if err := f.env.LogOperator().CheckEpoch(f.mbx, n, epoch); err != nil {
		t.Fatalf("bob's epoch not appended: %v", err)
	}
	logMatchesStore(t, f.env, f.mbx)
	_ = carol
}

// TestLogForeignUserSuperseded: bob's user.rec in the data directory is
// rolled back below his logged generation 2 (a rolled back user.rec
// hides a revocation, 2.3): alice does not use it (CheckUser:
// ErrSuperseded) and warns that it is outdated.
func TestLogForeignUserSuperseded(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	old := mustRead(t, f.env.Store.UserFile(bob.ID))
	f.env.Clock.Advance(time.Minute)
	f.env.Rotate(bob)
	if err := store.WriteFileAtomic(f.env.Store.UserFile(bob.ID), old); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if _, err := f.u.Client.Share(f.mbx, bob.ID, client.ShareOptions{}); !errors.Is(err, client.ErrSuperseded) || !errors.Is(err, translog.ErrSuperseded) {
		t.Fatalf("share with an outdated user.rec: %v", err)
	}
	warningWith(t, f.env.Warnings.Take(), bob.ID.String(), "veraltet")
	// bob's own client refuses it as well.
	bob.Client.Close()
	if _, err := client.Open(f.env.ClientConfig(bob.Dir), testenv.Passphrase); err == nil {
		t.Fatal("bob opens with an outdated user.rec")
	}
}

// platformKeys derives identity 1 and ingest generation gen from the root
// of the development ceremony of env (its key directory).
func platformKeys(t *testing.T, env *testenv.Env, gen uint32) (identity, ingest ed25519.PrivateKey) {
	t.Helper()
	text := string(mustRead(t, filepath.Join(env.KeyDir, ceremony.RootFile)))
	i := strings.Index(text, "seed: ")
	if i < 0 {
		t.Fatal("no seed in the root file")
	}
	b, err := hex.DecodeString(strings.Fields(text[i+len("seed: "):])[0])
	if err != nil || len(b) != len(keys.Seed{}) {
		t.Fatal("seed", err)
	}
	var seed keys.Seed
	copy(seed[:], b)
	p := keys.DerivePlatform(&seed)
	defer p.Zero()
	if identity, err = p.IdentityKey(1); err != nil {
		t.Fatal(err)
	}
	if ingest, err = p.IngestKey(gen); err != nil {
		t.Fatal(err)
	}
	return identity, ingest
}

// TestLogIngestSuperseded: once ingest-2.cert is a valid entry of the log,
// generation 1 signs validly only metadata received before its valid_from
// (translog doc.go "Platform generations", strictest reading without Q8):
// a mail signed by generation 1 and received later is not shown.
func TestLogIngestSuperseded(t *testing.T) {
	f := newFixture(t)
	early := f.deliver(t, "before", "gen 1")
	identity, ingest2 := platformKeys(t, f.env, 2)
	defer keys.Wipe(identity)
	defer keys.Wipe(ingest2)
	switchAt := f.env.Clock.Now().Add(time.Hour)
	cert, err := keys.NewPlatformCert(identity, 1, keys.RoleIngest, 2, ingest2.Public().(ed25519.PublicKey), switchAt.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	data, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(f.env.Store.Path("platform", "ingest-2.cert"), data); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.LogOperator().Append(translog.KindPlatform, data); err != nil {
		t.Fatal(err)
	}
	f.env.MustPublishHead()
	f.env.Clock.Advance(30 * time.Minute)
	c := f.env.Reopen(f.u)
	deliverTo(t, f, "a@example.org", "still gen 1")
	if list, err := c.List(f.mbx, store.ID{}); err != nil || !strings.Contains(subjects(list), "still gen 1") {
		t.Fatalf("before the switch: %v %s", err, subjects(list))
	}
	f.env.Clock.Advance(time.Hour)
	deliverTo(t, f, "a@example.org", "after the switch")
	f.env.Warnings.Take()
	list, err := c.List(f.mbx, store.ID{})
	if err != nil || strings.Contains(subjects(list), "after the switch") {
		t.Fatalf("after the switch: %v %s", err, subjects(list))
	}
	warningWith(t, f.env.Warnings.Take(), "Plattformzertifikat oder Annahmeschlüssel nicht gültig")
	readBody(t, f.env, c, f.mbx, early.ID, "gen 1")
}

// TestLogRecoverReadTemp: RecoverRead keeps the audit index of its client
// log in a directory of its own, removed by Close and on every error.
func TestLogRecoverReadTemp(t *testing.T) {
	f := newFixture(t)
	old, _, words := restoredRecovery(t, f)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	if _, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, f.u.Words); !errors.Is(err, client.ErrRecovery) {
		t.Fatalf("wrong words: %v", err)
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("left after an error: %v", ents)
	}
	rc, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, words)
	if err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 1 {
		t.Fatalf("audit index directory: %v", ents)
	}
	readBody(t, f.env, rc, f.mbx, old.ID, "before the loss")
	rc.Close()
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("left after Close: %v", ents)
	}
}

// TestLogPendingAfterRollback: alice's own entry (the user entry of her
// registration) is dropped by a rollback of tree.rec by one, and another
// writer takes its index (translog doc.go "Withheld entries", task 11
// addendum (b)). Her next Open finds it replaced (ErrConsistency), removes
// it from the pending entries, appends user.rec again under a new index
// and goes on; without that the client log would take over no head.
func TestLogPendingAfterRollback(t *testing.T) {
	env := testenv.New(t)
	env.NewUser("bob")
	env.AutoHeads = false
	h0 := env.MustPublishHead()
	dir := filepath.Join(env.Base, "clients", "alice")
	cfg := env.ClientConfig(dir)
	id, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
	if err != nil {
		t.Fatal(err)
	}
	code, _ := env.Store.CreateInvite(env.Clock.Now().UnixMilli())
	if _, err := client.Register(cfg, code); err != nil {
		t.Fatal(err)
	}
	if p := logStateOf(t, dir).Pending; len(p) != 1 || p[0].Index != h0.Size {
		t.Fatalf("pending after Register: %+v", p)
	}
	// tree.rec back to the size of h0: the own entry is gone.
	tree, err := rec.New(translog.TreeSchema).SetI64(1, h0.Size).SetBytes(2, h0.Hash[:]).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(env.Store.Path(translog.TreeFile), tree); err != nil {
		t.Fatal(err)
	}
	// Another writer (a new process) appends and removes the leftover.
	odir := filepath.Join(env.Base, "clients", "other")
	if _, err := client.Keygen(env.ClientConfig(odir), testenv.Passphrase, &testenv.Echo{}); err != nil {
		t.Fatal(err)
	}
	fresh := env.OpenOperator()
	if i, err := fresh.Append(translog.KindUser, mustRead(t, filepath.Join(odir, "user.rec"))); err != nil || i != h0.Size {
		t.Fatalf("append of the other writer: %d %v", i, err)
	}
	signer, err := translog.NewLogSigner(env.IngestKey)
	if err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(time.Minute)
	h1, err := fresh.SignHead(signer, env.Clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	text, _ := h1.Text()
	if h1.Note, err = note.Sign(&note.Note{Text: string(text)}, signer, env.WitnessSigner); err != nil {
		t.Fatal(err)
	}
	if err := fresh.PublishHead(h1); err != nil {
		t.Fatal(err)
	}
	// Without the repair the own entry blocks every head.
	client.SetLogHook(t, func(l translog.Log) translog.Log { return l })
	env.Warnings.Take()
	env.AutoHeads = true
	c, err := client.Open(cfg, testenv.Passphrase)
	if err != nil {
		t.Fatalf("open after the rollback: %v", err)
	}
	defer c.Close()
	warningWith(t, env.Warnings.Take(), "fehlt im Transparenzlog", "erneut eingetragen")
	ents, err := env.LogOperator().Lookup(translog.KindUser, id[:])
	if err != nil || len(ents) != 1 || ents[0].Index <= h0.Size {
		t.Fatalf("own entry appended again: %+v %v", ents, err)
	}
	if p := logStateOf(t, dir).Pending; len(p) != 0 {
		t.Fatalf("pending: %+v", p)
	}
}

// Tests of the verification of task 06h (attacker H1 and H2, spec
// tests), taken over by task 14 (mandatory points 1 to 4 of D84).

// TestH1HiddenMailboxRecDuringContinuation (06h point 2): device lost
// runs while mailbox.rec is withheld after an earlier device lost marked
// the mailbox. It never reports success while the head names the revoked
// generation: the mark stays and the result is ErrPartial. Once the file
// is back, Sync creates the epoch generation-revoked and clears the mark;
// alice reads her old mail.
func TestH1HiddenMailboxRecDuringContinuation(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	mrec := f.env.Store.MailboxFile(f.mbx)
	good := mustRead(t, mrec)
	if err := store.WriteFileAtomic(mrec, []byte("not a mailbox record")); err != nil {
		t.Fatal(err)
	}
	gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
	if gen != 2 || !errors.Is(err, client.ErrPartial) || reissueMark(t, f.u.Dir, f.mbx) != 2 {
		t.Fatalf("device lost: generation %d, %v, mark %d", gen, err, reissueMark(t, f.u.Dir, f.mbx))
	}
	before := memoryOf(t, f.u.Dir, f.mbx)
	if err := os.Remove(mrec); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	gen, err = client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
	noSeed(t, f.env.Warnings.Take(), f.u.Words)
	if gen != 3 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("device lost with mailbox.rec withheld: generation %d, %v", gen, err)
	}
	if m := reissueMark(t, f.u.Dir, f.mbx); m != 2 {
		t.Fatalf("mark %d", m)
	}
	notSmaller(t, "device lost with mailbox.rec withheld", before, memoryOf(t, f.u.Dir, f.mbx))
	if err := store.WriteFileAtomic(mrec, good); err != nil {
		t.Fatal(err)
	}
	if g := headGen(t, f, f.u); g != 1 {
		t.Fatalf("head names generation %d", g)
	}
	// The own wraps are still for generation 1 (no run checked the
	// chain): Sync names the remedy, device lost (generation 4) completes
	// it.
	f.env.Clock.Advance(time.Minute)
	if err := f.env.Reopen(f.u).Sync(); !errors.Is(err, client.ErrPartial) || !strings.Contains(err.Error(), "run device lost again") {
		t.Fatalf("Sync: %v", err)
	}
	if m := reissueMark(t, f.u.Dir, f.mbx); m == 0 {
		t.Fatal("mark cleared while the head names the revoked generation")
	}
	f.u.Client.Close()
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 4 || err != nil {
		t.Fatalf("device lost with mailbox.rec back: generation %d, %v", gen, err)
	}
	if g := headGen(t, f, f.u); g != 4 || reissueMark(t, f.u.Dir, f.mbx) != 0 {
		t.Fatalf("head names generation %d, mark %d", g, reissueMark(t, f.u.Dir, f.mbx))
	}
	readBody(t, f.env, f.env.Reopen(f.u), f.mbx, old.ID, "secret")
}

// TestH2StrawmanCannotBlockGenerations (06h point 1): mallory lists alice
// as a user member of her mailbox without a wrap. Alice's device lost
// cannot complete that mailbox (marked, ErrPartial), but a second device
// lost creates generation 3 all the same: the strawman blocks nothing.
func TestH2StrawmanCannotBlockGenerations(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	mallory := f.env.NewUser("mallory")
	mbox := f.env.Mailbox(mallory, "M", "m@example.org")
	f.env.Clock.Advance(time.Minute)
	f.env.ForgeEpoch(mallory, mbox, f.env.Clock.Now(), store.ReasonMemberAdded, []store.Member{{Kind: store.MemberUser, ID: f.u.ID, Gen: 1}}, "M")
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	f.env.Warnings.Take()
	gen, _ := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
	noSeed(t, f.env.Warnings.Take(), f.u.Words)
	if gen != 2 || headGen(t, f, f.u) != 2 {
		t.Fatalf("first device lost: generation %d", gen)
	}
	readBody(t, f.env, f.env.Reopen(f.u), f.mbx, old.ID, "secret")
	f.u.Client.Close()
	f.env.Clock.Advance(time.Minute)
	gen2, _ := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
	noSeed(t, f.env.Warnings.Take(), f.u.Words)
	if gen2 != 3 || generations(t, f, f.u) != 3 || headGen(t, f, f.u) != 3 {
		t.Fatalf("second device lost: generation %d, %d generations", gen2, generations(t, f, f.u))
	}
	readBody(t, f.env, f.env.Reopen(f.u), f.mbx, old.ID, "secret")
}

// TestVerifyForeignRevokedSignerNotProvenBySeed (verifier of 06h, point
// 4): alice's wraps in bob's mailbox are signed by bob's generation 1,
// which bob revoked; alice never checked them. Her device lost does not
// seal them again from the seed (the seed proves only her own
// signatures), and the epoch does not open for her; bob's device lost
// issues them again (2.2 point 4).
func TestVerifyForeignRevokedSignerNotProvenBySeed(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	mbox := f.env.Mailbox(bob, "B", "b@example.org")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(bob, mbox, f.u, client.ShareOptions{From: 1})
	if len(f.u.Client.Mailboxes()) != 1 {
		t.Fatal("alice knows bob's mailbox")
	}
	f.env.Clock.Advance(time.Minute)
	f.env.Rotate(bob)
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	chain := chainOf(t, f.env, mbox)
	head := chain[len(chain)-1]
	wraps := map[uint32][]byte{}
	for _, e := range chain {
		if wrapExists(f.env, mbox, e.Number, f.u.ID) {
			wraps[e.Number] = mustRead(t, f.env.Store.WrapFile(mbox, e.Number, f.u.ID))
			w := parse(t, wraps[e.Number])
			if store.ID(w.Trailer.Signer.ID) != bob.ID || w.Trailer.Signer.Gen != 1 {
				t.Fatalf("alice's wrap of epoch %d is not signed by bob's generation 1", e.Number)
			}
		}
	}
	if len(wraps) == 0 {
		t.Fatal("alice has no wrap in bob's mailbox")
	}
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
	w := f.env.Warnings.Take()
	noSeed(t, w, f.u.Words)
	if gen != 2 {
		t.Fatalf("device lost: generation %d, %v", gen, err)
	}
	for n, d := range wraps {
		if got := mustRead(t, f.env.Store.WrapFile(mbox, n, f.u.ID)); string(got) != string(d) {
			t.Fatalf("alice's wrap of epoch %d, signed by bob's revoked generation, was sealed again\n%s", n, strings.Join(w, "\n"))
		}
	}
	if _, err := f.env.Reopen(f.u).FoldersOfEpoch(mbox, head.Number); err == nil {
		t.Fatal("epoch of bob's mailbox opens for alice with a wrap signed by a revoked foreign generation")
	}
	f.env.Clock.Advance(time.Minute)
	bob.Client.Close()
	if bgen, berr := client.DeviceLost(f.env.ClientConfig(bob.Dir), testenv.Passphrase, bob.Words); bgen != 3 {
		t.Fatalf("bob's device lost: generation %d, %v", bgen, berr)
	}
	hw := wrapOf(t, f.env, mbox, head.Number, f.u.ID)
	if hw.Recipients[0].Gen != 2 || store.ID(hw.Trailer.Signer.ID) != bob.ID || hw.Trailer.Signer.Gen != 3 {
		t.Fatalf("alice's wrap of epoch %d after bob's device lost: for generation %d, signed by generation %d", head.Number, hw.Recipients[0].Gen, hw.Trailer.Signer.Gen)
	}
}

// TestVerifyStuckSoleMember (verifier of 06h, point 3, Q18): alice is the
// only member; her check records are gone and folders.gml of the newest
// epoch is signed by her revoked generation 1. Sync and device lost name
// the fixed cause (no checked folder list; no remedy at present, Q18),
// never "run device lost again", and no raw error text.
func TestVerifyStuckSoleMember(t *testing.T) {
	f := newFixture(t)
	f.deliver(t, "old", "secret")
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	forgetChecks(t, f.u.Dir, f.mbx)
	cfg := f.env.ClientConfig(f.u.Dir)
	mrec := f.env.Store.MailboxFile(f.mbx)
	good := mustRead(t, mrec)
	if err := store.WriteFileAtomic(mrec, []byte("not a mailbox record")); err != nil {
		t.Fatal(err)
	}
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("device lost: generation %d, %v", gen, err)
	}
	if err := store.WriteFileAtomic(mrec, good); err != nil {
		t.Fatal(err)
	}
	// Device lost again seals the own wraps for generation 3 (the seed
	// proves them), but folders.gml stays unchecked: the fixed cause of
	// Q18, in the error and the warning.
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
	w := f.env.Warnings.Take()
	noSeed(t, w, f.u.Words)
	if gen != 3 || !errors.Is(err, client.ErrPartial) || !strings.Contains(err.Error(), "Q18") || strings.Contains(err.Error(), "device lost run again") {
		t.Fatalf("device lost again: generation %d, %v", gen, err)
	}
	q18 := func(w []string) {
		t.Helper()
		warningWith(t, w, f.mbx.String(), "einzige Mitglied", "keine geprüfte Ordnerliste der Epoche", "derzeit keine Abhilfe, siehe Q18")
		for _, s := range w {
			if strings.Contains(s, f.mbx.String()) && strings.Contains(s, "device lost erneut") {
				t.Fatalf("remedy that never helps: %s", s)
			}
		}
	}
	q18(w)
	f.env.Clock.Advance(time.Minute)
	err = f.env.Reopen(f.u).Sync()
	w = f.env.Warnings.Take()
	noSeed(t, w, f.u.Words)
	if !errors.Is(err, client.ErrPartial) || !strings.Contains(err.Error(), "Q18") || strings.Contains(err.Error(), "device lost again") {
		t.Fatalf("Sync: %v", err)
	}
	q18(w)
	if g := headGen(t, f, f.u); g != 1 || reissueMark(t, f.u.Dir, f.mbx) == 0 {
		t.Fatalf("head names generation %d, mark %d", g, reissueMark(t, f.u.Dir, f.mbx))
	}
}

// TestVerifyBothStaleHint (verifier of 06h, point 3: the hint also when
// another member's entry is stale): alice and bob are members, both
// entries of the head are stale and alice has no checked folder list.
// Her Sync names the fixed cause (another member creates the epoch) in
// a warning without error text, creates no epoch and keeps the mark.
func TestVerifyBothStaleHint(t *testing.T) {
	f := newFixture(t)
	f.deliver(t, "old", "secret")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 1})
	if _, err := bob.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	forgetChecks(t, f.u.Dir, f.mbx)
	cfg := f.env.ClientConfig(f.u.Dir)
	mrec := f.env.Store.MailboxFile(f.mbx)
	good := mustRead(t, mrec)
	if err := store.WriteFileAtomic(mrec, []byte("not a mailbox record")); err != nil {
		t.Fatal(err)
	}
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("device lost: generation %d, %v", gen, err)
	}
	if err := store.WriteFileAtomic(mrec, good); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	f.env.Rotate(bob)
	bob.Client.Close()
	before := chainOf(t, f.env, f.mbx)
	f.env.Clock.Advance(time.Minute)
	f.env.Warnings.Take()
	err := f.env.Reopen(f.u).Sync()
	w := f.env.Warnings.Take()
	noSeed(t, w, f.u.Words)
	onlyIDs(t, w)
	// The error, if any, is the one of the index (Index after the epoch
	// supply: the own wraps are not readable before device lost); the
	// generation part names its fixed cause in the warnings.
	t.Logf("Sync: %v", err)
	warningWith(t, w, f.mbx.String(), "anderes Mitglied")
	if len(chainOf(t, f.env, f.mbx)) != len(before) {
		t.Fatal("an epoch was created without a checked folder list")
	}
	if m := reissueMark(t, f.u.Dir, f.mbx); m != 2 {
		t.Fatalf("mark %d", m)
	}
}
