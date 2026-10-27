package client_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 14: the client log (translog doc.go "Tasks" point 14,
// PLAN 10.1 "Transparenzlog" and "Szenarien").

// resign publishes head h again with the time at, signed by the log key
// and cosigned by the witness: a server that keeps re-signing an old
// size (translog doc.go "Withheld entries").
func resign(t *testing.T, env *testenv.Env, h *translog.Head, at time.Time) {
	t.Helper()
	signer, err := translog.NewLogSigner(env.IngestKey)
	if err != nil {
		t.Fatal(err)
	}
	c := *h
	c.Time, c.Sigs = at.UnixMilli(), nil
	text, err := c.Text()
	if err != nil {
		t.Fatal(err)
	}
	if c.Note, err = note.Sign(&note.Note{Text: string(text)}, signer, env.WitnessSigner); err != nil {
		t.Fatal(err)
	}
	if err := env.LogOperator().PublishHead(&c); err != nil {
		t.Fatal(err)
	}
}

// logState is the log part of state.json (client.logMemory).
type logState struct {
	Head    string `json:"head"`
	Pending []struct {
		Index  int64  `json:"index"`
		Kind   uint8  `json:"kind"`
		Record []byte `json:"record"`
	} `json:"pending"`
}

func logStateOf(t *testing.T, dir string) logState {
	t.Helper()
	var st struct {
		Log logState `json:"log"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "state.json")), &st); err != nil {
		t.Fatal(err)
	}
	return st.Log
}

// headOfState parses the reference head kept in state.json.
func headOfState(t *testing.T, dir string) *translog.Head {
	t.Helper()
	msg := logStateOf(t, dir).Head
	i := strings.Index(msg, "\n\n")
	if i < 0 {
		t.Fatalf("no head in the state of %s", dir)
	}
	h, err := translog.ParseHeadText([]byte(msg[:i+1]))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// deviceOf returns the device ID in state.json of dir.
func deviceOf(t *testing.T, dir string) store.ID {
	t.Helper()
	var st struct {
		Device string `json:"device"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "state.json")), &st); err != nil {
		t.Fatal(err)
	}
	id, err := store.ParseID(st.Device)
	if err != nil {
		t.Fatalf("device of %s: %v", dir, err)
	}
	return id
}

// logMatchesStore checks that every epoch of the chain of mbx up to
// mailbox.rec is the logged one (K2 rule 4: store and log agree).
func logMatchesStore(t *testing.T, env *testenv.Env, mbx store.ID) {
	t.Helper()
	for _, e := range chainOf(t, env, mbx) {
		_, data, err := env.Store.ReadEpoch(mbx, e.Number)
		if err != nil {
			t.Fatal(err)
		}
		if err := env.LogOperator().CheckEpoch(mbx, e.Number, data); err != nil {
			t.Fatalf("epoch %d of the data directory is not the logged one: %v", e.Number, err)
		}
	}
}

// TestLogHeadsAndCheckpoints: two users of one mailbox, a head every
// HeadInterval for 30 hours; each start refreshes the client log (the
// reference head in state.json moves on) and writes the checkpoint of the
// client into the mailbox (2.7 "Abgleich zwischen Clients"); the
// checkpoints of the other member check against the own head without a
// warning.
func TestLogHeadsAndCheckpoints(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	m := f.deliver(t, "heads", "every hour")
	f.env.AutoHeads = false
	var last *translog.Head
	for i := 0; i < 30; i++ {
		f.env.Clock.Advance(translog.HeadInterval)
		last = f.env.MustPublishHead()
		for _, u := range []*testenv.User{f.u, bob} {
			c := f.env.Reopen(u)
			if _, err := c.List(f.mbx, store.ID{}); err != nil {
				t.Fatalf("hour %d: %v", i, err)
			}
			if h := headOfState(t, u.Dir); h.Size != last.Size || h.Time != last.Time {
				t.Fatalf("hour %d: reference head %d/%d, published %d/%d", i, h.Size, h.Time, last.Size, last.Time)
			}
		}
	}
	readBody(t, f.env, f.u.Client, f.mbx, m.ID, "every hour")
	refs, err := f.env.Store.ListCheckpoints(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[store.ID]bool{}
	for _, ref := range refs {
		cp, err := f.env.Store.ReadCheckpoint(f.mbx, ref.User, ref.Device)
		if err != nil {
			t.Fatal(err)
		}
		if cp.Origin != f.env.Pin.Origin || cp.Size != last.Size || cp.HeadTime != last.Time || cp.RootHash != last.Hash || cp.UserGen != 1 {
			t.Fatalf("checkpoint of %s: %+v", ref.User, cp)
		}
		seen[ref.User] = true
	}
	if !seen[f.u.ID] || !seen[bob.ID] || len(refs) != 2 {
		t.Fatalf("checkpoints %v", refs)
	}
	for _, w := range f.env.Warnings.Take() {
		if strings.Contains(w, "Vermerk") || strings.Contains(w, "Transparenzlog") {
			t.Fatalf("warning: %s", w)
		}
	}
}

// TestLogStaleStops: no head newer than 24 hours (2.3): every read and
// change stops with ErrLog (translog.ErrStale) and a clear warning, and
// Open refuses; a fresh head lets the client work again.
func TestLogStaleStops(t *testing.T) {
	f := newFixture(t)
	m := f.deliver(t, "stale", "24 hours")
	f.env.AutoHeads = false
	f.env.Clock.Advance(translog.MaxHeadAge + time.Minute)
	f.env.Warnings.Take()
	stale := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, client.ErrLog) || !errors.Is(err, translog.ErrStale) {
			t.Fatalf("%s with a head older than 24 hours: %v", what, err)
		}
	}
	_, err := f.u.Client.List(f.mbx, store.ID{})
	stale("List", err)
	warningWith(t, f.env.Warnings.Take(), "höchstens 24 Stunden", "keine neuen Signaturen")
	_, _, err = f.u.Client.Read(f.mbx, m.ID)
	stale("Read", err)
	stale("Sync", f.u.Client.Sync())
	_, err = f.u.Client.CreateMailbox("B")
	stale("CreateMailbox", err)
	f.u.Client.Close()
	_, err = client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
	stale("Open", err)
	f.env.AutoHeads = true
	readBody(t, f.env, f.env.Reopen(f.u), f.mbx, m.ID, "24 hours")
}

// TestLogWithheldOwnEntry: the server keeps re-signing the size before
// an own entry more than HeadInterval after the append (translog doc.go
// "Withheld entries"): ErrWithheld stops the client; the pending entries
// are in state.json before anything relies on them, and a head that
// covers them clears them.
func TestLogWithheldOwnEntry(t *testing.T) {
	f := newFixture(t)
	f.env.AutoHeads = false
	h := f.env.MustPublishHead()
	f.env.Clock.Advance(time.Minute)
	if _, err := f.u.Client.CreateMailbox("B"); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range logStateOf(t, f.u.Dir).Pending {
		found = found || p.Index == h.Size && p.Kind == uint8(translog.KindEpoch) && len(p.Record) > 0
	}
	if !found {
		t.Fatalf("pending entries in state.json: %+v", logStateOf(t, f.u.Dir).Pending)
	}
	f.env.Clock.Advance(translog.HeadInterval + time.Minute)
	resign(t, f.env, h, f.env.Clock.Now())
	f.u.Client.Close()
	f.env.Warnings.Take()
	_, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
	if !errors.Is(err, client.ErrLog) || !errors.Is(err, translog.ErrWithheld) {
		t.Fatalf("withheld own entry: %v", err)
	}
	warningWith(t, f.env.Warnings.Take(), "hält einen eigenen Eintrag", "zurück")
	f.env.AutoHeads = true
	f.env.Reopen(f.u)
	if p := logStateOf(t, f.u.Dir).Pending; len(p) != 0 {
		t.Fatalf("pending entries after a covering head: %+v", p)
	}
	if hd := headOfState(t, f.u.Dir); hd.Size <= h.Size {
		t.Fatalf("reference head %d", hd.Size)
	}
}

// forgeCheckpoint writes the checkpoint of u (device dev) into mbx with
// the head fields of h, changed by change, signed with key.
func forgeCheckpoint(t *testing.T, env *testenv.Env, mbx store.ID, u *testenv.User, dev store.ID, gen uint32, key ed25519.PrivateKey, h *translog.Head, change func(cp *store.Checkpoint)) {
	t.Helper()
	cp := &store.Checkpoint{UserID: u.ID, DeviceID: dev, Origin: h.Origin, Size: h.Size, RootHash: h.Hash, HeadTime: h.Time, UserGen: gen}
	if change != nil {
		change(cp)
	}
	if err := cp.Sign(key); err != nil {
		t.Fatal(err)
	}
	if err := env.Store.WriteCheckpoint(mbx, cp); err != nil {
		t.Fatal(err)
	}
}

// TestLogSplitView: bob's checkpoint names another log than alice's
// reference head (2.7 "verschiedene Sichten"): the same size with another
// root, or a smaller size signed after alice's head. Alice stops with
// ErrLog and a warning. A checkpoint of a non-member, of a revoked
// generation or with a bad signature is ignored with a warning.
func TestLogSplitView(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	mallory := f.env.NewUser("mallory")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	if _, err := bob.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	f.env.Reopen(bob)
	f.env.AutoHeads = false
	f.env.Clock.Advance(time.Minute)
	h := f.env.MustPublishHead()
	c := f.env.Reopen(f.u)
	if _, err := c.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	bks := f.env.Keystore(bob)
	defer bks.Zero()
	dev := deviceOf(t, bob.Dir)
	split := func(name string, change func(cp *store.Checkpoint)) {
		t.Helper()
		forgeCheckpoint(t, f.env, f.mbx, bob, dev, 1, bks.Identity, h, change)
		f.env.Warnings.Take()
		if _, err := c.List(f.mbx, store.ID{}); !errors.Is(err, client.ErrLog) || !errors.Is(err, translog.ErrConsistency) {
			t.Fatalf("%s: %v", name, err)
		}
		warningWith(t, f.env.Warnings.Take(), bob.ID.String(), "widerspricht dem eigenen Baumkopf", "verschiedene Logs")
	}
	split("same size, other root", func(cp *store.Checkpoint) { cp.RootHash[0] ^= 1 })
	split("smaller size signed later", func(cp *store.Checkpoint) { cp.Size--; cp.HeadTime++ })
	// The genuine checkpoint of bob agrees.
	forgeCheckpoint(t, f.env, f.mbx, bob, dev, 1, bks.Identity, h, nil)
	if _, err := c.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	ignored := func(name, cause string, u *testenv.User, gen uint32, key ed25519.PrivateKey) {
		t.Helper()
		d, _ := store.NewID(nil)
		forgeCheckpoint(t, f.env, f.mbx, u, d, gen, key, h, func(cp *store.Checkpoint) { cp.RootHash[0] ^= 1 })
		f.env.Warnings.Take()
		if _, err := c.List(f.mbx, store.ID{}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		warningWith(t, f.env.Warnings.Take(), "Vermerk in "+f.mbx.String(), d.String(), "wird ignoriert", cause)
		if err := os.Remove(f.env.Store.CheckpointFile(f.mbx, u.ID, d)); err != nil {
			t.Fatal(err)
		}
	}
	mks := f.env.Keystore(mallory)
	defer mks.Zero()
	ignored("non-member", "kein Benutzer-Mitglied", mallory, 1, mks.Identity)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	ignored("bad signature", "Signatur ungültig", bob, 1, other)
	ignored("unlogged generation", "nicht im Transparenzlog", bob, 2, bks.Identity)
}

// TestLogThiefEpochRevokedGeneration: the thief of alice's device signs
// epochs with her generation 1 (2.2 rule 4, K2 rule 1 over the log).
// Logged before the entry of generation 2 that revokes it, such an epoch
// stays valid; written after it, it can never be logged (ErrOrder) and is
// replaced in store by the next change (a share; store.ReplaceEpoch).
func TestLogThiefEpochRevokedGeneration(t *testing.T) {
	f := newFixture(t)
	thief := &testenv.User{Dir: copyClientDir(t, f.u.Dir, filepath.Join(f.env.Base, "clients", "thief")), ID: f.u.ID}
	f.env.Clock.Advance(time.Minute)
	before := f.env.ForgeEpoch(thief, f.mbx, f.env.Clock.Now(), store.ReasonMemberAdded, nil, "A")
	_, beforeData, err := f.env.Store.ReadEpoch(f.mbx, before.Number)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.env.LogOperator().CheckEpoch(f.mbx, before.Number, beforeData); err != nil {
		t.Fatalf("thief's epoch before the revocation not logged: %v", err)
	}
	f.env.Clock.Advance(time.Minute)
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	// Before the revocation: valid (CheckRevokedSignature).
	chain := chainOf(t, f.env, f.mbx)
	if chain[before.Number-1].SignerGen != 1 || headGen(t, f, f.u) != 2 {
		t.Fatal("chain after device lost")
	}
	if _, err := f.u.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatalf("epoch logged before the revocation: %v", err)
	}
	// After the revocation: the thief plants epoch head+1 signed by
	// generation 1 (mailbox.rec unchanged).
	f.env.Clock.Advance(time.Minute)
	id1 := identityOf(t, f.u.Words, 1)
	defer keys.Wipe(id1)
	planted := beyondEpoch(t, f, asGen1(f.u.ID), id1)
	n := headOf(t, f.env, f.mbx) + 1
	if err := store.MkdirAll(f.env.Store.EpochDir(f.mbx, n)); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(f.env.Store.EpochFile(f.mbx, n), planted); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.LogOperator().Append(translog.KindEpoch, planted); !errors.Is(err, translog.ErrOrder) {
		t.Fatalf("thief's epoch after the revocation: %v", err)
	}
	bob := f.env.NewUser("bob")
	f.env.Warnings.Take()
	if _, err := f.u.Client.Share(f.mbx, bob.ID, client.ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	got := mustRead(t, f.env.Store.EpochFile(f.mbx, n))
	if bytes.Equal(got, planted) {
		t.Fatal("the thief's unloggable epoch was not replaced")
	}
	e, err := store.DecodeEpoch(got)
	if err != nil || e.SignerID != f.u.ID || e.SignerGen != 2 {
		t.Fatalf("replacement signed by generation %d: %v", e.SignerGen, err)
	}
	warningWith(t, f.env.Warnings.Take(), "Die ungültige Epoche", "wurde ersetzt")
	logMatchesStore(t, f.env, f.mbx)
	if _, err := f.u.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	// The same with mailbox.rec pointing to it: the chain ends before it
	// for every reader (it is not in the log and never can be).
	f.env.Clock.Advance(time.Minute)
	planted = beyondEpoch(t, f, asGen1(f.u.ID), id1)
	n = headOf(t, f.env, f.mbx) + 1
	store.MkdirAll(f.env.Store.EpochDir(f.mbx, n))
	if err := store.WriteFileAtomic(f.env.Store.EpochFile(f.mbx, n), planted); err != nil {
		t.Fatal(err)
	}
	mrec, err := f.env.Store.ReadMailbox(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	mrec.Epoch = n
	if err := f.env.Store.WriteMailbox(mrec); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if _, err := f.env.Reopen(f.u).List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("thief's epoch %d as the head: %v", n, err)
	}
	// (checkSignerGen, the local bound of Q13, rejects it before the log
	// is asked: the chain names generation 2; the log then shows that it
	// can never be logged, task 14b point 3, and readers name the cause
	// with its remedy.)
	warningWith(t, f.env.Warnings.Take(), "ist nicht loggbar", "share, revoke oder sync")
}

// asGen1 makes an epoch signed by generation 1 of id, as its member.
func asGen1(id store.ID) func(e *store.Epoch) {
	return func(e *store.Epoch) {
		e.SignerGen = 1
		for i := range e.Members {
			if e.Members[i].ID == id {
				e.Members[i].Gen = 1
			}
		}
	}
}

// TestLogLoserEpochReplaced: K2 rule 3 over the log. Two clients created
// epoch n at the same time; the log holds the winner (n, in store, the
// head of mailbox.rec), and the loser left its next epoch n+1, built on
// its own epoch n, beyond the head. It can never be logged (ErrOrder:
// prev_hash is not the logged epoch n); the next change replaces it. An
// epoch.rec beyond the head that contradicts a logged epoch of the same
// number (ErrDuplicate, K2 rule 4) is never replaced (translog doc.go
// "Unlogged epoch.rec" step 4, the reading of task 14b).
func TestLogLoserEpochReplaced(t *testing.T) {
	f := newFixture(t)
	f.env.Clock.Advance(time.Minute)
	ks := f.env.Keystore(f.u)
	defer ks.Zero()
	var other [32]byte
	rand.Read(other[:])
	loser := beyondEpoch(t, f, func(e *store.Epoch) { e.PrevHash = other }, ks.Identity)
	n := headOf(t, f.env, f.mbx) + 1
	store.MkdirAll(f.env.Store.EpochDir(f.mbx, n))
	if err := store.WriteFileAtomic(f.env.Store.EpochFile(f.mbx, n), loser); err != nil {
		t.Fatal(err)
	}
	bob := f.env.NewUser("bob")
	f.env.Warnings.Take()
	if _, err := f.u.Client.Share(f.mbx, bob.ID, client.ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(mustRead(t, f.env.Store.EpochFile(f.mbx, n)), loser) {
		t.Fatal("the loser's epoch was not replaced")
	}
	warningWith(t, f.env.Warnings.Take(), "wurde ersetzt")
	logMatchesStore(t, f.env, f.mbx)
	if _, err := bob.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}

	// The file of epoch n+1 contradicts the logged epoch n+1 (somebody
	// logged it without writing it): never replaced, the chain stops.
	m, err := f.env.Store.ReadMailbox(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	logged := f.env.ForgeEpoch(f.u, f.mbx, f.env.Clock.Now(), store.ReasonMemberAdded, nil, "A")
	if err := f.env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	other2 := beyondEpoch(t, f, func(e *store.Epoch) { e.Begin++ }, ks.Identity)
	if err := store.WriteFileAtomic(f.env.Store.EpochFile(f.mbx, logged.Number), other2); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if err := f.u.Client.Sync(); err == nil {
		t.Fatal("Sync over an epoch that contradicts the log")
	}
	if !bytes.Equal(mustRead(t, f.env.Store.EpochFile(f.mbx, logged.Number)), other2) {
		t.Fatal("an epoch that contradicts the log was replaced")
	}
}

// TestLogEpochRaceThroughLog: two clients without an effective mailbox
// lock create epoch n at once (K2 rule 3, TestEpochRace); afterwards the
// data directory and the log hold the same chain (K2 rule 4).
func TestLogEpochRaceThroughLog(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	carol := f.env.NewUser("carol")
	dave := f.env.NewUser("dave")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	bob.Client.WithoutMailboxLock()
	fired := false
	var bobErr error
	client.SetCrashHook(t, func(p string) bool {
		if p == "epoch-folders" && !fired {
			fired = true
			_, bobErr = bob.Client.Share(f.mbx, dave.ID, client.ShareOptions{})
		}
		return false
	})
	if _, err := f.u.Client.Share(f.mbx, carol.ID, client.ShareOptions{}); err != nil || bobErr != nil {
		t.Fatal(err, bobErr)
	}
	client.SetCrashHook(t, nil)
	logMatchesStore(t, f.env, f.mbx)
	for _, c := range []*client.Client{f.u.Client, carol.Client, dave.Client} {
		if _, err := c.List(f.mbx, store.ID{}); err != nil {
			t.Fatal(err)
		}
	}
}

// deliverTo delivers a mail to addr through the ingest of f (an
// Unverified log on the server side: the server delivers what
// addresses.json names).
func deliverTo(t *testing.T, f *fixture, addr, subject string) {
	t.Helper()
	d, err := f.in.Begin(smtpd.Session{ID: "t"}, "s@x.example", []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	d.Write([]byte("Subject: " + subject + "\r\n\r\nbody\r\n"))
	if err := d.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestLogAddressNotAssigned: a mail for an address that the log does not
// assign to the mailbox at its receipt (2.3, "stilles Umleiten"), or
// assigns to another mailbox, is not shown: a warning "Adresse nicht
// zugeordnet"; neither the warning nor the error names the address.
func TestLogAddressNotAssigned(t *testing.T) {
	f := newFixture(t)
	const silent = "umgeleitet@example.org"
	if _, err := f.env.Store.AddAddress(silent, f.mbx); err != nil {
		t.Fatal(err)
	}
	deliverTo(t, f, silent, "redirected")
	second := f.env.Mailbox(f.u, "B")
	const other = "andere@example.org"
	f.env.AssignAddress(other, second)
	if _, err := f.env.Store.AddAddress(other, f.mbx); err != nil {
		t.Fatal(err)
	}
	deliverTo(t, f, other, "other mailbox")
	f.env.Warnings.Take()
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("listed: %s", subjects(list))
	}
	w := f.env.Warnings.Take()
	n := 0
	for _, s := range w {
		if strings.Contains(s, "example.org") {
			t.Fatalf("warning names the address: %s", s)
		}
		if strings.Contains(s, "Adresse nicht zugeordnet") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("warnings: %q", w)
	}
	ids, err := f.env.Store.ListMails(f.mbx, f.inbox(t))
	if err != nil || len(ids) != 2 {
		t.Fatal(ids, err)
	}
	for _, id := range ids {
		_, _, err := f.u.Client.Read(f.mbx, id)
		if !errors.Is(err, client.ErrAddress) || strings.Contains(err.Error(), "example.org") {
			t.Fatalf("read: %v", err)
		}
	}
	// Assigned in the log from now on: an earlier receipt stays
	// unassigned (the newest valid_from <= receipt decides, Q9).
	f.env.Clock.Advance(time.Minute)
	f.env.AssignAddress(silent, f.mbx)
	if list, _ := f.u.Client.List(f.mbx, store.ID{}); len(list) != 0 {
		t.Fatal("mail received before the assignment listed")
	}
	deliverTo(t, f, silent, "assigned")
	if list, err := f.u.Client.List(f.mbx, store.ID{}); err != nil || subjects(list) != "assigned" {
		t.Fatalf("after the assignment: %v %s", err, subjects(list))
	}
}

// TestLogDevPinRefused: the pin of the development ceremony is refused
// unless Config.AllowDevIdentity is set, which only tests do (task 14:
// no command line flag); nothing is written.
func TestLogDevPinRefused(t *testing.T) {
	f := newFixture(t)
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	cfg.AllowDevIdentity = false
	if _, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrDevIdentity) {
		t.Fatalf("Open: %v", err)
	}
	if _, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); !errors.Is(err, client.ErrDevIdentity) {
		t.Fatalf("DeviceLost: %v", err)
	}
	if _, err := client.RecoverRead(cfg, f.mbx, f.u.Words); !errors.Is(err, client.ErrDevIdentity) {
		t.Fatalf("RecoverRead: %v", err)
	}
	ncfg := f.env.ClientConfig(filepath.Join(f.env.Base, "new"))
	ncfg.AllowDevIdentity = false
	if _, err := client.Keygen(ncfg, testenv.Passphrase, &testenv.Echo{}); !errors.Is(err, client.ErrDevIdentity) {
		t.Fatalf("Keygen: %v", err)
	}
	if _, err := os.Stat(ncfg.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("client directory written with a development pin")
	}
	if _, err := client.Register(ncfg, store.ID{1}); !errors.Is(err, client.ErrDevIdentity) {
		t.Fatalf("Register: %v", err)
	}
	if _, err := client.Restore(ncfg, client.RestoreOptions{Words: f.u.Words}, testenv.Passphrase); !errors.Is(err, client.ErrDevIdentity) {
		t.Fatalf("Restore: %v", err)
	}
}
