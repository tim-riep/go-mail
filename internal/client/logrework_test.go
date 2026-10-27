package client_test

import (
	"bytes"
	"crypto/ecdh"
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

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 14b (rework of the client log after the verification of
// task 14). The scenarios follow the tests of the verifiers (verify14
// attack and spec).

// plantSignedHead writes heads/<size>.sig with the text of h, signed by
// the log key and, with witness, cosigned by the witness (a server with a
// colluding witness).
func plantSignedHead(t *testing.T, env *testenv.Env, h *translog.Head, witness bool) {
	t.Helper()
	signer, err := translog.NewLogSigner(env.IngestKey)
	if err != nil {
		t.Fatal(err)
	}
	c := *h
	c.Sigs = nil
	text, err := c.Text()
	if err != nil {
		t.Fatal(err)
	}
	signers := []note.Signer{signer}
	if witness {
		signers = append(signers, env.WitnessSigner)
	}
	msg, err := note.Sign(&note.Note{Text: string(text)}, signers...)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(headFile(env, h.Size), msg); err != nil {
		t.Fatal(err)
	}
}

func headFile(env *testenv.Env, size int64) string {
	return env.Store.Path("log", "heads", fmt.Sprint(size)+".sig")
}

// noWarningWith fails if a warning holds every part.
func noWarningWith(t *testing.T, warnings []string, parts ...string) {
	t.Helper()
	for _, w := range warnings {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(w, p)
		}
		if ok {
			t.Fatalf("unexpected warning: %s", w)
		}
	}
}

// TestLogCheckpointAheadCompared (point 1): bob's checkpoint names a
// larger head than the server shows alice. Alice refreshes once and
// compares again: while bob's head stays larger she is warned on every
// operation; once the server re-signs the old size for her with a time
// after bob's head (it withholds the newer entries from her), bob's
// checkpoint shows it: ErrLog with ErrConsistency.
func TestLogCheckpointAheadCompared(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	if _, err := bob.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	f.env.AutoHeads = false
	f.env.Clock.Advance(time.Minute)
	hS := f.env.MustPublishHead()
	c := f.env.Reopen(f.u)
	if _, err := c.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	if hs := headOfState(t, f.u.Dir); hs.Size != hS.Size {
		t.Fatalf("alice at %d, want %d", hs.Size, hS.Size)
	}
	// The log grows; the server shows S+1 to bob, who writes his
	// checkpoint, and then removes the head again.
	f.env.Clock.Advance(time.Minute)
	f.env.AssignAddress("grow2@example.org", f.mbx)
	f.env.Clock.Advance(time.Minute)
	hS1 := f.env.MustPublishHead()
	bc := f.env.Reopen(bob)
	if _, err := bc.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	cp, err := f.env.Store.ReadCheckpoint(f.mbx, bob.ID, deviceOf(t, bob.Dir))
	if err != nil || cp.Size != hS1.Size {
		t.Fatalf("bob's checkpoint: %+v %v", cp, err)
	}
	if err := os.Remove(headFile(f.env, hS1.Size)); err != nil {
		t.Fatal(err)
	}
	// Alice's head (S, signed before bob's) is older than bob's: after
	// one refresh his checkpoint is still beyond it, a warning on every
	// operation, no stop.
	for run := 0; run < 2; run++ {
		f.env.Warnings.Take()
		if _, err := c.List(f.mbx, store.ID{}); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		warningWith(t, f.env.Warnings.Take(), "Ein Mitglied hat einen neueren Kopf gesehen, den der Server hier nicht zeigt", bob.ID.String())
	}
	// The server re-signs S for alice with a time after bob's head:
	// withholding, seen through bob's checkpoint.
	f.env.Clock.Advance(time.Minute)
	resign(t, f.env, hS, f.env.Clock.Now())
	c = f.env.Reopen(f.u)
	if hs := headOfState(t, f.u.Dir); hs.Size != hS.Size || hs.Time <= cp.HeadTime {
		t.Fatalf("alice's head %d at %d, bob's %d at %d", hs.Size, hs.Time, cp.Size, cp.HeadTime)
	}
	f.env.Warnings.Take()
	_, err = c.List(f.mbx, store.ID{})
	if !errors.Is(err, client.ErrLog) || !errors.Is(err, translog.ErrConsistency) {
		t.Fatalf("checkpoint ahead, signed before the own head: %v", err)
	}
	warningWith(t, f.env.Warnings.Take(), bob.ID.String(), "widerspricht dem eigenen Baumkopf", "Einträge vor")
}

// TestLogCheckpointAheadRefreshed (point 1): bob's checkpoint names a
// published head that alice, whose head is fresh, has not taken over
// yet: she refreshes once, compares, and nothing is reported.
func TestLogCheckpointAheadRefreshed(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	if _, err := bob.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	f.env.AutoHeads = false
	f.env.Clock.Advance(time.Minute)
	hS := f.env.MustPublishHead()
	c := f.env.Reopen(f.u)
	if _, err := c.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	f.env.AssignAddress("grow5@example.org", f.mbx)
	f.env.Clock.Advance(time.Minute)
	hS1 := f.env.MustPublishHead()
	if _, err := f.env.Reopen(bob).List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	if hs := headOfState(t, f.u.Dir); hs.Size != hS.Size {
		t.Fatalf("alice at %d before the comparison", hs.Size)
	}
	f.env.Warnings.Take()
	if _, err := c.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	noWarningWith(t, f.env.Warnings.Take(), "neueren Kopf")
	if hs := headOfState(t, f.u.Dir); hs.Size != hS1.Size {
		t.Fatalf("alice at %d after the comparison, want %d", hs.Size, hS1.Size)
	}
}

// TestLogOlderHeadOnly (point 2): the server deletes the newest head;
// the older one left in heads/ is an older view of the same log: a
// warning, the reference head stays and counts while fresh, after 24
// hours ErrStale. A smaller head of another tree, or one signed after
// the reference head, stops the client (ErrConsistency).
func TestLogOlderHeadOnly(t *testing.T) {
	f := newFixture(t)
	f.env.AutoHeads = false
	f.env.Clock.Advance(time.Minute)
	h1 := f.env.MustPublishHead()
	f.env.AssignAddress("grow1@example.org", f.mbx)
	f.env.Clock.Advance(time.Minute)
	h2 := f.env.MustPublishHead()
	if h2.Size <= h1.Size {
		t.Fatal("log did not grow")
	}
	c := f.env.Reopen(f.u)
	if _, err := c.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(headFile(f.env, h2.Size)); err != nil {
		t.Fatal(err)
	}
	f.u.Client.Close()
	f.env.Warnings.Take()
	f.env.Clock.Advance(time.Minute)
	c2, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
	if err != nil {
		t.Fatalf("Open with only an older head published: %v", err)
	}
	f.u.Client = c2
	warningWith(t, f.env.Warnings.Take(), "älterer Kopf veröffentlicht")
	if hs := headOfState(t, f.u.Dir); hs.Size != h2.Size || hs.Hash != h2.Hash {
		t.Fatalf("reference head %d, want %d", hs.Size, h2.Size)
	}
	if _, err := c2.List(f.mbx, store.ID{}); err != nil {
		t.Fatalf("List with the fresh reference head: %v", err)
	}
	// A smaller head of another tree (a server with a colluding witness).
	other := *h1
	rand.Read(other.Hash[:])
	plantSignedHead(t, f.env, &other, true)
	c2.Close()
	if _, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase); !errors.Is(err, client.ErrLog) || !errors.Is(err, translog.ErrConsistency) {
		t.Fatalf("smaller head of another tree: %v", err)
	}
	// The same head without the witness only warns (ErrWitness).
	plantSignedHead(t, f.env, &other, false)
	c3, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
	if err != nil {
		t.Fatalf("smaller head without quorum: %v", err)
	}
	c3.Close()
	// The true older head re-signed after the reference head: an old
	// size signed after a larger one (withholding).
	later := *h1
	later.Time = f.env.Clock.Now().UnixMilli()
	plantSignedHead(t, f.env, &later, true)
	if _, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase); !errors.Is(err, client.ErrLog) || !errors.Is(err, translog.ErrConsistency) {
		t.Fatalf("smaller head signed after the reference head: %v", err)
	}
	// Back to the true older head: the reference head counts until it
	// is 24 hours old.
	plantSignedHead(t, f.env, h1, true)
	c4, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	f.u.Client = c4
	f.env.Clock.Advance(translog.MaxHeadAge)
	if _, err := c4.List(f.mbx, store.ID{}); !errors.Is(err, client.ErrLog) || !errors.Is(err, translog.ErrStale) {
		t.Fatalf("after 24 hours: %v", err)
	}
}

// TestLogUnloggableHeadHealed (point 3): the thief of alice's revoked
// device plants epoch n, which can never be logged (ErrOrder), and sets
// mailbox.rec to it. Readers report the fixed cause with the remedy;
// Sync of a user member replaces epoch n by a new epoch n of its own
// (store.ReplaceEpoch), mailbox.rec keeps naming n, and the second run is
// clean.
func TestLogUnloggableHeadHealed(t *testing.T) {
	f := newFixture(t)
	m := f.deliver(t, "before", "secret body")
	f.env.Clock.Advance(time.Minute)
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	m2 := f.deliver(t, "after-rotation", "second body")
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
	mrec, err := f.env.Store.ReadMailbox(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	mrec.Epoch = n
	if err := f.env.Store.WriteMailbox(mrec); err != nil {
		t.Fatal(err)
	}
	c := f.env.Reopen(f.u)
	f.env.Warnings.Take()
	if _, err := c.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("reader with the unloggable head: %v", err)
	}
	warningWith(t, f.env.Warnings.Take(), fmt.Sprintf("Epoche %d von %s ist nicht loggbar", n, f.mbx), "share, revoke oder sync")
	if !bytes.Equal(mustRead(t, f.env.Store.EpochFile(f.mbx, n)), planted) {
		t.Fatal("a reader replaced the epoch")
	}
	// Sync of the member heals.
	if err := c.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	got := mustRead(t, f.env.Store.EpochFile(f.mbx, n))
	e, err := store.DecodeEpoch(got)
	if bytes.Equal(got, planted) || err != nil || e.SignerID != f.u.ID || e.SignerGen != 2 {
		t.Fatalf("epoch %d after Sync: %v", n, err)
	}
	warningWith(t, f.env.Warnings.Take(), fmt.Sprintf("nicht loggbare Epoche %d", n), "ersetzt")
	if h := headOf(t, f.env, f.mbx); h < n {
		t.Fatalf("mailbox.rec set back to %d", h)
	}
	logMatchesStore(t, f.env, f.mbx)
	readBody(t, f.env, c, f.mbx, m.ID, "secret body")
	readBody(t, f.env, c, f.mbx, m2.ID, "second body")
	// Second run: clean.
	c = f.env.Reopen(f.u)
	f.env.Warnings.Take()
	if err := c.Sync(); err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	readBody(t, f.env, c, f.mbx, m2.ID, "second body")
	noWarningWith(t, f.env.Warnings.Take(), "nicht loggbar")
	bob := f.env.NewUser("bob")
	if _, err := c.Share(f.mbx, bob.ID, client.ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
}

// TestLogUnloggableHeadNonMember (point 3): a delegate cannot replace
// the unloggable head (only user members create epochs, K2 rule 1); its
// Sync fails with the fixed cause and changes nothing.
func TestLogUnloggableHeadNonMember(t *testing.T) {
	f := newFixture(t)
	dele := f.env.NewUser("dele")
	f.env.Clock.Advance(time.Minute)
	f.env.Share(f.u, f.mbx, dele, client.ShareOptions{Delegate: true})
	if _, err := dele.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	ks := f.env.Keystore(f.u)
	defer ks.Zero()
	var other [32]byte
	rand.Read(other[:])
	// Epoch n with a wrong prev_hash: ErrOrder for good.
	planted := beyondEpoch(t, f, func(e *store.Epoch) { e.PrevHash = other }, ks.Identity)
	n := headOf(t, f.env, f.mbx) + 1
	store.MkdirAll(f.env.Store.EpochDir(f.mbx, n))
	if err := store.WriteFileAtomic(f.env.Store.EpochFile(f.mbx, n), planted); err != nil {
		t.Fatal(err)
	}
	mrec, _ := f.env.Store.ReadMailbox(f.mbx)
	mrec.Epoch = n
	if err := f.env.Store.WriteMailbox(mrec); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if err := dele.Client.Sync(); !errors.Is(err, client.ErrNotMember) {
		t.Fatalf("delegate's Sync: %v", err)
	}
	warningWith(t, f.env.Warnings.Take(), "ist nicht loggbar")
	if !bytes.Equal(mustRead(t, f.env.Store.EpochFile(f.mbx, n)), planted) || headOf(t, f.env, f.mbx) != n {
		t.Fatal("changed by a delegate")
	}
	// The member repairs it.
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	logMatchesStore(t, f.env, f.mbx)
	if _, err := dele.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
}

// dupEpochLog makes every Append of the epoch.rec data fail with
// ErrDuplicate, as if another epoch with its number had been logged in
// the meantime.
type dupEpochLog struct {
	translog.Log
	data []byte
}

func (l *dupEpochLog) Append(kind translog.Kind, content []byte) (int64, error) {
	if kind == translog.KindEpoch && bytes.Equal(content, l.data) {
		return 0, fmt.Errorf("%w: test", translog.ErrDuplicate)
	}
	return l.Log.Append(kind, content)
}

// TestLogDuplicateNeverReplaced (point 13): an epoch.rec beyond the head
// whose append answers ErrDuplicate (another epoch with this number is
// logged, K2 rule 4) is never replaced, even when it is signed by a
// revoked generation; the mailbox stays blocked and the warning names
// the fixed cause and the remedy of the operator (translog doc.go
// "Unlogged epoch.rec" step 4).
func TestLogDuplicateNeverReplaced(t *testing.T) {
	f := newFixture(t)
	f.env.Clock.Advance(time.Minute)
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	f.env.Clock.Advance(time.Minute)
	id1 := identityOf(t, f.u.Words, 1)
	defer keys.Wipe(id1)
	planted := beyondEpoch(t, f, asGen1(f.u.ID), id1)
	n := headOf(t, f.env, f.mbx) + 1
	store.MkdirAll(f.env.Store.EpochDir(f.mbx, n))
	if err := store.WriteFileAtomic(f.env.Store.EpochFile(f.mbx, n), planted); err != nil {
		t.Fatal(err)
	}
	client.SetLogHook(t, func(l translog.Log) translog.Log { return &dupEpochLog{Log: l, data: planted} })
	c := f.env.Reopen(f.u)
	bob := f.env.NewUser("bob")
	f.env.Warnings.Take()
	if _, err := c.Share(f.mbx, bob.ID, client.ShareOptions{}); err == nil {
		t.Fatal("share over an epoch that contradicts the log")
	}
	warningWith(t, f.env.Warnings.Take(), fmt.Sprintf("Epoche %d von %s widerspricht dem Transparenzlog", n, f.mbx), "nie ersetzt", "Abhilfe (Betreiber)", "nachdem der Logeintrag geprüft wurde")
	c.Sync()
	warningWith(t, f.env.Warnings.Take(), fmt.Sprintf("Epoche %d von %s widerspricht dem Transparenzlog", n, f.mbx))
	if !bytes.Equal(mustRead(t, f.env.Store.EpochFile(f.mbx, n)), planted) {
		t.Fatal("an epoch that contradicts the log was replaced")
	}
}

// TestLogCheckpointAfterRestore (point 4): a restored device writes its
// checkpoint at the first Open, although the reference head did not
// change since Restore.
func TestLogCheckpointAfterRestore(t *testing.T) {
	f := newFixture(t)
	f.deliver(t, "a", "x")
	before, _ := f.env.Store.ListCheckpoints(f.mbx)
	f.env.Clock.Advance(time.Minute)
	f.env.MustPublishHead()
	f.env.AutoHeads = false
	dir := filepath.Join(f.env.Base, "clients", "alice2")
	if _, err := client.Restore(f.env.ClientConfig(dir), client.RestoreOptions{Words: f.u.Words}, testenv.Passphrase); err != nil {
		t.Fatal(err)
	}
	c, err := client.Open(f.env.ClientConfig(dir), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	after, _ := f.env.Store.ListCheckpoints(f.mbx)
	if len(after) != len(before)+1 {
		t.Fatalf("checkpoints before %d, after the first Open of the restored device %d", len(before), len(after))
	}
	cp, err := f.env.Store.ReadCheckpoint(f.mbx, f.u.ID, deviceOf(t, dir))
	if err != nil || cp.Size != headOfState(t, dir).Size {
		t.Fatalf("checkpoint of the restored device: %+v %v", cp, err)
	}
	// A new head: written again, still one file per device.
	f.env.AutoHeads = true
	f.env.Clock.Advance(time.Minute)
	c.Close()
	c2, err := client.Open(f.env.ClientConfig(dir), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if after2, _ := f.env.Store.ListCheckpoints(f.mbx); len(after2) != len(before)+1 {
		t.Fatalf("after a new head: %d checkpoints", len(after2))
	}
}

// TestLogCheckpointAfterDeviceLost (point 4): after device lost the
// checkpoint of the device names the new generation at the next Open,
// without a new head; the other member accepts it.
func TestLogCheckpointAfterDeviceLost(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	if _, err := f.u.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	if gen := f.env.DeviceLost(f.u); gen != 2 {
		t.Fatal(gen)
	}
	f.env.AutoHeads = false
	c := f.env.Reopen(f.u)
	if _, err := c.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	cp, err := f.env.Store.ReadCheckpoint(f.mbx, f.u.ID, deviceOf(t, f.u.Dir))
	if err != nil || cp.UserGen != 2 {
		t.Fatalf("alice's checkpoint after device lost: %+v %v", cp, err)
	}
	f.env.Warnings.Take()
	if _, err := f.env.Reopen(bob).List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	noWarningWith(t, f.env.Warnings.Take(), "wird ignoriert")
}

// failFirstAppend lets the first Append after it was set fail.
type failFirstAppend struct {
	translog.Log
	done *bool
}

func (l *failFirstAppend) Append(k translog.Kind, c []byte) (int64, error) {
	if !*l.done {
		*l.done = true
		return 0, errors.New("transient failure")
	}
	return l.Log.Append(k, c)
}

// rollBackByOne registers alice while the log does not move, then sets
// log/tree.rec back by one (her user entry is dropped), lets another
// writer take the index and publishes a head over it. It returns her
// configuration and the index of her dropped entry.
func rollBackByOne(t *testing.T, env *testenv.Env) (client.Config, int64) {
	t.Helper()
	env.NewUser("bob")
	env.AutoHeads = false
	h0 := env.MustPublishHead()
	dir := filepath.Join(env.Base, "clients", "alice")
	cfg := env.ClientConfig(dir)
	if _, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{}); err != nil {
		t.Fatal(err)
	}
	code, _ := env.Store.CreateInvite(env.Clock.Now().UnixMilli())
	if _, err := client.Register(cfg, code); err != nil {
		t.Fatal(err)
	}
	if p := logStateOf(t, dir).Pending; len(p) != 1 || p[0].Index != h0.Size {
		t.Fatalf("pending after register: %+v", p)
	}
	tree, err := rec.New(translog.TreeSchema).SetI64(1, h0.Size).SetBytes(2, h0.Hash[:]).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(env.Store.Path(translog.TreeFile), tree); err != nil {
		t.Fatal(err)
	}
	odir := filepath.Join(env.Base, "clients", "other")
	if _, err := client.Keygen(env.ClientConfig(odir), testenv.Passphrase, &testenv.Echo{}); err != nil {
		t.Fatal(err)
	}
	fresh := env.OpenOperator()
	if i, err := fresh.Append(translog.KindUser, mustRead(t, filepath.Join(odir, "user.rec"))); err != nil || i != h0.Size {
		t.Fatalf("append of the other writer: %d %v", i, err)
	}
	signer, _ := translog.NewLogSigner(env.IngestKey)
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
	return cfg, h0.Size
}

// TestLogRepairPendingAtomic (point 5): the record of an own entry that a
// rollback of the log dropped is appended again; when that append fails,
// the pending entry stays in state.json (nothing is lost), and the next
// start repairs it.
func TestLogRepairPendingAtomic(t *testing.T) {
	env := testenv.New(t)
	cfg, i := rollBackByOne(t, env)
	done := false
	client.SetLogHook(t, func(l translog.Log) translog.Log { return &failFirstAppend{Log: l, done: &done} })
	env.AutoHeads = true
	if _, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrLog) {
		t.Fatalf("open with a failing re-append: %v", err)
	}
	if p := logStateOf(t, cfg.Dir).Pending; len(p) != 1 || p[0].Index != i || len(p[0].Record) == 0 {
		t.Fatalf("pending after the failed re-append: %+v", p)
	}
	client.SetLogHook(t, nil)
	env.Warnings.Take()
	c, err := client.Open(cfg, testenv.Passphrase)
	if err != nil {
		t.Fatalf("open afterwards: %v", err)
	}
	defer c.Close()
	warningWith(t, env.Warnings.Take(), "eigener Eintrag fehlt", "erneut eingetragen")
	for _, p := range logStateOf(t, cfg.Dir).Pending {
		if p.Index == i {
			t.Fatalf("the dropped entry %d is still pending", i)
		}
	}
	if err := env.LogOperator().CheckUser(c.UserID(), mustRead(t, filepath.Join(cfg.Dir, "user.rec"))); err != nil {
		t.Fatalf("own user.rec not in the log: %v", err)
	}
}

// TestLogOwnUserAppendedAgain (point 5): a client whose pending entry was
// lost (an earlier version removed it before the re-append) finds its
// own user.rec not in the log at Open and appends it once more before it
// gives up (Append is idempotent).
func TestLogOwnUserAppendedAgain(t *testing.T) {
	env := testenv.New(t)
	cfg, _ := rollBackByOne(t, env)
	p := filepath.Join(cfg.Dir, "state.json")
	var st map[string]json.RawMessage
	if err := json.Unmarshal(mustRead(t, p), &st); err != nil {
		t.Fatal(err)
	}
	var lg map[string]json.RawMessage
	if err := json.Unmarshal(st["log"], &lg); err != nil {
		t.Fatal(err)
	}
	delete(lg, "pending")
	st["log"], _ = json.Marshal(lg)
	b, _ := json.Marshal(st)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	env.AutoHeads = true
	env.Warnings.Take()
	c, err := client.Open(cfg, testenv.Passphrase)
	if err != nil {
		t.Fatalf("open with the own entry lost: %v", err)
	}
	defer c.Close()
	warningWith(t, env.Warnings.Take(), "eigene user.rec fehlt im Transparenzlog")
	if err := env.LogOperator().CheckUser(c.UserID(), mustRead(t, filepath.Join(cfg.Dir, "user.rec"))); err != nil {
		t.Fatalf("own user.rec not in the log: %v", err)
	}
}

// TestLogUnconfirmedUntilCheckpoint (point 6, Q20): a restored device
// stays marked after Open (a witnessed head does not suffice) and warns
// on every start, until a checkpoint of another user member agrees with
// its head; the checkpoint of another device of the same user does not
// count, and a sole member stays marked.
func TestLogUnconfirmedUntilCheckpoint(t *testing.T) {
	t.Run("other member", func(t *testing.T) {
		f := newFixture(t)
		bob := f.env.NewUser("bob")
		f.env.Clock.Advance(time.Minute)
		f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
		if _, err := bob.Client.List(f.mbx, store.ID{}); err != nil {
			t.Fatal(err)
		}
		f.env.Reopen(bob) // bob writes his checkpoint
		dir := filepath.Join(f.env.Base, "clients", "alice2")
		if _, err := client.Restore(f.env.ClientConfig(dir), client.RestoreOptions{Words: f.u.Words}, testenv.Passphrase); err != nil {
			t.Fatal(err)
		}
		f.env.Warnings.Take()
		c, err := client.Open(f.env.ClientConfig(dir), testenv.Passphrase)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		warningWith(t, f.env.Warnings.Take(), "Noch kein bestätigter Zustand", "Sicht noch nicht mit einem anderen Mitglied abgeglichen")
		if !unconfirmed(t, dir) {
			t.Fatal("cleared by the witnessed head alone")
		}
		if _, err := c.List(f.mbx, store.ID{}); err != nil {
			t.Fatal(err)
		}
		warningWith(t, f.env.Warnings.Take(), "abgeglichen", bob.ID.String())
		if unconfirmed(t, dir) {
			t.Fatal("still marked after bob's checkpoint agreed")
		}
		c.Close()
		c2, err := client.Open(f.env.ClientConfig(dir), testenv.Passphrase)
		if err != nil {
			t.Fatal(err)
		}
		defer c2.Close()
		noWarningWith(t, f.env.Warnings.Take(), "Noch kein bestätigter Zustand")
	})
	t.Run("sole member", func(t *testing.T) {
		f := newFixture(t)
		f.deliver(t, "a", "x")
		f.env.Reopen(f.u) // alice's first device writes its checkpoint
		if refs, _ := f.env.Store.ListCheckpoints(f.mbx); len(refs) != 1 {
			t.Fatalf("checkpoints of alice's first device: %d", len(refs))
		}
		dir := filepath.Join(f.env.Base, "clients", "alice2")
		if _, err := client.Restore(f.env.ClientConfig(dir), client.RestoreOptions{Words: f.u.Words}, testenv.Passphrase); err != nil {
			t.Fatal(err)
		}
		for run := 0; run < 2; run++ {
			f.env.Warnings.Take()
			c, err := client.Open(f.env.ClientConfig(dir), testenv.Passphrase)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.List(f.mbx, store.ID{}); err != nil {
				t.Fatal(err)
			}
			c.Close()
			warningWith(t, f.env.Warnings.Take(), "Sicht noch nicht mit einem anderen Mitglied abgeglichen")
			if !unconfirmed(t, dir) {
				t.Fatalf("run %d: a sole member was confirmed by its own other device", run)
			}
		}
	})
}

// TestLogIndexEmptyTables (point 7): an audit index with the size and
// root of the reference head but empty tables is rebuilt at Open.
func TestLogIndexEmptyTables(t *testing.T) {
	f := newFixture(t)
	m := f.deliver(t, "idx", "body")
	idx := filepath.Join(f.u.Dir, "log-index.json")
	var st map[string]json.RawMessage
	if err := json.Unmarshal(mustRead(t, idx), &st); err != nil {
		t.Fatal(err)
	}
	emptied, _ := json.Marshal(map[string]json.RawMessage{"version": st["version"], "anchor": st["anchor"], "size": st["size"], "root": st["root"]})
	f.u.Client.Close()
	if err := os.WriteFile(idx, emptied, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
	if err != nil {
		t.Fatalf("open with an index without its entries: %v", err)
	}
	f.u.Client = c
	readBody(t, f.env, c, f.mbx, m.ID, "body")
	if bytes.Equal(mustRead(t, idx), emptied) {
		t.Fatal("index not rebuilt")
	}
}

// notInLogUser answers ErrNotInLog for the own user.rec the first times
// CheckUser is asked (an index that does not see the entry).
type notInLogUser struct {
	translog.Log
	left *int
}

func (l *notInLogUser) CheckUser(id store.ID, raw []byte) error {
	if *l.left > 0 {
		*l.left--
		return fmt.Errorf("%w: test", translog.ErrNotInLog)
	}
	return l.Log.CheckUser(id, raw)
}

// TestLogOwnUserIndexRebuilt (points 5 and 7): the own user.rec "not in
// the log" at Open is checked again after a rebuild of the audit index,
// and once more after appending it again, before Open fails.
func TestLogOwnUserIndexRebuilt(t *testing.T) {
	f := newFixture(t)
	f.u.Client.Close()
	for _, x := range []struct {
		left    int
		ok      bool
		appends bool
	}{{1, true, false}, {2, true, true}, {3, false, true}} {
		left := x.left
		client.SetLogHook(t, func(l translog.Log) translog.Log { return &notInLogUser{Log: l, left: &left} })
		f.env.Warnings.Take()
		c, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
		ws := f.env.Warnings.Take()
		if x.ok != (err == nil) || (!x.ok && !errors.Is(err, translog.ErrNotInLog)) {
			t.Fatalf("%d answers not in the log: %v", x.left, err)
		}
		if err == nil {
			c.Close()
		}
		if x.appends {
			warningWith(t, ws, "eigene user.rec fehlt")
		} else {
			noWarningWith(t, ws, "eigene user.rec fehlt")
		}
	}
	client.SetLogHook(t, nil)
	f.env.Reopen(f.u)
}

// TestLogPlantedNewMailboxCopy (point 8): a copy in new-mailboxes/ that
// this user did not make (bob's real epoch 1, garbage beside it) is
// removed with a warning; nothing is written into bob's mailbox. So is a
// copy whose wrap or folders.gml is not what CreateMailbox writes.
func TestLogPlantedNewMailboxCopy(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	bobBox := f.env.Mailbox(bob, "B")
	_, e1data, err := f.env.Store.ReadEpoch(bobBox, 1)
	if err != nil {
		t.Fatal(err)
	}
	plant := func(id store.ID, files map[string][]byte) string {
		t.Helper()
		dir := filepath.Join(f.u.Dir, "new-mailboxes", id.String())
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	mrec, _ := (&store.Mailbox{ID: bobBox, Epoch: 1, Inbox: store.ID{1}}).Encode()
	dir := plant(bobBox, map[string][]byte{"wrap": []byte("x"), "folders.gml": []byte("y"), "mailbox.rec": mrec, "epoch.rec": e1data})
	f.env.Warnings.Take()
	f.env.Reopen(f.u)
	warningWith(t, f.env.Warnings.Take(), bobBox.String(), "stammt nicht von diesem Benutzer")
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("planted copy kept")
	}
	if _, err := os.Stat(f.env.Store.WrapFile(bobBox, 1, f.u.ID)); err == nil {
		t.Fatal("a wrap for alice was written into bob's mailbox")
	}
	if _, err := bob.Client.List(bobBox, store.ID{}); err != nil {
		t.Fatalf("bob after the planted copy: %v", err)
	}
	// An epoch 1 of alice herself with a foreign wrap and folders.gml.
	ks := f.env.Keystore(f.u)
	defer ks.Zero()
	id, _ := store.NewID(nil)
	inbox, _ := store.NewID(nil)
	content, _ := ecdh.X25519().GenerateKey(rand.Reader)
	meta, _ := ecdh.X25519().GenerateKey(rand.Reader)
	e := &store.Epoch{MailboxID: id, Number: 1, Begin: f.env.Clock.Now().UnixMilli(), Reason: store.ReasonRegular, Suite: envelope.Suite1,
		ContentPub: content.PublicKey(), MetaPub: meta.PublicKey(),
		Members: []store.Member{{Kind: store.MemberUser, ID: f.u.ID, Gen: 1}}, SignerID: f.u.ID, SignerGen: 1}
	if err := e.Sign(ks.Identity); err != nil {
		t.Fatal(err)
	}
	edata, _ := e.Encode()
	mrec2, _ := (&store.Mailbox{ID: id, Epoch: 1, Inbox: inbox}).Encode()
	wrapOther := mustRead(t, f.env.Store.WrapFile(f.mbx, 1, f.u.ID)) // a wrap of another mailbox
	dir2 := plant(id, map[string][]byte{"wrap": wrapOther, "folders.gml": []byte("y"), "mailbox.rec": mrec2, "epoch.rec": edata})
	f.env.Warnings.Take()
	f.env.Reopen(f.u)
	warningWith(t, f.env.Warnings.Take(), id.String(), "stammt nicht von diesem Benutzer")
	if _, err := os.Stat(dir2); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("copy with a foreign wrap kept")
	}
	if _, err := os.Stat(f.env.Store.MailboxDir(id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mailbox of the foreign copy written")
	}
}

// TestLogForeignUserRecRolledBack (point 9): bob's user.rec in the data
// directory is rolled back to generation 1 while the log holds
// generation 2; alice warns that it is outdated and checks the epoch bob
// signed with generation 2 against the logged user.rec instead.
func TestLogForeignUserRecRolledBack(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	old := mustRead(t, f.env.Store.UserFile(bob.ID))
	f.env.Clock.Advance(time.Minute)
	f.env.Rotate(bob)
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	carol := f.env.NewUser("carol")
	f.env.Clock.Advance(time.Minute)
	f.env.Share(bob, f.mbx, carol, client.ShareOptions{})
	m := f.deliver(t, "signed-by-bob-gen2", "body")
	if err := store.WriteFileAtomic(f.env.Store.UserFile(bob.ID), old); err != nil {
		t.Fatal(err)
	}
	c := f.env.Reopen(f.u)
	f.env.Warnings.Take()
	readBody(t, f.env, c, f.mbx, m.ID, "body")
	warningWith(t, f.env.Warnings.Take(), "user.rec von "+bob.ID.String()+" ist veraltet")
}

// TestLogRegisterDuplicateRemedy (point 10): Register after somebody
// logged the user ID first names the whole remedy; following it (delete
// the client directory, keygen, register with a new code) works.
func TestLogRegisterDuplicateRemedy(t *testing.T) {
	env := testenv.New(t)
	env.NewUser("bob")
	dir := filepath.Join(env.Base, "clients", "alice")
	cfg := env.ClientConfig(dir)
	id, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
	if err != nil {
		t.Fatal(err)
	}
	rootPub, root, _ := ed25519.GenerateKey(rand.Reader)
	idPub, _, _ := ed25519.GenerateKey(rand.Reader)
	unwrap, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cert, err := keys.NewGenerationCert(root, 1, idPub, unwrap.PublicKey(), env.Clock.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: id, RootPub: rootPub, Generations: []*keys.GenerationCert{cert}}
	if err := u.Sign(root); err != nil {
		t.Fatal(err)
	}
	data, err := u.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.LogOperator().Append(translog.KindUser, data); err != nil {
		t.Fatal(err)
	}
	code, _ := env.Store.CreateInvite(env.Clock.Now().UnixMilli())
	_, err = client.Register(cfg, code)
	if !errors.Is(err, translog.ErrDuplicate) {
		t.Fatalf("register with a taken ID: %v", err)
	}
	for _, part := range []string{"delete the client directory", dir, "run keygen again", "new invitation code"} {
		if !strings.Contains(err.Error(), part) {
			t.Fatalf("remedy without %q: %v", part, err)
		}
	}
	if _, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{}); !errors.Is(err, client.ErrRegistered) {
		t.Fatalf("keygen over the unregistered user: %v", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{}); err != nil {
		t.Fatal(err)
	}
	code2, _ := env.Store.CreateInvite(env.Clock.Now().UnixMilli())
	if _, err := client.Register(cfg, code2); err != nil {
		t.Fatal(err)
	}
	c, err := client.Open(cfg, testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

// TestLogSyncRefreshes (point 12): Sync refreshes the client log once,
// although the reference head is fresh.
func TestLogSyncRefreshes(t *testing.T) {
	f := newFixture(t)
	f.env.AutoHeads = false
	f.env.Clock.Advance(time.Minute)
	f.env.MustPublishHead()
	c := f.env.Reopen(f.u)
	f.env.AssignAddress("grow4@example.org", f.mbx)
	f.env.Clock.Advance(time.Minute)
	h2 := f.env.MustPublishHead()
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if hs := headOfState(t, f.u.Dir); hs.Size != h2.Size || hs.Time != h2.Time {
		t.Fatalf("reference head after Sync: %d, want %d", hs.Size, h2.Size)
	}
	cp, err := f.env.Store.ReadCheckpoint(f.mbx, f.u.ID, deviceOf(t, f.u.Dir))
	if err != nil || cp.Size != h2.Size {
		t.Fatalf("checkpoint after Sync: %+v %v", cp, err)
	}
}
