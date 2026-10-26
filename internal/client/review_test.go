package client_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Review finding A1: the epoch rule must hold when the next epoch is
// removed and mailbox.rec reset, using the begin remembered earlier.
func TestStaleEpochWithNextEpochRemoved(t *testing.T) {
	f := newFixture(t)
	f.u.Client.List(f.mbx, store.ID{}) // the client has seen epochs 1-4
	e1, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	e2, _, _ := f.env.Store.ReadEpoch(f.mbx, 2)
	late := time.UnixMilli(e2.Begin).Add(time.Hour)
	id := f.forge(t, e1, late, "stale", 1, f.env.IngestKey, 1)
	os.Remove(f.env.Store.EpochFile(f.mbx, 2))
	m, _ := f.env.Store.ReadMailbox(f.mbx)
	m.Epoch = 1
	f.env.Store.WriteMailbox(m)
	if _, _, err := f.u.Client.Read(f.mbx, id); !errors.Is(err, client.ErrStaleEpoch) {
		t.Fatalf("stale mail with epoch 2 removed: %v", err)
	}
	if list, _ := f.u.Client.List(f.mbx, store.ID{}); len(list) != 0 {
		t.Fatal("stale mail listed")
	}
	// A mail of epoch 1 received before epoch 2 began is still fine.
	ok := f.forge(t, e1, time.UnixMilli(e2.Begin).Add(-time.Hour), "fine", 1, f.env.IngestKey, 1)
	if _, _, err := f.u.Client.Read(f.mbx, ok); err != nil {
		t.Fatal(err)
	}
}

// Without any memory of epoch 2 (a client that never saw it), a broken
// chain right after epoch 1 makes its mails undecidable: rejected.
func TestBrokenChainWithoutMemory(t *testing.T) {
	f := newFixture(t)
	e1, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	id := f.forge(t, e1, testenv.Start.Add(time.Minute), "x", 1, f.env.IngestKey, 1)
	// Forget the begins, then damage epoch 2.
	sp := filepath.Join(f.u.Dir, "state.json")
	var st map[string]any
	json.Unmarshal(mustRead(t, sp), &st)
	mb := st["mailboxes"].(map[string]any)[f.mbx.String()].(map[string]any)
	mb["begins"] = map[string]any{}
	mb["epoch"] = 1
	d1 := mustRead(t, f.env.Store.EpochFile(f.mbx, 1))
	h := sha256.Sum256(d1)
	mb["epoch_hash"] = hex.EncodeToString(h[:])
	b, _ := json.Marshal(st)
	f.u.Client.Close()
	os.WriteFile(sp, b, 0o600)
	os.WriteFile(f.env.Store.EpochFile(f.mbx, 2), []byte("junk"), 0o600)
	c := f.env.Reopen(f.u)
	if _, _, err := c.Read(f.mbx, id); !errors.Is(err, client.ErrEpoch) {
		t.Fatalf("undecidable epoch rule: %v", err)
	}
}

// Review finding A2: a crash after writing epochs but before mailbox.rec
// and the local state must not block the mailbox; leftovers of an
// interrupted epoch creation are cleaned up.
func TestSupplyCrashRecovers(t *testing.T) {
	f := newFixture(t)
	m, _ := f.env.Store.ReadMailbox(f.mbx)
	sp := filepath.Join(f.u.Dir, "state.json")
	before := mustRead(t, sp)
	f.env.Clock.Set(time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC))
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	// Simulate the crash: mailbox.rec and state.json as before the sync.
	f.u.Client.Close()
	f.env.Store.WriteMailbox(m)
	os.WriteFile(sp, before, 0o600)
	// And an interrupted creation of epoch 7: wrap and keys, no epoch.rec.
	store.MkdirAll(filepath.Join(f.env.Store.EpochDir(f.mbx, 7), "members"))
	os.WriteFile(f.env.Store.WrapFile(f.mbx, 7, f.u.ID), []byte("partial"), 0o600)
	os.WriteFile(filepath.Join(f.env.Store.EpochDir(f.mbx, 7), "content.pub"), []byte("x"), 0o600)
	c := f.env.Reopen(f.u)
	f.env.Clock.Set(time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC))
	if err := c.Sync(); err != nil {
		t.Fatalf("sync after the crash: %v", err)
	}
	m2, _ := f.env.Store.ReadMailbox(f.mbx)
	if m2.Epoch != 7 {
		t.Fatalf("head %d, want 7", m2.Epoch)
	}
	// Epoch 7 is complete and its wrap matches.
	if _, err := c.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	e7, _, err := f.env.Store.ReadEpoch(f.mbx, 7)
	if err != nil || mustRead(t, filepath.Join(f.env.Store.EpochDir(f.mbx, 7), "content.pub"))[0] != e7.ContentPub.Bytes()[0] {
		t.Fatal("epoch 7 incomplete")
	}
	// An existing epoch.rec is never replaced.
	if err := f.env.Store.RemoveIncompleteEpoch(f.mbx, 7); !errors.Is(err, store.ErrExists) {
		t.Fatal("complete epoch removed")
	}
	if _, err := f.env.Store.WriteEpoch(e7); !errors.Is(err, store.ErrExists) {
		t.Fatal("epoch written twice")
	}
}

// Review finding B2: an epoch created shortly before its month begins
// starts after the delay.
func TestSupplyAtMonthEnd(t *testing.T) {
	env := testenv.New(t)
	env.Clock.Set(time.Date(2026, 10, 31, 23, 58, 0, 0, time.UTC))
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A")
	e2, _, _ := env.Store.ReadEpoch(mbx, 2)
	if want := env.Clock.Now().Add(client.ImmediateDelay).UnixMilli(); e2.Begin != want {
		t.Fatalf("epoch 2 begins %v, want %v", time.UnixMilli(e2.Begin).UTC(), time.UnixMilli(want).UTC())
	}
	e3, _, _ := env.Store.ReadEpoch(mbx, 3)
	if time.UnixMilli(e3.Begin).UTC() != time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatal("epoch 3")
	}
}

// Review finding B5: term lists are checked against the certificate's
// validity and every rejection warns.
func TestPendingBeforeCertificate(t *testing.T) {
	f := newFixture(t)
	e1, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	id, _ := store.NewID(nil)
	p := &store.Pending{MailboxID: f.mbx, Epoch: 1, Entries: []store.PendingEntry{{MailID: id, Unprocessed: true}}}
	plain, _ := p.Encode()
	early := testenv.Start.Add(-24 * time.Hour).UnixMilli()
	data, _ := envelope.Seal(envelope.Header{Kind: envelope.KindPending, MailboxID: f.mbx, Epoch: 1, FileID: id, Created: early},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: f.mbx, Gen: 1, PublicKey: e1.MetaPub}}, plain,
		&envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerIngest, Gen: 1, Key: f.env.IngestKey}})
	store.MkdirAll(f.env.Store.PendingDir(f.mbx, 1))
	store.WriteFileAtomic(f.env.Store.PendingFile(f.mbx, 1, id), data)
	f.env.Warnings.Take()
	if _, err := f.u.Client.OpenPending(f.mbx, 1, id); !errors.Is(err, client.ErrPlatform) {
		t.Fatalf("term list before the certificate: %v", err)
	}
	if !warned(f.env, "Begriffsliste") {
		t.Fatal("no warning")
	}
}

// Review remark C8: one client process per client directory.
func TestClientDirectoryLock(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	if _, err := client.Open(env.ClientConfig(u.Dir), testenv.Passphrase); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("second client on one directory: %v", err)
	}
	u.Client.Close()
	c, err := client.Open(env.ClientConfig(u.Dir), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
