// Package testenv builds a complete development platform for tests: a
// data directory from the development ceremony, users with key stores,
// mailboxes and address assignments, and a controllable clock. It is used
// only by tests.
package testenv

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Clock is a settable clock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// Now returns the current time of the clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Set sets the clock.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Env is a development platform.
type Env struct {
	T         testing.TB
	Base      string
	Store     *store.Store
	Log       translog.Log
	Pin       *store.PlatformPin
	IngestKey ed25519.PrivateKey
	AdminKey  ed25519.PrivateKey
	KeyDir    string
	Clock     *Clock
	Warnings  *Warnings
}

// Warnings collects client warnings.
type Warnings struct {
	mu   sync.Mutex
	list []string
}

// Add records a warning.
func (w *Warnings) Add(s string) {
	w.mu.Lock()
	w.list = append(w.list, s)
	w.mu.Unlock()
}

// Take returns and clears the warnings.
func (w *Warnings) Take() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	l := w.list
	w.list = nil
	return l
}

// Start is the default clock start: 2026-10-26 10:00 UTC.
var Start = time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)

// New runs the development ceremony in a temporary directory.
func New(t testing.TB) *Env {
	t.Helper()
	base := t.TempDir()
	log, err := translog.NewUnverified(true)
	if err != nil {
		t.Fatal(err)
	}
	clock := &Clock{t: Start}
	res, err := ceremony.InitDev(filepath.Join(base, "data"), filepath.Join(base, "keys"), clock.Now().Add(-time.Hour), log)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(base, "data"))
	if err != nil {
		t.Fatal(err)
	}
	ingest, _, err := ceremony.ReadKey(filepath.Join(res.KeyDir, ceremony.IngestKeyFile), store.KeyRoleIngest)
	if err != nil {
		t.Fatal(err)
	}
	admin, _, err := ceremony.ReadKey(filepath.Join(res.KeyDir, ceremony.AdminKeyFile), store.KeyRoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return &Env{T: t, Base: base, Store: st, Log: log, Pin: res.Pin, IngestKey: ingest, AdminKey: admin, KeyDir: res.KeyDir, Clock: clock, Warnings: &Warnings{}}
}

// ClientConfig returns the configuration of a client in dir.
func (e *Env) ClientConfig(dir string) client.Config {
	return client.Config{Store: e.Store, Dir: dir, Pin: e.Pin, Log: e.Log, Now: e.Clock.Now, Warn: e.Warnings.Add}
}

// Echo answers the seed confirmation correctly.
type Echo struct{ words []string }

// ShowWords remembers the words.
func (p *Echo) ShowWords(w []string) error { p.words = append([]string(nil), w...); return nil }

// AskWord returns the word at pos.
func (p *Echo) AskWord(pos int) (string, error) { return p.words[pos-1], nil }

// Passphrase of test users.
var Passphrase = []byte("correct horse battery staple")

// User is a registered user with an open client.
type User struct {
	Dir    string
	ID     store.ID
	Client *client.Client
}

// NewUser creates, registers and opens a user.
func (e *Env) NewUser(name string) *User {
	e.T.Helper()
	dir := filepath.Join(e.Base, "clients", name)
	cfg := e.ClientConfig(dir)
	if _, err := client.Keygen(cfg, Passphrase, &Echo{}); err != nil {
		e.T.Fatal(err)
	}
	code, err := e.Store.CreateInvite(e.Clock.Now().UnixMilli())
	if err != nil {
		e.T.Fatal(err)
	}
	id, err := client.Register(cfg, code)
	if err != nil {
		e.T.Fatal(err)
	}
	c, err := client.Open(cfg, Passphrase)
	if err != nil {
		e.T.Fatal(err)
	}
	e.T.Cleanup(c.Close)
	return &User{Dir: dir, ID: id, Client: c}
}

// Reopen opens the user's client again (a new process).
func (e *Env) Reopen(u *User) *client.Client {
	e.T.Helper()
	u.Client.Close()
	c, err := client.Open(e.ClientConfig(u.Dir), Passphrase)
	if err != nil {
		e.T.Fatal(err)
	}
	e.T.Cleanup(c.Close)
	u.Client = c
	return c
}

// Mailbox creates a mailbox of u and assigns the addresses to it.
func (e *Env) Mailbox(u *User, name string, addrs ...string) store.ID {
	e.T.Helper()
	id, err := u.Client.CreateMailbox(name)
	if err != nil {
		e.T.Fatal(err)
	}
	for _, a := range addrs {
		if _, err := e.Store.AddAddress(a, id); err != nil {
			e.T.Fatal(err)
		}
	}
	return id
}

// ImmediateEpoch appends an epoch with immediate effect (2.4) to mailbox
// mbx, created and signed by its member u like a client would do it:
// fresh random keys, the wrap for u, folders.gml with name and the inbox
// of mailbox.rec as the only folder, discards naming every epoch of the
// chain up to the head of mailbox.rec that is not discarded and begins
// after begin (2.4 rule 1), epoch.rec in the log and mailbox.rec pointing
// to the new epoch. It holds the mailbox lock while it writes.
//
// It serves every reason with immediate effect alike (member-added,
// member-removed, delegation-ended, recovery-changed, generation-revoked):
// reason is written into epoch.rec as given and changes nothing else, so
// the member list is always u alone, whatever the reason says about the
// members. The reason regular is planned and discards nothing (2.4 rule
// 2): if discards would not be empty, the epoch record is refused and the
// test fails; otherwise the result is a planned epoch beginning at begin.
// Clients do not create epochs with immediate effect yet;
// tests use it to check how client and server treat them.
func (e *Env) ImmediateEpoch(u *User, mbx store.ID, begin time.Time, reason store.Reason, name string) *store.Epoch {
	e.T.Helper()
	fail := func(err error) {
		e.T.Helper()
		if err != nil {
			e.T.Fatal(err)
		}
	}
	unlock, err := e.Store.LockMailbox(mbx)
	fail(err)
	defer unlock()
	m, err := e.Store.ReadMailbox(mbx)
	fail(err)
	links := store.NewChain()
	var headData []byte
	for n := uint32(1); n <= m.Epoch; n++ {
		ep, data, err := e.Store.ReadEpoch(mbx, n)
		fail(err)
		fail(links.Add(ep, data))
		headData = data
	}
	var discards []uint32
	for n := uint32(1); n <= m.Epoch; n++ {
		if !links.Discarded(n) && links.Epoch(n).Begin > begin.UnixMilli() {
			discards = append(discards, n)
		}
	}
	ksData, err := keys.ReadKeystoreFile(filepath.Join(u.Dir, "keystore"))
	fail(err)
	ks, err := keys.OpenKeystore(ksData, Passphrase)
	keys.Wipe(ksData)
	fail(err)
	defer ks.Zero()
	content, err := ecdh.X25519().GenerateKey(rand.Reader)
	fail(err)
	meta, err := ecdh.X25519().GenerateKey(rand.Reader)
	fail(err)
	n := m.Epoch + 1
	ek := &store.EpochKeys{MailboxID: mbx, Epoch: n, Content: content, Meta: meta}
	_, err = io.ReadFull(rand.Reader, ek.Index[:])
	fail(err)
	defer ek.Zero()
	ep := &store.Epoch{
		MailboxID: mbx, Number: n, Begin: begin.UnixMilli(), Reason: reason, Suite: envelope.Suite1,
		ContentPub: content.PublicKey(), MetaPub: meta.PublicKey(),
		Members:  []store.Member{{Kind: store.MemberUser, ID: u.ID, Gen: ks.Generation}},
		Discards: discards, PrevHash: store.EpochHash(headData),
		SignerID: u.ID, SignerGen: ks.Generation,
	}
	fail(ep.Sign(ks.Identity))
	signer := &envelope.Signer{Type: envelope.SignerUser, ID: u.ID, Gen: ks.Generation, Key: ks.Identity}
	now := e.Clock.Now().UnixMilli()
	plain, err := ek.Encode()
	fail(err)
	wrap, err := envelope.Seal(
		envelope.Header{Kind: envelope.KindWrap, MailboxID: mbx, Epoch: n, FileID: u.ID, Created: now},
		[]envelope.Recipient{{Type: envelope.RecipientUserUnwrap, ID: u.ID, Gen: ks.Generation, PublicKey: ks.Unwrap.PublicKey()}},
		plain, &envelope.SealOptions{Signer: signer})
	keys.Wipe(plain)
	fail(err)
	fail(e.Store.WriteWrap(mbx, n, u.ID, wrap))
	list, err := (&store.FolderList{MailboxID: mbx, Epoch: n, Name: name, Folders: []store.Folder{{ID: m.Inbox, Name: client.InboxName}}}).Encode()
	fail(err)
	folders, err := envelope.Seal(
		envelope.Header{Kind: envelope.KindMeta, MailboxID: mbx, Epoch: n, FileID: m.Inbox, Created: now, Version: 1},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: mbx, Gen: n, PublicKey: ep.MetaPub}},
		list, &envelope.SealOptions{Signer: signer})
	fail(err)
	fail(e.Store.WriteFolders(mbx, n, folders))
	data, err := e.Store.WriteEpoch(ep)
	fail(err)
	fail(e.Log.AppendEpoch(mbx, n, data))
	next := *m
	next.Epoch = n
	fail(e.Store.WriteMailbox(&next))
	return ep
}
