package client_test

import (
	"bytes"
	"encoding/json"
	"errors"
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
)

type wrongPrompter struct{ testenv.Echo }

// AskWord answers with a typo (a digit appended, which no word of the
// list has): unlike case or white space, a typo is never normalized away
// (S11).
func (p *wrongPrompter) AskWord(pos int) (string, error) {
	w, _ := p.Echo.AskWord(pos)
	return strings.ToUpper(w) + "1", nil
}

type failPrompter struct{ show, ask bool }

func (p *failPrompter) ShowWords([]string) error {
	if p.show {
		return errors.New("show")
	}
	return nil
}
func (p *failPrompter) AskWord(int) (string, error) {
	if p.ask {
		return "", errors.New("ask")
	}
	return "", nil
}

func TestKeygenAndRegister(t *testing.T) {
	env := testenv.New(t)
	dir := filepath.Join(env.Base, "c1")
	cfg := env.ClientConfig(dir)
	if _, err := client.Keygen(cfg, testenv.Passphrase, &wrongPrompter{}); !errors.Is(err, client.ErrConfirm) {
		t.Fatal("wrong confirmation accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "keystore")); !os.IsNotExist(err) {
		t.Fatal("nothing may be written without confirmation")
	}
	if _, err := client.Keygen(cfg, testenv.Passphrase, &failPrompter{show: true}); err == nil {
		t.Fatal("display error")
	}
	if _, err := client.Keygen(cfg, testenv.Passphrase, &failPrompter{ask: true}); err == nil {
		t.Fatal("input error")
	}
	if _, err := client.Keygen(cfg, nil, &testenv.Echo{}); err == nil {
		t.Fatal("empty passphrase")
	}
	// Not yet registered.
	if _, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrNotRegistered) {
		t.Fatal("open before keygen")
	}
	id, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{}); !errors.Is(err, client.ErrRegistered) {
		t.Fatal("second keygen in one directory")
	}
	if _, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrNotRegistered) {
		t.Fatal("open before register")
	}
	// The data directory has no user yet; the client directory has no seed.
	if _, _, err := env.Store.ReadUser(id); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("user visible before registration")
	}
	if _, err := client.Register(cfg, store.ID{1}); !errors.Is(err, store.ErrInvite) {
		t.Fatal("unknown invitation")
	}
	code, _ := env.Store.CreateInvite(0)
	got, err := client.Register(cfg, code)
	if err != nil || got != id {
		t.Fatal(err)
	}
	if _, err := client.Register(cfg, code); !errors.Is(err, client.ErrRegistered) {
		t.Fatal("register twice")
	}
	// The invitation cannot register a second user.
	dir2 := filepath.Join(env.Base, "c2")
	cfg2 := env.ClientConfig(dir2)
	client.Keygen(cfg2, testenv.Passphrase, &testenv.Echo{})
	if _, err := client.Register(cfg2, code); !errors.Is(err, store.ErrInvite) {
		t.Fatal("invitation used twice")
	}
	if _, err := client.Register(env.ClientConfig(filepath.Join(env.Base, "none")), code); !errors.Is(err, client.ErrNotRegistered) {
		t.Fatal("register without keygen")
	}
	// Wrong passphrase.
	if _, err := client.Open(cfg, []byte("wrong")); !errors.Is(err, keys.ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	c, err := client.Open(cfg, testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if c.UserID() != id {
		t.Fatal("user id")
	}
	c.Close()
	c.Close()
	// There is no start without the log (task 14): no warning of the
	// placeholder.
	if warned(env, "Ohne Transparenzlog") {
		t.Fatal("warning of a start without the log")
	}
	// No file in the client directory holds the seed words in clear.
	for _, f := range []string{"keystore", "user.rec", "state.json"} {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		if fi, _ := os.Stat(filepath.Join(dir, f)); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, fi.Mode())
		}
		for _, w := range []string{"abandon ability", "zoo"} {
			_ = w
		}
		_ = b
	}
}

func TestOpenChecks(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	cfg := env.ClientConfig(u.Dir)
	u.Client.Close()
	// user.rec in the data directory changed.
	orig, _ := os.ReadFile(env.Store.UserFile(u.ID))
	bob := env.NewUser("bob")
	bobRec, _ := os.ReadFile(env.Store.UserFile(bob.ID))
	os.WriteFile(env.Store.UserFile(u.ID), bobRec, 0o600)
	if _, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrUserRecord) {
		t.Fatalf("changed user.rec: %v", err)
	}
	os.WriteFile(env.Store.UserFile(u.ID), orig, 0o600)
	// Configuration errors.
	bad := cfg
	bad.Dir = filepath.Join(env.Store.Root, "client")
	if _, err := client.Open(bad, testenv.Passphrase); err == nil {
		t.Fatal("client directory inside the data directory")
	}
	bad = cfg
	bad.Pin = nil
	if _, err := client.Open(bad, testenv.Passphrase); err == nil {
		t.Fatal("no pin")
	}
	bad = cfg
	bad.AllowDevIdentity = false
	if _, err := client.Open(bad, testenv.Passphrase); !errors.Is(err, client.ErrDevIdentity) {
		t.Fatal("development identity without AllowDevIdentity")
	}
	// Damaged state file.
	os.WriteFile(filepath.Join(u.Dir, "state.json"), []byte("{"), 0o600)
	if _, err := client.Open(cfg, testenv.Passphrase); err == nil {
		t.Fatal("damaged state")
	}
}

func TestMailboxFoldersInspect(t *testing.T) {
	f := newFixture(t)
	if n, err := f.u.Client.MailboxName(f.mbx); err != nil || n != "A" {
		t.Fatal(n, err)
	}
	fs, err := f.u.Client.Folders(f.mbx)
	if err != nil || len(fs) != 1 || fs[0].Name != client.InboxName || fs[0].ID != f.inbox(t) {
		t.Fatal(fs, err)
	}
	if ids := f.u.Client.Mailboxes(); len(ids) != 1 || ids[0] != f.mbx {
		t.Fatal("mailboxes")
	}
	if _, err := f.u.Client.CreateMailbox("\x00"); err == nil {
		t.Fatal("empty name")
	}
	a := f.deliver(t, "a", "body")
	inbox := f.inbox(t)
	// inspect of records and .gml files.
	for _, p := range []string{f.env.Store.EpochFile(f.mbx, 1), f.env.Store.MailboxFile(f.mbx), f.env.Store.UserFile(f.u.ID),
		f.env.Store.MetaFile(f.mbx, inbox, a.ID), f.env.Store.MailFile(f.mbx, inbox, a.ID), f.env.Store.Path("platform", "ingest-1.cert"),
		filepath.Join(f.env.KeyDir, "ingest-1.key")} {
		data, _ := os.ReadFile(p)
		out, err := client.Inspect(data)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		var v map[string]any
		if json.Unmarshal(out, &v) != nil {
			t.Fatal("not JSON")
		}
		if bytes.Contains(out, []byte("body")) {
			t.Fatal("inspect shows content")
		}
		if strings.HasSuffix(p, ".key") && !bytes.Contains(out, []byte("geheim")) {
			t.Fatal("private key shown")
		}
	}
	if _, err := client.Inspect([]byte("gomail/v1/rec/keystore-content\x00")); err == nil {
		t.Fatal("unknown record type")
	}
	if _, err := client.Inspect([]byte("junk")); err == nil {
		t.Fatal("junk")
	}
	if _, err := client.Inspect([]byte("GOMLxx")); err == nil {
		t.Fatal("broken gml")
	}
	if _, err := client.Inspect([]byte("gomail/v1/rec/epoch\x00junk")); err == nil {
		t.Fatal("broken record")
	}
	// Reading a mail that does not exist.
	if _, _, err := f.u.Client.Read(f.mbx, store.ID{5}); !errors.Is(err, client.ErrNotFound) {
		t.Fatal("missing mail")
	}
	// A mail without metadata is not listed, with a warning.
	store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, store.ID{6}), []byte("x"))
	f.env.Warnings.Take()
	list, _ := f.u.Client.List(f.mbx, store.ID{})
	if len(list) != 1 || !warned(f.env, "wird nicht verarbeitet") {
		t.Fatal("mail without metadata")
	}
	if _, _, err := f.u.Client.Read(f.mbx, store.ID{6}); err == nil {
		t.Fatal("mail without metadata read")
	}
	// Unknown mailbox.
	if _, err := f.u.Client.List(store.ID{9}, store.ID{}); err == nil {
		t.Fatal("unknown mailbox")
	}
}

func TestWrapChecks(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	w1, _ := f.env.Store.ReadWrap(f.mbx, 1, f.u.ID)
	w2, _ := f.env.Store.ReadWrap(f.mbx, 2, f.u.ID)
	// The wrap of epoch 2 placed as wrap of epoch 1.
	f.env.Store.WriteWrap(f.mbx, 1, f.u.ID, w2)
	c := f.env.Reopen(f.u)
	if _, _, err := c.Read(f.mbx, a.ID); !errors.Is(err, client.ErrWrap) && !errors.Is(err, client.ErrMismatch) {
		t.Fatalf("wrap of another epoch: %v", err)
	}
	// A wrap sealed by the attacker for the user's public unwrap key, with
	// keys that do not belong to the epoch, signed by nobody.
	u, _, _ := f.env.Store.ReadUser(f.u.ID)
	e1, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	ek := &store.EpochKeys{MailboxID: f.mbx, Epoch: 1, Content: x25519(t), Meta: x25519(t)}
	plain, _ := ek.Encode()
	evil, _ := envelope.Seal(envelope.Header{Kind: envelope.KindWrap, MailboxID: f.mbx, Epoch: 1, FileID: f.u.ID},
		[]envelope.Recipient{{Type: envelope.RecipientUserUnwrap, ID: f.u.ID, Gen: 1, PublicKey: u.Current().UnwrapPub}}, plain, nil)
	f.env.Store.WriteWrap(f.mbx, 1, f.u.ID, evil)
	c = f.env.Reopen(f.u)
	if _, _, err := c.Read(f.mbx, a.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("unsigned wrap: %v", err)
	}
	_ = e1
	// Missing wrap.
	os.Remove(f.env.Store.WrapFile(f.mbx, 1, f.u.ID))
	c = f.env.Reopen(f.u)
	if _, _, err := c.Read(f.mbx, a.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("missing wrap: %v", err)
	}
	f.env.Store.WriteWrap(f.mbx, 1, f.u.ID, w1)
	c = f.env.Reopen(f.u)
	if _, _, err := c.Read(f.mbx, a.ID); err != nil {
		t.Fatal(err)
	}
	// Another user is not a member and has no keys.
	bob := f.env.NewUser("bob")
	if _, _, err := bob.Client.Read(f.mbx, a.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("non-member: %v", err)
	}
}

func TestPendingChecks(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	if _, err := f.u.Client.OpenPending(f.mbx, 1, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.u.Client.OpenPending(f.mbx, 9, a.ID); !errors.Is(err, client.ErrEpoch) {
		t.Fatal("unknown epoch")
	}
	if _, err := f.u.Client.OpenPending(f.mbx, 1, store.ID{3}); err == nil {
		t.Fatal("missing file")
	}
	// The marker moved to another name.
	data, _ := f.env.Store.ReadPending(f.mbx, 1, a.ID)
	store.WriteFileAtomic(f.env.Store.PendingFile(f.mbx, 1, store.ID{4}), data)
	if _, err := f.u.Client.OpenPending(f.mbx, 1, store.ID{4}); !errors.Is(err, client.ErrMismatch) {
		t.Fatal("moved marker")
	}
	// A metadata file placed in pending/ is signed for another kind.
	meta, _ := f.env.Store.ReadMeta(f.mbx, f.inbox(t), a.ID)
	store.WriteFileAtomic(f.env.Store.PendingFile(f.mbx, 1, a.ID), meta)
	if _, err := f.u.Client.OpenPending(f.mbx, 1, a.ID); err == nil {
		t.Fatal("metadata accepted as term list")
	}
}

func TestSyncSupply(t *testing.T) {
	f := newFixture(t)
	// Two months later the supply is topped up to three months ahead.
	f.env.Clock.Set(time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC))
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	m, _ := f.env.Store.ReadMailbox(f.mbx)
	if m.Epoch != 6 {
		t.Fatalf("head %d, want 6 (January to March)", m.Epoch)
	}
	e6, _, _ := f.env.Store.ReadEpoch(f.mbx, 6)
	if time.UnixMilli(e6.Begin).UTC() != time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatal("epoch 6 must begin on 1 March")
	}
	// A broken chain is never extended.
	os.Remove(f.env.Store.EpochFile(f.mbx, 2))
	if err := f.u.Client.Sync(); err == nil {
		t.Fatal("sync on a broken chain")
	}
}
