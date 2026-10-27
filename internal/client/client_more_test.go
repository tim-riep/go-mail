package client_test

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

func TestSyncAfterFallbackNote(t *testing.T) {
	f := newFixture(t)
	f.env.Clock.Set(time.Date(2027, 4, 2, 0, 0, 0, 0, time.UTC))
	f.deliver(t, "late", "x")
	if n, _ := f.env.Store.ReadNote(f.mbx); n == nil {
		t.Fatal("no note")
	}
	f.env.Warnings.Take()
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	if !warned(f.env, "fehlte eine Epoche") {
		t.Fatal("the fallback must be reported")
	}
	e5, _, _ := f.env.Store.ReadEpoch(f.mbx, 5)
	if e5.Reason != store.ReasonRegular {
		t.Fatal("immediate epoch")
	}
	// A damaged note is reported and does not stop the supply.
	os.WriteFile(f.env.Store.NoteFile(f.mbx), []byte("x"), 0o600)
	f.env.Clock.Set(time.Date(2027, 6, 2, 0, 0, 0, 0, time.UTC))
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	if !warned(f.env, "Vermerk des Servers") {
		t.Fatal("damaged note not reported")
	}
}

// sealFolders seals a folder list for the meta key of epoch e with the
// inbox as file ID.
func sealFolders(e *store.Epoch, epoch uint32, inbox store.ID, plain []byte, signer *envelope.Signer) []byte {
	var opts *envelope.SealOptions
	if signer != nil {
		opts = &envelope.SealOptions{Signer: signer}
	}
	data, _ := envelope.Seal(envelope.Header{Kind: envelope.KindMeta, MailboxID: e.MailboxID, Epoch: epoch, FileID: inbox, Created: 1, Version: 1},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: e.MailboxID, Gen: epoch, PublicKey: e.MetaPub}}, plain, opts)
	return data
}

func TestNameAndFoldersTampered(t *testing.T) {
	f := newFixture(t)
	m, _ := f.env.Store.ReadMailbox(f.mbx)
	// The client reads folders.gml of the newest epoch it is a member of.
	n := m.Epoch
	head, _, _ := f.env.Store.ReadEpoch(f.mbx, n)
	orig, _ := f.env.Store.ReadFolders(f.mbx, n)
	if name, err := f.u.Client.MailboxName(f.mbx); err != nil || name != "A" {
		t.Fatalf("name: %q %v", name, err)
	}
	// Older lists are not read.
	os.Remove(f.env.Store.FoldersFile(f.mbx, 1))
	if _, err := f.u.Client.Folders(f.mbx); err != nil {
		t.Fatalf("list of an older epoch read: %v", err)
	}
	restore := func() { f.env.Store.WriteFolders(f.mbx, n, orig) }
	ks, _ := keys.OpenKeystore(mustRead(t, filepath.Join(f.u.Dir, "keystore")), testenv.Passphrase)
	alice := &envelope.Signer{Type: envelope.SignerUser, ID: f.u.ID, Gen: 1, Key: ks.Identity}
	plain := func(epoch uint32, folders []store.Folder) []byte {
		b, err := (&store.FolderList{MailboxID: f.mbx, Epoch: epoch, Name: "x", Folders: folders}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	inboxOnly := []store.Folder{{ID: m.Inbox, Name: client.InboxName}}
	bob := f.env.NewUser("bob")
	bks, _ := keys.OpenKeystore(mustRead(t, filepath.Join(bob.Dir, "keystore")), testenv.Passphrase)
	defer bks.Zero()
	defer ks.Zero()
	prevList, _ := f.env.Store.ReadFolders(f.mbx, n-1)
	for name, c := range map[string]struct {
		data []byte
		want error
	}{
		"list of the previous epoch": {prevList, client.ErrMismatch},
		"junk":                       {[]byte("junk"), envelope.ErrTruncated},
		"sealed for epoch 9":         {sealFolders(head, 9, m.Inbox, plain(9, inboxOnly), alice), client.ErrMismatch},
		"unsigned":                   {sealFolders(head, n, m.Inbox, plain(n, inboxOnly), nil), envelope.ErrUnsigned},
		"signed by the server": {sealFolders(head, n, m.Inbox, plain(n, inboxOnly),
			&envelope.Signer{Type: envelope.SignerIngest, Gen: 1, Key: f.env.IngestKey}), client.ErrSigner},
		"signed by a non-member": {sealFolders(head, n, m.Inbox, plain(n, inboxOnly),
			&envelope.Signer{Type: envelope.SignerUser, ID: bob.ID, Gen: 1, Key: bks.Identity}), client.ErrSigner},
		"plaintext of another epoch": {sealFolders(head, n, m.Inbox, plain(n-1, inboxOnly), alice), store.ErrRecord},
		"no inbox":                   {sealFolders(head, n, m.Inbox, plain(n, []store.Folder{{ID: m.Inbox, Name: "Archiv"}}), alice), client.ErrMismatch},
		"inbox under another id":     {sealFolders(head, n, store.ID{7}, plain(n, inboxOnly), alice), client.ErrMismatch},
	} {
		f.env.Store.WriteFolders(f.mbx, n, c.data)
		if _, err := f.u.Client.MailboxName(f.mbx); !errors.Is(err, c.want) {
			t.Fatalf("%s: name: %v", name, err)
		}
		if _, err := f.u.Client.Folders(f.mbx); !errors.Is(err, c.want) {
			t.Fatalf("%s: folders: %v", name, err)
		}
		restore()
	}
	// A valid list signed by the member is read.
	f.env.Store.WriteFolders(f.mbx, n, sealFolders(head, n, m.Inbox, plain(n, inboxOnly), alice))
	if name, err := f.u.Client.MailboxName(f.mbx); err != nil || name != "x" {
		t.Fatalf("resealed list: %q %v", name, err)
	}
	// folders.gml missing.
	os.Remove(f.env.Store.FoldersFile(f.mbx, n))
	if _, err := f.u.Client.Folders(f.mbx); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("missing folders")
	}
	if _, err := f.u.Client.List(f.mbx, store.ID{}); err == nil {
		t.Fatal("list without a valid folders.gml")
	}
	if err := f.u.Client.Sync(); err != nil {
		t.Fatalf("sync without new epochs needs no folders: %v", err)
	}
	f.env.Clock.Set(time.Date(2027, 6, 2, 0, 0, 0, 0, time.UTC))
	if err := f.u.Client.Sync(); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("new epochs without the current folders: %v", err)
	}
	restore()
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	m2, _ := f.env.Store.ReadMailbox(f.mbx)
	if name, err := f.u.Client.MailboxName(f.mbx); err != nil || m2.Epoch <= n || name != "A" {
		t.Fatalf("name in the new epochs: %q %v", name, err)
	}
	for e := n + 1; e <= m2.Epoch; e++ {
		if _, err := f.env.Store.ReadFolders(f.mbx, e); err != nil {
			t.Fatalf("epoch %d without folders.gml", e)
		}
	}
	// Without mailbox.rec nothing works.
	os.Remove(f.env.Store.MailboxFile(f.mbx))
	if _, err := f.u.Client.MailboxName(f.mbx); err == nil {
		t.Fatal("name without mailbox.rec")
	}
	if _, err := f.u.Client.Folders(f.mbx); err == nil {
		t.Fatal("folders without mailbox.rec")
	}
	if _, _, err := f.u.Client.Read(f.mbx, store.ID{1}); err == nil {
		t.Fatal("read without mailbox.rec")
	}
	if _, err := f.u.Client.OpenPending(f.mbx, 1, store.ID{1}); err == nil {
		t.Fatal("pending without mailbox.rec")
	}
	if err := f.u.Client.Sync(); err == nil {
		t.Fatal("sync without mailbox.rec")
	}
}

func TestMailHeaderChecks(t *testing.T) {
	f := newFixture(t)
	e1, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	inbox := f.inbox(t)
	at := testenv.Start.Add(time.Minute)
	mk := func(hdr envelope.Header, signed bool) store.ID {
		id, _ := store.NewID(nil)
		hdr.FileID = id
		if hdr.Kind == 0 {
			hdr.Kind = envelope.KindMail
		}
		var opts *envelope.SealOptions
		if signed {
			opts = &envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerIngest, Gen: 1, Key: f.env.IngestKey}}
		}
		mail, _ := envelope.Seal(hdr, []envelope.Recipient{{Type: envelope.RecipientEpochContent, ID: f.mbx, Gen: 1, PublicKey: e1.ContentPub}}, []byte("x"), opts)
		f.writeMeta(t, e1, id, inbox, at.UnixMilli(), sha256Sum(mail), 1, f.env.IngestKey, 1)
		store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, id), mail)
		return id
	}
	for name, id := range map[string]store.ID{
		"other mailbox": mk(envelope.Header{MailboxID: store.ID{1}, Epoch: 1}, false),
		"other epoch":   mk(envelope.Header{MailboxID: f.mbx, Epoch: 2}, false),
		"signed mail":   mk(envelope.Header{MailboxID: f.mbx, Epoch: 1}, true),
		"kind meta":     mk(envelope.Header{Kind: envelope.KindMeta, MailboxID: f.mbx, Epoch: 1, Version: 1}, false),
	} {
		if _, _, err := f.u.Client.Read(f.mbx, id); !errors.Is(err, client.ErrMismatch) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Metadata in another folder than its mail.
	id := f.forge(t, e1, at, "x", 1, f.env.IngestKey, 1)
	folder2 := store.ID{8}
	meta, _ := f.env.Store.ReadMeta(f.mbx, inbox, id)
	store.MkdirAll(f.env.Store.MailDir(f.mbx, folder2))
	os.Rename(f.env.Store.MailFile(f.mbx, inbox, id), f.env.Store.MailFile(f.mbx, folder2, id))
	store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, folder2, id), meta)
	if _, _, err := f.u.Client.Read(f.mbx, id); !errors.Is(err, client.ErrMismatch) {
		t.Fatalf("metadata of another folder: %v", err)
	}
	// Unsigned metadata and metadata signed by a user.
	id2, _ := store.NewID(nil)
	m := &store.MailMeta{Version: 1, MailID: id2, Received: at.UnixMilli(), Folder: inbox, Recipients: []string{"a@example.org"}}
	plain, _ := m.Encode()
	unsigned, _ := envelope.Seal(envelope.Header{Kind: envelope.KindMeta, MailboxID: f.mbx, Epoch: 1, FileID: id2, Created: at.UnixMilli(), Version: 1},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: f.mbx, Gen: 1, PublicKey: e1.MetaPub}}, plain, nil)
	store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, inbox, id2), unsigned)
	store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, id2), []byte("x"))
	if _, _, err := f.u.Client.Read(f.mbx, id2); !errors.Is(err, client.ErrSigner) {
		t.Fatalf("unsigned metadata: %v", err)
	}
	ks, _ := keys.OpenKeystore(mustRead(t, filepath.Join(f.u.Dir, "keystore")), testenv.Passphrase)
	userSigned, _ := envelope.Seal(envelope.Header{Kind: envelope.KindMeta, MailboxID: f.mbx, Epoch: 1, FileID: id2, Created: at.UnixMilli(), Version: 1},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: f.mbx, Gen: 1, PublicKey: e1.MetaPub}}, plain,
		&envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerUser, ID: f.u.ID, Gen: 1, Key: ks.Identity}})
	ks.Zero()
	store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, inbox, id2), userSigned)
	if _, _, err := f.u.Client.Read(f.mbx, id2); !errors.Is(err, client.ErrSigner) {
		t.Fatalf("user-signed metadata in phase 1: %v", err)
	}
	// Junk metadata.
	store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, inbox, id2), []byte("junk"))
	if _, _, err := f.u.Client.Read(f.mbx, id2); err == nil {
		t.Fatal("junk metadata")
	}
	// A broken mail file whose hash matches (the server wrote it so).
	id3, _ := store.NewID(nil)
	f.writeMeta(t, e1, id3, inbox, at.UnixMilli(), sha256Sum([]byte("junk")), 1, f.env.IngestKey, 1)
	store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, id3), []byte("junk"))
	if _, _, err := f.u.Client.Read(f.mbx, id3); err == nil {
		t.Fatal("junk mail")
	}
	// A mail whose blocks do not authenticate although the hash matches.
	id4, _ := store.NewID(nil)
	good, _ := envelope.Seal(envelope.Header{Kind: envelope.KindMail, MailboxID: f.mbx, Epoch: 1, FileID: id4, Created: at.UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientEpochContent, ID: f.mbx, Gen: 1, PublicKey: e1.ContentPub}}, []byte("content"), nil)
	good[len(good)-1] ^= 1
	f.writeMeta(t, e1, id4, inbox, at.UnixMilli(), sha256Sum(good), 1, f.env.IngestKey, 1)
	store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, id4), good)
	if _, _, err := f.u.Client.Read(f.mbx, id4); !errors.Is(err, envelope.ErrDecrypt) {
		t.Fatalf("broken block: %v", err)
	}
}

// TestRevokedGeneration builds a user with a known seed, lets generation
// 1 create a mailbox, then moves the user to generation 2 ("device
// lost"). Epochs signed by generation 1 are logged records and stay
// valid (through the log check); the wrap signed by generation 1 is not
// logged and is no longer accepted (strict reading, SPEC-ISSUES S13).
func TestRevokedGeneration(t *testing.T) {
	env := testenv.New(t)
	dir := filepath.Join(env.Base, "manual")
	seed := keys.Seed{42}
	d := keys.DeriveUser(&seed)
	root, _ := d.RootKey()
	id1, _ := d.IdentityKey(1)
	uw1, _ := d.UnwrapKey(1)
	c1, _ := keys.NewGenerationCert(root, 1, id1.Public().(ed25519.PublicKey), uw1.PublicKey(), 1)
	uid := store.ID{42, 42}
	user := &store.User{ID: uid, RootPub: root.Public().(ed25519.PublicKey), Generations: []*keys.GenerationCert{c1}}
	write := func(u *store.User, ks *keys.Keystore) {
		u.Sign(root)
		data, _ := u.Encode()
		os.MkdirAll(dir, 0o700)
		store.WriteFileAtomic(filepath.Join(dir, "user.rec"), data)
		store.MkdirAll(filepath.Dir(env.Store.UserFile(uid)))
		store.WriteFileAtomic(env.Store.UserFile(uid), data)
		ksd, _ := ks.Seal(testenv.Passphrase, nil)
		keys.WriteKeystoreFile(filepath.Join(dir, "keystore"), ksd)
	}
	write(user, &keys.Keystore{Generation: 1, Identity: id1, Unwrap: uw1})
	st, _ := json.Marshal(map[string]any{"user_id": uid.String(), "registered": true, "mailboxes": map[string]any{}})
	store.WriteFileAtomic(filepath.Join(dir, "state.json"), st)
	cl, err := client.Open(env.ClientConfig(dir), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	mbx, err := cl.CreateMailbox("M")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.MailboxName(mbx); err != nil {
		t.Fatal(err)
	}
	cl.Close()
	// Generation 2.
	id2, _ := d.IdentityKey(2)
	uw2, _ := d.UnwrapKey(2)
	c2, _ := keys.NewGenerationCert(root, 2, id2.Public().(ed25519.PublicKey), uw2.PublicKey(), 2)
	user.Generations = append(user.Generations, c2)
	write(user, &keys.Keystore{Generation: 2, Identity: id2, Unwrap: uw2})
	cl, err = client.Open(env.ClientConfig(dir), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	// The chain verifies; as the only user member, whose wraps are for the
	// revoked generation, the user cannot create the epoch
	// generation-revoked: Sync reports ErrPartial (task 06h finding 2), not
	// a chain error.
	if err := cl.Sync(); !errors.Is(err, client.ErrPartial) || errors.Is(err, store.ErrChain) {
		t.Fatalf("epochs of the revoked generation must verify through the log: %v", err)
	}
	if _, err := cl.List(mbx, store.ID{}); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("folders.gml needs the keys of epoch 1: %v", err)
	}
	if _, err := cl.MailboxName(mbx); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("wrap of the revoked generation: %v", err)
	}
	// The keystore must hold the current generation.
	write(user, &keys.Keystore{Generation: 1, Identity: id1, Unwrap: uw1})
	if _, err := client.Open(env.ClientConfig(dir), testenv.Passphrase); err == nil {
		t.Fatal("key store of a revoked generation")
	}
}
