package client_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

type fixture struct {
	env *testenv.Env
	u   *testenv.User
	mbx store.ID
	in  *ingest.Ingest
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	in, err := ingest.New(ingest.Config{Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1, Now: env.Clock.Now,
		DiskSpace: func(string) (uint64, uint64, error) { return 1, 2, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{env: env, u: u, mbx: mbx, in: in}
}

func (f *fixture) deliver(t *testing.T, subject, body string) *client.Mail {
	t.Helper()
	d, err := f.in.Begin(smtpd.Session{ID: "t"}, "s@x.example", []string{"a@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	d.Write([]byte("Subject: " + subject + "\r\n\r\n" + body + "\r\n"))
	if err := d.Commit(); err != nil {
		t.Fatal(err)
	}
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range list {
		if m.Meta.Subject == subject {
			return m
		}
	}
	t.Fatalf("mail %q not listed: %v", subject, f.env.Warnings.Take())
	return nil
}

func (f *fixture) inbox(t *testing.T) store.ID {
	m, err := f.env.Store.ReadMailbox(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	return m.Inbox
}

// forge writes a mail and its metadata directly into the mailbox,
// signed with key as ingest generation gen, for epoch e.
func (f *fixture) forge(t *testing.T, e *store.Epoch, received time.Time, content string, version uint32, key ed25519.PrivateKey, gen uint32) store.ID {
	t.Helper()
	id, _ := store.NewID(nil)
	inbox := f.inbox(t)
	ms := received.UnixMilli()
	mail, err := envelope.Seal(envelope.Header{Kind: envelope.KindMail, MailboxID: f.mbx, Epoch: e.Number, FileID: id, Created: ms},
		[]envelope.Recipient{{Type: envelope.RecipientEpochContent, ID: f.mbx, Gen: e.Number, PublicKey: e.ContentPub}}, []byte(content), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.writeMeta(t, e, id, inbox, ms, sha256.Sum256(mail), version, key, gen)
	store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, id), mail)
	return id
}

func (f *fixture) writeMeta(t *testing.T, e *store.Epoch, id, folder store.ID, ms int64, hash [32]byte, version uint32, key ed25519.PrivateKey, gen uint32) []byte {
	t.Helper()
	m := &store.MailMeta{Version: version, MailID: id, Received: ms, MailHash: hash, Size: 1, Folder: folder, Recipients: []string{"a@example.org"}, Subject: "forged"}
	plain, _ := m.Encode()
	extra, _ := m.SignedExtra(f.mbx, e.Number)
	meta, err := envelope.Seal(envelope.Header{Kind: envelope.KindMeta, MailboxID: f.mbx, Epoch: e.Number, FileID: id, Created: ms, Version: version},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: f.mbx, Gen: e.Number, PublicKey: e.MetaPub}}, plain,
		&envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerIngest, Gen: gen, Key: key, Extra: extra}})
	if err != nil {
		t.Fatal(err)
	}
	store.MkdirAll(f.env.Store.MailDir(f.mbx, folder))
	store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, folder, id), meta)
	return meta
}

func warned(env *testenv.Env, part string) bool {
	for _, w := range env.Warnings.Take() {
		if strings.Contains(w, part) {
			return true
		}
	}
	return false
}

func TestForgedMailWithIngestKeyIsAccepted(t *testing.T) {
	// The forge helper itself produces valid mails with the real key, so
	// that the following rejections are caused by the manipulation alone.
	f := newFixture(t)
	e, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	id := f.forge(t, e, testenv.Start.Add(time.Minute), "hello", 1, f.env.IngestKey, 1)
	_, content, err := f.u.Client.Read(f.mbx, id)
	if err != nil || string(content) != "hello" {
		t.Fatal(err)
	}
}

func TestMailFileSwapped(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "first")
	b := f.deliver(t, "b", "second")
	inbox := f.inbox(t)
	da, _ := f.env.Store.ReadMail(f.mbx, inbox, a.ID)
	// Mail file of b replaced by the mail file of a; metadata unchanged.
	store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, b.ID), da)
	f.env.Warnings.Take()
	if _, _, err := f.u.Client.Read(f.mbx, b.ID); !errors.Is(err, client.ErrMailHash) {
		t.Fatalf("swapped mail file: %v", err)
	}
	if !warned(f.env, "weicht von ihren signierten Metadaten ab") {
		t.Fatal("no warning")
	}
	// A new mail file for the same mailbox, epoch and ID, encrypted by
	// the attacker with the public content key: the hash differs.
	e, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	evil, _ := envelope.Seal(envelope.Header{Kind: envelope.KindMail, MailboxID: f.mbx, Epoch: 1, FileID: b.ID, Created: b.Meta.Received},
		[]envelope.Recipient{{Type: envelope.RecipientEpochContent, ID: f.mbx, Gen: 1, PublicKey: e.ContentPub}}, []byte("evil"), nil)
	store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, b.ID), evil)
	if _, _, err := f.u.Client.Read(f.mbx, b.ID); !errors.Is(err, client.ErrMailHash) {
		t.Fatalf("replaced mail file: %v", err)
	}
	// A recipient entry of the mail changed: the hash covers it (S06).
	db, _ := f.env.Store.ReadMail(f.mbx, inbox, a.ID)
	db[60] ^= 1
	store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, a.ID), db)
	if _, _, err := f.u.Client.Read(f.mbx, a.ID); !errors.Is(err, client.ErrMailHash) {
		t.Fatalf("changed mail file: %v", err)
	}
	// Mail and metadata swapped together between two names.
	c := f.deliver(t, "c", "third")
	d := f.deliver(t, "d", "fourth")
	mc, _ := f.env.Store.ReadMeta(f.mbx, inbox, c.ID)
	fc, _ := f.env.Store.ReadMail(f.mbx, inbox, c.ID)
	store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, inbox, d.ID), mc)
	store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, d.ID), fc)
	if _, _, err := f.u.Client.Read(f.mbx, d.ID); !errors.Is(err, client.ErrMismatch) {
		t.Fatalf("swapped pair: %v", err)
	}
	// The intact mail is still readable.
	if _, content, err := f.u.Client.Read(f.mbx, c.ID); err != nil || !bytes.Contains(content, []byte("third")) {
		t.Fatal(err)
	}
}

func TestOlderMetadataVersion(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	inbox := f.inbox(t)
	v1, _ := f.env.Store.ReadMeta(f.mbx, inbox, a.ID)
	e, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	// Version 2 (here signed by the ingest key as a stand-in for a flag
	// change) is seen first.
	f.writeMeta(t, e, a.ID, inbox, a.Meta.Received, a.Meta.MailHash, 2, f.env.IngestKey, 1)
	list, _ := f.u.Client.List(f.mbx, store.ID{})
	if len(list) != 1 || list[0].Meta.Version != 2 {
		t.Fatal("version 2 not seen")
	}
	// Then the server puts version 1 back.
	store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, inbox, a.ID), v1)
	f.env.Warnings.Take()
	if _, _, err := f.u.Client.Read(f.mbx, a.ID); !errors.Is(err, client.ErrReplay) {
		t.Fatalf("older version: %v", err)
	}
	list, _ = f.u.Client.List(f.mbx, store.ID{})
	if len(list) != 0 || !warned(f.env, "older metadata version") {
		t.Fatal("older version listed or not warned")
	}
	// The memory survives a restart of the client.
	c := f.env.Reopen(f.u)
	if _, _, err := c.Read(f.mbx, a.ID); !errors.Is(err, client.ErrReplay) {
		t.Fatalf("after restart: %v", err)
	}
}

func TestEpochRecRemovedReplacedAndRollback(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x") // epoch 1; the client has seen epochs 1-4
	other := f.env.Mailbox(f.u, "B", "b@example.org")

	// epoch.rec of epoch 3 removed.
	p3 := f.env.Store.EpochFile(f.mbx, 3)
	orig3, _ := os.ReadFile(p3)
	os.Remove(p3)
	f.env.Warnings.Take()
	if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("removed epoch: %v", err)
	}
	if !warned(f.env, "Epochenkette") {
		t.Fatal("no warning for a removed epoch")
	}
	// Mails of the epochs before the break are still checked and listed.
	if _, _, err := f.u.Client.Read(f.mbx, a.ID); err != nil {
		t.Fatalf("epoch 1 mail: %v", err)
	}
	os.WriteFile(p3, orig3, 0o600)

	// epoch.rec of epoch 2 replaced by epoch 2 of another mailbox.
	p2 := f.env.Store.EpochFile(f.mbx, 2)
	orig2, _ := os.ReadFile(p2)
	foreign, _ := os.ReadFile(f.env.Store.EpochFile(other, 2))
	os.WriteFile(p2, foreign, 0o600)
	if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("foreign epoch: %v", err)
	}
	// Replaced by a validly signed epoch 2 that does not link (another
	// user signs a fresh one): rejected.
	bob := f.env.NewUser("bob")
	ep, _ := store.DecodeEpoch(orig2)
	ep.SignerID, ep.SignerGen = bob.ID, 1
	ks, _ := keys.OpenKeystore(mustRead(t, filepath.Join(bob.Dir, "keystore")), testenv.Passphrase)
	ep.Sign(ks.Identity)
	ks.Zero()
	forged, _ := ep.Encode()
	os.WriteFile(p2, forged, 0o600)
	if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("epoch signed by a non-member: %v", err)
	}
	os.WriteFile(p2, orig2, 0o600)
	if _, err := f.u.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatalf("restored chain: %v", err)
	}

	// mailbox.rec reset to epoch 1.
	m, _ := f.env.Store.ReadMailbox(f.mbx)
	old := *m
	old.Epoch = 1
	f.env.Store.WriteMailbox(&old)
	f.env.Warnings.Take()
	if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, client.ErrRollback) {
		t.Fatalf("reset mailbox.rec: %v", err)
	}
	if !warned(f.env, "zeigt auf Epoche 1") {
		t.Fatal("no warning for a reset mailbox.rec")
	}
	// Sync refuses to extend a chain that did not verify.
	if err := f.u.Client.Sync(); err == nil {
		t.Fatal("sync on a reset mailbox.rec")
	}
	f.env.Store.WriteMailbox(m)

	// The highest epoch seen (4) is replaced and the head reset to 3: both
	// the rollback and the missing epoch are reported.
	p4 := f.env.Store.EpochFile(f.mbx, 4)
	os.Remove(p4)
	three := *m
	three.Epoch = 3
	f.env.Store.WriteMailbox(&three)
	f.env.Warnings.Take()
	if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, client.ErrRollback) {
		t.Fatalf("removed head: %v", err)
	}
	if !warned(f.env, "Epoche 4") {
		t.Fatal("no warning for the removed head epoch")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMailForOlderEpochAfterNewBegan(t *testing.T) {
	f := newFixture(t)
	e1, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	e2, _, _ := f.env.Store.ReadEpoch(f.mbx, 2)
	// Received after epoch 2 began, but encrypted for epoch 1.
	late := time.UnixMilli(e2.Begin).Add(time.Hour)
	id := f.forge(t, e1, late, "stale", 1, f.env.IngestKey, 1)
	f.env.Warnings.Take()
	if _, _, err := f.u.Client.Read(f.mbx, id); !errors.Is(err, client.ErrStaleEpoch) {
		t.Fatalf("stale epoch: %v", err)
	}
	if !warned(f.env, "had begun") {
		t.Fatal("no warning")
	}
	// Received before its epoch began.
	early := f.forge(t, e2, time.UnixMilli(e2.Begin).Add(-time.Hour), "early", 1, f.env.IngestKey, 1)
	if _, _, err := f.u.Client.Read(f.mbx, early); !errors.Is(err, client.ErrStaleEpoch) {
		t.Fatalf("early: %v", err)
	}
	// An epoch beyond the chain.
	e9 := *e2
	e9.Number = 9
	if _, _, err := f.u.Client.Read(f.mbx, f.forge(t, &e9, late, "x", 1, f.env.IngestKey, 1)); !errors.Is(err, client.ErrEpoch) {
		t.Fatalf("unknown epoch: %v", err)
	}
	// In time for epoch 2: accepted.
	if _, _, err := f.u.Client.Read(f.mbx, f.forge(t, e2, late, "ok", 1, f.env.IngestKey, 1)); err != nil {
		t.Fatal(err)
	}
}

func TestUncertifiedIngestKey(t *testing.T) {
	f := newFixture(t)
	e1, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	at := testenv.Start.Add(time.Minute)
	rogue := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	// Signed with a key that claims generation 1: signature invalid.
	id := f.forge(t, e1, at, "rogue", 1, rogue, 1)
	f.env.Warnings.Take()
	if _, _, err := f.u.Client.Read(f.mbx, id); !errors.Is(err, client.ErrSigner) {
		t.Fatalf("rogue key as generation 1: %v", err)
	}
	if !warned(f.env, "nicht geöffnet") {
		t.Fatal("no warning")
	}
	// Generation 2 without certificate.
	if _, _, err := f.u.Client.Read(f.mbx, f.forge(t, e1, at, "x", 1, rogue, 2)); !errors.Is(err, client.ErrPlatform) {
		t.Fatalf("no certificate: %v", err)
	}
	// Generation 3 with a certificate signed by another identity.
	var seed keys.Seed
	seed[0] = 99
	p := keys.DerivePlatform(&seed)
	otherID, _ := p.IdentityKey(1)
	cert, _ := keys.NewPlatformCert(otherID, 1, keys.RoleIngest, 3, rogue.Public().(ed25519.PublicKey), 0)
	cd, _ := cert.Encode()
	f.env.Store.WritePlatformFile("ingest-3.cert", cd)
	f.env.Store.WritePlatformFile("ingest-3.pub", rogue.Public().(ed25519.PublicKey))
	if _, _, err := f.u.Client.Read(f.mbx, f.forge(t, e1, at, "x", 1, rogue, 3)); !errors.Is(err, client.ErrPlatform) {
		t.Fatalf("certificate of another identity: %v", err)
	}
	// Generation 4 certified by an unknown identity generation.
	cert4, _ := keys.NewPlatformCert(otherID, 2, keys.RoleIngest, 4, rogue.Public().(ed25519.PublicKey), 0)
	cd4, _ := cert4.Encode()
	f.env.Store.WritePlatformFile("ingest-4.cert", cd4)
	f.env.Store.WritePlatformFile("ingest-4.pub", rogue.Public().(ed25519.PublicKey))
	if _, _, err := f.u.Client.Read(f.mbx, f.forge(t, e1, at, "x", 1, rogue, 4)); !errors.Is(err, client.ErrPlatform) {
		t.Fatalf("certificate of identity generation 2: %v", err)
	}
	// Received before the certificate was valid.
	if _, _, err := f.u.Client.Read(f.mbx, f.forge(t, e1, testenv.Start.Add(-2*time.Hour), "x", 1, f.env.IngestKey, 1)); err == nil {
		t.Fatal("mail before the certificate's valid_from")
	}
}

func x25519(t *testing.T) *ecdhPriv {
	k, err := ecdhGen()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestInboxPointerRedirected: mailbox.rec is not signed; pointing its
// inbox elsewhere must not hide the inbox silently.
func TestInboxPointerRedirected(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	m, _ := f.env.Store.ReadMailbox(f.mbx)
	bad := *m
	bad.Inbox = store.ID{7, 7}
	f.env.Store.WriteMailbox(&bad)
	f.env.Warnings.Take()
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err != nil || len(list) != 1 || list[0].ID != a.ID {
		t.Fatalf("inbox from folders.gml: %v %d", err, len(list))
	}
	if !warned(f.env, "anderen Posteingang") {
		t.Fatal("no warning for a redirected inbox")
	}
	// Mails the server then delivers into the fake folder are reported.
	f.deliver2(t)
	f.env.Warnings.Take()
	f.u.Client.List(f.mbx, store.ID{})
	if !warned(f.env, "steht nicht in folders.gml") {
		t.Fatal("no warning for an unknown folder")
	}
	// folders.gml without an inbox is rejected.
	f.env.Store.WriteMailbox(m)
	e1, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	_ = e1
}

func (f *fixture) deliver2(t *testing.T) {
	t.Helper()
	d, err := f.in.Begin(smtpd.Session{ID: "t"}, "s@x.example", []string{"a@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	d.Write([]byte("Subject: hidden\r\n\r\nx\r\n"))
	if err := d.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestMetaHeaderVersionDiffersFromContent: the header says version 2, the
// encrypted metadata say version 1, and the signature (over the header
// values and the extra of the content) is valid. The client must compare
// the version inside the metadata with the header (section 7) and refuse
// the mail, with a warning that carries no content.
func TestMetaHeaderVersionDiffersFromContent(t *testing.T) {
	f := newFixture(t)
	e, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	id, _ := store.NewID(nil)
	inbox := f.inbox(t)
	ms := testenv.Start.Add(time.Minute).UnixMilli()
	mail, err := envelope.Seal(envelope.Header{Kind: envelope.KindMail, MailboxID: f.mbx, Epoch: e.Number, FileID: id, Created: ms},
		[]envelope.Recipient{{Type: envelope.RecipientEpochContent, ID: f.mbx, Gen: e.Number, PublicKey: e.ContentPub}}, []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "version-mismatch-subject"
	m := &store.MailMeta{Version: 1, MailID: id, Received: ms, MailHash: sha256.Sum256(mail), Size: 1, Folder: inbox,
		Recipients: []string{"a@example.org"}, Subject: secret}
	plain, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	extra, err := m.SignedExtra(f.mbx, e.Number)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := envelope.Seal(envelope.Header{Kind: envelope.KindMeta, MailboxID: f.mbx, Epoch: e.Number, FileID: id, Created: ms, Version: 2},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: f.mbx, Gen: e.Number, PublicKey: e.MetaPub}}, plain,
		&envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerIngest, Gen: 1, Key: f.env.IngestKey, Extra: extra}})
	if err != nil {
		t.Fatal(err)
	}
	// The forged file is validly signed: the mismatch alone must reject it.
	pf, err := envelope.Parse(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := pf.VerifySignature(f.env.IngestKey.Public().(ed25519.PublicKey), extra); err != nil {
		t.Fatalf("forged metadata not validly signed: %v", err)
	}
	store.MkdirAll(f.env.Store.MailDir(f.mbx, inbox))
	store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, inbox, id), meta)
	store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, id), mail)

	f.env.Warnings.Take()
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range list {
		if l.ID == id {
			t.Fatal("mail with header version 2 and content version 1 listed")
		}
	}
	warnings := f.env.Warnings.Take()
	found := false
	for _, w := range warnings {
		if strings.Contains(w, secret) {
			t.Fatalf("warning carries metadata content: %q", w)
		}
		if strings.Contains(w, id.String()) && strings.Contains(w, "wird nicht verarbeitet") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no warning for the version mismatch: %q", warnings)
	}
	if _, _, err := f.u.Client.Read(f.mbx, id); !errors.Is(err, client.ErrMismatch) {
		t.Fatalf("version mismatch: %v", err)
	}
	if warned(f.env, secret) {
		t.Fatal("warning of Read carries metadata content")
	}
}
