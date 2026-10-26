package client

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// ingestKeyFor returns the ingest key of generation gen (2.3, section 7):
// ingest-<gen>.cert signed by the pinned platform identity and present in
// the log.
func (c *Client) ingestKeyFor(gen uint32) (ingestKey, error) {
	c.mu.Lock()
	k, ok := c.ingest[gen]
	c.mu.Unlock()
	if ok {
		return k, nil
	}
	cert, err := c.st.ReadPlatformCert(keys.RoleIngest, gen)
	if err != nil {
		return ingestKey{}, fmt.Errorf("%w: ingest-%d.cert: %v", ErrPlatform, gen, err)
	}
	if cert.IdentityGen != c.cfg.Pin.Gen {
		// Successions of the platform identity (identity-<gen>.succ) are
		// not part of phase 1; only the pinned generation is trusted.
		return ingestKey{}, fmt.Errorf("%w: issued by identity generation %d", ErrPlatform, cert.IdentityGen)
	}
	if err := cert.Verify(c.cfg.Pin.Pub); err != nil {
		return ingestKey{}, fmt.Errorf("%w: %v", ErrPlatform, err)
	}
	name := store.PlatformFileName("ingest", gen, "cert")
	raw, err := c.st.ReadPlatformFile(name)
	if err != nil {
		return ingestKey{}, fmt.Errorf("%w: %v", ErrPlatform, err)
	}
	if err := c.cfg.Log.CheckPlatform(name, raw); err != nil {
		return ingestKey{}, err
	}
	k = ingestKey{pub: cert.Pub, validFrom: cert.ValidFrom}
	c.mu.Lock()
	c.ingest[gen] = k
	c.mu.Unlock()
	return k, nil
}

// Mail is the checked metadata of one mail.
type Mail struct {
	ID    store.ID
	Epoch uint32
	Meta  *store.MailMeta
}

// checkMeta opens and checks <mail-id>.meta.gml (section 7). It returns
// the metadata only if every check passed:
//   - kind meta, mailbox, file ID and folder as named by its location,
//   - epoch in the verified chain, suite of the epoch,
//   - signed by a certified ingest key valid at the time of receipt
//     (phase 1 accepts only ingest signatures),
//   - signature over the file and the fields of section 7,
//   - receipt time equal to the creation time of the file,
//   - the epoch rule of 2.4: no newer epoch had begun at receipt,
//   - the address assignment at receipt in the log,
//   - version not older than the highest seen.
func (c *Client) checkMeta(ch *chain, folder, id store.ID) (*Mail, error) {
	mbx := ch.mailbox.ID
	data, err := c.st.ReadMeta(mbx, folder, id)
	if err != nil {
		return nil, fmt.Errorf("%w: metadata: %v", ErrNotFound, err)
	}
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, err
	}
	h := f.Header
	if h.Kind != envelope.KindMeta || h.MailboxID != mbx || h.FileID != id {
		return nil, fmt.Errorf("%w: metadata header", ErrMismatch)
	}
	e := ch.epoch(h.Epoch)
	if e == nil {
		return nil, fmt.Errorf("%w: epoch %d", ErrEpoch, h.Epoch)
	}
	if f.Suite != e.Suite {
		return nil, envelope.ErrSuite
	}
	if f.Trailer == nil {
		return nil, fmt.Errorf("%w: metadata without signature", ErrSigner)
	}
	if f.Trailer.Signer.Type != envelope.SignerIngest || f.Trailer.Signer.ID != ([16]byte{}) {
		// User-signed metadata (flag changes, section 7) come with phase 2.
		return nil, fmt.Errorf("%w: metadata not signed by the ingest key", ErrSigner)
	}
	ik, err := c.ingestKeyFor(f.Trailer.Signer.Gen)
	if err != nil {
		return nil, err
	}
	k, err := c.keysFor(e)
	if err != nil {
		return nil, err
	}
	plain, err := f.Decrypt(envelope.RecipientKey{Type: envelope.RecipientEpochMeta, ID: mbx, Gen: e.Number, PrivateKey: k.Meta})
	if err != nil {
		return nil, err
	}
	m, err := store.DecodeMailMeta(plain)
	keys.Wipe(plain)
	if err != nil {
		return nil, err
	}
	// Nothing of m is used before the signature over it is verified.
	extra, err := m.SignedExtra(mbx, e.Number)
	if err != nil {
		return nil, err
	}
	if err := f.VerifySignature(ik.pub, extra); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigner, err)
	}
	if m.MailID != id || m.Folder != folder || m.Received != h.Created {
		return nil, fmt.Errorf("%w: metadata fields", ErrMismatch)
	}
	if m.Received < ik.validFrom {
		return nil, fmt.Errorf("%w: ingest key not yet valid at receipt", ErrPlatform)
	}
	if e.Begin > m.Received {
		return nil, fmt.Errorf("%w: epoch %d began after the receipt", ErrStaleEpoch, e.Number)
	}
	if next := ch.epoch(e.Number + 1); next != nil && next.Begin <= m.Received {
		return nil, fmt.Errorf("%w: epoch %d had begun", ErrStaleEpoch, next.Number)
	}
	for _, a := range m.Recipients {
		if err := c.cfg.Log.CheckAddress(a, mbx, m.Received); err != nil {
			return nil, err
		}
	}
	ms := c.mailboxState(mbx)
	if seen := ms.Versions[id.String()]; m.Version < seen {
		return nil, fmt.Errorf("%w: version %d, seen %d", ErrReplay, m.Version, seen)
	} else if m.Version > seen {
		ms.Versions[id.String()] = m.Version
		if err := c.save(); err != nil {
			return nil, err
		}
	}
	return &Mail{ID: id, Epoch: e.Number, Meta: m}, nil
}

// List returns the checked metadata of the mails in a folder (the inbox
// if folder is zero), sorted by receipt. Mails that fail a check are not
// listed; a warning names each.
func (c *Client) List(mbx, folder store.ID) ([]*Mail, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, err
	}
	if folder.IsZero() {
		folder = ch.mailbox.Inbox
	}
	ids, err := c.st.ListMails(mbx, folder)
	if err != nil {
		return nil, err
	}
	var out []*Mail
	for _, id := range ids {
		m, err := c.checkMeta(ch, folder, id)
		if err != nil {
			c.warn("WARNUNG: Mail %s wird nicht verarbeitet: %v", id, err)
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Meta.Received != out[j].Meta.Received {
			return out[i].Meta.Received < out[j].Meta.Received
		}
		return string(out[i].ID[:]) < string(out[j].ID[:])
	})
	return out, ch.err
}

// findFolder returns the folder holding mail id.
func (c *Client) findFolder(mbx, id store.ID) (store.ID, error) {
	folders, err := c.st.ListFolders(mbx)
	if err != nil {
		return store.ID{}, err
	}
	for _, f := range folders {
		ids, err := c.st.ListMails(mbx, f)
		if err != nil {
			return store.ID{}, err
		}
		for _, x := range ids {
			if x == id {
				return f, nil
			}
		}
	}
	return store.ID{}, ErrNotFound
}

// Read returns the content of mail id (section 7, "Prüfung beim Öffnen
// einer Mail"): the metadata are checked first, then the SHA-256 of the
// whole mail file is compared with the signed value, then mailbox, epoch
// and file ID of the mail header with the metadata. Only then is the mail
// decrypted; content is returned only after its last block authenticated.
func (c *Client) Read(mbx, id store.ID) (*Mail, []byte, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, nil, err
	}
	folder, err := c.findFolder(mbx, id)
	if err != nil {
		return nil, nil, err
	}
	m, err := c.checkMeta(ch, folder, id)
	if err != nil {
		c.warn("WARNUNG: Mail %s wird nicht geöffnet: %v", id, err)
		return nil, nil, err
	}
	data, err := c.st.ReadMail(mbx, folder, id)
	if err != nil {
		return nil, nil, err
	}
	if sha256.Sum256(data) != m.Meta.MailHash {
		c.warn("WARNUNG: Mail %s weicht von ihren signierten Metadaten ab und wird nicht geöffnet.", id)
		return nil, nil, ErrMailHash
	}
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, nil, err
	}
	h := f.Header
	if h.Kind != envelope.KindMail || h.MailboxID != mbx || h.Epoch != m.Epoch || h.FileID != id || f.Trailer != nil {
		c.warn("WARNUNG: Kopf der Mail %s passt nicht zu den Metadaten.", id)
		return nil, nil, ErrMismatch
	}
	e := ch.epoch(m.Epoch)
	if f.Suite != e.Suite {
		return nil, nil, envelope.ErrSuite
	}
	k, err := c.keysFor(e)
	if err != nil {
		return nil, nil, err
	}
	content, err := f.Decrypt(envelope.RecipientKey{Type: envelope.RecipientEpochContent, ID: mbx, Gen: e.Number, PrivateKey: k.Content})
	if err != nil {
		c.warn("WARNUNG: Mail %s lässt sich nicht entschlüsseln: %v", id, err)
		return nil, nil, err
	}
	return m, content, nil
}

var (
	_ = errors.Is
	_ ed25519.PublicKey
)

// OpenPending opens a term list or marker pending/<n>/<file>.gml (5.2
// step 3, 5.4): signed by a certified ingest key, kind pending, mailbox,
// epoch and file ID as named by its location, epoch in the verified
// chain. Indexing itself (6.2) is phase 5.
func (c *Client) OpenPending(mbx store.ID, epoch uint32, file store.ID) (*store.Pending, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, err
	}
	e := ch.epoch(epoch)
	if e == nil {
		return nil, ErrEpoch
	}
	data, err := c.st.ReadPending(mbx, epoch, file)
	if err != nil {
		return nil, err
	}
	k, err := c.keysFor(e)
	if err != nil {
		return nil, err
	}
	f, plain, err := envelope.Open(data, envelope.OpenOptions{
		ExpectedSuite: e.Suite,
		Key:           envelope.RecipientKey{Type: envelope.RecipientEpochMeta, ID: mbx, Gen: epoch, PrivateKey: k.Meta},
		ResolveSigner: func(ref envelope.SignerRef) (ed25519.PublicKey, error) {
			if ref.Type != envelope.SignerIngest || ref.ID != ([16]byte{}) {
				return nil, ErrSigner
			}
			ik, err := c.ingestKeyFor(ref.Gen)
			return ik.pub, err
		},
	})
	if err != nil {
		c.warn("WARNUNG: Begriffsliste %s wird nicht verarbeitet: %v", file, err)
		return nil, err
	}
	defer keys.Wipe(plain)
	if f.Header.Kind != envelope.KindPending || f.Header.MailboxID != mbx || f.Header.Epoch != epoch || f.Header.FileID != file {
		return nil, ErrMismatch
	}
	p, err := store.DecodePending(plain)
	if err != nil {
		return nil, err
	}
	if p.MailboxID != mbx || p.Epoch != epoch {
		return nil, ErrMismatch
	}
	return p, nil
}
