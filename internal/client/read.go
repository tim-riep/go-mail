package client

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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
	// TODO(phase3-translog): certificate in the log, generation not compromised (2.3, 7).
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
	// file is the SHA-256 of the metadata file that was checked; a flag
	// change replaces exactly this file (K4 point 1).
	file [32]byte
}

// checkMeta opens and checks <mail-id>.meta.gml (section 7). It returns
// the metadata only if every check passed:
//   - kind meta, mailbox, file ID and folder as named by its location,
//   - epoch in the verified chain and not discarded, suite of the epoch,
//   - version 1 signed by a certified ingest key valid at the time of
//     receipt; a later version (a flag change, section 7, K4) signed by a
//     user member (kind 1) of the epoch with the current generation of
//     its user.rec (TODO(S13): strictest reading, as for wraps). A user
//     signature on version 1 and an ingest signature on a later version
//     are rejected,
//   - signature over the file and the fields of section 7 (meta-signed),
//   - receipt time equal to the creation time of the file and version
//     equal to the header,
//   - the epoch rule of 2.4 (checkEpochRule): the epoch had begun at
//     receipt and no newer epoch that is not discarded had begun,
//   - the address assignment at receipt in the log,
//   - version not older than the highest seen, and epoch, receipt time
//     and mail hash equal to those remembered for the mail (the first
//     version seen).
//
// The highest version and the memo are noted in the state in memory
// only; the caller saves them once with saveSeen before it returns
// anything that depends on them (task 09, addendum).
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
	e, err := ch.usable(h.Epoch)
	if err != nil {
		return nil, err
	}
	if f.Suite != e.Suite {
		return nil, envelope.ErrSuite
	}
	if f.Trailer == nil {
		return nil, fmt.Errorf("%w: metadata without signature", ErrSigner)
	}
	var pub ed25519.PublicKey
	validFrom, ingest := int64(0), false
	switch ref := f.Trailer.Signer; {
	case ref.Type == envelope.SignerIngest && ref.ID == ([16]byte{}):
		if h.Version != 1 {
			return nil, fmt.Errorf("%w: ingest signature on metadata version %d", ErrSigner, h.Version)
		}
		ik, err := c.ingestKeyFor(ref.Gen)
		if err != nil {
			return nil, err
		}
		pub, validFrom, ingest = ik.pub, ik.validFrom, true
	case ref.Type == envelope.SignerUser:
		if h.Version < 2 {
			return nil, fmt.Errorf("%w: user signature on metadata version %d", ErrSigner, h.Version)
		}
		if _, ok := e.Member(store.ID(ref.ID)); !ok {
			return nil, fmt.Errorf("%w: metadata signed by a user who is not a user member of epoch %d", ErrSigner, e.Number)
		}
		if pub, err = c.userKey(store.ID(ref.ID), ref.Gen, nil); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: metadata signer", ErrSigner)
	}
	k, err := c.keysFor(ch, e)
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
	if err := f.VerifySignature(pub, extra); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigner, err)
	}
	if m.MailID != id || m.Folder != folder || m.Received != h.Created || m.Version != h.Version {
		return nil, fmt.Errorf("%w: metadata fields", ErrMismatch)
	}
	if ingest && m.Received < validFrom {
		return nil, fmt.Errorf("%w: ingest key not yet valid at receipt", ErrPlatform)
	}
	if err := c.checkEpochRule(ch, e, m.Received); err != nil {
		return nil, err
	}
	for _, a := range m.Recipients {
		// TODO(phase3-translog): address assigned to this mailbox at receipt (2.3).
		if err := c.cfg.Log.CheckAddress(a, mbx, m.Received); err != nil {
			return nil, err
		}
	}
	if err := c.noteVersion(mbx, e.Number, m); err != nil {
		return nil, err
	}
	return &Mail{ID: id, Epoch: e.Number, Meta: m, file: sha256.Sum256(data)}, nil
}

// noteVersion applies the rules against replay (section 7) to checked
// metadata m of epoch n and notes them in the state in memory: the
// version must not be older than the highest seen, and epoch, receipt
// time (created) and mail hash must equal those remembered for the mail.
// A higher version and the first memo set c.dirty; saveSeen writes them.
func (c *Client) noteVersion(mbx store.ID, n uint32, m *store.MailMeta) error {
	ms := c.mailboxState(mbx)
	key := m.MailID.String()
	seen := ms.Versions[key]
	if m.Version < seen {
		return fmt.Errorf("%w: version %d, seen %d", ErrReplay, m.Version, seen)
	}
	hash := hex.EncodeToString(m.MailHash[:])
	if ms.Mails == nil {
		ms.Mails = map[string]*mailMemo{}
	}
	if memo := ms.Mails[key]; memo != nil {
		if memo.Epoch != 0 && memo.Epoch != n || memo.Received != m.Received || memo.MailHash != hash {
			return fmt.Errorf("%w: version %d", ErrMetaChanged, m.Version)
		}
	} else {
		ms.Mails[key] = &mailMemo{Epoch: n, Received: m.Received, MailHash: hash}
		c.dirty = true
	}
	if m.Version > seen {
		ms.Versions[key] = m.Version
		c.dirty = true
	}
	return nil
}

// saveSeen saves the versions and memos noted since the last save, once
// per operation (task 09, addendum: List used to write state.json with
// fsync for every new mail version, so the first List grew with the
// square of the number of mails).
//
// The rule, fail closed: an operation returns nothing that depends on a
// version it noted before that version is saved; if saving fails, the
// operation returns only the error. The noted values stay in memory and
// keep counting as seen (they never decrease, so a replay within the same
// process is still rejected), and the next successful save writes them
// with everything else. Nothing that was saved before is ever lost,
// because state.json is always written as a whole and atomically.
func (c *Client) saveSeen() error {
	if !c.dirty {
		return nil
	}
	if err := c.save(); err != nil {
		return err
	}
	c.dirty = false
	return nil
}

// List returns the checked metadata of the mails in a folder (the inbox
// if folder is zero), sorted by receipt. Mails that fail a check are not
// listed; a warning names each.
func (c *Client) List(mbx, folder store.ID) ([]*Mail, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, err
	}
	inbox, known, err := c.inbox(ch)
	if err != nil {
		return nil, err
	}
	if folder.IsZero() {
		folder = inbox
	}
	// Mails in folder directories that folders.gml does not name would
	// never be listed: say so.
	dirs, err := c.st.ListFolders(mbx)
	if err != nil {
		return nil, err
	}
	for _, d := range dirs {
		found := false
		for _, f := range known {
			found = found || f.ID == d
		}
		if !found {
			c.warn("WARNUNG: Ordner %s von %s steht nicht in folders.gml; seine Mails werden nicht angezeigt.", d, mbx)
		}
	}
	ids, err := c.st.ListMails(mbx, folder)
	if err != nil {
		return nil, err
	}
	var out []*Mail
	for _, id := range ids {
		m, err := c.checkMeta(ch, folder, id)
		if err != nil {
			c.warnRejected(id, "wird nicht verarbeitet", err)
			continue
		}
		out = append(out, m)
	}
	if err := c.saveSeen(); err != nil {
		return nil, err
	}
	sortMails(out)
	return out, ch.err
}

// sortMails sorts by receipt, then by ID.
func sortMails(out []*Mail) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Meta.Received != out[j].Meta.Received {
			return out[i].Meta.Received < out[j].Meta.Received
		}
		return string(out[i].ID[:]) < string(out[j].ID[:])
	})
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
		c.warnRejected(id, "wird nicht geöffnet", err)
		return nil, nil, err
	}
	if err := c.saveSeen(); err != nil {
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
	e, err := ch.usable(m.Epoch)
	if err != nil {
		return nil, nil, err
	}
	if f.Suite != e.Suite {
		return nil, nil, envelope.ErrSuite
	}
	k, err := c.keysFor(ch, e)
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

// warnRejected warns about a mail that failed a check. A mail for a
// replaced or discarded epoch is shown as not deliverable, to be requested
// again (K8). The warning names only the mail ID and the error, never
// content.
func (c *Client) warnRejected(id store.ID, what string, err error) {
	if errors.Is(err, ErrStaleEpoch) || errors.Is(err, ErrDiscardedEpoch) {
		c.warn("WARNUNG: Mail %s %s: nicht zustellbar, bitte erneut anfordern (%v)", id, what, err)
		return
	}
	c.warn("WARNUNG: Mail %s %s: %v", id, what, err)
}

// OpenPending opens a term list or marker pending/<n>/<file>.gml (5.2
// step 3, 5.4): signed by a certified ingest key, kind pending, mailbox,
// epoch and file ID as named by its location, epoch in the verified
// chain and not discarded, and the epoch rule of 2.4 (checkEpochRule) for
// its creation time, which the server sets to the receipt of the mails
// it covers. Index and Search process pending/ with the same checks.
func (c *Client) OpenPending(mbx store.ID, epoch uint32, file store.ID) (*store.Pending, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, err
	}
	e, err := ch.usable(epoch)
	if err != nil {
		c.warn("WARNUNG: Begriffsliste %s wird nicht verarbeitet: %v", file, err)
		return nil, err
	}
	return c.openPending(ch, e, file)
}

// openPending is OpenPending for epoch e of the verified chain ch.
func (c *Client) openPending(ch *chain, e *store.Epoch, file store.ID) (*store.Pending, error) {
	mbx, epoch := ch.mailbox.ID, e.Number
	data, err := c.st.ReadPending(mbx, epoch, file)
	if err != nil {
		return nil, err
	}
	k, err := c.keysFor(ch, e)
	if err != nil {
		return nil, err
	}
	var ik ingestKey
	f, plain, err := envelope.Open(data, envelope.OpenOptions{
		ExpectedSuite: e.Suite,
		Key:           envelope.RecipientKey{Type: envelope.RecipientEpochMeta, ID: mbx, Gen: epoch, PrivateKey: k.Meta},
		ResolveSigner: func(ref envelope.SignerRef) (ed25519.PublicKey, error) {
			if ref.Type != envelope.SignerIngest || ref.ID != ([16]byte{}) {
				return nil, ErrSigner
			}
			var err error
			ik, err = c.ingestKeyFor(ref.Gen)
			return ik.pub, err
		},
	})
	if err != nil {
		c.warn("WARNUNG: Begriffsliste %s wird nicht verarbeitet: %v", file, err)
		return nil, signerErr(err)
	}
	defer keys.Wipe(plain)
	reject := func(err error) (*store.Pending, error) {
		c.warn("WARNUNG: Begriffsliste %s wird nicht verarbeitet: %v", file, err)
		return nil, err
	}
	if f.Header.Kind != envelope.KindPending || f.Header.MailboxID != mbx || f.Header.Epoch != epoch || f.Header.FileID != file {
		return reject(ErrMismatch)
	}
	if f.Header.Created < ik.validFrom {
		return reject(fmt.Errorf("%w: ingest key not yet valid", ErrPlatform))
	}
	if err := c.checkEpochRule(ch, e, f.Header.Created); err != nil {
		return reject(err)
	}
	p, err := store.DecodePending(plain)
	if err != nil {
		return reject(err)
	}
	if p.MailboxID != mbx || p.Epoch != epoch {
		return reject(ErrMismatch)
	}
	return p, nil
}
