package client

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// Flags of a mail (section 7, K4): the field flags of the metadata is a
// set, one bit per flag.
//
// TODO(ask): neither the specification nor DECISIONS assign names to the
// bits of the signed field flags. This is the strictest reading: exactly
// these five names (the system flags of IMAP), every other name is
// rejected, and bits a client does not know are kept unchanged.
var flagBits = map[string]uint32{
	"seen":     1 << 0,
	"answered": 1 << 1,
	"flagged":  1 << 2,
	"deleted":  1 << 3,
	"draft":    1 << 4,
}

// maxFlagAttempts bounds how often a flag change is applied again to a
// newer version written by another client (K4 point 2).
const maxFlagAttempts = 5

// flagsHook is called by tests between preparing a new metadata version
// and writing it, to let another client change the mail first. It is nil
// in production.
var flagsHook func()

// resignMetaHook is called by tests in resignMeta before the new version
// is sealed and written, to remove or change the file. It is nil in
// production.
var resignMetaHook func()

// FlagNames returns the names of the known flags set in flags, sorted.
func FlagNames(flags uint32) []string {
	var out []string
	for name, bit := range flagBits {
		if flags&bit != 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func flagMask(names []string) (uint32, error) {
	var m uint32
	for _, n := range names {
		bit, ok := flagBits[n]
		if !ok {
			return 0, fmt.Errorf("%w: unknown flag", ErrArgument)
		}
		m |= bit
	}
	return m, nil
}

// errStale reports that the metadata file changed between reading and
// writing; the change is applied again to the newer version.
var errStale = errors.New("client: metadata changed meanwhile")

// SetFlags sets and clears flags of mail id (section 7, K4) and returns
// the metadata as written. The current metadata are read and checked like
// in Read; the flags are changed as a set (only the flags named in set or
// clear); the new version has version+1, the same receipt time (created)
// and mail hash, and is sealed for the meta key of the mail's epoch and
// signed with this user's identity over meta-signed. It replaces the
// metadata file under the mailbox lock only if the file there is still
// the one that was read, so its version is exactly one less (K4 point 1);
// otherwise the newer version is read and the change applied to it again,
// at most maxFlagAttempts times (K4 point 2 and 3). Only a user member of
// the mail's epoch changes flags: readers accept user-signed metadata only
// from them. Nothing is written if the flags do not change.
func (c *Client) SetFlags(mbx, id store.ID, set, clear []string) (*Mail, error) {
	if err := c.open(); err != nil {
		return nil, err
	}
	if err := c.writable(); err != nil {
		return nil, err
	}
	on, err := flagMask(set)
	if err != nil {
		return nil, err
	}
	off, err := flagMask(clear)
	if err != nil {
		return nil, err
	}
	if on&off != 0 {
		return nil, fmt.Errorf("%w: a flag both set and cleared", ErrArgument)
	}
	for attempt := 1; attempt <= maxFlagAttempts; attempt++ {
		m, err := c.setFlags(mbx, id, on, off)
		if !errors.Is(err, errStale) {
			return m, err
		}
	}
	return nil, fmt.Errorf("%w: mail %s, %d attempts", ErrConflict, id, maxFlagAttempts)
}

// setFlags is one attempt of SetFlags.
func (c *Client) setFlags(mbx, id store.ID, on, off uint32) (*Mail, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, err
	}
	if ch.err != nil {
		return nil, ch.err
	}
	folder, err := c.findFolder(mbx, id)
	if err != nil {
		return nil, err
	}
	cur, err := c.checkMeta(ch, folder, id)
	if err != nil {
		c.warnRejected(id, "wird nicht geändert", err)
		return nil, err
	}
	if err := c.saveSeen(); err != nil {
		return nil, err
	}
	e, err := ch.usable(cur.Epoch)
	if err != nil {
		return nil, err
	}
	if !c.isUserMember(e) {
		return nil, fmt.Errorf("%w: not a user member of epoch %d of %s", ErrNotMember, e.Number, mbx)
	}
	flags := cur.Meta.Flags&^off | on
	if flags == cur.Meta.Flags {
		return cur, nil
	}
	if cur.Meta.Version == math.MaxUint32 {
		return nil, fmt.Errorf("%w: version of the metadata exhausted", ErrArgument)
	}
	next := *cur.Meta
	next.Version, next.Flags = cur.Meta.Version+1, flags
	data, err := c.sealMetaVersion(mbx, e, &next)
	if err != nil {
		return nil, err
	}
	if flagsHook != nil {
		flagsHook()
	}
	if err := c.replaceMeta(mbx, folder, id, cur.file, data); err != nil {
		return nil, err
	}
	m := &Mail{ID: id, Epoch: e.Number, Meta: &next, file: sha256.Sum256(data)}
	if err := c.noteVersion(mbx, e.Number, &next, m.file); err != nil {
		return nil, err
	}
	// The new file is signed by this user's current generation: its check
	// record proves that this client verified it (2.2 rule 4).
	c.noteCheckedLater(mbx, metaMemo(id), data, c.me, c.ks.Generation)
	return m, c.saveSeen()
}

// sealMetaVersion seals metadata next of epoch e as a new metadata file
// (section 7, K4): created is the receipt time, the version is that of
// next, sealed for the meta key of e and signed with this user's identity
// over meta-signed.
func (c *Client) sealMetaVersion(mbx store.ID, e *store.Epoch, next *store.MailMeta) ([]byte, error) {
	plain, err := next.Encode()
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(plain)
	extra, err := next.SignedExtra(mbx, e.Number)
	if err != nil {
		return nil, err
	}
	signer := c.signer()
	signer.Extra = extra
	return envelope.Seal(
		envelope.Header{Kind: envelope.KindMeta, MailboxID: mbx, Epoch: e.Number, FileID: next.MailID, Created: next.Received, Version: next.Version},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: mbx, Gen: e.Number, PublicKey: e.MetaPub}},
		plain, &envelope.SealOptions{Signer: signer})
}

// replaceMeta replaces the metadata file of mail id with data under the
// mailbox lock (withMailboxLock: taken here unless the running change
// holds it) if it is still the file with SHA-256 old (K4 point 1);
// otherwise errStale.
func (c *Client) replaceMeta(mbx, folder, id store.ID, old [32]byte, data []byte) error {
	return c.withMailboxLock(mbx, func() error {
		now, err := c.st.ReadMeta(mbx, folder, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("%w: metadata: %v", ErrNotFound, err)
			}
			return err
		}
		if sha256.Sum256(now) != old {
			return errStale
		}
		return store.WriteFileAtomic(c.st.MetaFile(mbx, folder, id), data)
	})
}

// resignMeta signs the metadata cur of mail id in folder of epoch e again
// after checkMeta took them over (they were signed by a revoked generation
// and this client's check record from before the revocation names the
// file, 2.2 rule 4): a new file with the same content, version one above
// and created unchanged, signed by this user, which replaces the file
// only while it is still the one checked (replaceMeta). Only a user member
// of e whose key store holds its current generation and that may write
// does it; otherwise cur is returned as checked. If the file changed
// meanwhile, the key store's generation is not the current one by
// user.rec and the log, or the version is the highest one, cur is
// returned as checked and the next read checks the file in place, except
// in step 4 of DeviceLost and its continuation (c.reissuing), where it is
// errNotReissued (task 09e: no silent exits). If sealing or writing the
// new file fails, a warning says so and cur is returned as checked as
// well (task 09c), except in step 4 of DeviceLost and its continuation,
// where it is errNotReissued (task 09d); a file that is gone is always an
// error. It returns the metadata in place afterwards.
func (c *Client) resignMeta(ch *chain, e *store.Epoch, folder store.ID, cur *Mail) (*Mail, error) {
	mbx := ch.mailbox.ID
	if c.writable() != nil || c.ks == nil || !c.isUserMember(e) {
		return cur, nil
	}
	// In step 4 of DeviceLost and its continuation these are not issued
	// again (task 09e: notIssued); elsewhere they are used as checked.
	if cur.Meta.Version == math.MaxUint32 {
		return c.metaNotIssued(cur, errVersionLimit)
	}
	if err := c.ownGenValid(); err != nil {
		return c.metaNotIssued(cur, err)
	}
	next := *cur.Meta
	next.Version++
	if resignMetaHook != nil {
		resignMetaHook()
	}
	data, err := c.sealMetaVersion(mbx, e, &next)
	if err == nil {
		err = c.replaceMeta(mbx, folder, cur.ID, cur.file, data)
	}
	switch {
	case errors.Is(err, errStale):
		return c.metaNotIssued(cur, fmt.Errorf("%w: %w", errChanged, err))
	case errors.Is(err, ErrNotFound):
		return nil, err
	case err != nil && c.reissuing:
		// Step 4 of DeviceLost or its continuation (task 09d): a failure
		// of the mailbox; reissueMetaAndSegments warns and marks it.
		return nil, fmt.Errorf("%w: %w: %w", errNotReissued, errResign, err)
	case err != nil:
		// The file checked; only signing it again failed (task 09c):
		// it is used as it is, and a later read signs it again.
		c.warn("WARNUNG: Die Metadaten der Mail %s waren von einer widerrufenen Generation signiert und wurden nicht neu signiert: %s. Sie werden geprüft verwendet; ein späterer Lauf holt die Neusignatur nach.", cur.ID, warnCause(fmt.Errorf("%w: %w", errResign, err)))
		return cur, nil
	}
	c.warn("Hinweis: Die Metadaten der Mail %s waren von einer widerrufenen Generation signiert; sie wurden übernommen und neu signiert.", cur.ID)
	m := &Mail{ID: cur.ID, Epoch: e.Number, Meta: &next, file: sha256.Sum256(data)}
	if err := c.noteVersion(mbx, e.Number, &next, m.file); err != nil {
		return nil, err
	}
	c.noteCheckedLater(mbx, metaMemo(cur.ID), data, c.me, c.ks.Generation)
	if crash("meta-resigned") {
		return nil, errCrashed
	}
	return m, nil
}

// errVersionLimit is the fixed cause of metadata taken over that are not
// signed again because their version is the highest one (math.MaxUint32).
var errVersionLimit = errors.New("client: the version of the metadata is exhausted")

// metaNotIssued is the result of resignMeta for metadata cur taken over
// that it does not sign again for cause (notIssued): cur as checked in
// Search, List and Read, errNotReissued in step 4 of DeviceLost and its
// continuation (task 09e).
func (c *Client) metaNotIssued(cur *Mail, cause error) (*Mail, error) {
	if err := c.notIssued(cause); err != nil {
		return nil, fmt.Errorf("%w: %w", errNotReissued, err)
	}
	return cur, nil
}
