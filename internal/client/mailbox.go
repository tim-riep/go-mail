package client

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// SupplyMonths is how far ahead epochs are created (2.4: "Epochen für die
// nächsten drei Monate").
const SupplyMonths = 3

// ImmediateDelay is how far in the future the fallback epoch starts that
// sync creates when the supply ran out (2.4 "Vorrat"). That epoch carries
// the reason regular (QUESTIONS Q5) and is therefore planned: like every
// planned epoch it begins at the earliest five minutes after it was
// created (2.4 lead time rule 1). The delay covers the time until the new
// epoch.rec and mailbox.rec are visible to the server and a moderate clock
// difference between client and server; without it a mail received in
// that window would be encrypted for the old epoch after the new one began
// and the client would reject it (DECISIONS D50, which now holds only for
// planned epochs). Epochs with immediate effect have no delay; the server
// and the client allow store.ImmediateLead instead (K8).
const ImmediateDelay = 5 * time.Minute

// InboxName is the folder name of the inbox in folders.gml.
const InboxName = "INBOX"

// monthStart returns the first millisecond of the month k months after
// the month of t (UTC).
func monthStart(t time.Time, k int) int64 {
	t = t.UTC()
	return time.Date(t.Year(), t.Month()+time.Month(k), 1, 0, 0, 0, 0, time.UTC).UnixMilli()
}

func monthOf(ms int64) int {
	t := time.UnixMilli(ms).UTC()
	return t.Year()*12 + int(t.Month()) - 1
}

func (c *Client) signer() *envelope.Signer {
	return &envelope.Signer{Type: envelope.SignerUser, ID: c.me, Gen: c.ks.Generation, Key: c.ks.Identity}
}

// sealMeta seals plaintext for the meta key of epoch e, signed by the
// user (kind meta: mailbox name and folders), with header version
// version (3.1 field 8). The signature carries no extra fields: the
// version is in the signed header.
func (c *Client) sealMeta(e *store.Epoch, fileID store.ID, plain []byte, version uint32) ([]byte, error) {
	return envelope.Seal(
		envelope.Header{Kind: envelope.KindMeta, MailboxID: e.MailboxID, Epoch: e.Number, FileID: fileID, Created: c.cfg.Now().UnixMilli(), Version: version},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: e.MailboxID, Gen: e.Number, PublicKey: e.MetaPub}},
		plain, &envelope.SealOptions{Signer: c.signer()})
}

// folderInfo is what folders.gml of every new epoch holds (section 4,
// S20): the mailbox name and the current folder list; the inbox is the
// file ID of folders.gml (D56).
type folderInfo struct {
	name    string
	inbox   store.ID
	folders []store.Folder
}

// folderSource returns the folderInfo for a new epoch when it is needed.
type folderSource func() (*folderInfo, error)

// currentFolders reads the folder list of the newest accessible epoch of
// ch once, when a new epoch needs it.
func (c *Client) currentFolders(ch *chain) folderSource {
	var fi *folderInfo
	return func() (*folderInfo, error) {
		if fi == nil {
			l, inbox, err := c.folderList(ch)
			if err != nil {
				return nil, err
			}
			fi = &folderInfo{name: l.Name, inbox: inbox, folders: l.Folders}
		}
		return fi, nil
	}
}

// newMember is a member of a new epoch with the public key its wrap is
// sealed for: the current unwrap key of a user or delegate from its
// user.rec, or the unwrap key of the recovery recipient.
type newMember struct {
	store.Member
	unwrap *ecdh.PublicKey
}

// errRace reports that epoch n could not be written because an epoch.rec
// with that number exists that is neither adopted nor replaced: another
// client wrote it first (K2 rule 3), or it is invalid but cannot be
// replaced (errKept). It wraps store.ErrExists. The change is created
// again on the basis of the chain as it is then.
var errRace = errors.New("client: epoch number taken")

// errKept marks an errRace for an epoch.rec that did not verify but is not
// known to be invalid for good (an error reading it or the signer's
// user.rec, or the log), so it is not replaced.
var errKept = errors.New("client: invalid epoch kept")

func lostRace(n uint32, err error) error {
	return fmt.Errorf("%w: another client created epoch %d first: %w", errRace, n, err)
}

// taken returns the errRace for an existing epoch.rec n, with the reason
// why it was neither adopted nor replaced.
func (c *Client) taken(mbx store.ID, n uint32, err error) error {
	if x := c.next; x != nil && x.mailbox == mbx && x.number == n && !x.replace {
		return fmt.Errorf("%w: %w: epoch %d exists, did not verify (%v) and is not replaced: %w", errRace, errKept, n, x.cause, err)
	}
	return lostRace(n, err)
}

// nextEpoch is the epoch.rec after the end of the verified chain, beyond
// the head of mailbox.rec, that loadChain with adopt did not adopt.
type nextEpoch struct {
	mailbox store.ID
	number  uint32
	// replace: it can never become valid (task 06c, readBeyond).
	replace bool
	// unlogged: it decodes and its append to the log failed with
	// ErrOrder (task 14); it is replaced by store.ReplaceEpoch, every
	// other replaceable file by store.ReplaceInvalidEpoch.
	unlogged bool
	// data is its content if replace (nil: larger than
	// store.MaxRecordFile).
	data []byte
	// cause is why it was not adopted.
	cause error
}

// replaceable reports whether the epoch.rec of epoch n, which createEpoch
// is about to create after prev, exists and can never become valid, and
// returns its content (nil: larger than store.MaxRecordFile) and whether
// it decodes and is replaced through the log (unlogged, store.ReplaceEpoch)
// or does not decode (store.ReplaceInvalidEpoch). Only an epoch.rec
// beyond the head of mailbox.rec is ever replaced (the server never uses
// it), or the one at the head that can never be logged (ingest refuses
// a head that is not logged, so the server never used it either; task
// 14b point 3), and only by a user member of the end of the verified
// chain under the mailbox lock (the callers of createEpoch):
//
//   - the epoch.rec after the verified chain that loadChain found invalid
//     for good (c.next: readBeyond, or the unloggable head, healHead);
//   - an epoch.rec n after an epoch n-1 that this change wrote (or one of
//     the chain whose successor was missing): it does not decode or names
//     another mailbox or number (task 06c), or it decodes, does not name
//     prev as its predecessor and its append to the log fails with
//     ErrOrder (task 14: only the log decides that a decodable epoch.rec
//     can never become valid).
//
// An epoch.rec that names prev and decodes may be valid: that is a race
// (K2 rule 3), never replaced; one that verifies is adopted by loadChain
// and never reaches createEpoch.
func (c *Client) replaceable(mbx store.ID, n uint32, prev []byte) (replace, unlogged bool, old []byte, err error) {
	if x := c.next; x != nil && x.mailbox == mbx && x.number == n {
		return x.replace, x.unlogged, x.data, nil
	}
	if prev == nil {
		return false, false, nil, nil
	}
	data, err := store.ReadFileLimited(c.st.EpochFile(mbx, n), store.MaxRecordFile)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, false, nil, nil
	case errors.Is(err, store.ErrTooLarge):
		return true, false, nil, nil
	case err != nil:
		return false, false, nil, err
	}
	if data == nil {
		data = []byte{}
	}
	e, err := store.ParseEpoch(mbx, n, data)
	if err != nil {
		return true, false, data, nil
	}
	if e.PrevHash == store.EpochHash(prev) {
		return false, false, nil, nil
	}
	if err := c.logEpoch(mbx, n, data); errors.Is(err, translog.ErrOrder) {
		return true, true, data, nil
	}
	return false, false, nil, nil
}

// createEpoch creates, signs and writes epoch n with fresh random keys
// (2.4: random, not derived): a wrap for every member and the recovery
// recipient, folders.gml of the epoch with the current name and folders,
// then epoch.rec. prev is the encoded predecessor (nil for epoch 1),
// discards the epochs an immediate epoch discards (2.4 rule 1). The
// caller holds the lock and has checked that this user is a user member
// of the predecessor (K2 rule 1).
//
// Every file is created exclusively: an existing wrap or folders.gml in
// the directory of epoch n, or an existing epoch.rec, means that another
// client is creating epoch n as well, and the result is errRace (K2 rule
// 3); a file of another client is never replaced. Leftovers of a crashed
// attempt (files without epoch.rec) are removed first (DECISIONS D57); an
// existing epoch.rec is never touched, unless it lies beyond the head of
// mailbox.rec and can never become valid (replaceable): then the other
// files of its directory are removed first and epoch.rec is replaced as
// the last file (store.ReplaceInvalidEpoch).
func (c *Client) createEpoch(mbx store.ID, n uint32, begin int64, reason store.Reason, prev []byte, members []newMember, discards []uint32, folders folderSource) (*store.Epoch, []byte, error) {
	fi, err := folders()
	if err != nil {
		return nil, nil, err
	}
	replace, unlogged, old, err := c.replaceable(mbx, n, prev)
	if err != nil {
		return nil, nil, err
	}
	// The files of a replacement through the log, by path, so that they
	// are written again if another member cleared the directory while
	// store.ReplaceEpoch held the lock (replaceUnlogged).
	var written map[string][]byte
	if unlogged {
		written = map[string][]byte{}
	}
	if replace {
		err = c.st.ClearInvalidEpoch(mbx, n, old)
	} else {
		err = c.st.RemoveIncompleteEpoch(mbx, n)
	}
	if err != nil {
		if errors.Is(err, store.ErrExists) {
			return nil, nil, c.taken(mbx, n, err)
		}
		return nil, nil, err
	}
	content, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	meta, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ek := &store.EpochKeys{MailboxID: mbx, Epoch: n, Content: content, Meta: meta}
	if _, err := io.ReadFull(rand.Reader, ek.Index[:]); err != nil {
		return nil, nil, err
	}
	defer ek.Zero()
	list := make([]store.Member, 0, len(members))
	for _, m := range members {
		list = append(list, m.Member)
	}
	e := &store.Epoch{
		MailboxID: mbx, Number: n, Begin: begin, Reason: reason, Suite: envelope.Suite1,
		ContentPub: content.PublicKey(), MetaPub: meta.PublicKey(),
		Members: list, Discards: discards,
		SignerID: c.me, SignerGen: c.ks.Generation,
	}
	if prev != nil {
		e.PrevHash = store.EpochHash(prev)
	}
	if err := e.Sign(c.ks.Identity); err != nil {
		return nil, nil, err
	}
	// The wraps first: an epoch.rec without a wrap for its members would
	// be unusable.
	plain, err := ek.Encode()
	if err != nil {
		return nil, nil, err
	}
	defer keys.Wipe(plain)
	for _, m := range members {
		if err := c.createWrapNoted(mbx, n, m, plain, written); err != nil {
			if errors.Is(err, store.ErrExists) {
				return nil, nil, lostRace(n, err)
			}
			return nil, nil, err
		}
	}
	if crash("epoch-wraps") {
		return nil, nil, errCrashed
	}
	// folders.gml of this epoch with the current name and folders, also
	// before epoch.rec (section 4, S20).
	fl, err := (&store.FolderList{MailboxID: mbx, Epoch: n, Name: fi.name, Folders: fi.folders}).Encode()
	if err != nil {
		return nil, nil, err
	}
	sealedFolders, err := c.sealMeta(e, fi.inbox, fl, 1)
	if err != nil {
		return nil, nil, err
	}
	if err := store.MkdirAll(c.st.EpochDir(mbx, n)); err != nil {
		return nil, nil, err
	}
	if err := store.CreateFileAtomic(c.st.FoldersFile(mbx, n), sealedFolders); err != nil {
		if errors.Is(err, store.ErrExists) {
			return nil, nil, lostRace(n, err)
		}
		return nil, nil, err
	}
	if written != nil {
		written[c.st.FoldersFile(mbx, n)] = sealedFolders
	}
	if crash("epoch-folders") {
		return nil, nil, errCrashed
	}
	var data []byte
	switch {
	case unlogged:
		data, err = c.replaceUnlogged(mbx, n, old, e, written)
	case replace:
		data, err = c.st.ReplaceInvalidEpoch(mbx, n, old, e)
	default:
		data, err = c.st.WriteEpoch(e)
	}
	if err != nil {
		if errors.Is(err, store.ErrExists) {
			return nil, nil, c.taken(mbx, n, err)
		}
		return nil, nil, err
	}
	if replace {
		c.warn("WARNUNG: Die ungültige Epoche %d von %s wurde ersetzt.", n, mbx)
	}
	// Record first, then the log entry (translog doc.go "Who writes":
	// epoch n > 1), with the earlier epochs and the signer's user.rec if
	// they are missing (logEpoch); the pending entry is in state.json
	// before anything relies on it.
	if err := c.logEpoch(mbx, n, data); err != nil {
		return nil, nil, err
	}
	// Remembered once it is part of the head (commitHead).
	c.created = append(c.created, e)
	if crash("epoch-written") {
		return nil, nil, errCrashed
	}
	return e, data, nil
}

// sealWrap seals the epoch keys plain of epoch n for member m (2.4
// "Verpackung für Mitglieder", DECISIONS D61): kind wrap, file ID the ID
// of the recipient, one recipient entry (user-unwrap with the user's
// generation, or recovery with the recovery ID and generation 1), signed
// with this user's identity.
func (c *Client) sealWrap(mbx store.ID, n uint32, m newMember, plain []byte) ([]byte, error) {
	rt := envelope.RecipientUserUnwrap
	if m.Kind == store.MemberRecovery {
		// TODO(Q1): file ID, ID and generation of the recovery entry.
		rt = envelope.RecipientRecovery
	}
	return envelope.Seal(
		envelope.Header{Kind: envelope.KindWrap, MailboxID: mbx, Epoch: n, FileID: m.ID, Created: c.cfg.Now().UnixMilli()},
		[]envelope.Recipient{{Type: rt, ID: m.ID, Gen: m.Gen, PublicKey: m.unwrap}},
		plain, &envelope.SealOptions{Signer: c.signer()})
}

// createWrap creates members/<id>.wrap or members/recovery.wrap of epoch
// n for m. An existing wrap is never replaced (store.ErrExists).
func (c *Client) createWrap(mbx store.ID, n uint32, m newMember, plain []byte) error {
	return c.createWrapNoted(mbx, n, m, plain, nil)
}

// createWrapNoted is createWrap that notes the path and content of the
// wrap in written (when not nil).
func (c *Client) createWrapNoted(mbx store.ID, n uint32, m newMember, plain []byte, written map[string][]byte) error {
	data, err := c.sealWrap(mbx, n, m, plain)
	if err != nil {
		return err
	}
	p := c.st.WrapFile(mbx, n, m.ID)
	if m.Kind == store.MemberRecovery {
		p = c.st.RecoveryWrapFile(mbx, n)
	}
	if err := store.MkdirAll(filepath.Dir(p)); err != nil {
		return err
	}
	if err := store.CreateFileAtomic(p, data); err != nil {
		return err
	}
	if written != nil {
		written[p] = data
	}
	return nil
}

// replaceUnlogged replaces the epoch.rec old of epoch n, which decodes
// and can never be logged, by e (translog doc.go "Unlogged epoch.rec"
// step 3, task 14): store.ReplaceEpoch takes the mailbox lock itself, so
// the change releases its lock for it (withoutLock); ReplaceEpoch
// replaces only while the file is still old and the append of old to the
// log still fails with ErrOrder (unloggable, which runs under its lock:
// lock order mailbox, log). Back under the lock, the wraps and
// folders.gml written for e (written, by path) are written again if
// another member changed them in between, and mailbox.rec must be
// unchanged (errRace otherwise, after e is logged: it is valid). It
// returns the encoding of e.
func (c *Client) replaceUnlogged(mbx store.ID, n uint32, old []byte, e *store.Epoch, written map[string][]byte) ([]byte, error) {
	data, err := e.Encode()
	if err != nil {
		return nil, err
	}
	before, err := store.ReadFileLimited(c.st.MailboxFile(mbx), store.MaxRecordFile)
	if err != nil {
		return nil, err
	}
	unloggable := func(o []byte) bool { return errors.Is(c.logEpoch(mbx, n, o), translog.ErrOrder) }
	if err := c.withoutLock(mbx, func() error { return c.st.ReplaceEpoch(mbx, n, old, data, unloggable) }); err != nil {
		return nil, err
	}
	for p, b := range written {
		if cur, err := store.ReadFileLimited(p, store.MaxMetaFile); err == nil && bytes.Equal(cur, b) {
			continue
		}
		if err := store.MkdirAll(filepath.Dir(p)); err != nil {
			return nil, err
		}
		if err := store.WriteFileAtomic(p, b); err != nil {
			return nil, err
		}
	}
	after, err := store.ReadFileLimited(c.st.MailboxFile(mbx), store.MaxRecordFile)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(before, after) {
		if err := c.logEpoch(mbx, n, data); err != nil {
			return nil, err
		}
		return nil, lostRace(n, fmt.Errorf("%w: mailbox.rec changed while epoch %d was replaced", store.ErrExists, n))
	}
	return data, nil
}

// CreateMailbox creates a mailbox with one member, this user (2.4): epoch
// 1 beginning now, the supply for the next three months, each epoch with
// folders.gml holding the name and the inbox, and mailbox.rec as the last
// file.
//
// Epoch 1 is the first entry of the mailbox ID in the log, bound to
// nothing but its own content, so the order is reversed (translog doc.go
// "Who writes", findings 03c-1, 03d-4, 03d-5): (1) the exact files of
// step 3 (the wrap for this user, folders.gml, mailbox.rec naming epoch
// 1 and, last, epoch.rec 1) are written to the client directory
// (newMailboxDir), never to the data directory; (2) epoch.rec 1 is
// appended to the log, without any mailbox lock: before its entry the
// mailbox exists nowhere in the data directory. ErrDuplicate means that
// somebody else logged the ID first: the copy is removed and the mailbox
// gets a new ID (at most maxEpochAttempts times). (3) Only then the
// mailbox lock is taken and the files are written to the data directory
// (finishMailbox), the copy is removed right after mailbox.rec, and the
// supply follows under the same lock like any epoch n > 1. A crash after
// step 2 is completed by the next Open (resumeMailboxes).
func (c *Client) CreateMailbox(name string) (store.ID, error) {
	if err := c.writable(); err != nil {
		return store.ID{}, err
	}
	name = strings.TrimSpace(store.CleanText(name, 256))
	if name == "" {
		return store.ID{}, fmt.Errorf("client: empty mailbox name")
	}
	if err := c.ready(); err != nil {
		return store.ID{}, err
	}
	for attempt := 1; ; attempt++ {
		nm, fi, err := c.prepareMailbox(name)
		if err != nil {
			return store.ID{}, err
		}
		if crash("mailbox-copy") {
			return store.ID{}, errCrashed
		}
		_, err = c.lg.appendRecord(translog.KindEpoch, nm.epoch)
		if errors.Is(err, translog.ErrDuplicate) && attempt < maxEpochAttempts {
			// Somebody logged an epoch 1 with this ID first (K2 rule 4):
			// the ID is his, this mailbox gets another one.
			if rerr := os.RemoveAll(nm.dir); rerr != nil {
				return store.ID{}, rerr
			}
			c.warn("Hinweis: Die gewählte Postfach-ID ist im Transparenzlog bereits vergeben; eine neue wird gewählt.")
			continue
		}
		if err != nil {
			return store.ID{}, err
		}
		if crash("mailbox-logged") {
			return store.ID{}, errCrashed
		}
		return nm.id, c.finishMailbox(nm, fi)
	}
}

// newMailboxesDir is the directory of the first-entry copies of new
// mailboxes in the client directory (translog doc.go "Who writes").
const newMailboxesDir = "new-mailboxes"

// newMailbox is the copy of a new mailbox in the client directory: the
// files of step 3, byte for byte (epoch.rec 1, the wrap for its creator,
// folders.gml, mailbox.rec naming epoch 1).
type newMailbox struct {
	dir                         string
	id                          store.ID
	mailbox                     *store.Mailbox
	e1                          *store.Epoch
	epoch, wrap, folders, mrecd []byte
}

const (
	copyEpoch   = "epoch.rec"
	copyWrap    = "wrap"
	copyFolders = "folders.gml"
	copyMailbox = "mailbox.rec"
)

// prepareMailbox makes epoch 1 of a new mailbox with fresh IDs and keys
// and writes the copy of step 1 into the client directory, epoch.rec
// last. It returns the copy and the folder information of the supply.
func (c *Client) prepareMailbox(name string) (*newMailbox, *folderInfo, error) {
	id, err := store.NewID(nil)
	if err != nil {
		return nil, nil, err
	}
	inbox, err := store.NewID(nil)
	if err != nil {
		return nil, nil, err
	}
	now := c.cfg.Now()
	fi := &folderInfo{name: name, inbox: inbox, folders: []store.Folder{{ID: inbox, Name: InboxName}}}
	content, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	meta, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ek := &store.EpochKeys{MailboxID: id, Epoch: 1, Content: content, Meta: meta}
	if _, err := io.ReadFull(rand.Reader, ek.Index[:]); err != nil {
		return nil, nil, err
	}
	defer ek.Zero()
	me := newMember{Member: store.Member{Kind: store.MemberUser, ID: c.me, Gen: c.ks.Generation}, unwrap: c.ks.Unwrap.PublicKey()}
	e := &store.Epoch{
		MailboxID: id, Number: 1, Begin: now.UnixMilli(), Reason: store.ReasonRegular, Suite: envelope.Suite1,
		ContentPub: content.PublicKey(), MetaPub: meta.PublicKey(),
		Members:  []store.Member{me.Member},
		SignerID: c.me, SignerGen: c.ks.Generation,
	}
	if err := e.Sign(c.ks.Identity); err != nil {
		return nil, nil, err
	}
	nm := &newMailbox{dir: filepath.Join(c.cfg.Dir, newMailboxesDir, id.String()), id: id, e1: e,
		mailbox: &store.Mailbox{ID: id, Epoch: 1, Inbox: inbox}}
	if nm.epoch, err = e.Encode(); err != nil {
		return nil, nil, err
	}
	plain, err := ek.Encode()
	if err != nil {
		return nil, nil, err
	}
	nm.wrap, err = c.sealWrap(id, 1, me, plain)
	keys.Wipe(plain)
	if err != nil {
		return nil, nil, err
	}
	fl, err := (&store.FolderList{MailboxID: id, Epoch: 1, Name: fi.name, Folders: fi.folders}).Encode()
	if err != nil {
		return nil, nil, err
	}
	if nm.folders, err = c.sealMeta(e, inbox, fl, 1); err != nil {
		return nil, nil, err
	}
	if nm.mrecd, err = nm.mailbox.Encode(); err != nil {
		return nil, nil, err
	}
	if err := mkdirClient(nm.dir); err != nil {
		return nil, nil, err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{copyWrap, nm.wrap}, {copyFolders, nm.folders}, {copyMailbox, nm.mrecd}, {copyEpoch, nm.epoch}} {
		if err := store.WritePrivateFileAtomic(filepath.Join(nm.dir, f.name), f.data); err != nil {
			return nil, nil, err
		}
	}
	return nm, fi, nil
}

// errForeignCopy marks a copy in new-mailboxes/ that this client did not
// make for itself (task 14b point 8): it is removed with a warning and
// never appended or written to the data directory.
var errForeignCopy = errors.New("client: copy of a new mailbox not made by this user")

// readNewMailbox reads a copy of step 1 from dir; a copy without
// epoch.rec is a leftover from before step 2 (ErrNotFound). The copy
// must be one this user made (errForeignCopy otherwise, task 14b point
// 8): epoch.rec 1 signed by this user, who is a user member of it, the
// wrap a wrap of epoch 1 of the mailbox for this user (header kind,
// mailbox, epoch, file ID and its one recipient), and folders.gml a meta
// file of epoch 1 of the mailbox with the inbox of mailbox.rec as file
// ID. The signatures are checked when the mailbox is read.
func (c *Client) readNewMailbox(dir string) (*newMailbox, error) {
	nm, err := readNewMailboxFiles(dir)
	if err != nil {
		return nil, err
	}
	foreign := func(what string) error { return fmt.Errorf("%w: %s", errForeignCopy, what) }
	if nm.e1.SignerID != c.me {
		return nil, foreign("epoch 1 signed by another user")
	}
	if _, ok := nm.e1.Member(c.me); !ok {
		return nil, foreign("not a user member of epoch 1")
	}
	w, err := envelope.Parse(nm.wrap)
	if err != nil {
		return nil, foreign("wrap does not parse")
	}
	if h := w.Header; h.Kind != envelope.KindWrap || store.ID(h.MailboxID) != nm.id || h.Epoch != 1 || store.ID(h.FileID) != c.me ||
		len(w.Recipients) != 1 || w.Recipients[0].Type != envelope.RecipientUserUnwrap || store.ID(w.Recipients[0].ID) != c.me {
		return nil, foreign("not the wrap of epoch 1 for this user")
	}
	f, err := envelope.Parse(nm.folders)
	if err != nil {
		return nil, foreign("folders.gml does not parse")
	}
	if h := f.Header; h.Kind != envelope.KindMeta || store.ID(h.MailboxID) != nm.id || h.Epoch != 1 || store.ID(h.FileID) != nm.mailbox.Inbox {
		return nil, foreign("folders.gml is not the folder list of epoch 1")
	}
	return nm, nil
}

// readNewMailboxFiles reads the files of a copy and checks that they
// belong together.
func readNewMailboxFiles(dir string) (*newMailbox, error) {
	nm := &newMailbox{dir: dir}
	var err error
	if nm.epoch, err = store.ReadFileLimited(filepath.Join(dir, copyEpoch), store.MaxRecordFile); err != nil {
		return nil, err
	}
	if nm.wrap, err = store.ReadFileLimited(filepath.Join(dir, copyWrap), store.MaxWrapFile); err != nil {
		return nil, err
	}
	if nm.folders, err = store.ReadFileLimited(filepath.Join(dir, copyFolders), store.MaxMetaFile); err != nil {
		return nil, err
	}
	if nm.mrecd, err = store.ReadFileLimited(filepath.Join(dir, copyMailbox), store.MaxRecordFile); err != nil {
		return nil, err
	}
	if nm.e1, err = store.DecodeEpoch(nm.epoch); err != nil {
		return nil, err
	}
	if nm.mailbox, err = store.DecodeMailbox(nm.mrecd); err != nil {
		return nil, err
	}
	nm.id = nm.e1.MailboxID
	if nm.mailbox.ID != nm.id || nm.e1.Number != 1 || nm.mailbox.Epoch != 1 || filepath.Base(dir) != nm.id.String() {
		return nil, fmt.Errorf("%w: copy of a new mailbox does not belong together", store.ErrRecord)
	}
	return nm, nil
}

// finishMailbox is step 3 of CreateMailbox for the copy nm, whose epoch 1
// is logged: under the mailbox lock (which creates mailboxes/<id>/) the
// wrap, folders.gml, epoch.rec 1 and mailbox.rec are written in this
// order (a file that exists with exactly these bytes counts as written,
// one with other content is store.ErrExists: somebody with write access
// to the data directory wrote it), the copy is removed, and with fi (not
// on resuming) the supply follows under the same lock.
func (c *Client) finishMailbox(nm *newMailbox, fi *folderInfo) error {
	id := nm.id
	if !c.skipLock {
		unlock, err := c.st.LockMailbox(id)
		if err != nil {
			return err
		}
		c.mbxUnlock = unlock
		defer func() {
			if c.mbxUnlock != nil {
				c.mbxUnlock()
			}
			c.mbxUnlock = nil
		}()
	}
	c.locked = id
	defer func() { c.locked, c.created = store.ID{}, nil }()
	if err := store.MkdirAll(c.st.EpochDir(id, 1)); err != nil {
		return err
	}
	for _, f := range []struct {
		path string
		data []byte
		max  int64
	}{{c.st.WrapFile(id, 1, c.me), nm.wrap, store.MaxWrapFile}, {c.st.FoldersFile(id, 1), nm.folders, store.MaxMetaFile}} {
		if err := store.MkdirAll(filepath.Dir(f.path)); err != nil {
			return err
		}
		if err := createOrSame(f.path, f.data, f.max); err != nil {
			return err
		}
	}
	d1, err := c.st.EnsureEpoch(nm.e1)
	if err != nil {
		return err
	}
	if !bytes.Equal(d1, nm.epoch) {
		return fmt.Errorf("%w: epoch 1 of %s", store.ErrExists, id)
	}
	if cur, err := store.ReadFileLimited(c.st.MailboxFile(id), store.MaxRecordFile); err == nil {
		if !bytes.Equal(cur, nm.mrecd) {
			return fmt.Errorf("%w: mailbox.rec of %s", store.ErrExists, id)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	} else if err := c.st.WriteMailbox(nm.mailbox); err != nil {
		return err
	}
	if crash("mailbox-written") {
		return errCrashed
	}
	if err := os.RemoveAll(nm.dir); err != nil {
		return err
	}
	ms := c.mailboxState(id)
	c.remember(ms, []*store.Epoch{nm.e1})
	if ms.Epoch == 0 {
		ms.Epoch, ms.EpochHash = 1, hashHex(nm.epoch)
	}
	if err := c.save(); err != nil {
		return err
	}
	if fi == nil {
		return nil
	}
	folders := func() (*folderInfo, error) { return fi, nil }
	head, headData, err := c.supply(id, nm.e1, nm.epoch, folders)
	if err != nil {
		return err
	}
	if head.Number != 1 {
		if err := c.st.WriteMailbox(&store.Mailbox{ID: id, Epoch: head.Number, Inbox: nm.mailbox.Inbox}); err != nil {
			return err
		}
	}
	c.remember(ms, c.created)
	c.created = nil
	ms.Epoch, ms.EpochHash = head.Number, hashHex(headData)
	return c.save()
}

// createOrSame creates path with data (exclusive); a file that exists
// with exactly data counts as written, one with other content is
// store.ErrExists (store.EnsureEpoch for the other files of step 3).
func createOrSame(path string, data []byte, max int64) error {
	err := store.CreateFileAtomic(path, data)
	if !errors.Is(err, store.ErrExists) {
		return err
	}
	cur, rerr := store.ReadFileLimited(path, max)
	if rerr == nil && bytes.Equal(cur, data) {
		return nil
	}
	return err
}

// resumeMailboxes completes every CreateMailbox interrupted after step 1
// (translog doc.go "Who writes", finding 03d-5): a copy without epoch.rec
// is a leftover from before step 2 and is removed; a copy with it is
// appended again (Append is idempotent) and finished (finishMailbox,
// without the supply, which the next Sync creates). ErrDuplicate means
// that somebody else logged the ID first: the copy is removed with a
// warning and nothing is written. Any other failure keeps the copy for
// the next start and warns.
func (c *Client) resumeMailboxes() error {
	if c.rk != nil {
		return nil
	}
	root := filepath.Join(c.cfg.Dir, newMailboxesDir)
	ents, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, de := range ents {
		dir := filepath.Join(root, de.Name())
		nm, err := c.readNewMailbox(dir)
		if errors.Is(err, store.ErrNotFound) {
			if _, serr := os.Lstat(filepath.Join(dir, copyEpoch)); errors.Is(serr, os.ErrNotExist) {
				if err := os.RemoveAll(dir); err != nil {
					return err
				}
				continue
			}
		}
		if errors.Is(err, errForeignCopy) {
			c.warn("WARNUNG: Eine Kopie eines neuen Postfachs im Client-Verzeichnis (%s) stammt nicht von diesem Benutzer und wird entfernt.", de.Name())
			if err := os.RemoveAll(dir); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			c.warn("WARNUNG: Die Kopie eines neuen Postfachs im Client-Verzeichnis ist unvollständig oder ungültig und bleibt liegen.")
			continue
		}
		_, err = c.lg.appendRecord(translog.KindEpoch, nm.epoch)
		if errors.Is(err, translog.ErrDuplicate) {
			c.warn("WARNUNG: Das unterbrochen angelegte Postfach %s wurde nicht fertiggestellt: seine ID ist im Transparenzlog bereits vergeben.", nm.id)
			if err := os.RemoveAll(dir); err != nil {
				return err
			}
			continue
		}
		if err == nil {
			err = c.finishMailbox(nm, nil)
		}
		if errors.Is(err, errCrashed) {
			return err
		}
		if err != nil {
			c.warn("WARNUNG: Das unterbrochen angelegte Postfach %s wird beim nächsten Start fertiggestellt: %s.", nm.id, warnCause(err))
			continue
		}
		c.warn("Hinweis: Das unterbrochen angelegte Postfach %s wurde fertiggestellt; Sync legt den Epochenvorrat an.", nm.id)
	}
	return nil
}

func hashHex(data []byte) string {
	h := store.EpochHash(data)
	return hex.EncodeToString(h[:])
}

// supply appends the epochs of the next SupplyMonths months after head
// and returns the new head (2.4). Every new epoch has the members of head,
// users and delegates with their current generation, and the recovery
// recipient; after an immediate epoch that is the supply without the
// removed member (2.4 rule 5). The caller holds the lock.
func (c *Client) supply(mbx store.ID, head *store.Epoch, headData []byte, folders folderSource) (*store.Epoch, []byte, error) {
	now := c.cfg.Now()
	var members []newMember
	for k := 1; k <= SupplyMonths; k++ {
		begin := monthStart(now, k)
		if head.Begin >= begin {
			continue
		}
		// An epoch created seconds before its month begins gets the same
		// delay as an immediate one (DECISIONS D50).
		if min := now.Add(ImmediateDelay).UnixMilli(); begin < min {
			begin = min
		}
		if members == nil {
			var err error
			if members, err = c.resolveMembers(mbx, head.Members); err != nil {
				return nil, nil, err
			}
		}
		e, d, err := c.createEpoch(mbx, head.Number+1, begin, store.ReasonRegular, headData, members, nil, folders)
		if err != nil {
			return nil, nil, err
		}
		head, headData = e, d
	}
	return head, headData, nil
}

// chain is the verified epoch chain of a mailbox.
type chain struct {
	mailbox *store.Mailbox
	epochs  []*store.Epoch // epochs[i] is epoch i+1, all verified
	data    [][]byte
	err     error // why the chain ends before the head, if it does
	// discarded holds the epochs that a verified epoch of the chain
	// discards (2.4) and those remembered as discarded from earlier runs:
	// a discarded epoch never becomes valid again (K1 point 3).
	discarded map[uint32]bool
	// beyond holds the remembered epochs after the end of the verified
	// chain that are not discarded, for the epoch rule of a broken chain
	// (DECISIONS D50).
	beyond []*epochMemo
	// links is the structural chain checker over epochs (store.Chain).
	links *store.Chain
	// next is the epoch.rec after the end of the chain, beyond the head
	// of mailbox.rec, that was not adopted (adopt only), nil if none; or
	// the unloggable epoch.rec at the head (unloggableHead).
	next *nextEpoch
	// unloggableHead reports (adopt only) that the epoch.rec named by
	// mailbox.rec can never be logged (task 14b point 3): the chain ends
	// before it, next describes it, and mutate replaces it by a new epoch
	// with the same number before the change runs (healHead).
	unloggableHead bool
}

// head returns the newest epoch of the verified chain and its encoding.
func (ch *chain) head() (*store.Epoch, []byte) {
	if len(ch.epochs) == 0 {
		return nil, nil
	}
	return ch.epochs[len(ch.epochs)-1], ch.data[len(ch.data)-1]
}

// current returns the epoch in force at now (milliseconds): the newest
// epoch that is not discarded and has begun; nil if none has.
func (ch *chain) current(now int64) *store.Epoch {
	var cur *store.Epoch
	for _, e := range ch.epochs {
		if e.Begin <= now && !ch.discarded[e.Number] {
			cur = e
		}
	}
	return cur
}

// discardsAfter returns the epochs an immediate epoch beginning at begin
// must discard (2.4 rule 1): exactly the epochs of the chain that are not
// yet discarded and begin later, in ascending order. The structural chain
// decides what is discarded, as store.Chain checks it.
func (ch *chain) discardsAfter(begin int64) []uint32 {
	var out []uint32
	for _, e := range ch.epochs {
		if !ch.links.Discarded(e.Number) && e.Begin > begin {
			out = append(out, e.Number)
		}
	}
	return out
}

func (ch *chain) epoch(n uint32) *store.Epoch {
	if n == 0 || int(n) > len(ch.epochs) {
		return nil
	}
	return ch.epochs[n-1]
}

// usable returns epoch n if the verified chain holds it and it is not
// discarded: ErrEpoch for an epoch outside the chain, ErrDiscardedEpoch
// for a discarded one (2.4 rule 3).
func (ch *chain) usable(n uint32) (*store.Epoch, error) {
	e := ch.epoch(n)
	if e == nil {
		return nil, fmt.Errorf("%w: epoch %d", ErrEpoch, n)
	}
	if ch.discarded[n] {
		return nil, fmt.Errorf("%w: epoch %d", ErrDiscardedEpoch, n)
	}
	return e, nil
}

// userGen returns generation gen of user id from its user.rec, checked
// against the log, and whether a later generation revoked it (2.2).
//
// A foreign user.rec of the data directory that a newer logged one
// supersedes (ErrSuperseded: rolled back, which would hide a revocation)
// is not used, with the warning of checkUser; the newest valid user
// entry of the log takes its place (Lookup(KindUser), task 14b point 9),
// so that a rolled back user.rec of another member does not break the
// chain for everybody. The own user.rec is never replaced this way
// (Open refuses a rolled back one).
func (c *Client) userGen(id store.ID, gen uint32) (*keys.GenerationCert, bool, error) {
	u, raw, err := c.st.ReadUser(id)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrSigner, err)
	}
	// The signer's user.rec is included in the log and not outdated
	// (2.7, CheckUser: ErrSuperseded warns and is not used).
	if err := c.checkUser(id, raw); err != nil {
		if id == c.me || !errors.Is(err, ErrSuperseded) {
			return nil, false, err
		}
		if u, err = c.loggedUser(id); err != nil {
			return nil, false, err
		}
	}
	g := u.Generation(gen)
	if g == nil {
		return nil, false, fmt.Errorf("%w: unknown generation %d", ErrSigner, gen)
	}
	// A generation is valid only from its log entry on (2.2 rule 3).
	if err := c.logged(func(l translog.Log) error { return l.CheckGeneration(id, gen) }); err != nil {
		return nil, false, err
	}
	return g, gen != u.Current().Gen, nil
}

// loggedUser returns the newest valid user entry of id in the reference
// tree (Lookup(KindUser)), decoded strictly; it must name id.
func (c *Client) loggedUser(id store.ID) (*store.User, error) {
	ents, err := c.lg.log.Lookup(translog.KindUser, id[:])
	if err != nil {
		return nil, err
	}
	var newest *translog.Entry
	for i := range ents {
		if newest == nil || ents[i].Seq > newest.Seq {
			newest = &ents[i]
		}
	}
	if newest == nil {
		return nil, fmt.Errorf("%w: user entry of %s", translog.ErrNotInLog, id)
	}
	u, err := store.DecodeUser(newest.Content)
	if err != nil {
		return nil, err
	}
	if u.ID != id {
		return nil, fmt.Errorf("%w: user entry names another user", translog.ErrMismatch)
	}
	return u, nil
}

// userKey returns the identity key of generation gen of user id, for a
// signature on data. A revoked generation (2.2 rule 4, S13) counts for a
// logged record (epoch.rec) if the log shows it before the revocation;
// for a file that is never logged (wraps, folders.gml) it is rejected
// with ErrRevoked: such a file counts only through a wrap-accept of the
// reader (keysFor) or the reader's own check record before the
// revocation (takeover, readFolders).
func (c *Client) userKey(id store.ID, gen uint32, logged []byte) (ed25519.PublicKey, error) {
	g, revoked, err := c.userGen(id, gen)
	if err != nil {
		return nil, err
	}
	if revoked {
		if logged == nil {
			return nil, fmt.Errorf("%w: %w: generation %d is revoked", ErrSigner, ErrRevoked, gen)
		}
		// Logged before the revocation (2.2 rule 4, K2 rule 1 over the
		// log; checkSignerGen stays as a local bound, TODO(Q13)).
		if err := c.logged(func(l translog.Log) error { return l.CheckRevokedSignature(id, gen, logged) }); err != nil {
			return nil, err
		}
	}
	return g.IdentityPub, nil
}

// verifyChain checks the epoch chain of a mailbox (2.4): every epoch from
// 1 to the head, linked by hashes, signed by a member of the previous
// epoch (epoch 1 by one of its own members), in the log, with
// non-decreasing begin and suite; the head of mailbox.rec not below the
// highest epoch this client has seen, and that epoch unchanged.
// Warnings are emitted for every violation; the returned chain holds the
// valid prefix.
func (c *Client) verifyChain(id store.ID) (*chain, error) { return c.loadChain(id, false) }

// loadChain verifies the chain like verifyChain. The head of the chain is
// mailbox.rec, for the client as for the server (which uses only the
// epochs up to it): epochs after it are not used and not remembered.
// With adopt (only under the mailbox lock, before a change or Sync)
// valid epochs after the head are verified and added as well, as they
// exist after a crash between writing epochs and mailbox.rec (D57); the
// caller makes them the head with commitHead, and only then are they
// remembered. The remembered head never rises above mailbox.rec, so an
// interrupted change is a repair for Sync, not a rollback.
func (c *Client) loadChain(id store.ID, adopt bool) (*chain, error) {
	// Nothing is processed without a fresh verified tree head (2.3).
	if err := c.ready(); err != nil {
		return nil, err
	}
	m, err := c.st.ReadMailbox(id)
	if err != nil {
		c.warn("WARNUNG: mailbox.rec von %s fehlt oder ist ungültig.", id)
		return nil, err
	}
	ch := &chain{mailbox: m}
	ms := c.mailboxState(id)
	head := m.Epoch
	if head < ms.Epoch {
		c.warn("WARNUNG: mailbox.rec von %s zeigt auf Epoche %d, gesehen wurde bereits Epoche %d.", id, head, ms.Epoch)
		ch.err = ErrRollback
		head = ms.Epoch
	}
	// The head of mailbox.rec is compared with the newest epoch of the
	// mailbox in the log (translog doc.go "Tasks" table, checkEpoch, and
	// Log.CheckEpoch: Lookup(KindEpoch); a lower head is a rollback,
	// 2.4). Every logged epoch up to it belongs to the chain and must
	// verify, so that a mailbox.rec that lags behind the log cannot hide
	// an epoch that had begun; for a reader that is ErrRollback, as for
	// ingest (ingest.ErrRollback), also after a change interrupted
	// between its log entries and mailbox.rec. A change (adopt, under
	// the mailbox lock) adopts those epochs and writes mailbox.rec, which
	// repairs it (Sync).
	logged, err := c.newestLoggedEpoch(id)
	if err != nil {
		return nil, err
	}
	if logged > head {
		c.warn("WARNUNG: mailbox.rec von %s zeigt auf Epoche %d, das Transparenzlog enthält bereits Epoche %d; die Kette wird bis dahin geprüft.", id, m.Epoch, logged)
		if !adopt && ch.err == nil {
			ch.err = ErrRollback
		}
		head = logged
	}
	links := store.NewChain()
	ch.links = links
	for n := uint32(1); ; n++ {
		if n > head && !adopt {
			break
		}
		if n > head {
			// Epochs beyond the head of mailbox.rec exist after a crash
			// between writing epochs and mailbox.rec (supply, 2.4). They
			// are adopted if they verify like any other epoch; a missing
			// or invalid one simply ends the chain, and an invalid one is
			// noted for createEpoch (ch.next).
			e, data, next := c.readBeyond(links, id, n)
			if next != nil {
				if errors.Is(next.cause, errEpochContradicts) {
					c.warnContradicts(id, n)
					ch.next = next
				} else if !errors.Is(next.cause, store.ErrNotFound) {
					c.warn("WARNUNG: Epoche %d von %s nach dem Kopf von mailbox.rec ist ungültig und wird ignoriert: %s.", n, id, warnCause(next.cause))
					ch.next = next
				}
				break
			}
			ch.epochs = append(ch.epochs, e)
			ch.data = append(ch.data, data)
			continue
		}
		e, data, err := c.st.ReadEpoch(id, n)
		if err == nil {
			err = c.checkEpoch(links, e, data)
		}
		if err != nil && e != nil && n == head && n == m.Epoch && n > ms.Epoch && n > logged && ch.err == nil &&
			errors.Is(c.epochLogged(e, data), translog.ErrOrder) {
			// The epoch.rec that mailbox.rec names can never be logged
			// (translog doc.go "Unlogged epoch.rec" steps 1 and 2, then
			// Append: ErrOrder; task 14b point 3). Readers report the
			// fixed cause; a change (adopt, under the mailbox lock)
			// replaces it by a new epoch with the same number (mutate,
			// healHead); mailbox.rec is never set back (2.4).
			c.warn("WARNUNG: Epochenkette von %s bricht bei Epoche %d ab: %s.", id, n, warnCause(err))
			c.warn("WARNUNG: Epoche %d von %s ist nicht loggbar (sie verletzt eine Regel des Transparenzlogs und kann nie eingetragen werden); ein Mitglied behebt das mit share, revoke oder sync.", n, id)
			if adopt {
				ch.next = &nextEpoch{mailbox: id, number: n, replace: true, unlogged: true, data: data, cause: err}
				ch.unloggableHead = true
			} else {
				ch.err = fmt.Errorf("%w: epoch %d: %w: %v", store.ErrChain, n, errUnloggableHead, err)
			}
			break
		}
		if err != nil {
			c.warn("WARNUNG: Epochenkette von %s bricht bei Epoche %d ab: %s.", id, n, warnCause(err))
			if ch.err == nil {
				ch.err = fmt.Errorf("%w: epoch %d: %v", store.ErrChain, n, err)
			}
			break
		}
		ch.epochs = append(ch.epochs, e)
		ch.data = append(ch.data, data)
	}
	// links holds only epochs of ch.epochs: an epoch that passed
	// store.Chain.Add but failed a later check is dropped again, so that
	// its discards do not count (discardsAfter).
	if h := links.Head(); h != nil && (len(ch.epochs) == 0 || h != ch.epochs[len(ch.epochs)-1]) {
		links = store.NewChain()
		for i, e := range ch.epochs {
			if err := links.Add(e, ch.data[i]); err != nil {
				return nil, err
			}
		}
		ch.links = links
	}
	// The highest epoch seen must still be the same file.
	if ms.Epoch > 0 {
		if int(ms.Epoch) > len(ch.epochs) {
			c.warn("WARNUNG: Epoche %d von %s fehlt oder ist ungültig, war aber bereits gesehen.", ms.Epoch, id)
			if ch.err == nil {
				ch.err = fmt.Errorf("%w: epoch %d missing", store.ErrChain, ms.Epoch)
			}
		} else if hashHex(ch.data[ms.Epoch-1]) != ms.EpochHash {
			c.warn("WARNUNG: Epoche %d von %s wurde ersetzt.", ms.Epoch, id)
			// Nothing of this chain from the replaced epoch on is trusted.
			ch.epochs, ch.data = ch.epochs[:ms.Epoch-1], ch.data[:ms.Epoch-1]
			ch.err = fmt.Errorf("%w: epoch %d replaced", store.ErrChain, ms.Epoch)
		}
	}
	// Remember begin and reason of every verified epoch up to the head,
	// the first values seen, and every epoch they discard. A remembered
	// discard stays even if the chain no longer shows it. Adopted epochs
	// after the head count for this chain but are remembered only once
	// they are the head (commitHead).
	ch.discarded = map[uint32]bool{}
	for _, e := range ch.epochs {
		for _, n := range e.Discards {
			ch.discarded[n] = true
		}
	}
	upto := ch.epochs
	if uint64(len(upto)) > uint64(head) {
		upto = upto[:head]
	}
	changed := c.remember(ms, upto)
	for k, m := range ms.Epochs {
		n, err := strconv.ParseUint(k, 10, 32)
		if err != nil || n == 0 {
			continue
		}
		if m.Discarded {
			ch.discarded[uint32(n)] = true
		} else if n > uint64(len(ch.epochs)) {
			ch.beyond = append(ch.beyond, m)
		}
	}
	if top := min(len(ch.epochs), int(m.Epoch)); ch.err == nil && top > 0 && uint32(top) > ms.Epoch {
		ms.Epoch, ms.EpochHash = uint32(top), hashHex(ch.data[top-1])
		changed = true
	}
	if changed {
		if err := c.save(); err != nil {
			return nil, err
		}
	}
	// The checkpoints of the other members against the own reference
	// head (2.7 "Abgleich zwischen Clients"): a split view stops here.
	if err := c.checkCheckpoints(ch); err != nil {
		return nil, err
	}
	return ch, nil
}

// errUnloggableHead reports that the epoch.rec named by mailbox.rec can
// never be logged (task 14b point 3); a user member replaces it with
// share, revoke or sync (healHead).
var errUnloggableHead = errors.New("client: the head epoch can never be logged; a member repairs it with share, revoke or sync")

// errEpochContradicts marks an epoch.rec that contradicts the log:
// another epoch with its number is logged (CheckEpoch: ErrMismatch;
// Append: ErrDuplicate, K2 rule 4). It is never replaced (translog
// doc.go "Unlogged epoch.rec" step 4).
var errEpochContradicts = errors.New("client: another epoch with this number is in the log")

// warnContradicts warns about epoch.rec n of mbx beyond the head of
// mailbox.rec that contradicts the log, with the fixed cause and the
// remedy, which is the operator's (translog doc.go "Unlogged epoch.rec"
// step 4, task 14b point 13). An epoch of the chain up to the head that
// contradicts the log breaks the chain with the usual warning: removing
// it would not help, the logged content belongs there.
func (c *Client) warnContradicts(mbx store.ID, n uint32) {
	c.warn("WARNUNG: Epoche %d von %s widerspricht dem Transparenzlog: dort ist eine andere Epoche %d eingetragen. Sie wird nie ersetzt; das Postfach bleibt blockiert. Abhilfe (Betreiber): die Datei entfernen, nachdem der Logeintrag geprüft wurde.", n, mbx, n)
}

// remember notes begin and effect of each epoch in ms (the first values
// seen) and marks the epochs they discard. It reports whether ms changed.
func (c *Client) remember(ms *mailboxState, epochs []*store.Epoch) bool {
	changed := false
	for _, e := range epochs {
		k := fmt.Sprint(e.Number)
		if _, ok := ms.Epochs[k]; !ok {
			ms.Epochs[k] = &epochMemo{Begin: e.Begin, Immediate: e.Reason.Immediate()}
			changed = true
		}
		for _, n := range e.Discards {
			if m := ms.Epochs[fmt.Sprint(n)]; m != nil && !m.Discarded {
				m.Discarded = true
				changed = true
			}
		}
	}
	return changed
}

// checkEpochRule applies the epoch rule of 2.4 to a file of epoch e
// received at received (milliseconds): it is accepted only if
//
//	(a) e is not discarded (rule 3);
//	(b) e has begun at receipt: Begin(e) <= received, for an epoch with
//	    immediate effect Begin(e) - store.ImmediateLead <= received (lead time
//	    rule 3);
//	(c) no later epoch k that is not discarded had begun at receipt:
//	    Begin(k) <= received rejects the file, whatever the reason of k
//	    (lead time rule 3, second sentence: for the predecessor of an
//	    immediate epoch every mail received after its begin is rejected).
//
// Later epochs come from the verified chain and, if the chain now ends
// earlier, from the begins remembered in earlier runs (DECISIONS D50).
// If the chain is broken and no later epoch is known, whether the file
// is stale cannot be decided and it is rejected (ErrEpoch).
func (c *Client) checkEpochRule(ch *chain, e *store.Epoch, received int64) error {
	if ch.discarded[e.Number] {
		return fmt.Errorf("%w: epoch %d", ErrDiscardedEpoch, e.Number)
	}
	begin := e.Begin
	if e.Reason.Immediate() {
		begin -= store.ImmediateLead.Milliseconds()
	}
	if begin > received {
		return fmt.Errorf("%w: epoch %d began after the receipt", ErrStaleEpoch, e.Number)
	}
	later := false
	for _, k := range ch.epochs[e.Number:] {
		if ch.discarded[k.Number] {
			continue
		}
		later = true
		if k.Begin <= received {
			return fmt.Errorf("%w: epoch %d had begun", ErrStaleEpoch, k.Number)
		}
	}
	for _, m := range ch.beyond {
		later = true
		if m.Begin <= received {
			return fmt.Errorf("%w: a later epoch had begun", ErrStaleEpoch)
		}
	}
	if !later && ch.err != nil {
		// The chain is broken after this epoch and no later epoch was
		// ever seen: whether the file is stale cannot be decided (2.4).
		return fmt.Errorf("%w: the chain ends after epoch %d", ErrEpoch, e.Number)
	}
	return nil
}

// readBeyond reads and verifies epoch n after the end of the chain links,
// beyond the head of mailbox.rec, with the checks of checkEpoch; the
// caller holds the mailbox lock (loadChain with adopt). If it does not
// verify, it returns why (a missing file: store.ErrNotFound) and whether
// it can never become valid, for createEpoch:
//
//   - a file that does not decode or names another mailbox or number
//     (also one larger than store.MaxRecordFile) is replaced by
//     store.ReplaceInvalidEpoch (task 06c);
//   - a file that decodes is judged by the log alone (task 14, translog
//     doc.go "Unlogged epoch.rec"): without a log entry this member
//     appends it (epochLogged); only when that fails with ErrOrder (the
//     signer was revoked before, the signature or the chain is wrong, the
//     signer's user.rec cannot yield the generation) may it be replaced,
//     by store.ReplaceEpoch (unlogged). ErrDuplicate (another epoch with
//     this number is logged, K2 rule 4) and every other failure keep it:
//     it is never replaced.
//
// A logged epoch that fails a local check is kept as well.
func (c *Client) readBeyond(links *store.Chain, id store.ID, n uint32) (*store.Epoch, []byte, *nextEpoch) {
	x := &nextEpoch{mailbox: id, number: n}
	data, err := store.ReadFileLimited(c.st.EpochFile(id, n), store.MaxRecordFile)
	if err != nil {
		x.cause, x.replace = err, errors.Is(err, store.ErrTooLarge)
		return nil, nil, x
	}
	if data == nil {
		data = []byte{}
	}
	e, err := store.ParseEpoch(id, n, data)
	if err != nil {
		x.cause, x.replace, x.data = err, true, data
		return nil, nil, x
	}
	if err := c.epochLogged(e, data); err != nil {
		x.cause = err
		if errors.Is(err, translog.ErrOrder) {
			x.replace, x.unlogged, x.data = true, true, data
		}
		return nil, nil, x
	}
	if err := links.Add(e, data); err != nil {
		x.cause = err
		return nil, nil, x
	}
	if err := c.checkSignerGen(links, e); err != nil {
		x.cause = err
		return nil, nil, x
	}
	pub, err := c.userKey(e.SignerID, e.SignerGen, data)
	if err == nil {
		err = e.VerifySignature(pub)
	}
	if err != nil {
		x.cause = err
		return nil, nil, x
	}
	return e, data, nil
}

// checkEpoch checks epoch e of the chain up to the head (data its
// encoding): store.Chain rules against the epochs before it, the local
// bound checkSignerGen (TODO(Q13)), the log (epochLogged: CheckEpoch for
// every epoch of the chain, K2 rule 3 decided by the log order; an
// unlogged one is appended first), the signer's generation from the log
// (userKey: CheckUser, CheckGeneration, CheckRevokedSignature) and the
// signature.
func (c *Client) checkEpoch(links *store.Chain, e *store.Epoch, data []byte) error {
	if err := links.Add(e, data); err != nil {
		return err
	}
	if err := c.checkSignerGen(links, e); err != nil {
		return err
	}
	if err := c.epochLogged(e, data); err != nil {
		return err
	}
	pub, err := c.userKey(e.SignerID, e.SignerGen, data)
	if err != nil {
		return err
	}
	return e.VerifySignature(pub)
}

// checkSignerGen rejects epoch e of the chain links (already added) if
// its signer signed it with a generation lower than one that an earlier
// epoch of the chain names for the same user, as a member or as its
// signer, and that the user's user.rec holds (ErrRevoked). That earlier
// epoch precedes e in the hash chain and shows that the newer generation,
// which revokes the older one, existed before e was signed; a signature
// of a revoked generation counts only before the revocation (2.2 rule 4).
// This is how a client without a verifying log keeps a thief with the key
// store of a revoked generation from appending epochs once the chain names
// the new one (device lost). A generation that user.rec does not hold
// proves nothing and is not counted.
//
// TODO(ask): this local rule is the strictest reading of 2.2 rule 4 for
// a chain checked without the log; neither the specification nor the
// task names it. With the log (task 14) CheckRevokedSignature decides
// the same by log order, and before the first epoch that names the new
// generation only the log can.
func (c *Client) checkSignerGen(links *store.Chain, e *store.Epoch) error {
	u, _, err := c.st.ReadUser(e.SignerID)
	if err != nil {
		// The signature check fails as well (userKey).
		return nil
	}
	known := u.Current().Gen
	for n := uint32(1); n < e.Number; n++ {
		p := links.Epoch(n)
		if p == nil {
			break
		}
		newer := p.SignerID == e.SignerID && p.SignerGen > e.SignerGen && p.SignerGen <= known
		for _, m := range p.Members {
			if m.Kind != store.MemberRecovery && m.ID == e.SignerID && m.Gen > e.SignerGen && m.Gen <= known {
				newer = true
			}
		}
		if newer {
			return fmt.Errorf("%w: %w: epoch %d is signed by generation %d of %s, epoch %d names a newer generation", ErrSigner, ErrRevoked, e.Number, e.SignerGen, e.SignerID, n)
		}
	}
	return nil
}

// keysFor returns the private keys of epoch e of the verified chain ch
// (2.4, DECISIONS D61). A client has access to epoch e if a wrap for it
// exists (members/<user-id>.wrap, or members/recovery.wrap for a client
// opened with RecoverRead) that
//   - is for this client's current unwrap key (or the recovery key),
//   - names the mailbox, epoch e and the recipient in its header,
//   - is signed by a user member (kind 1) of e with a valid generation,
//     or with a revoked one if this client's own wrap-accept of its
//     current generation countersigns exactly this wrap (2.2 rule 4, S13),
//   - holds keys whose public parts equal those of the signed epoch.rec.
//
// After the check the client countersigns the wrap (members/<me>.accept,
// once per epoch and wrap, acceptWrap), so that it stays usable when the
// member who made it later loses a generation.
//
// Membership of the reader is not required: a delegate for a past period
// reads with wraps of epochs it is not a member of (2.5). Membership of
// kind 1 is required only to create epochs and to write folders.gml. A
// discarded epoch is never used (2.4 rule 3).
func (c *Client) keysFor(ch *chain, e *store.Epoch) (*store.EpochKeys, error) {
	if ch.discarded[e.Number] {
		return nil, fmt.Errorf("%w: epoch %d", ErrDiscardedEpoch, e.Number)
	}
	ref := epochRef{e.MailboxID, e.Number}
	c.mu.Lock()
	k := c.epochKeys[ref]
	c.mu.Unlock()
	if k != nil {
		return k, nil
	}
	k, data, err := c.openOwnWrap(e)
	if err != nil {
		return nil, err
	}
	c.acceptWrap(e, data)
	c.mu.Lock()
	c.epochKeys[ref] = k
	c.mu.Unlock()
	return k, nil
}

// openOwnWrap reads and checks the own wrap of epoch e like keysFor,
// without the cache and without countersigning it, and returns the keys
// with the exact bytes it checked.
func (c *Client) openOwnWrap(e *store.Epoch) (*store.EpochKeys, []byte, error) {
	data, key, err := c.readOwnWrap(e.MailboxID, e.Number)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrWrap, err)
	}
	// envelope.Open wraps the error of the resolver with %v, so its cause
	// (ErrRevoked above all) is kept here for the warning (task 06h).
	var resolveErr error
	f, plain, err := envelope.Open(data, envelope.OpenOptions{
		ExpectedSuite: e.Suite,
		Key:           key,
		ResolveSigner: func(ref envelope.SignerRef) (ed25519.PublicKey, error) {
			pub, err := c.resolveWrapSigner(e, ref, data)
			resolveErr = err
			return pub, err
		},
	})
	if err != nil {
		cause := err
		if resolveErr != nil {
			cause = resolveErr
		}
		c.warn("WARNUNG: Verpackung der Epoche %d von %s abgelehnt: %s.", e.Number, e.MailboxID, warnCause(cause))
		return nil, nil, fmt.Errorf("%w: %v", ErrWrap, err)
	}
	defer keys.Wipe(plain)
	h := f.Header
	if h.Kind != envelope.KindWrap || h.MailboxID != e.MailboxID || h.Epoch != e.Number || h.FileID != key.ID {
		return nil, nil, fmt.Errorf("%w: wrap header does not match its location", ErrMismatch)
	}
	k, err := store.DecodeEpochKeys(plain)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrWrap, err)
	}
	if !k.Matches(e) {
		k.Zero()
		c.warn("WARNUNG: Schlüssel der Verpackung passen nicht zur signierten Epoche %d von %s.", e.Number, e.MailboxID)
		return nil, nil, fmt.Errorf("%w: keys do not match epoch.rec", ErrWrap)
	}
	return k, data, nil
}

// resolveWrapSigner returns the key that checks the signature named by
// ref on the own wrap data of epoch e: a user member of e (wrapSignerKey).
func (c *Client) resolveWrapSigner(e *store.Epoch, ref envelope.SignerRef, data []byte) (ed25519.PublicKey, error) {
	if ref.Type != envelope.SignerUser {
		return nil, ErrSigner
	}
	if _, ok := e.Member(store.ID(ref.ID)); !ok {
		return nil, fmt.Errorf("%w: wrap signed by a non-member", ErrSigner)
	}
	return c.wrapSignerKey(e, store.ID(ref.ID), ref.Gen, data)
}

// readOwnWrap reads the wrap of epoch n meant for this client and returns
// it with the key that opens it: members/<me>.wrap for the current
// generation, or members/recovery.wrap for a client opened with
// RecoverRead (recipient type 4, TODO(Q1)). During DeviceLost a wrap for
// a revoked generation of this user is opened with its key store (prevGen).
func (c *Client) readOwnWrap(mbx store.ID, n uint32) ([]byte, envelope.RecipientKey, error) {
	if c.rk != nil {
		data, err := c.st.ReadRecoveryWrap(mbx, n)
		return data, envelope.RecipientKey{Type: envelope.RecipientRecovery, ID: c.rk.id, Gen: store.RecoveryGen, PrivateKey: c.rk.unwrap}, err
	}
	data, err := c.st.ReadWrap(mbx, n, c.me)
	ks := c.ks
	if err == nil && c.prevKs != nil {
		if f, perr := envelope.Parse(data); perr == nil && len(f.Recipients) == 1 {
			if p := c.prevGen(f.Recipients[0].Gen); p != nil {
				ks = p
			}
		}
	}
	return data, envelope.RecipientKey{Type: envelope.RecipientUserUnwrap, ID: c.me, Gen: ks.Generation, PrivateKey: ks.Unwrap}, err
}

// ownWrapExists reports whether a wrap for this client exists in epoch n
// (without checking it).
func (c *Client) ownWrapExists(mbx store.ID, n uint32) bool {
	p := c.st.WrapFile(mbx, n, c.me)
	if c.rk != nil {
		p = c.st.RecoveryWrapFile(mbx, n)
	}
	_, err := os.Lstat(p)
	return err == nil
}

// listed reports whether epoch e names this client in its member list,
// as a user, a delegate or (for RecoverRead) the recovery recipient.
func (c *Client) listed(e *store.Epoch) bool {
	for _, m := range e.Members {
		if c.rk != nil {
			if m.Kind == store.MemberRecovery && m.ID == c.rk.id {
				return true
			}
		} else if m.Kind != store.MemberRecovery && m.ID == c.me {
			return true
		}
	}
	return false
}

// isUserMember reports whether this client is a user member (kind 1) of
// e, the condition for creating the epoch after e and for writing
// folders.gml of e (K2 rule 1). A client opened with RecoverRead never is.
func (c *Client) isUserMember(e *store.Epoch) bool {
	if c.rk != nil || e == nil {
		return false
	}
	_, ok := e.Member(c.me)
	return ok
}

// Sync keeps the epoch supply of every mailbox of this client (2.4): if
// no epoch has begun in the current month (the server noted a fallback),
// an epoch with immediate begin is created, then epochs for the next
// three months. Before that a user member wraps the epochs again for
// every member whose generation was revoked (device lost, 2.2 point 5),
// issues again the wraps of the listed members, its own and recovery.wrap
// that a revoked generation signed (rewrapGenerations), and, while the
// head still names a revoked generation (its own entry as well), creates
// an epoch generation-revoked that discards the supply (K1 point 4).
// Then it processes pending/ of the mailbox (Index, 6.2). It refreshes
// the client log once first (2.7 "bei jedem Sync", task 14b point 12),
// which also writes the checkpoints that are due.
func (c *Client) Sync() error {
	if err := c.writable(); err != nil {
		return err
	}
	if err := c.refreshLog(); err != nil {
		return err
	}
	var first error
	for _, id := range c.Mailboxes() {
		if err := c.syncMailbox(id); err != nil && first == nil {
			first = err
		}
		if _, err := c.Index(id); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (c *Client) syncMailbox(id store.ID) error {
	return c.mutate(id, func(ch *chain) error {
		c.acceptOwnWraps(ch)
		head, headData := ch.head()
		if !c.isUserMember(head) {
			// The supply is created by user members only (K2 rule 1); a
			// delegate, a former member or a reader of past epochs only
			// verifies the chain, and repairs mailbox.rec if valid epochs
			// follow it.
			if head.Number != ch.mailbox.Epoch {
				return c.commitHead(ch, head, headData)
			}
			return nil
		}
		now := c.cfg.Now()
		// Generations revoked by members (2.2 point 5, K1 point 4).
		if done, err := c.syncGenerations(ch, now); done || err != nil {
			return err
		}
		folders := c.currentFolders(ch)
		note, err := c.st.ReadNote(id)
		if err != nil {
			c.warn("WARNUNG: Vermerk des Servers zu %s ist ungültig.", id)
		}
		// The epoch in force now is the last one that has begun and is not
		// discarded.
		current := ch.current(now.UnixMilli())
		if current != nil && head == current && monthOf(current.Begin) < monthOf(now.UnixMilli()) {
			if note != nil {
				c.warn("Hinweis: Für %s fehlte eine Epoche; der Server hat %d Mails mit Epoche %d angenommen.", id, note.Count, note.Epoch)
			}
			members, err := c.resolveMembers(id, head.Members)
			if err != nil {
				return err
			}
			e, d, err := c.createEpoch(id, head.Number+1, now.Add(ImmediateDelay).UnixMilli(), store.ReasonRegular, headData, members, nil, folders)
			if err != nil {
				return err
			}
			head, headData = e, d
		}
		head, headData, err = c.supply(id, head, headData, folders)
		if err != nil {
			return err
		}
		if err := c.commitHead(ch, head, headData); err != nil {
			return err
		}
		if note != nil && monthOf(head.Begin) >= monthOf(now.UnixMilli()) {
			if err := c.st.RemoveNote(id); err != nil {
				return err
			}
		}
		return nil
	})
}

// MailboxName decrypts the name of a mailbox from folders.gml of the
// newest epoch this user has access to (section 4).
func (c *Client) MailboxName(id store.ID) (string, error) {
	ch, err := c.verifyChain(id)
	if err != nil {
		return "", err
	}
	l, _, err := c.folderList(ch)
	if err != nil {
		return "", err
	}
	return l.Name, nil
}

// Folders decrypts folders.gml of the newest epoch this user has access
// to (section 4).
func (c *Client) Folders(id store.ID) ([]store.Folder, error) {
	ch, err := c.verifyChain(id)
	if err != nil {
		return nil, err
	}
	return c.folders(ch)
}

func (c *Client) folders(ch *chain) ([]store.Folder, error) {
	l, _, err := c.folderList(ch)
	if err != nil {
		return nil, err
	}
	return l.Folders, nil
}

// folderList opens epochs/<n>/folders.gml of the newest epoch of the
// verified chain that is not discarded and this client has access to
// (section 4: "Ein Client liest die Liste der neuesten Epoche, auf die er
// Zugriff hat") and returns it with the inbox, its file ID. The epoch is
// the newest one that names this client as a member or holds a wrap for
// it; if its wrap does not open, the list is not read from an older epoch
// instead (a deleted or damaged wrap must not roll back the folders).
func (c *Client) folderList(ch *chain) (*store.FolderList, store.ID, error) {
	var e *store.Epoch
	for i := len(ch.epochs) - 1; i >= 0 && e == nil; i-- {
		x := ch.epochs[i]
		if !ch.discarded[x.Number] && (c.listed(x) || c.ownWrapExists(ch.mailbox.ID, x.Number)) {
			e = x
		}
	}
	if e == nil {
		return nil, store.ID{}, fmt.Errorf("%w: no epoch of %s with access", ErrWrap, ch.mailbox.ID)
	}
	return c.foldersOf(ch, e.Number)
}

// foldersOf opens epochs/<n>/folders.gml of epoch n of the verified
// chain; the folders of a discarded epoch are never read (2.4 rule 3).
func (c *Client) foldersOf(ch *chain, n uint32) (*store.FolderList, store.ID, error) {
	l, inbox, _, err := c.foldersAt(ch, n)
	return l, inbox, err
}

// foldersAt is foldersOf that also returns the version of the file.
// folders.gml of an epoch is rewritten whenever a member changes the
// folders (section 4); each rewrite raises its header version by one, and
// the client remembers the highest version seen per epoch and rejects an
// older one (like metadata, section 7 "Gegen Wiedereinspielen"), so the
// server cannot put back an older list.
func (c *Client) foldersAt(ch *chain, n uint32) (*store.FolderList, store.ID, uint32, error) {
	l, inbox, v, err := c.readFolders(ch, n)
	if err != nil {
		return nil, store.ID{}, 0, err
	}
	ms := c.mailboxState(ch.mailbox.ID)
	k := fmt.Sprint(n)
	if seen := ms.Folders[k]; v < seen {
		c.warn("WARNUNG: folders.gml der Epoche %d von %s ist älter als bereits gesehen und wird nicht verwendet.", n, ch.mailbox.ID)
		return nil, store.ID{}, 0, fmt.Errorf("%w: folders.gml of epoch %d version %d, seen %d", ErrReplay, n, v, seen)
	} else if v > seen {
		ms.Folders[k] = v
		if err := c.save(); err != nil {
			return nil, store.ID{}, 0, err
		}
	}
	return l, inbox, v, nil
}

func (c *Client) readFolders(ch *chain, n uint32) (*store.FolderList, store.ID, uint32, error) {
	id := ch.mailbox.ID
	e, err := ch.usable(n)
	if err != nil {
		return nil, store.ID{}, 0, err
	}
	data, err := c.st.ReadFolders(id, e.Number)
	if err != nil {
		return nil, store.ID{}, 0, err
	}
	// folders.gml carries the inbox ID as its file ID; the inbox entry is
	// checked below against the list itself.
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, store.ID{}, 0, err
	}
	if f.Header.Epoch != e.Number {
		return nil, store.ID{}, 0, fmt.Errorf("%w: folders.gml of epoch %d is for epoch %d", ErrMismatch, e.Number, f.Header.Epoch)
	}
	inbox := store.ID(f.Header.FileID)
	plain, taken, err := c.openUserMetaChecked(ch, data, inbox, foldersMemo(e.Number))
	if err != nil {
		return nil, store.ID{}, 0, err
	}
	defer keys.Wipe(plain)
	l, err := store.DecodeFolders(id, e.Number, plain)
	if err != nil {
		return nil, store.ID{}, 0, err
	}
	for _, fo := range l.Folders {
		if fo.Name == InboxName && fo.ID == inbox {
			// The version is part of the signed header (envelope checks
			// field 8 is at least 1 for kind meta).
			v := f.Header.Version
			seen := c.mailboxState(id).Folders[fmt.Sprint(e.Number)]
			switch {
			case v < seen:
				// Rejected by foldersAt; never recorded or taken over.
			case taken && c.noTakeover:
				// Step 2 of DeviceLost: the check record names it; step 4
				// takes it over with the new generation.
			case taken:
				// Checked before the revocation: signed again by this
				// user (2.2 rule 4 "Übernahme durch andere Mitglieder").
				if v, err = c.resignFolders(ch, e, data, l, inbox, v); err != nil {
					return nil, store.ID{}, 0, err
				}
			case f.Trailer != nil: // always: openUserMetaChecked verified it
				if err := c.noteChecked(id, foldersMemo(e.Number), data, store.ID(f.Trailer.Signer.ID), f.Trailer.Signer.Gen); err != nil {
					return nil, store.ID{}, 0, err
				}
			}
			return l, inbox, v, nil
		}
	}
	return nil, store.ID{}, 0, fmt.Errorf("%w: folders.gml names no inbox", ErrMismatch)
}

// inbox returns the inbox from the signed folders.gml (D56). mailbox.rec
// is not signed; if it names another folder, the server delivers there
// and the client warns.
func (c *Client) inbox(ch *chain) (store.ID, []store.Folder, error) {
	list, err := c.folders(ch)
	if err != nil {
		c.warn("WARNUNG: folders.gml von %s ist ungültig: %s.", ch.mailbox.ID, warnCause(err))
		return store.ID{}, nil, err
	}
	var inbox store.ID
	for _, f := range list {
		if f.Name == InboxName {
			inbox = f.ID
		}
	}
	if inbox != ch.mailbox.Inbox {
		c.warn("WARNUNG: mailbox.rec von %s nennt einen anderen Posteingang als die signierte folders.gml.", ch.mailbox.ID)
	}
	return inbox, list, nil
}

// openUserMeta opens a meta file signed by a member (name, folders). A
// signature of a revoked generation is rejected (ErrRevoked).
func (c *Client) openUserMeta(ch *chain, data []byte, fileID store.ID) ([]byte, error) {
	plain, _, err := c.openUserMetaChecked(ch, data, fileID, "")
	return plain, err
}

// openUserMetaChecked is openUserMeta with the local check record of
// file memo (2.2 rule 4, takeover; empty: none): a file signed by a
// revoked generation is accepted only if the record names exactly it
// (taken reports that), and rejected with a warning otherwise. Recording
// a file verified with a valid generation is the caller's task, after its
// own checks (noteChecked).
func (c *Client) openUserMetaChecked(ch *chain, data []byte, fileID store.ID, memo string) (plain []byte, taken bool, err error) {
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, false, err
	}
	e, err := ch.usable(f.Header.Epoch)
	if err != nil {
		return nil, false, err
	}
	if f.Header.Kind != envelope.KindMeta || f.Header.MailboxID != ch.mailbox.ID || f.Header.FileID != fileID {
		return nil, false, ErrMismatch
	}
	k, err := c.keysFor(ch, e)
	if err != nil {
		return nil, false, err
	}
	mbx := ch.mailbox.ID
	// envelope.Open wraps the error of the resolver with %v; its cause
	// (ErrRevoked above all, for the fixed cause of Q18 in
	// syncGenerations) is kept here (task 14, as openOwnWrap does).
	var resolveErr error
	_, plain, err = envelope.Open(data, envelope.OpenOptions{
		ExpectedSuite: e.Suite,
		Key:           envelope.RecipientKey{Type: envelope.RecipientEpochMeta, ID: e.MailboxID, Gen: e.Number, PrivateKey: k.Meta},
		ResolveSigner: func(ref envelope.SignerRef) (pub ed25519.PublicKey, err error) {
			defer func() { resolveErr = err }()
			if ref.Type != envelope.SignerUser {
				return nil, ErrSigner
			}
			signer := store.ID(ref.ID)
			if _, ok := e.Member(signer); !ok {
				return nil, ErrSigner
			}
			pub, err = c.userKey(signer, ref.Gen, nil)
			if !errors.Is(err, ErrRevoked) {
				return pub, err
			}
			if memo == "" || !c.checkedBefore(mbx, memo, data, signer, ref.Gen) {
				c.warn("WARNUNG: Eine Datei der Epoche %d von %s ist von der widerrufenen Generation %d signiert und wurde von diesem Client vorher nicht geprüft; sie wird nicht verwendet.", e.Number, mbx, ref.Gen)
				return nil, err
			}
			taken = true
			return c.revokedKey(signer, ref.Gen)
		},
	})
	if err != nil {
		if resolveErr != nil {
			return nil, false, fmt.Errorf("%w: %w", signerErr(err), resolveErr)
		}
		return nil, false, signerErr(err)
	}
	return plain, taken, nil
}

// signerErr maps signature failures of envelope to ErrSigner.
func signerErr(err error) error {
	if errors.Is(err, envelope.ErrSigner) || errors.Is(err, envelope.ErrSignature) {
		return fmt.Errorf("%w: %v", ErrSigner, err)
	}
	return err
}
