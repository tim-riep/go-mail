package client

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
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
// user (kind meta: mailbox name and folders).
func (c *Client) sealMeta(e *store.Epoch, fileID store.ID, plain []byte) ([]byte, error) {
	return envelope.Seal(
		envelope.Header{Kind: envelope.KindMeta, MailboxID: e.MailboxID, Epoch: e.Number, FileID: fileID, Created: c.cfg.Now().UnixMilli(), Version: 1},
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

// createEpoch creates, signs and writes epoch n with fresh random keys
// (2.4: random, not derived), the wrap for this user and folders.gml of
// the epoch. prev is the encoded predecessor (nil for epoch 1). The caller
// holds the lock.
func (c *Client) createEpoch(mbx store.ID, n uint32, begin int64, reason store.Reason, prev []byte, folders folderSource) (*store.Epoch, []byte, error) {
	fi, err := folders()
	if err != nil {
		return nil, nil, err
	}
	// Leftovers of a crashed attempt (wrap and public keys without
	// epoch.rec) are removed; an existing epoch.rec is never touched.
	if err := c.st.RemoveIncompleteEpoch(mbx, n); err != nil {
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
	e := &store.Epoch{
		MailboxID: mbx, Number: n, Begin: begin, Reason: reason, Suite: envelope.Suite1,
		ContentPub: content.PublicKey(), MetaPub: meta.PublicKey(),
		// Phase 1: mailboxes have exactly one member. The member list is
		// a list, so further members need no format change.
		Members:  []store.Member{{Kind: store.MemberUser, ID: c.me, Gen: c.ks.Generation}},
		SignerID: c.me, SignerGen: c.ks.Generation,
	}
	if prev != nil {
		e.PrevHash = store.EpochHash(prev)
	}
	if err := e.Sign(c.ks.Identity); err != nil {
		return nil, nil, err
	}
	// The wrap first: an epoch.rec without a wrap for its member would be
	// unusable.
	plain, err := ek.Encode()
	if err != nil {
		return nil, nil, err
	}
	wrap, err := envelope.Seal(
		envelope.Header{Kind: envelope.KindWrap, MailboxID: mbx, Epoch: n, FileID: c.me, Created: c.cfg.Now().UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientUserUnwrap, ID: c.me, Gen: c.ks.Generation, PublicKey: c.ks.Unwrap.PublicKey()}},
		plain, &envelope.SealOptions{Signer: c.signer()})
	keys.Wipe(plain)
	if err != nil {
		return nil, nil, err
	}
	if err := c.st.WriteWrap(mbx, n, c.me, wrap); err != nil {
		return nil, nil, err
	}
	// folders.gml of this epoch with the current name and folders, also
	// before epoch.rec (section 4, S20).
	list, err := (&store.FolderList{MailboxID: mbx, Epoch: n, Name: fi.name, Folders: fi.folders}).Encode()
	if err != nil {
		return nil, nil, err
	}
	sealedFolders, err := c.sealMeta(e, fi.inbox, list)
	if err != nil {
		return nil, nil, err
	}
	if err := c.st.WriteFolders(mbx, n, sealedFolders); err != nil {
		return nil, nil, err
	}
	data, err := c.st.WriteEpoch(e)
	if err != nil {
		return nil, nil, err
	}
	// TODO(phase3-translog): epoch.rec into the log (2.7).
	if err := c.cfg.Log.AppendEpoch(mbx, n, data); err != nil {
		return nil, nil, err
	}
	c.mailboxState(mbx).Epochs[fmt.Sprint(n)] = &epochMemo{Begin: begin, Immediate: reason.Immediate()}
	return e, data, nil
}

// CreateMailbox creates a mailbox with one member, this user (2.4): epoch
// 1 beginning now, the supply for the next three months, each epoch with
// folders.gml holding the name and the inbox, and mailbox.rec as the last
// file.
func (c *Client) CreateMailbox(name string) (store.ID, error) {
	name = strings.TrimSpace(store.CleanText(name, 256))
	if name == "" {
		return store.ID{}, fmt.Errorf("client: empty mailbox name")
	}
	id, err := store.NewID(nil)
	if err != nil {
		return store.ID{}, err
	}
	inbox, err := store.NewID(nil)
	if err != nil {
		return store.ID{}, err
	}
	unlock, err := c.st.LockMailbox(id)
	if err != nil {
		return store.ID{}, err
	}
	defer unlock()
	now := c.cfg.Now()
	fi := &folderInfo{name: name, inbox: inbox, folders: []store.Folder{{ID: inbox, Name: InboxName}}}
	folders := func() (*folderInfo, error) { return fi, nil }
	e1, d1, err := c.createEpoch(id, 1, now.UnixMilli(), store.ReasonRegular, nil, folders)
	if err != nil {
		return store.ID{}, err
	}
	head, headData, err := c.supply(id, e1, d1, folders)
	if err != nil {
		return store.ID{}, err
	}
	if err := c.st.WriteMailbox(&store.Mailbox{ID: id, Epoch: head.Number, Inbox: inbox}); err != nil {
		return store.ID{}, err
	}
	ms := c.mailboxState(id)
	ms.Epoch, ms.EpochHash = head.Number, hashHex(headData)
	return id, c.save()
}

func hashHex(data []byte) string {
	h := store.EpochHash(data)
	return hex.EncodeToString(h[:])
}

// supply appends the epochs of the next SupplyMonths months after head
// and returns the new head (2.4). The caller holds the lock.
func (c *Client) supply(mbx store.ID, head *store.Epoch, headData []byte, folders folderSource) (*store.Epoch, []byte, error) {
	now := c.cfg.Now()
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
		e, d, err := c.createEpoch(mbx, head.Number+1, begin, store.ReasonRegular, headData, folders)
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

// userGeneration returns the identity key of generation gen of user id,
// for a signature on data. Logged records (epoch.rec) are checked with
// the log; for files that are not logged (wraps), only the current
// generation is accepted.
func (c *Client) userKey(id store.ID, gen uint32, logged []byte) (ed25519.PublicKey, error) {
	u, raw, err := c.st.ReadUser(id)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigner, err)
	}
	// TODO(phase3-translog): signer's user.rec included in the log (2.7).
	if err := c.cfg.Log.CheckUser(id, raw); err != nil {
		return nil, err
	}
	g := u.Generation(gen)
	if g == nil {
		return nil, fmt.Errorf("%w: unknown generation %d", ErrSigner, gen)
	}
	// TODO(phase3-translog): generation valid only from its log entry on (2.2 rule 3).
	if err := c.cfg.Log.CheckGeneration(id, gen); err != nil {
		return nil, err
	}
	if gen != u.Current().Gen {
		// TODO(S13): a revoked generation counts only for records logged
		// before the revocation; files that are never logged are not
		// accepted from a revoked generation. Strictest reading until
		// SPEC-ISSUES S13 is decided.
		if logged == nil {
			return nil, fmt.Errorf("%w: generation %d is revoked", ErrSigner, gen)
		}
		// TODO(phase3-translog): logged before the revocation (2.2 rule 4).
		if err := c.cfg.Log.CheckRevokedSignature(id, gen, logged); err != nil {
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
func (c *Client) verifyChain(id store.ID) (*chain, error) {
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
	links := store.NewChain()
	for n := uint32(1); ; n++ {
		e, data, err := c.st.ReadEpoch(id, n)
		if n > head {
			// Epochs beyond the head of mailbox.rec exist after a crash
			// between writing epochs and mailbox.rec (supply, 2.4). They
			// are adopted if they verify like any other epoch; a missing
			// or invalid one simply ends the chain.
			if errors.Is(err, store.ErrNotFound) {
				break
			}
			if err == nil {
				err = c.checkEpoch(links, e, data)
			}
			if err != nil {
				c.warn("WARNUNG: Epoche %d von %s nach dem Kopf von mailbox.rec ist ungültig und wird ignoriert: %v", n, id, err)
				break
			}
		} else {
			if err == nil {
				err = c.checkEpoch(links, e, data)
			}
			if err != nil {
				c.warn("WARNUNG: Epochenkette von %s bricht bei Epoche %d ab: %v", id, n, err)
				if ch.err == nil {
					ch.err = fmt.Errorf("%w: epoch %d: %v", store.ErrChain, n, err)
				}
				break
			}
		}
		ch.epochs = append(ch.epochs, e)
		ch.data = append(ch.data, data)
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
	// Remember begin and reason of every verified epoch, the first values
	// seen, and every epoch the verified chain discards. A remembered
	// discard stays even if the chain no longer shows it.
	changed := false
	ch.discarded = map[uint32]bool{}
	for _, e := range ch.epochs {
		k := fmt.Sprint(e.Number)
		if _, ok := ms.Epochs[k]; !ok {
			ms.Epochs[k] = &epochMemo{Begin: e.Begin, Immediate: e.Reason.Immediate()}
			changed = true
		}
		for _, n := range e.Discards {
			ch.discarded[n] = true
			if m := ms.Epochs[fmt.Sprint(n)]; m != nil && !m.Discarded {
				m.Discarded = true
				changed = true
			}
		}
	}
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
	if ch.err == nil && len(ch.epochs) > 0 && uint32(len(ch.epochs)) > ms.Epoch {
		top := len(ch.epochs)
		ms.Epoch, ms.EpochHash = uint32(top), hashHex(ch.data[top-1])
		changed = true
	}
	if changed {
		if err := c.save(); err != nil {
			return nil, err
		}
	}
	return ch, nil
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

func (c *Client) checkEpoch(links *store.Chain, e *store.Epoch, data []byte) error {
	if err := links.Add(e, data); err != nil {
		return err
	}
	pub, err := c.userKey(e.SignerID, e.SignerGen, data)
	if err != nil {
		return err
	}
	if err := e.VerifySignature(pub); err != nil {
		return err
	}
	// TODO(phase3-translog): epoch.rec included in the log (2.7).
	return c.cfg.Log.CheckEpoch(e.MailboxID, e.Number, data)
}

// keysFor returns the private keys of epoch e of the verified chain ch
// from this user's wrap (2.4): e not discarded, the wrap signed by a
// member of the epoch, for this user's current unwrap key, and matching
// the public keys of the signed epoch.rec.
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
	if _, ok := e.Member(c.me); !ok {
		return nil, fmt.Errorf("%w: not a member of epoch %d", ErrWrap, e.Number)
	}
	data, err := c.st.ReadWrap(e.MailboxID, e.Number, c.me)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWrap, err)
	}
	f, plain, err := envelope.Open(data, envelope.OpenOptions{
		ExpectedSuite: e.Suite,
		Key:           envelope.RecipientKey{Type: envelope.RecipientUserUnwrap, ID: c.me, Gen: c.ks.Generation, PrivateKey: c.ks.Unwrap},
		ResolveSigner: func(ref envelope.SignerRef) (ed25519.PublicKey, error) {
			if ref.Type != envelope.SignerUser {
				return nil, ErrSigner
			}
			if _, ok := e.Member(store.ID(ref.ID)); !ok {
				return nil, fmt.Errorf("%w: wrap signed by a non-member", ErrSigner)
			}
			return c.userKey(store.ID(ref.ID), ref.Gen, nil)
		},
	})
	if err != nil {
		c.warn("WARNUNG: Verpackung der Epoche %d von %s abgelehnt: %v", e.Number, e.MailboxID, err)
		return nil, fmt.Errorf("%w: %v", ErrWrap, err)
	}
	defer keys.Wipe(plain)
	h := f.Header
	if h.Kind != envelope.KindWrap || h.MailboxID != e.MailboxID || h.Epoch != e.Number || h.FileID != c.me {
		return nil, fmt.Errorf("%w: wrap header does not match its location", ErrMismatch)
	}
	k, err = store.DecodeEpochKeys(plain)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWrap, err)
	}
	if !k.Matches(e) {
		k.Zero()
		c.warn("WARNUNG: Schlüssel der Verpackung passen nicht zur signierten Epoche %d von %s.", e.Number, e.MailboxID)
		return nil, fmt.Errorf("%w: keys do not match epoch.rec", ErrWrap)
	}
	c.mu.Lock()
	c.epochKeys[ref] = k
	c.mu.Unlock()
	return k, nil
}

// Sync keeps the epoch supply of every mailbox of this client (2.4): if
// no epoch has begun in the current month (the server noted a fallback),
// an epoch with immediate begin is created, then epochs for the next
// three months. Phase 1 does nothing else in Sync (no term lists).
func (c *Client) Sync() error {
	var first error
	for _, id := range c.Mailboxes() {
		if err := c.syncMailbox(id); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (c *Client) syncMailbox(id store.ID) error {
	unlock, err := c.st.LockMailbox(id)
	if err != nil {
		return err
	}
	defer unlock()
	ch, err := c.verifyChain(id)
	if err != nil {
		return err
	}
	if ch.err != nil {
		// Never extend a chain that did not verify.
		return ch.err
	}
	if len(ch.epochs) == 0 {
		return fmt.Errorf("%w: no epochs", store.ErrChain)
	}
	head, headData := ch.epochs[len(ch.epochs)-1], ch.data[len(ch.data)-1]
	folders := c.currentFolders(ch)
	now := c.cfg.Now()
	note, err := c.st.ReadNote(id)
	if err != nil {
		c.warn("WARNUNG: Vermerk des Servers zu %s ist ungültig.", id)
	}
	// The epoch in force now is the last one that has begun and is not
	// discarded.
	var current *store.Epoch
	for _, e := range ch.epochs {
		if e.Begin <= now.UnixMilli() && !ch.discarded[e.Number] {
			current = e
		}
	}
	if current != nil && head == current && monthOf(current.Begin) < monthOf(now.UnixMilli()) {
		if note != nil {
			c.warn("Hinweis: Für %s fehlte eine Epoche; der Server hat %d Mails mit Epoche %d angenommen.", id, note.Count, note.Epoch)
		}
		e, d, err := c.createEpoch(id, head.Number+1, now.Add(ImmediateDelay).UnixMilli(), store.ReasonRegular, headData, folders)
		if err != nil {
			return err
		}
		head, headData = e, d
	}
	head, headData, err = c.supply(id, head, headData, folders)
	if err != nil {
		return err
	}
	if head.Number != ch.mailbox.Epoch {
		m := *ch.mailbox
		m.Epoch = head.Number
		if err := c.st.WriteMailbox(&m); err != nil {
			return err
		}
	}
	if note != nil && monthOf(head.Begin) >= monthOf(now.UnixMilli()) {
		if err := c.st.RemoveNote(id); err != nil {
			return err
		}
	}
	ms := c.mailboxState(id)
	ms.Epoch, ms.EpochHash = head.Number, hashHex(headData)
	return c.save()
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
// verified chain that is not discarded and this user is a member of
// (section 4: "Ein Client liest die Liste der neuesten Epoche, auf die er
// Zugriff hat") and returns it with the inbox, its file ID.
func (c *Client) folderList(ch *chain) (*store.FolderList, store.ID, error) {
	var e *store.Epoch
	for i := len(ch.epochs) - 1; i >= 0 && e == nil; i-- {
		if _, ok := ch.epochs[i].Member(c.me); ok && !ch.discarded[ch.epochs[i].Number] {
			e = ch.epochs[i]
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
	id := ch.mailbox.ID
	e, err := ch.usable(n)
	if err != nil {
		return nil, store.ID{}, err
	}
	data, err := c.st.ReadFolders(id, e.Number)
	if err != nil {
		return nil, store.ID{}, err
	}
	// folders.gml carries the inbox ID as its file ID; the inbox entry is
	// checked below against the list itself.
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, store.ID{}, err
	}
	if f.Header.Epoch != e.Number {
		return nil, store.ID{}, fmt.Errorf("%w: folders.gml of epoch %d is for epoch %d", ErrMismatch, e.Number, f.Header.Epoch)
	}
	inbox := store.ID(f.Header.FileID)
	plain, err := c.openUserMeta(ch, data, inbox)
	if err != nil {
		return nil, store.ID{}, err
	}
	defer keys.Wipe(plain)
	l, err := store.DecodeFolders(id, e.Number, plain)
	if err != nil {
		return nil, store.ID{}, err
	}
	for _, fo := range l.Folders {
		if fo.Name == InboxName && fo.ID == inbox {
			return l, inbox, nil
		}
	}
	return nil, store.ID{}, fmt.Errorf("%w: folders.gml names no inbox", ErrMismatch)
}

// inbox returns the inbox from the signed folders.gml (D56). mailbox.rec
// is not signed; if it names another folder, the server delivers there
// and the client warns.
func (c *Client) inbox(ch *chain) (store.ID, []store.Folder, error) {
	list, err := c.folders(ch)
	if err != nil {
		c.warn("WARNUNG: folders.gml von %s ist ungültig: %v", ch.mailbox.ID, err)
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

// openUserMeta opens a meta file signed by a member (name, folders).
func (c *Client) openUserMeta(ch *chain, data []byte, fileID store.ID) ([]byte, error) {
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, err
	}
	e, err := ch.usable(f.Header.Epoch)
	if err != nil {
		return nil, err
	}
	if f.Header.Kind != envelope.KindMeta || f.Header.MailboxID != ch.mailbox.ID || f.Header.FileID != fileID {
		return nil, ErrMismatch
	}
	k, err := c.keysFor(ch, e)
	if err != nil {
		return nil, err
	}
	_, plain, err := envelope.Open(data, envelope.OpenOptions{
		ExpectedSuite: e.Suite,
		Key:           envelope.RecipientKey{Type: envelope.RecipientEpochMeta, ID: e.MailboxID, Gen: e.Number, PrivateKey: k.Meta},
		ResolveSigner: func(ref envelope.SignerRef) (ed25519.PublicKey, error) {
			if ref.Type != envelope.SignerUser {
				return nil, ErrSigner
			}
			if _, ok := e.Member(store.ID(ref.ID)); !ok {
				return nil, ErrSigner
			}
			return c.userKey(store.ID(ref.ID), ref.Gen, nil)
		},
	})
	if err != nil {
		return nil, signerErr(err)
	}
	return plain, nil
}

// signerErr maps signature failures of envelope to ErrSigner.
func signerErr(err error) error {
	if errors.Is(err, envelope.ErrSigner) || errors.Is(err, envelope.ErrSignature) {
		return fmt.Errorf("%w: %v", ErrSigner, err)
	}
	return err
}
