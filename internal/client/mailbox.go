package client

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// SupplyMonths is how far ahead epochs are created (2.4: "Epochen für die
// nächsten drei Monate").
const SupplyMonths = 3

// ImmediateDelay is how far in the future an epoch "with immediate begin"
// starts (2.4). The delay covers the time until the new epoch.rec and
// mailbox.rec are visible to the server and a moderate clock difference
// between client and server; without it a mail received in that window
// would be encrypted for the old epoch after the new one began and the
// client would reject it (DECISIONS D50).
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
		envelope.Header{Kind: envelope.KindMeta, MailboxID: e.MailboxID, Epoch: e.Number, FileID: fileID, Created: c.cfg.Now().UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: e.MailboxID, Gen: e.Number, PublicKey: e.MetaPub}},
		plain, &envelope.SealOptions{Signer: c.signer()})
}

// createEpoch creates, signs and writes epoch n with fresh random keys
// (2.4: random, not derived) and the wrap for this user. prev is the
// encoded predecessor (nil for epoch 1). The caller holds the lock.
func (c *Client) createEpoch(mbx store.ID, n uint32, begin int64, reason store.Reason, prev []byte) (*store.Epoch, []byte, error) {
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
	data, err := c.st.WriteEpoch(e)
	if err != nil {
		return nil, nil, err
	}
	if err := c.cfg.Log.AppendEpoch(mbx, n, data); err != nil {
		return nil, nil, err
	}
	return e, data, nil
}

// CreateMailbox creates a mailbox with one member, this user (2.4): epoch
// 1 beginning now, the supply for the next three months, folders.gml with
// the inbox, and mailbox.rec as the last file.
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
	e1, d1, err := c.createEpoch(id, 1, now.UnixMilli(), store.ReasonInitial, nil)
	if err != nil {
		return store.ID{}, err
	}
	namePlain, err := store.EncodeMailboxName(id, name)
	if err != nil {
		return store.ID{}, err
	}
	sealedName, err := c.sealMeta(e1, id, namePlain)
	if err != nil {
		return store.ID{}, err
	}
	folders, err := store.EncodeFolders(id, []store.Folder{{ID: inbox, Name: InboxName}})
	if err != nil {
		return store.ID{}, err
	}
	sealedFolders, err := c.sealMeta(e1, inbox, folders)
	if err != nil {
		return store.ID{}, err
	}
	if err := c.st.WriteFolders(id, sealedFolders); err != nil {
		return store.ID{}, err
	}
	head, headData, err := c.supply(id, e1, d1)
	if err != nil {
		return store.ID{}, err
	}
	if err := c.st.WriteMailbox(&store.Mailbox{ID: id, Epoch: head.Number, Inbox: inbox, Name: sealedName}); err != nil {
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
func (c *Client) supply(mbx store.ID, head *store.Epoch, headData []byte) (*store.Epoch, []byte, error) {
	now := c.cfg.Now()
	for k := 1; k <= SupplyMonths; k++ {
		begin := monthStart(now, k)
		if head.Begin >= begin {
			continue
		}
		e, d, err := c.createEpoch(mbx, head.Number+1, begin, store.ReasonMonthly, headData)
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
}

func (ch *chain) epoch(n uint32) *store.Epoch {
	if n == 0 || int(n) > len(ch.epochs) {
		return nil
	}
	return ch.epochs[n-1]
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
	if err := c.cfg.Log.CheckUser(id, raw); err != nil {
		return nil, err
	}
	g := u.Generation(gen)
	if g == nil {
		return nil, fmt.Errorf("%w: unknown generation %d", ErrSigner, gen)
	}
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
	var prev *store.Epoch
	var prevData []byte
	for n := uint32(1); n <= head; n++ {
		e, data, err := c.st.ReadEpoch(id, n)
		if err == nil {
			err = c.checkEpoch(e, data, prev, prevData)
		}
		if err != nil {
			c.warn("WARNUNG: Epochenkette von %s bricht bei Epoche %d ab: %v", id, n, err)
			if ch.err == nil {
				ch.err = fmt.Errorf("%w: epoch %d: %v", store.ErrChain, n, err)
			}
			break
		}
		ch.epochs = append(ch.epochs, e)
		ch.data = append(ch.data, data)
		prev, prevData = e, data
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
	if ch.err == nil && len(ch.epochs) > 0 && uint32(len(ch.epochs)) > ms.Epoch {
		top := len(ch.epochs)
		ms.Epoch, ms.EpochHash = uint32(top), hashHex(ch.data[top-1])
		if err := c.save(); err != nil {
			return nil, err
		}
	}
	return ch, nil
}

func (c *Client) checkEpoch(e *store.Epoch, data []byte, prev *store.Epoch, prevData []byte) error {
	if prev == nil {
		if _, ok := e.Member(e.SignerID); !ok {
			return fmt.Errorf("%w: epoch 1 signed by a non-member", store.ErrChain)
		}
	} else if err := store.CheckLink(prev, prevData, e); err != nil {
		return err
	}
	pub, err := c.userKey(e.SignerID, e.SignerGen, data)
	if err != nil {
		return err
	}
	if err := e.VerifySignature(pub); err != nil {
		return err
	}
	return c.cfg.Log.CheckEpoch(e.MailboxID, e.Number, data)
}

// keysFor returns the private keys of epoch e from this user's wrap
// (2.4): signed by a member of the epoch, for this user's current unwrap
// key, and matching the public keys of the signed epoch.rec.
func (c *Client) keysFor(e *store.Epoch) (*store.EpochKeys, error) {
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
	now := c.cfg.Now()
	note, err := c.st.ReadNote(id)
	if err != nil {
		c.warn("WARNUNG: Vermerk des Servers zu %s ist ungültig.", id)
	}
	// The epoch in force now is the last one that has begun.
	var current *store.Epoch
	for _, e := range ch.epochs {
		if e.Begin <= now.UnixMilli() {
			current = e
		}
	}
	if current != nil && head == current && monthOf(current.Begin) < monthOf(now.UnixMilli()) {
		if note != nil {
			c.warn("Hinweis: Für %s fehlte eine Epoche; der Server hat %d Mails mit Epoche %d angenommen.", id, note.Count, note.Epoch)
		}
		e, d, err := c.createEpoch(id, head.Number+1, now.Add(ImmediateDelay).UnixMilli(), store.ReasonImmediate, headData)
		if err != nil {
			return err
		}
		head, headData = e, d
	}
	head, headData, err = c.supply(id, head, headData)
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

// MailboxName decrypts the name of a mailbox.
func (c *Client) MailboxName(id store.ID) (string, error) {
	ch, err := c.verifyChain(id)
	if err != nil {
		return "", err
	}
	plain, err := c.openUserMeta(ch, ch.mailbox.Name, id)
	if err != nil {
		return "", err
	}
	defer keys.Wipe(plain)
	return store.DecodeMailboxName(id, plain)
}

// Folders decrypts folders.gml.
func (c *Client) Folders(id store.ID) ([]store.Folder, error) {
	ch, err := c.verifyChain(id)
	if err != nil {
		return nil, err
	}
	data, err := c.st.ReadFolders(id)
	if err != nil {
		return nil, err
	}
	plain, err := c.openUserMeta(ch, data, ch.mailbox.Inbox)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(plain)
	return store.DecodeFolders(id, plain)
}

// openUserMeta opens a meta file signed by a member (name, folders).
func (c *Client) openUserMeta(ch *chain, data []byte, fileID store.ID) ([]byte, error) {
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, err
	}
	e := ch.epoch(f.Header.Epoch)
	if e == nil {
		return nil, ErrEpoch
	}
	if f.Header.Kind != envelope.KindMeta || f.Header.MailboxID != ch.mailbox.ID || f.Header.FileID != fileID {
		return nil, ErrMismatch
	}
	k, err := c.keysFor(e)
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
