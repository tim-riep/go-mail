package client

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// The recovery recipient (2.4 "Wiederherstellungsempfänger", K3,
// QUESTIONS Q1). TODO(Q1): everything here is the internal API of the
// proposal (a) to (d) of Q1; no command uses it until the question is
// decided. The recovery key is a seed of its own, derived like a user
// seed with generation 1 (Q1 (a)); its record recovery-pub carries a
// random ID and the public keys (Q1 (b), (c)). A user member enters it as
// member kind 2 with an epoch recovery-changed after confirming its
// fingerprint (K3 point 3); every epoch then has members/recovery.wrap
// (recipient type 4). It never appears in a mail or metadata file (3.1).
// With the seed the recovery recipient only reads (Q1 (d)); it never
// creates an epoch (K2 rule 1).

// recoveryKey is the private key of a client opened with RecoverRead.
type recoveryKey struct {
	id     store.ID
	unwrap *ecdh.PrivateKey
}

// RecoveryKeygen creates a recovery key (K3 point 1, Q1): a seed from
// crypto/rand, shown as 24 words through p, three of them asked back;
// then identity and unwrap key of generation 1 are derived like those of
// a user (keys.DeriveUser) and a random ID is drawn. The seed and the
// private keys are wiped; only the public record is returned. Splitting
// the seed into shares is not part of this function.
func RecoveryKeygen(p Prompter) (*store.RecoveryPub, error) {
	seed, err := keys.NewSeed(nil)
	if err != nil {
		return nil, err
	}
	defer seed.Zero()
	if err := showAndConfirm(seed, p); err != nil {
		return nil, err
	}
	u := keys.DeriveUser(seed)
	defer u.Zero()
	identity, err := u.IdentityKey(store.RecoveryGen)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(identity)
	unwrap, err := u.UnwrapKey(store.RecoveryGen)
	if err != nil {
		return nil, err
	}
	id, err := store.NewID(nil)
	if err != nil {
		return nil, err
	}
	return &store.RecoveryPub{ID: id, UnwrapPub: unwrap.PublicKey(), IdentityPub: identity.Public().(ed25519.PublicKey)}, nil
}

// recordHash is what the local state remembers of a confirmed record.
func recordHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// confirmedRecovery returns the recovery-pub record of recipient rid of
// mailbox mbx if this device confirmed exactly these bytes (K3 point 3).
// The file in the data directory is not signed: an unconfirmed or changed
// record is never used, so the server cannot slip in a key of its own.
func (c *Client) confirmedRecovery(mbx, rid store.ID) (*store.RecoveryPub, error) {
	want := c.mailboxState(mbx).Recovery[rid.String()]
	if want == "" {
		return nil, fmt.Errorf("%w: the recovery key %s of %s is not confirmed on this device (ConfirmRecovery)", ErrRecovery, rid, mbx)
	}
	p, raw, err := c.st.ReadRecoveryPub(mbx, rid)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecovery, err)
	}
	if recordHash(raw) != want {
		c.warn("WARNUNG: Der Wiederherstellungsschlüssel von %s weicht vom bestätigten ab.", mbx)
		return nil, fmt.Errorf("%w: recovery/%s.pub differs from the confirmed record", ErrRecovery, rid)
	}
	return p, nil
}

// recoveryMember returns the recovery recipient of e, if any.
func recoveryMember(e *store.Epoch) (store.Member, bool) {
	for _, m := range e.Members {
		if m.Kind == store.MemberRecovery {
			return m, true
		}
	}
	return store.Member{}, false
}

// SetRecovery enters pub as the recovery recipient of the mailbox (K3,
// Q1). confirm is shown the fingerprint of the record (SHA-256 as 8
// groups of hex digits) and must return true; nothing is written
// otherwise. Then, under the mailbox lock:
//
//  1. the record is written to mailboxes/<id>/recovery/<recovery-id>.pub
//     (never replaced) so that other members can confirm and use it;
//  2. if another recovery recipient is entered, its recovery.wrap files
//     of the epochs that are not discarded are deleted;
//  3. an epoch recovery-changed with immediate effect has the new
//     recipient as member kind 2 and its recovery.wrap, the supply after
//     it as well;
//  4. the existing epochs that have begun get a recovery.wrap, as far as
//     this user is a user member of them (2.4 "Wird er nachträglich
//     festgelegt, verpackt ein Mitglied die bestehenden Epochen für ihn").
//
// Running SetRecovery again with the same record completes an
// interrupted run. If an existing epoch that has begun and is not
// discarded could not be wrapped in step 4 (this user is not a user member
// of it, or its keys are not available), the recipient is still entered
// and the error is ErrPartial, naming the skipped epochs.
func (c *Client) SetRecovery(mbx store.ID, pub *store.RecoveryPub, confirm func(fingerprint string) bool) error {
	if err := c.writable(); err != nil {
		return err
	}
	data, err := pub.Encode()
	if err != nil {
		return err
	}
	if pub.ID == c.me {
		return fmt.Errorf("%w: the recovery ID is a user ID", ErrArgument)
	}
	// Asked before the mailbox lock is taken: the server must not wait
	// for the user.
	if confirm == nil || !confirm(store.FingerprintOf(data)) {
		return fmt.Errorf("%w: fingerprint not confirmed", ErrRecovery)
	}
	ms := c.mailboxState(mbx)
	ms.Recovery[pub.ID.String()] = recordHash(data)
	if err := c.save(); err != nil {
		return err
	}
	var skipped []uint32
	err = c.mutate(mbx, func(ch *chain) error {
		// Only the result of the last attempt counts (K2 rule 3).
		skipped = nil
		if err := c.mayCreate(ch); err != nil {
			return err
		}
		head, _ := ch.head()
		if m, ok := memberEntry(head, pub.ID); ok && m.Kind != store.MemberRecovery {
			return fmt.Errorf("%w: the recovery ID is a member", ErrArgument)
		}
		if err := c.st.WriteRecoveryPub(mbx, pub); err != nil {
			return err
		}
		member := newMember{Member: store.Member{Kind: store.MemberRecovery, ID: pub.ID, Gen: store.RecoveryGen}, unwrap: pub.UnwrapPub}
		now := c.cfg.Now().UnixMilli()
		cur := ch.current(now)
		if old, ok := recoveryMember(head); ok && old.ID == pub.ID {
			if err := c.finish(ch); err != nil {
				return err
			}
		} else {
			if err := c.removeRecoveryWraps(ch, pub.ID); err != nil {
				return err
			}
			if crash("recovery-wraps") {
				return errCrashed
			}
			// A zero old.ID (no recipient yet) removes nobody.
			members := append(without(head, old.ID), member.Member)
			if err := c.immediate(ch, store.ReasonRecoveryChanged, members); err != nil {
				return err
			}
		}
		if cur == nil {
			return nil
		}
		var err error
		_, skipped, err = c.wrapExisting(ch, member, 1, cur.Number)
		return err
	})
	if err == nil && len(skipped) > 0 {
		// The recipient is entered; some existing epochs could not be
		// wrapped for it (like Share).
		err = fmt.Errorf("%w: epochs %v of %s", ErrPartial, skipped, mbx)
	}
	return err
}

// removeRecoveryWraps deletes recovery.wrap of every epoch of ch that is
// not discarded, except wraps for recovery recipient keep (zero: all).
func (c *Client) removeRecoveryWraps(ch *chain, keep store.ID) error {
	mbx := ch.mailbox.ID
	for _, e := range ch.epochs {
		if ch.discarded[e.Number] {
			continue
		}
		data, err := c.st.ReadRecoveryWrap(mbx, e.Number)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err == nil && !keep.IsZero() {
			if f, perr := envelope.Parse(data); perr == nil && len(f.Recipients) == 1 && store.ID(f.Recipients[0].ID) == keep {
				continue
			}
		}
		if err := c.st.RemoveRecoveryWrap(mbx, e.Number); err != nil {
			return err
		}
	}
	return nil
}

// ClearRecovery removes the recovery recipient (K3): its recovery.wrap
// files of the epochs that are not discarded are deleted and an epoch
// recovery-changed with immediate effect without it begins, with the
// supply after it. Running it again completes an interrupted run.
func (c *Client) ClearRecovery(mbx store.ID) error {
	if err := c.writable(); err != nil {
		return err
	}
	return c.mutate(mbx, func(ch *chain) error {
		if err := c.mayCreate(ch); err != nil {
			return err
		}
		if err := c.removeRecoveryWraps(ch, store.ID{}); err != nil {
			return err
		}
		if crash("recovery-wraps") {
			return errCrashed
		}
		head, _ := ch.head()
		old, ok := recoveryMember(head)
		if !ok {
			return c.finish(ch)
		}
		return c.immediate(ch, store.ReasonRecoveryChanged, without(head, old.ID))
	})
}

// ConfirmRecovery lets a user member confirm the recovery recipient that
// another member entered (K3 point 3): confirm is shown the fingerprint
// of recovery/<recovery-id>.pub of the newest epoch's recipient; only
// after that does this device wrap new epochs for it.
func (c *Client) ConfirmRecovery(mbx store.ID, confirm func(fingerprint string) bool) error {
	if err := c.writable(); err != nil {
		return err
	}
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return err
	}
	if ch.err != nil {
		return ch.err
	}
	head, _ := ch.head()
	if head == nil {
		return fmt.Errorf("%w: no epochs", store.ErrChain)
	}
	m, ok := recoveryMember(head)
	if !ok {
		return fmt.Errorf("%w: %s has no recovery recipient", ErrRecovery, mbx)
	}
	_, raw, err := c.st.ReadRecoveryPub(mbx, m.ID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRecovery, err)
	}
	if confirm == nil || !confirm(store.FingerprintOf(raw)) {
		return fmt.Errorf("%w: fingerprint not confirmed", ErrRecovery)
	}
	c.mailboxState(mbx).Recovery[m.ID.String()] = recordHash(raw)
	return c.save()
}

// RecoverRead opens mailbox mbx with the recovery seed words (Q1 (d)):
// the returned client unwraps the epochs from members/recovery.wrap,
// lists and reads mails and folders, and changes nothing (ErrReadOnly).
// Its state is kept in memory only (first contact, 2.7). The recovery
// recipient is the one of the chain whose recovery/<id>.pub holds the
// keys derived from the seed; every wrap is checked like a member's
// (signed by a user member of its epoch, keys equal to epoch.rec).
// The words are normalized like every word input (2.2 "Eingabe von
// Wörtern", S11: NFKD, lower case, any white space), then they must be
// exactly words of the list (keys.SeedFromWords).
func RecoverRead(cfg Config, mbx store.ID, words []string) (*Client, error) {
	if err := cfg.checkReader(); err != nil {
		return nil, err
	}
	if !cfg.Log.Verified() {
		cfg.Warn(translog.Warning)
	}
	// TODO(phase3-translog): tree head with witness signature at most 24 hours old (2.3).
	if err := cfg.Log.CheckFresh(cfg.Now()); err != nil {
		return nil, err
	}
	normalized, err := normalizeList(words)
	if err != nil {
		return nil, err
	}
	seed, err := keys.SeedFromWords(normalized)
	if err != nil {
		return nil, err
	}
	defer seed.Zero()
	u := keys.DeriveUser(seed)
	defer u.Zero()
	identity, err := u.IdentityKey(store.RecoveryGen)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(identity)
	unwrap, err := u.UnwrapKey(store.RecoveryGen)
	if err != nil {
		return nil, err
	}
	c := &Client{cfg: cfg, st: cfg.Store, rk: &recoveryKey{unwrap: unwrap}, state: &state{Mailboxes: map[string]*mailboxState{}},
		ingest: map[uint32]ingestKey{}, epochKeys: map[epochRef]*store.EpochKeys{}}
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, err
	}
	idPub := identity.Public().(ed25519.PublicKey)
	for i := len(ch.epochs) - 1; i >= 0 && c.rk.id.IsZero(); i-- {
		m, ok := recoveryMember(ch.epochs[i])
		if !ok {
			continue
		}
		p, _, err := c.st.ReadRecoveryPub(mbx, m.ID)
		if err == nil && p.UnwrapPub.Equal(unwrap.PublicKey()) && p.IdentityPub.Equal(idPub) {
			c.rk.id = m.ID
		}
	}
	if c.rk.id.IsZero() {
		return nil, fmt.Errorf("%w: no recovery recipient of %s matches the seed", ErrRecovery, mbx)
	}
	c.me = c.rk.id
	return c, nil
}
