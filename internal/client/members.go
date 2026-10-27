package client

import (
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// Members of a mailbox (2.5, K1, K2, K3, QUESTIONS Q1 and Q6).
//
// Every change of the members is an epoch with immediate effect (2.4):
// it begins now, discards exactly the epochs of the chain that are not
// discarded and begin later (rule 1), carries a wrap for every member
// (users and delegates with the current generation of their user.rec,
// and the recovery recipient) and folders.gml with the current name and
// folders. After it the supply is created again from its members (rule
// 5). The order of the writes follows DECISIONS D57 and D61: wraps and
// folders.gml before epoch.rec, every epoch before mailbox.rec, mailbox.rec
// last; a change interrupted at any point is completed or cleaned up by
// running it (or Sync) again.

// maxEpochAttempts bounds how often a change is created anew after
// another client wrote an epoch with the same number first (K2 rule 3).
const maxEpochAttempts = 3

// crashHook simulates a process crash at a named point. It is nil in
// production and set only by tests of this package: when it returns true,
// the operation stops immediately and leaves everything as a killed
// process would (no cleanup, no state saved).
var crashHook func(point string) bool

// errCrashed is returned after a simulated crash.
var errCrashed = errors.New("client: simulated crash")

func crash(point string) bool { return crashHook != nil && crashHook(point) }

// ErrArgument reports an invalid argument of a change (a share with
// oneself, an unknown user, an invalid folder list).
var ErrArgument = errors.New("client: invalid argument")

// mutate runs op under the mailbox lock on the verified chain, which must
// be complete (a chain that did not verify is never extended, D57). If op
// loses the race for an epoch number (errRace: another client wrote that
// epoch first, K2 rule 3, or an epoch.rec that did not verify is kept,
// errKept), the chain is verified again and op runs again on the basis
// of the winner, at most maxEpochAttempts times in all. An
// epoch.rec after the chain that can never become valid is replaced by the
// change (createEpoch, task 06c); after the last attempt the error names
// the cause of that attempt.
func (c *Client) mutate(mbx store.ID, op func(ch *chain) error) error {
	if err := c.writable(); err != nil {
		return err
	}
	if !c.skipLock {
		unlock, err := c.st.LockMailbox(mbx)
		if err != nil {
			return err
		}
		defer unlock()
	}
	defer func() { c.next = nil }()
	for attempt := 1; ; attempt++ {
		c.created, c.next = nil, nil
		ch, err := c.loadChain(mbx, true)
		if err != nil {
			return err
		}
		c.next = ch.next
		if ch.err != nil {
			return ch.err
		}
		if len(ch.epochs) == 0 {
			return fmt.Errorf("%w: no epochs", store.ErrChain)
		}
		err = op(ch)
		if !errors.Is(err, errRace) {
			return err
		}
		// K2 rule 3: the epoch written first under the mailbox lock wins;
		// the loser creates its change again on the basis of the winner.
		// TODO(phase3-translog): K2 rule 4, the order in the transparency
		// log replaces "first written".
		if attempt >= maxEpochAttempts {
			return fmt.Errorf("client: no epoch of %s written in %d attempts, last attempt: %w", mbx, attempt, err)
		}
		if !errors.Is(err, errKept) {
			c.warn("Hinweis: Ein anderer Client hat zugleich eine Epoche von %s angelegt; die Änderung wird auf ihrer Grundlage neu angelegt.", mbx)
		}
	}
}

// currentGeneration returns the current generation of user id and its
// unwrap key from users/<id>/user.rec (2.2), checked against the log.
func (c *Client) currentGeneration(id store.ID) (uint32, *ecdh.PublicKey, error) {
	if id == c.me && c.ks != nil {
		return c.ks.Generation, c.ks.Unwrap.PublicKey(), nil
	}
	u, raw, err := c.st.ReadUser(id)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: user.rec of %s: %v", ErrArgument, id, err)
	}
	// TODO(phase3-translog): user.rec in the log, generation valid only
	// from its log entry on (2.2 rule 3).
	if err := c.cfg.Log.CheckUser(id, raw); err != nil {
		return 0, nil, err
	}
	g := u.Current()
	if err := c.cfg.Log.CheckGeneration(id, g.Gen); err != nil {
		return 0, nil, err
	}
	return g.Gen, g.UnwrapPub, nil
}

// resolveMembers returns the members of a new epoch with the keys their
// wraps are sealed for: users and delegates with the current generation
// of their user.rec (2.4 "für den aktuellen Entpackschlüssel"), the
// recovery recipient with the record confirmed on this device.
func (c *Client) resolveMembers(mbx store.ID, list []store.Member) ([]newMember, error) {
	out := make([]newMember, 0, len(list))
	for _, m := range list {
		if m.Kind == store.MemberRecovery {
			p, err := c.confirmedRecovery(mbx, m.ID)
			if err != nil {
				return nil, err
			}
			out = append(out, newMember{Member: store.Member{Kind: m.Kind, ID: m.ID, Gen: store.RecoveryGen}, unwrap: p.UnwrapPub})
			continue
		}
		gen, pub, err := c.currentGeneration(m.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, newMember{Member: store.Member{Kind: m.Kind, ID: m.ID, Gen: gen}, unwrap: pub})
	}
	return out, nil
}

// memberEntry returns the entry of id in e, whatever its kind.
func memberEntry(e *store.Epoch, id store.ID) (store.Member, bool) {
	for _, m := range e.Members {
		if m.ID == id {
			return m, true
		}
	}
	return store.Member{}, false
}

// without returns the members of e except id.
func without(e *store.Epoch, id store.ID) []store.Member {
	out := make([]store.Member, 0, len(e.Members))
	for _, m := range e.Members {
		if m.ID != id {
			out = append(out, m)
		}
	}
	return out
}

// mayCreate reports ErrNotMember unless this client is a user member of
// the head of ch, the only one allowed to sign the next epoch (K2 rule 1,
// store.Chain rule 5).
func (c *Client) mayCreate(ch *chain) error {
	head, _ := ch.head()
	if !c.isUserMember(head) {
		return fmt.Errorf("%w: not a user member of epoch %d of %s", ErrNotMember, head.Number, ch.mailbox.ID)
	}
	return nil
}

// immediate creates the epoch with immediate effect after the head of ch
// (2.4): begin now, the given reason and members, discards complete
// (rule 1), then the supply after it (rule 5) and mailbox.rec.
func (c *Client) immediate(ch *chain, reason store.Reason, members []store.Member) error {
	mbx := ch.mailbox.ID
	head, headData := ch.head()
	nm, err := c.resolveMembers(mbx, members)
	if err != nil {
		return err
	}
	now := c.cfg.Now().UnixMilli()
	folders := c.currentFolders(ch)
	e, d, err := c.createEpoch(mbx, head.Number+1, now, reason, headData, nm, ch.discardsAfter(now), folders)
	if err != nil {
		return err
	}
	if crash("immediate") {
		return errCrashed
	}
	if e, d, err = c.supply(mbx, e, d, folders); err != nil {
		return err
	}
	if crash("supply") {
		return errCrashed
	}
	return c.commitHead(ch, e, d)
}

// finish completes an interrupted change whose epoch already exists: the
// supply after the head and mailbox.rec.
func (c *Client) finish(ch *chain) error {
	head, headData := ch.head()
	e, d, err := c.supply(ch.mailbox.ID, head, headData, c.currentFolders(ch))
	if err != nil {
		return err
	}
	return c.commitHead(ch, e, d)
}

// commitHead writes mailbox.rec with head, the last file of every change
// (DECISIONS D57, D61), and remembers head as the highest epoch seen.
func (c *Client) commitHead(ch *chain, head *store.Epoch, headData []byte) error {
	if head.Number != ch.mailbox.Epoch {
		m := *ch.mailbox
		m.Epoch = head.Number
		if err := c.st.WriteMailbox(&m); err != nil {
			return err
		}
	}
	if crash("mailbox") {
		return errCrashed
	}
	ms := c.mailboxState(ch.mailbox.ID)
	for _, list := range [][]*store.Epoch{ch.epochs, c.created} {
		for _, e := range list {
			if e.Number <= head.Number {
				c.remember(ms, []*store.Epoch{e})
			}
		}
	}
	c.created = nil
	ms.Epoch, ms.EpochHash = head.Number, hashHex(headData)
	return c.save()
}

// wrapExisting creates wraps for m in the epochs from..to of ch (2.5 "Ein
// bestehendes Mitglied entpackt die Epochenschlüssel und verpackt sie für
// das neue Mitglied"). Epochs that are discarded are skipped (2.4 rule 3),
// and so are epochs this user is not a user member of: a reader accepts a
// wrap only from a user member of its epoch. An existing wrap is never
// replaced. It returns, in ascending order, the epochs that have a wrap for
// m afterwards and the epochs that are not discarded but were skipped.
func (c *Client) wrapExisting(ch *chain, m newMember, from, to uint32) (wrapped, skipped []uint32, err error) {
	mbx := ch.mailbox.ID
	for n := from; n != 0 && n <= to; n++ {
		e := ch.epoch(n)
		if e == nil || ch.discarded[n] {
			continue
		}
		if !c.isUserMember(e) {
			c.warn("Hinweis: Epoche %d von %s wird nicht weitergegeben: dieser Benutzer ist dort kein Mitglied.", n, mbx)
			skipped = append(skipped, n)
			continue
		}
		k, err := c.keysFor(ch, e)
		if err != nil {
			c.warn("Hinweis: Epoche %d von %s wird nicht weitergegeben: %v", n, mbx, err)
			skipped = append(skipped, n)
			continue
		}
		plain, err := k.Encode()
		if err != nil {
			return wrapped, skipped, err
		}
		err = c.createWrap(mbx, n, m, plain)
		keys.Wipe(plain)
		if err != nil && !errors.Is(err, store.ErrExists) {
			return wrapped, skipped, err
		}
		wrapped = append(wrapped, n)
		if crash("wrap-existing") {
			return wrapped, skipped, errCrashed
		}
		if n == ^uint32(0) {
			break
		}
	}
	return wrapped, skipped, nil
}

// ShareOptions selects the epochs of a share (2.5, 9.2 "--from", "--to").
type ShareOptions struct {
	// From is the first existing epoch the user gets (0: none of the
	// existing epochs if To is open, epoch 1 if To is set).
	From uint32
	// To is the last epoch of a past period (0: open, the user becomes a
	// member from now on). A set To must lie before the epoch in force
	// now: a period that includes the running epoch or the future would
	// need a planned end, which M1 does not build.
	To uint32
	// Delegate makes the user a delegate (member kind 3) instead of a
	// member (kind 1) when To is open: it gets the wraps of every epoch
	// from now on but never creates epochs or writes folders.gml.
	// TODO(Q6): kind 3 is the strictest reading of QUESTIONS Q6.
	Delegate bool
}

// Share gives user access to the mailbox (2.5):
//
//  1. wraps of the existing epochs From..To that are not discarded, for
//     the user's current generation and signed with this user's identity;
//  2. if To is open, an epoch member-added with immediate effect that has
//     the user as a member (kind 1) or delegate (kind 3), and the supply
//     after it.
//
// For a past period (To set) only the wraps are written: the user is
// never a member of these epochs, so K2 rule 1 holds structurally. Only a
// user member of the newest epoch shares. Running Share again completes
// an interrupted share; wraps that exist are never replaced.
//
// Share returns the existing epochs of step 1, in ascending order, that
// have a wrap for the user afterwards (written now or by an earlier run).
// The epochs of step 2 are not listed: the user is a member of them and
// gets its wrap with each of them. If a requested epoch that is not
// discarded could not be wrapped (this user is not a user member of it, or
// its keys are not available), the share is still completed and the error
// is ErrPartial, naming the skipped epochs; the wraps written stay. If no
// epoch of a past period could be wrapped at all, the error is ErrWrap.
func (c *Client) Share(mbx, user store.ID, opts ShareOptions) ([]uint32, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	if user == c.me {
		return nil, fmt.Errorf("%w: a member cannot share a mailbox with itself", ErrArgument)
	}
	gen, pub, err := c.currentGeneration(user)
	if err != nil {
		return nil, err
	}
	kind := store.MemberUser
	if opts.Delegate {
		kind = store.MemberDelegate
	}
	target := newMember{Member: store.Member{Kind: kind, ID: user, Gen: gen}, unwrap: pub}
	var wrapped, skipped []uint32
	err = c.mutate(mbx, func(ch *chain) error {
		// Only the result of the last attempt counts (K2 rule 3).
		wrapped, skipped = nil, nil
		if err := c.mayCreate(ch); err != nil {
			return err
		}
		head, _ := ch.head()
		if m, ok := memberEntry(head, user); ok && m.Kind == store.MemberRecovery {
			return fmt.Errorf("%w: %s is the recovery recipient", ErrArgument, user)
		}
		now := c.cfg.Now().UnixMilli()
		cur := ch.current(now)
		if cur == nil {
			return fmt.Errorf("%w: no epoch of %s has begun", ErrEpoch, mbx)
		}
		from, to := opts.From, opts.To
		if to != 0 {
			if from == 0 {
				from = 1
			}
			if from > to || to >= cur.Number {
				return fmt.Errorf("%w: %d to %d, the epoch in force is %d", ErrRange, from, to, cur.Number)
			}
		} else if from > cur.Number {
			return fmt.Errorf("%w: from %d, the epoch in force is %d", ErrRange, from, cur.Number)
		}
		if from != 0 {
			// Only epochs that have begun: the immediate epoch below
			// discards every later one.
			last := to
			if last == 0 {
				last = cur.Number
			}
			var err error
			wrapped, skipped, err = c.wrapExisting(ch, target, from, last)
			if err != nil {
				return err
			}
			if to != 0 && len(wrapped) == 0 {
				return fmt.Errorf("%w: no epoch of %d to %d could be wrapped", ErrWrap, from, to)
			}
		}
		if crash("share-wraps") {
			return errCrashed
		}
		if to != 0 {
			return nil
		}
		if m, ok := memberEntry(head, user); ok {
			if m.Kind != kind {
				return fmt.Errorf("%w: %s is already a member of another kind", ErrArgument, user)
			}
			// Already a member: an interrupted share is completed.
			return c.finish(ch)
		}
		members := append(append([]store.Member(nil), head.Members...), target.Member)
		return c.immediate(ch, store.ReasonMemberAdded, members)
	})
	if err == nil && len(skipped) > 0 {
		err = fmt.Errorf("%w: epochs %v of %s", ErrPartial, skipped, mbx)
	}
	return wrapped, err
}

// Revoke withdraws the access of user (2.5 "Zugriff entziehen"): its wraps
// of every epoch that is not discarded are deleted, then an epoch with
// immediate effect without it begins (member-removed, or delegation-ended
// for a delegate) and discards the supply, which is created again without
// it (K1). Mails it has already read stay with it; that cannot be
// prevented. A member never revokes itself: the removing epoch must come
// from a remaining member (K2 rule 2), and the last user member stays.
// Running Revoke again completes an interrupted revocation.
func (c *Client) Revoke(mbx, user store.ID) error {
	if err := c.writable(); err != nil {
		return err
	}
	return c.mutate(mbx, func(ch *chain) error {
		head, _ := ch.head()
		if user == c.me {
			users := 0
			for _, m := range head.Members {
				if m.Kind == store.MemberUser {
					users++
				}
			}
			if users <= 1 && c.isUserMember(head) {
				return fmt.Errorf("%w: the last user member of %s", ErrSelfRevoke, mbx)
			}
			return fmt.Errorf("%w: K2 rule 2", ErrSelfRevoke)
		}
		if err := c.mayCreate(ch); err != nil {
			return err
		}
		m, listed := memberEntry(head, user)
		if listed && m.Kind == store.MemberRecovery {
			return fmt.Errorf("%w: %s is the recovery recipient (ClearRecovery)", ErrArgument, user)
		}
		for _, e := range ch.epochs {
			if ch.discarded[e.Number] {
				continue
			}
			if err := store.RemoveDurable(c.st.WrapFile(ch.mailbox.ID, e.Number, user)); err != nil {
				return err
			}
		}
		if crash("revoke-wraps") {
			return errCrashed
		}
		if !listed {
			// Not a member (any more): a reader of a past period, or an
			// interrupted revocation whose epoch exists.
			return c.finish(ch)
		}
		reason := store.ReasonMemberRemoved
		if m.Kind == store.MemberDelegate {
			reason = store.ReasonDelegationEnded
		}
		return c.immediate(ch, reason, without(head, user))
	})
}
