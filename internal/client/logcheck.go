package client

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Checks against the client log (task 14; translog doc.go "Tasks" point
// 14 and the table of open phase-3 sites).

// refreshLog refreshes the client log (logConn.refresh) and, when the
// reference head changed, forgets the cached ingest keys (whose validity
// depends on the certificates of the tree); it writes the checkpoints
// that are due (2.7, doc.go "Client checkpoints", writeCheckpoints).
func (c *Client) refreshLog() error {
	changed, err := c.lg.refresh()
	if err != nil {
		return err
	}
	if changed {
		c.mu.Lock()
		c.ingest = map[uint32]ingestKey{}
		c.mu.Unlock()
	}
	c.writeCheckpoints()
	return nil
}

// checkOwnUser checks the own user.rec local against the log at Open
// (CheckUser). An answer "not in the log" (ErrNotInLog, not ErrPending)
// is tried once more after a rebuild of the audit index (task 14b point
// 7: an index damaged in a way its checks do not see) and then once more
// after appending the record again (task 14b point 5: Append is
// idempotent, so this repairs an own entry that an earlier run lost, and
// it can log nothing but this registered user.rec); only then does Open
// fail. ErrPending is refreshed by checkUser itself.
func (c *Client) checkOwnUser(local []byte) error {
	err := c.checkUser(c.me, local)
	if !errors.Is(err, translog.ErrNotInLog) || errors.Is(err, translog.ErrPending) {
		return err
	}
	if rerr := c.lg.rebuildIndex(); rerr != nil {
		return errors.Join(err, rerr)
	}
	if err = c.checkUser(c.me, local); !errors.Is(err, translog.ErrNotInLog) || errors.Is(err, translog.ErrPending) {
		return err
	}
	c.warn("WARNUNG: Die eigene user.rec fehlt im Transparenzlog; sie wird erneut eingetragen.")
	if _, aerr := c.lg.appendRecord(translog.KindUser, local); aerr != nil {
		return errors.Join(err, aerr)
	}
	return c.checkUser(c.me, local)
}

// ready reports ErrLog unless the reference head is fresh (CheckFresh;
// 2.3: a client whose last verified head with witness signatures is
// older than 24 hours, or that sees an own entry withheld, processes no
// new signatures). A head that is not fresh is refreshed once first.
// Every read and change of a mailbox runs it (loadChain).
func (c *Client) ready() error {
	c.addrRefreshed = false
	c.lg.mu.Lock()
	err := c.lg.log.CheckFresh(c.cfg.Now())
	c.lg.mu.Unlock()
	if err == nil {
		return nil
	}
	return c.refreshLog()
}

// logged runs a check of the client log. An entry beyond the reference
// head (ErrPending) is checked once more after a Refresh: the next head
// may cover it. Every other answer is final (fail closed).
func (c *Client) logged(check func(translog.Log) error) error {
	err := check(c.lg.log)
	if errors.Is(err, translog.ErrPending) {
		if rerr := c.refreshLog(); rerr != nil {
			return rerr
		}
		err = check(c.lg.log)
	}
	return err
}

// checkUser checks a user.rec of the data directory against the log
// (CheckUser, 2.7): own and foreign. A user.rec that a newer logged one
// supersedes is outdated (ErrSuperseded): a warning says so, and it is
// not used.
func (c *Client) checkUser(id store.ID, raw []byte) error {
	err := c.logged(func(l translog.Log) error { return l.CheckUser(id, raw) })
	if errors.Is(err, translog.ErrSuperseded) {
		c.warn("WARNUNG: user.rec von %s ist veraltet: das Transparenzlog enthält eine neuere; sie wird nicht verwendet.", id)
		if id == c.me {
			// The own user.rec of the data directory is rolled back.
			return fmt.Errorf("%w: %w: %w", ErrUserRecord, ErrSuperseded, err)
		}
		return fmt.Errorf("%w: %w", ErrSuperseded, err)
	}
	return err
}

// withMailboxLock runs f under the lock of mailbox mbx: directly when
// the running change holds it (mutate) or the test skips the lock,
// otherwise it takes the lock for f (lock order mailbox, log: f appends
// to the log, which takes log/lock inside).
func (c *Client) withMailboxLock(mbx store.ID, f func() error) error {
	if c.skipLock || (c.locked == mbx && c.mbxUnlock != nil) {
		return f()
	}
	unlock, err := c.st.LockMailbox(mbx)
	if err != nil {
		return err
	}
	defer unlock()
	return f()
}

// withoutLock releases the lock of mailbox mbx that the running change
// holds, runs f and takes the lock again: store.ReplaceEpoch takes the
// lock itself and must not be called under it (the lock is not
// reentrant within a process, translog doc.go "Who writes").
func (c *Client) withoutLock(mbx store.ID, f func() error) error {
	if c.mbxUnlock == nil {
		return f()
	}
	c.mbxUnlock()
	c.mbxUnlock = nil
	err := f()
	unlock, lerr := c.st.LockMailbox(mbx)
	if lerr != nil {
		return errors.Join(err, lerr)
	}
	c.mbxUnlock = unlock
	return err
}

// epochLogged checks that epoch.rec data of epoch e is in the log
// (CheckEpoch, 2.7; K2 rule 4: of two epochs with one number the first
// logged one is the only valid one). An epoch.rec without a valid log
// entry (ErrNotInLog, not ErrPending) is appended by this member itself
// (translog doc.go "Unlogged epoch.rec", logEpoch) under the mailbox
// lock, then checked again; the result of a failed append (ErrOrder:
// it can never be logged; ErrDuplicate: another epoch with this number
// is logged) is returned. A client opened with RecoverRead changes
// nothing and appends nothing.
func (c *Client) epochLogged(e *store.Epoch, data []byte) error {
	return contradicts(c.epochLoggedErr(e, data))
}

// contradicts marks ErrMismatch and ErrDuplicate of the log for an
// epoch.rec with errEpochContradicts: another epoch with this number is
// logged.
func contradicts(err error) error {
	if errors.Is(err, translog.ErrMismatch) || errors.Is(err, translog.ErrDuplicate) {
		return fmt.Errorf("%w: %w", errEpochContradicts, err)
	}
	return err
}

func (c *Client) epochLoggedErr(e *store.Epoch, data []byte) error {
	check := func(l translog.Log) error { return l.CheckEpoch(e.MailboxID, e.Number, data) }
	err := c.logged(check)
	if !errors.Is(err, translog.ErrNotInLog) || errors.Is(err, translog.ErrPending) || c.rk != nil {
		return err
	}
	if err := c.withMailboxLock(e.MailboxID, func() error { return c.logEpoch(e.MailboxID, e.Number, data) }); err != nil {
		return err
	}
	return c.logged(check)
}

// logEpoch appends epoch.rec data (epoch n of mbx) to the log, as the
// creator of an epoch n > 1 does after writing it and as every member
// does for an epoch.rec found without a log entry (translog doc.go "Who
// writes", "Unlogged epoch.rec" steps 1 and 2, and "Tasks" 14 (a)). The
// caller holds the mailbox lock (lock order mailbox, log). On
// ErrUnloggedSigner (checked first, it is an ErrPrerequisite) the
// signer's user.rec of the data directory is appended (logSigner), on any
// other ErrPrerequisite the missing earlier epochs of the mailbox from
// the data directory (logEarlier), and then data again. A signer's
// user.rec that cannot yield the generation makes data unloggable
// (translog.ErrOrder). Every other error is returned as it is (fail
// closed: nothing may be replaced for it).
func (c *Client) logEpoch(mbx store.ID, n uint32, data []byte) error {
	return c.logEpochFill(mbx, n, data, true)
}

func (c *Client) logEpochFill(mbx store.ID, n uint32, data []byte, fill bool) error {
	signer, earlier := false, false
	for {
		_, err := c.lg.appendRecord(translog.KindEpoch, data)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, translog.ErrUnloggedSigner) && !signer:
			signer = true
			if err := c.logSigner(data); err != nil {
				return err
			}
		case errors.Is(err, translog.ErrPrerequisite) && !errors.Is(err, translog.ErrUnloggedSigner) && fill && !earlier && n > 1:
			earlier = true
			if err := c.logEarlier(mbx, n); err != nil {
				return err
			}
		default:
			return err
		}
	}
}

// logSigner appends users/<signer>/user.rec of the data directory for
// the epoch.rec data (translog doc.go "Unlogged epoch.rec" step 2): it
// is checked by the validity rules like every append, so it cannot log
// anything the signer did not sign. If that cannot yield the generation
// signer_gen (user.rec missing or not decoding, its append fails with
// ErrOrder or ErrPrerequisite, or it holds fewer generations), the epoch
// can never be logged: translog.ErrOrder.
func (c *Client) logSigner(data []byte) error {
	e, err := store.DecodeEpoch(data)
	if err != nil {
		return fmt.Errorf("%w: %v", translog.ErrOrder, err)
	}
	raw, err := store.ReadFileLimited(c.st.UserFile(e.SignerID), store.MaxUserFile)
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrTooLarge) {
		return fmt.Errorf("%w: user.rec of the signer is missing", translog.ErrOrder)
	}
	if err != nil {
		return err
	}
	u, err := store.DecodeUser(raw)
	if err != nil || u.ID != e.SignerID {
		return fmt.Errorf("%w: user.rec of the signer does not decode", translog.ErrOrder)
	}
	_, err = c.lg.appendRecord(translog.KindUser, raw)
	if errors.Is(err, translog.ErrOrder) || errors.Is(err, translog.ErrPrerequisite) {
		return fmt.Errorf("%w: user.rec of the signer cannot be logged: %v", translog.ErrOrder, err)
	}
	if err != nil {
		return err
	}
	if uint64(len(u.Generations)) < uint64(e.SignerGen) {
		return fmt.Errorf("%w: user.rec of the signer has no generation %d", translog.ErrOrder, e.SignerGen)
	}
	return nil
}

// logEarlier appends the epochs of mbx after the newest one in the log
// up to n-1 from the data directory (translog doc.go "Unlogged
// epoch.rec" step 1), each with its signer; an epoch that is missing or
// cannot be logged ends it with that error.
func (c *Client) logEarlier(mbx store.ID, n uint32) error {
	ents, err := c.lg.log.Lookup(translog.KindEpoch, mbx[:])
	if err != nil {
		return err
	}
	from := uint32(1)
	for _, e := range ents {
		if e.Seq >= int64(from) && e.Seq < int64(n) {
			from = uint32(e.Seq) + 1
		}
	}
	for k := from; k < n; k++ {
		data, err := store.ReadFileLimited(c.st.EpochFile(mbx, k), store.MaxRecordFile)
		if err != nil {
			return fmt.Errorf("%w: epoch %d: %v", translog.ErrPrerequisite, k, err)
		}
		if err := c.logEpochFill(mbx, k, data, false); err != nil {
			return err
		}
	}
	return nil
}

// newestLoggedEpoch returns the number of the newest valid epoch entry of
// mbx in the log (Lookup, translog doc.go "Tasks" table: the head of
// mailbox.rec is compared with it), 0 if none.
func (c *Client) newestLoggedEpoch(mbx store.ID) (uint32, error) {
	ents, err := c.lg.log.Lookup(translog.KindEpoch, mbx[:])
	if err != nil {
		return 0, err
	}
	var n uint32
	for _, e := range ents {
		if e.Seq > int64(n) && e.Seq <= int64(^uint32(0)) {
			n = uint32(e.Seq)
		}
	}
	return n, nil
}

// checkpointMark names the reference head h and generation gen of a
// written checkpoint (state.Checkpointed): the generation and the
// SHA-256 of the signed note.
func checkpointMark(h *translog.Head, gen uint32) string {
	sum := sha256.Sum256(h.Note)
	return fmt.Sprintf("%d:%s", gen, hex.EncodeToString(sum[:]))
}

// writeCheckpoints writes this client's checkpoint
// (checkpoints/<user>-<device>.rec, 2.7 "Abgleich zwischen Clients", 3.7
// "checkpoint") with its reference head into every mailbox of the local
// state whose head epoch names this user as a user member (translog
// doc.go "Client checkpoints": origin, size, root, head time and the
// current generation, signed with its identity), unless the checkpoint
// of that mailbox was already written for this head and generation
// (state.Checkpointed, task 14b point 4: so Open writes it after Restore
// and DeviceLost as well, which change no head). A failure only warns: a
// missing checkpoint weakens the comparison, it hides nothing; it is
// tried again at the next refresh.
func (c *Client) writeCheckpoints() {
	if c.rk != nil || c.ks == nil {
		return
	}
	h := c.lg.head()
	if h == nil {
		return
	}
	mark := checkpointMark(h, c.ks.Generation)
	var due []store.ID
	for _, mbx := range c.Mailboxes() {
		if c.state.Checkpointed[mbx.String()] != mark {
			due = append(due, mbx)
		}
	}
	if len(due) == 0 {
		return
	}
	dev, err := c.device()
	if err != nil {
		c.warn("WARNUNG: Der Vermerk des Baumkopfs wird nicht geschrieben: keine Geräte-ID.")
		return
	}
	changed := false
	for _, mbx := range due {
		m, err := c.st.ReadMailbox(mbx)
		if err != nil {
			continue
		}
		e, _, err := c.st.ReadEpoch(mbx, m.Epoch)
		if err != nil {
			continue
		}
		if _, ok := e.Member(c.me); !ok {
			continue
		}
		cp := &store.Checkpoint{UserID: c.me, DeviceID: dev, Origin: h.Origin, Size: h.Size, RootHash: h.Hash,
			HeadTime: h.Time, UserGen: c.ks.Generation}
		if err = cp.Sign(c.ks.Identity); err == nil {
			err = c.st.WriteCheckpoint(mbx, cp)
		}
		if err != nil {
			c.warn("WARNUNG: Der Vermerk des Baumkopfs für %s wurde nicht geschrieben.", mbx)
			continue
		}
		if c.state.Checkpointed == nil {
			c.state.Checkpointed = map[string]string{}
		}
		c.state.Checkpointed[mbx.String()] = mark
		changed = true
	}
	if changed {
		if err := c.save(); err != nil {
			c.warn("WARNUNG: Der Zustand nach dem Schreiben der Vermerke wurde nicht gespeichert.")
		}
	}
}

// errIgnored marks a checkpoint that says nothing about the log and is
// ignored with a warning (translog doc.go "Client checkpoints", rules 1
// to 4 for the caller).
var errIgnored = errors.New("client: checkpoint ignored")

// checkCheckpoints checks the checkpoints of the other clients and
// devices in the mailbox of the verified chain ch against the reference
// head (Verifier.CheckCheckpoint, 2.7 "Abgleich zwischen Clients"). A
// checkpoint that contradicts it shows that the server showed the two
// clients different logs: a warning, and ErrLog, which stops the
// processing (split view). A checkpoint that fails a rule for the caller
// is ignored with a warning. Each file is checked once per reference
// head.
//
// A checkpoint beyond the reference head (ErrPending, task 14b point 1)
// makes this client refresh, once per call (one chain load), and compare
// again: one that stays larger shows that another member saw a newer
// head than the server shows here, a warning on every operation (it is
// not remembered as seen); one signed before the reference head is
// ErrConsistency (CheckCheckpoint: entries withheld from this client),
// which stops the processing like a split view.
//
// TODO(Q20): a checkpoint of another user (a user member, rule 2) that
// agrees with the reference head clears the mark Unconfirmed of Restore.
func (c *Client) checkCheckpoints(ch *chain) error {
	head, _ := ch.head()
	last := c.lg.head()
	if head == nil || last == nil {
		return nil
	}
	mbx := ch.mailbox.ID
	refs, err := c.st.ListCheckpoints(mbx)
	if err != nil {
		return nil
	}
	if c.cpSeen == nil {
		c.cpSeen = map[string]string{}
	}
	refreshed := false
	for _, ref := range refs {
		if ref.User == c.me && ref.Device.String() == c.state.Device {
			continue
		}
		data, err := store.ReadFileLimited(c.st.CheckpointFile(mbx, ref.User, ref.Device), store.MaxRecordFile)
		if err != nil {
			continue
		}
		key := mbx.String() + "/" + ref.User.String() + "-" + ref.Device.String()
		seenOf := func() string {
			sum := sha256.Sum256(append(append([]byte(nil), data...), last.Note...))
			return hex.EncodeToString(sum[:])
		}
		if c.cpSeen[key] == seenOf() {
			continue
		}
		err = c.checkCheckpoint(head, ref, data)
		if errors.Is(err, translog.ErrPending) && !refreshed {
			// The next head may cover it: refresh once and compare again.
			refreshed = true
			if rerr := c.refreshLog(); rerr != nil {
				return rerr
			}
			if last = c.lg.head(); last == nil {
				return nil
			}
			err = c.checkCheckpoint(head, ref, data)
		}
		seen := seenOf()
		switch {
		case err == nil:
			c.cpSeen[key] = seen
			if ref.User != c.me {
				c.confirmed(mbx, ref.User)
			}
		case errors.Is(err, translog.ErrPending):
			// Still beyond the reference head after a refresh: not
			// remembered as seen, compared again on the next operation.
			c.warn("WARNUNG: Ein Mitglied hat einen neueren Kopf gesehen, den der Server hier nicht zeigt (Vermerk von %s, Gerät %s, in %s). Der Server hält diesem Client möglicherweise Einträge vor (2.7).", ref.User, ref.Device, mbx)
		case errors.Is(err, translog.ErrConsistency):
			c.warn("WARNUNG: Der Vermerk von %s (Gerät %s) in %s widerspricht dem eigenen Baumkopf: der Server zeigt den Clients verschiedene Logs oder hält einem von ihnen Einträge vor (2.7). Die Verarbeitung wird eingestellt.", ref.User, ref.Device, mbx)
			return fmt.Errorf("%w: split view: checkpoint of %s in %s: %w", ErrLog, ref.User, mbx, err)
		default:
			c.cpSeen[key] = seen
			c.warn("WARNUNG: Ein Vermerk in %s (Gerät %s) wird ignoriert: %s.", mbx, ref.Device, checkpointCause(err))
		}
	}
	return nil
}

// confirmed clears the mark Unconfirmed of Restore once a checkpoint of
// another user member, user, in mailbox mbx agreed with the reference
// head (TODO(Q20), task 14b point 6: the strictest reading; a witnessed
// head alone does not clear it).
func (c *Client) confirmed(mbx, user store.ID) {
	if !c.state.Unconfirmed || c.rk != nil {
		return
	}
	c.state.Unconfirmed = false
	if err := c.save(); err != nil {
		c.state.Unconfirmed = true
		return
	}
	c.warn("Hinweis: Der wiederhergestellte Zustand ist jetzt mit dem Vermerk eines anderen Mitglieds (%s in %s) abgeglichen.", user, mbx)
}

// checkpointCause is the fixed cause of an ignored checkpoint.
func checkpointCause(err error) string {
	switch {
	case errors.Is(err, errNotMember):
		return "kein Benutzer-Mitglied der Kopfepoche"
	case errors.Is(err, translog.ErrSuperseded):
		return "nicht die aktuelle Generation des Benutzers"
	case errors.Is(err, translog.ErrNotInLog):
		return "Generation nicht im Transparenzlog"
	case errors.Is(err, errBadSignature):
		return "Signatur ungültig"
	default:
		return "Format oder Baumkopf ungültig"
	}
}

var (
	errNotMember    = errors.New("client: checkpoint of a non-member")
	errBadSignature = errors.New("client: checkpoint signature")
)

// checkCheckpoint applies the rules for the caller of
// Verifier.CheckCheckpoint (translog doc.go "Client checkpoints") to the
// checkpoint file data of ref, then CheckCheckpoint itself:
//
//  1. it decodes strictly and names exactly the user and device of its
//     file name;
//  2. its user is a user member of head, the head of the verified chain;
//  3. its generation is the current one of the user according to the
//     log: the user entry (user, gen) is valid and no entry (user,
//     gen+1) is (ErrSuperseded);
//  4. the signature verifies with the identity key of that generation
//     from the logged user entry.
func (c *Client) checkCheckpoint(head *store.Epoch, ref store.CheckpointRef, data []byte) error {
	cp, err := store.DecodeCheckpoint(data)
	if err != nil {
		return fmt.Errorf("%w: %v", errIgnored, err)
	}
	if cp.UserID != ref.User || cp.DeviceID != ref.Device {
		return fmt.Errorf("%w: file name", errIgnored)
	}
	if _, ok := head.Member(cp.UserID); !ok {
		return errNotMember
	}
	if err := c.logged(func(l translog.Log) error { return l.CheckGeneration(cp.UserID, cp.UserGen) }); err != nil {
		if errors.Is(err, translog.ErrPending) {
			// The generation is not covered even after a refresh: the
			// checkpoint is ignored, not taken as one beyond the head.
			return fmt.Errorf("%w: %w: generation not yet covered", errIgnored, translog.ErrNotInLog)
		}
		return err
	}
	ents, err := c.lg.log.Lookup(translog.KindUser, cp.UserID[:])
	if err != nil {
		return err
	}
	var entry *translog.Entry
	for i := range ents {
		if ents[i].Seq > int64(cp.UserGen) {
			return fmt.Errorf("%w: generation %d of the checkpoint is revoked", translog.ErrSuperseded, cp.UserGen)
		}
		if ents[i].Seq == int64(cp.UserGen) {
			entry = &ents[i]
		}
	}
	if entry == nil {
		return fmt.Errorf("%w: user entry", translog.ErrNotInLog)
	}
	u, err := store.DecodeUser(entry.Content)
	if err != nil {
		return fmt.Errorf("%w: %v", errIgnored, err)
	}
	g := u.Generation(cp.UserGen)
	if g == nil || cp.Verify(g.IdentityPub) != nil {
		return errBadSignature
	}
	c.lg.mu.Lock()
	defer c.lg.mu.Unlock()
	last := c.lg.v.Last
	var proof tlog.TreeProof
	if last != nil && cp.Size >= 1 && cp.Size < last.Size {
		if proof, err = c.lg.log.ConsistencyProof(cp.Size, last.Size); err != nil {
			return err
		}
	}
	return c.lg.v.CheckCheckpoint(cp.Origin, cp.Size, cp.RootHash, cp.HeadTime, proof)
}
