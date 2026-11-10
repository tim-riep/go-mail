package client

import (
	"bytes"
	"cmp"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Device lost (2.2 "Generationen" points 2 to 5, 2.4 generation-revoked,
// K1 point 4, task 06b A).

// warnDeviceLostPending is shown when Open finds an interrupted device
// lost.
const warnDeviceLostPending = "WARNUNG: Ein Gerätewechsel (device lost) wurde unterbrochen: user.rec nennt bereits die neue Generation, der Schlüsselspeicher noch die alte. Bitte device lost mit dem Seed erneut ausführen."

// extendsUser reports whether the encoded user.rec remote extends local
// by exactly one generation (same user and root, the generations of local
// byte for byte): the state of a device lost interrupted after
// store.ReplaceUser.
func extendsUser(local *store.User, remote []byte) bool {
	r, err := store.DecodeUser(remote)
	if err != nil || r.ID != local.ID || !r.RootPub.Equal(local.RootPub) || len(r.Generations) != len(local.Generations)+1 {
		return false
	}
	return sameGenerations(local.Generations, r.Generations[:len(local.Generations)])
}

// sameGenerations reports whether a and b are the same certificates.
func sameGenerations(a, b []*keys.GenerationCert) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, err1 := a[i].Encode()
		y, err2 := b[i].Encode()
		if err1 != nil || err2 != nil || !bytes.Equal(x, y) {
			return false
		}
	}
	return true
}

// DeviceLost creates the next generation of the user after the loss of a
// device (2.2 "Generationen", gomailctl device lost). It needs the seed
// words (normalized like every word input, S11) and the passphrase of the
// key store in cfg.Dir, which holds the generation g that the lost device
// held as well; the new key store gets the same passphrase. It returns
// the new generation g+1. In this order:
//
//  1. The root is derived from the seed for a moment and must be the root
//     of the user (ErrSeed, nothing written); identity and unwrap key of
//     g+1 are derived, the certificate of g+1 (which revokes g) is signed
//     by the root, and user.rec is signed again by the root (store.User.Sign).
//     Seed and root are wiped right after.
//  2. While g is still valid, every own wrap of every mailbox is checked
//     with the key store of g (keysFor) and countersigned by g+1
//     (members/<me>.accept, wrap-accept), and folders.gml of every epoch
//     with access, every index segment of these epochs and the metadata of
//     every mail that this user signed (a flag change) are checked (check
//     records in state.json): after the revocation these are the proofs
//     that the client checked them before (2.2 rule 4). A failure on a
//     file of the data directory here (a directory where a wrap-accept,
//     the index or the mails belong, an unreadable directory) never stops
//     the revocation (task 09c): the mailbox is warned about with a fixed
//     cause and marked, the result is ErrPartial, and the files not
//     checked are not taken over afterwards.
//  3. users/<id>/user.rec is replaced (store.ReplaceUser) and appended to
//     the log (record first, then log entry, translog doc.go "Who writes").
//  4. For every mailbox, in two parts that do not depend on each other
//     (reissue): first the files outside the log: the own wraps are
//     sealed again for g+1 from the old ones (opened with the old key
//     store) and countersigned, then every file that g signed is issued
//     again with g+1: wraps that this user made for the members the
//     signed epoch.rec names and for the confirmed recovery recipient,
//     each only after the old wrap checked with the old key store
//     (checkTemplate); folders.gml of every epoch signed by a revoked
//     generation (taken over through the check record of step 2); the
//     metadata of every mail signed by a revoked generation, as version +
//     1 (checkMeta, resignMeta), and every index segment signed by one, as
//     a new segment of this device (readSegments, resignSegment), each
//     taken over through the check record of step 2 or of an earlier
//     check, task 09b; a file without such a record is warned about and
//     left. Here, unlike in Search, List and Read, a file taken over that
//     cannot be signed again, and metadata signed by a revoked generation
//     that do not check, make the mailbox incomplete (task 09d:
//     errNotReissued, mark, ErrPartial, a warning that it was not issued
//     again); Sync goes on with them while the mailbox is marked
//     (syncGenerations). Wraps of readers of past periods are not issued again: their
//     template is signed by the revoked generation g (reissueTarget,
//     TODO(Q15)). Then an epoch generation-revoked with immediate effect
//     names (me, g+1), discards the supply (K1 point 4) and the supply is
//     created again.
//  5. user.rec in cfg.Dir, and as the very last step the key store with
//     g+1, which replaces the old one.
//
// The mailboxes worked on are those of the local state and every other
// mailbox of the data directory this user is a member of or holds a wrap
// in and whose chain verifies (adoptMemberships, like Restore): a mailbox
// never opened on this device gets its epoch generation-revoked as well.
//
// In step 4 the own wraps are opened with the key store of the generation
// they are made for (the old one, or one derived from the seed for an
// older generation), and an own wrap made for and signed by such a
// generation counts because the seed proves it (seedProof); its keys must
// equal epoch.rec. So a mailbox whose chain did not check in step 2 (no
// wrap-accept of g+1) keeps its access: step 2 warns, names the cause and
// marks it, step 4 or the continuation seal its wraps again for g+1.
//
// A crash at any point loses no access: until step 5 the old key store
// stays, Open reports ErrDeviceLostPending once user.rec names g+1, and
// running DeviceLost again with the seed completes every step (each one
// is idempotent). A mailbox whose files cannot all be issued again (the
// recovery recipient is not confirmed on this device, its chain is
// broken, ...) does not stop the others, and in a mailbox a failure of
// one part of step 4 does not stop the other; the key store is still
// replaced, the mailbox is marked in the local state (mailboxState.Reissue)
// and the error is ErrPartial naming the mailboxes and the remedy (with
// ErrRecovery: ConfirmRecovery, then Sync). Sync completes it (2.2 point
// 5: every user member issues again what a revoked generation signed,
// syncGenerations), and so does DeviceLost run again with the seed while
// a mailbox is marked (task 14, 06h point 1): every DeviceLost creates
// the next generation (2.2 point 2: the device with g+1 may be lost as
// well, so it must always be revocable), and step 4 of that run works on
// the marked mailboxes like on every other one, with the new generation
// and the earlier ones derived from the seed. A mark therefore never
// keeps the user from revoking a generation: a mailbox that stays marked
// (a strawman membership without a wrap, a chain that does not check)
// only makes the result ErrPartial again. A mailbox whose mailbox.rec no
// longer exists in the data directory (store.ErrNotFound) gets no new
// mark, keeps an existing one and makes the result ErrPartial; its local
// state stays as it is (mailboxState: no path makes
// that memory smaller); a warning names it. Other members wrap their
// epochs for g+1 on their next Sync (2.2 point 5).
func DeviceLost(cfg Config, passphrase []byte, seedWords []string) (uint32, error) {
	if err := cfg.check(); err != nil {
		return 0, err
	}
	if len(passphrase) == 0 {
		return 0, fmt.Errorf("client: empty passphrase")
	}
	words, err := normalizeList(seedWords)
	if err != nil {
		return 0, err
	}
	seed, err := keys.SeedFromWords(words)
	if err != nil {
		return 0, err
	}
	defer seed.Zero()
	c, local, remote, err := openForDeviceLost(cfg, passphrase)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if c.marked() {
		c.warn("Hinweis: Für vorgemerkte Postfächer wird die Neuausstellung mit der neuen Generation fortgesetzt.")
	}
	old := c.ks
	gen := old.Generation + 1
	next, err := nextGeneration(c, seed, local, remote, gen)
	if err != nil {
		return 0, err
	}
	nks := next.ks
	defer nks.Zero()
	// The earlier generations from the seed, for the own wraps and the
	// templates they made (a marked mailbox of an earlier run, an
	// interrupted run, a mailbox that step 2 could not prepare).
	prev, err := seedGenerations(seed, next.user, gen, old)
	if err != nil {
		return 0, err
	}
	defer zeroAll(prev)
	// Failures on files of the data directory before the revocation never
	// stop it (task 09c, 06h finding b): they are warned about, marked
	// and make the result ErrPartial.
	var steps stepFailures
	if err := c.adoptMemberships(); errors.Is(err, errNotListed) {
		steps.unlisted = true
	} else if err != nil {
		return 0, err
	}
	ksData, err := nks.Seal(passphrase, nil)
	if err != nil {
		return 0, err
	}
	defer keys.Wipe(ksData)

	// Step 4 of this run compares the own files with what it finds, and
	// with the segments step 2 checked (task 09f).
	c.checkedOwn = map[store.ID]*ownFiles{}
	defer func() { c.checkedOwn = nil }()
	fresh := remote.Current().Gen == old.Generation
	if fresh {
		// Step 2, while generation g is valid.
		c.noAccept, c.noTakeover = true, true
		for _, mbx := range c.Mailboxes() {
			checked, err := c.prepareDeviceLost(mbx, nks)
			if err != nil {
				return 0, err
			}
			if !checked {
				steps.unchecked = append(steps.unchecked, mbx)
			}
		}
		c.noAccept, c.noTakeover = false, false
		if crash("devicelost-prepared") {
			return 0, errCrashed
		}
		// Step 3.
		if _, err := c.st.ReplaceUser(next.user); err != nil {
			return 0, err
		}
		if crash("devicelost-user") {
			return 0, errCrashed
		}
	}
	// user.rec with generation g+1 into the log (record first, then log
	// entry: translog doc.go "Who writes"); the generation is valid only
	// from then on (2.2 rule 3). Appending is idempotent, so a resumed run
	// appends again; the pending entry is in state.json before anything
	// relies on it.
	if _, err := c.lg.appendRecord(translog.KindUser, next.data); err != nil {
		return 0, err
	}
	if crash("devicelost-logged") {
		return 0, errCrashed
	}
	// Step 4 with the new generation; the old key store and the earlier
	// generations derived from the seed open the old wraps and check the
	// templates they signed.
	c.prevKs, c.ks = append([]*keys.Keystore{old}, prev...), nks
	defer func() { c.ks, c.prevKs = old, nil }()
	out, err := c.reissueAll(c.Mailboxes(), gen)
	if err != nil {
		return 0, err
	}
	// A mailbox that step 2 could not check completely stays marked, also
	// if step 4 completed it.
	for _, mbx := range steps.unchecked {
		if ms, ok := c.state.Mailboxes[mbx.String()]; ok {
			ms.Reissue = gen
		}
	}
	out.steps = steps
	// The marks of the mailboxes not completed are saved before the key
	// store of g+1 replaces the old one.
	if err := c.save(); err != nil {
		return 0, err
	}
	// Step 5.
	if err := store.WritePrivateFileAtomic(cfg.userPath(), next.data); err != nil {
		return 0, err
	}
	if crash("devicelost-local") {
		return 0, errCrashed
	}
	if err := keys.WriteKeystoreFile(cfg.keystorePath(), ksData); err != nil {
		return 0, err
	}
	if err := c.save(); err != nil {
		return gen, err
	}
	return gen, out.err()
}

// reissueOutcome is the result of step 4 of DeviceLost over all mailboxes.
type reissueOutcome struct {
	failed   []string // mailboxes whose files were not all issued again
	recovery bool     // one of them for want of a confirmed recovery record
	// noFolders are the failed mailboxes of a sole user member without a
	// checked folder list of the epoch (Q18): no remedy at present.
	noFolders []string
	// steps are the failures before the revocation (step 2 and the
	// adoption of memberships).
	steps stepFailures
}

// stepFailures are the failures on files of the data directory before
// the revocation (task 09c): they never stop it, and make the result of
// DeviceLost ErrPartial.
type stepFailures struct {
	// unchecked are the mailboxes that step 2 could not check
	// completely: a file not checked has no check record and is not
	// taken over after the revocation (fail closed).
	unchecked []store.ID
	// unlisted reports that the mailboxes of the data directory could
	// not be listed (adoptMemberships): only those of the local state
	// were worked on.
	unlisted bool
}

// errNotListed is the fixed cause of a data directory whose mailboxes
// cannot be listed (adoptMemberships).
var errNotListed = errors.New("client: the mailboxes of the data directory cannot be listed")

// err returns ErrPartial naming the mailboxes not completed and the
// remedy, with ErrRecovery if a recovery record must be confirmed first,
// joined with ErrPartial for the failures before the revocation; nil if
// every mailbox is complete and nothing failed before.
func (o *reissueOutcome) err() error {
	var errs []error
	if err := o.failedErr(); err != nil {
		errs = append(errs, err)
	}
	if len(o.steps.unchecked) > 0 {
		list := make([]string, 0, len(o.steps.unchecked))
		for _, id := range o.steps.unchecked {
			list = append(list, id.String())
		}
		sort.Strings(list)
		errs = append(errs, fmt.Errorf("%w: mailboxes %s were not completely checked before the revocation; files not checked then are not taken over", ErrPartial, strings.Join(list, ", ")))
	}
	if o.steps.unlisted {
		errs = append(errs, fmt.Errorf("%w: %w; only the mailboxes known on this device were worked on", ErrPartial, errNotListed))
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return errors.Join(errs...)
}

// failedErr is the part of err for the mailboxes step 4 did not complete.
func (o *reissueOutcome) failedErr() error {
	if len(o.failed) == 0 {
		return nil
	}
	sort.Strings(o.failed)
	list := strings.Join(o.failed, ", ")
	if o.recovery {
		return fmt.Errorf("%w: %w: files of mailboxes %s not issued again; confirm the recovery recipient on this device (ConfirmRecovery), then Sync", ErrPartial, ErrRecovery, list)
	}
	if len(o.noFolders) == len(o.failed) {
		return fmt.Errorf("%w: the epoch generation-revoked of mailboxes %s is not created: %w", ErrPartial, list, errNoCheckedFolders)
	}
	if len(o.noFolders) > 0 {
		sort.Strings(o.noFolders)
		return fmt.Errorf("%w: files of mailboxes %s not issued again; Sync or device lost run again completes it, except for %s: %w", ErrPartial, list, strings.Join(o.noFolders, ", "), errNoCheckedFolders)
	}
	return fmt.Errorf("%w: files of mailboxes %s not issued again; Sync or device lost run again completes it", ErrPartial, list)
}

// reissueAll runs step 4 of DeviceLost (reissue) for the mailboxes boxes
// with the new generation gen in c.ks and the old ones in c.prevKs, and
// marks every mailbox not completed with gen (mailboxState.Reissue) and
// clears the mark of every completed one; the caller saves the state. A
// mailbox whose mailbox.rec is not in the data directory
// (store.ErrNotFound) gets no new mark, but an existing mark stays (task
// 14, 06h point 2: the head may still name the revoked generation, and
// hiding mailbox.rec must not make the continuation look complete), and
// it is counted as not completed (ErrPartial). Since every DeviceLost
// creates a new generation, a mark never blocks a further one. Its local
// state stays complete (task 06h): the highest epoch seen, the discarded
// epochs, the check records, the recovery record and the versions keep
// protecting it if it is put back, rolled back or not (mailboxState). A
// simulated crash is returned as the error.
func (c *Client) reissueAll(boxes []store.ID, gen uint32) (*reissueOutcome, error) {
	out := &reissueOutcome{}
	for _, mbx := range boxes {
		if _, err := c.st.ReadMailbox(mbx); errors.Is(err, store.ErrNotFound) {
			out.failed = append(out.failed, mbx.String())
			c.warn("WARNUNG: %s fehlt im Datenverzeichnis (mailbox.rec nicht gefunden); die Dateien werden nicht neu ausgestellt. Eine bestehende Vormerkung bleibt, eine neue wird nicht gesetzt; der lokale Zustand des Postfachs bleibt erhalten.", mbx)
			continue
		}
		err := c.reissue(mbx)
		if errors.Is(err, errCrashed) {
			return nil, err
		}
		ms := c.mailboxState(mbx)
		if err == nil {
			ms.Reissue = 0
			continue
		}
		ms.Reissue = gen
		out.failed = append(out.failed, mbx.String())
		if errors.Is(err, ErrRecovery) {
			out.recovery = true
			c.warn("WARNUNG: Die Dateien von %s wurden nicht vollständig neu ausgestellt: der Wiederherstellungsempfänger ist auf diesem Gerät nicht bestätigt. Abhilfe: ConfirmRecovery, dann Sync.", mbx)
		} else if errors.Is(err, errNoCheckedFolders) {
			out.noFolders = append(out.noFolders, mbx.String())
			c.warn("WARNUNG: Für %s wird die Epoche zur neuen Generation nicht angelegt: dieser Benutzer ist das einzige Mitglied, das Epochen anlegen kann, und es gibt keine geprüfte Ordnerliste der Epoche (folders.gml ist von einer widerrufenen Generation signiert und wurde vorher nicht geprüft); derzeit keine Abhilfe, siehe Q18.", mbx)
		} else {
			c.warn("WARNUNG: Die Dateien von %s wurden nicht vollständig neu ausgestellt. Abhilfe: Sync oder device lost erneut ausführen.", mbx)
		}
	}
	return out, nil
}

// marked reports whether a mailbox of the local state is marked for the
// continuation of an earlier DeviceLost (mailboxState.Reissue).
func (c *Client) marked() bool {
	for _, mbx := range c.Mailboxes() {
		if c.mailboxState(mbx).Reissue != 0 {
			return true
		}
	}
	return false
}

// seedGenerations derives from seed the key stores of the generations of
// u below gen, except the one have holds (nil: none): the root of seed
// must be the one of u (ErrSeed otherwise), and a generation whose
// certificate names other keys than the derived ones is left out. The
// caller zeroes them (zeroAll). The root is wiped before it returns.
func seedGenerations(seed *keys.Seed, u *store.User, gen uint32, have *keys.Keystore) ([]*keys.Keystore, error) {
	d := keys.DeriveUser(seed)
	defer d.Zero()
	root, err := d.RootKey()
	if err != nil {
		return nil, err
	}
	match := u.RootPub.Equal(root.Public())
	keys.Wipe(root)
	if !match {
		return nil, ErrSeed
	}
	var out []*keys.Keystore
	for _, g := range u.Generations {
		if g.Gen >= gen || (have != nil && g.Gen == have.Generation) || keystoreOf(out, g.Gen) != nil {
			continue
		}
		identity, err := d.IdentityKey(g.Gen)
		if err != nil {
			zeroAll(out)
			return nil, err
		}
		unwrap, err := d.UnwrapKey(g.Gen)
		if err != nil {
			keys.Wipe(identity)
			zeroAll(out)
			return nil, err
		}
		ks := &keys.Keystore{Generation: g.Gen, Identity: identity, Unwrap: unwrap}
		if !g.IdentityPub.Equal(identity.Public()) || !g.UnwrapPub.Equal(unwrap.PublicKey()) {
			ks.Zero()
			continue
		}
		out = append(out, ks)
	}
	return out, nil
}

// keystoreOf returns the key store of generation gen in list, nil if none.
func keystoreOf(list []*keys.Keystore, gen uint32) *keys.Keystore {
	for _, ks := range list {
		if ks.Generation == gen {
			return ks
		}
	}
	return nil
}

// zeroAll zeroes every key store of list.
func zeroAll(list []*keys.Keystore) {
	for _, ks := range list {
		ks.Zero()
	}
}

// adoptMemberships adds to the local state every mailbox of the data
// directory whose head names this user (as a user or delegate) or that
// holds a wrap for it in any epoch (userMailboxes, as for Restore), so
// that DeviceLost works on every membership, also of a mailbox never
// opened on this device: it gets its own wraps sealed again and its epoch
// generation-revoked like every known one. Its chain is trusted on first
// contact (2.7), as for Restore, but it must verify now (verifyChain): a
// mailbox without a valid chain is skipped with a warning and not added,
// so it is never marked (task 06h finding 5; a planted mailbox with a
// broken chain would otherwise block every further generation). The
// entry the check created is removed again; it held nothing remembered
// before this call.
//
// An existing entry is never replaced or touched: the memory of a mailbox
// is never made smaller (mailboxState). If the mailboxes of the data
// directory cannot be listed, it warns and returns errNotListed.
func (c *Client) adoptMemberships() error {
	boxes, err := userMailboxes(c.st, c.me)
	if err != nil {
		// A file of the data directory (task 09c): DeviceLost goes on
		// with the mailboxes of the local state.
		c.warn("WARNUNG: Die Postfächer des Datenverzeichnisses können nicht aufgelistet werden (%s); device lost bearbeitet nur die auf diesem Gerät bekannten Postfächer.", warnCause(err))
		return fmt.Errorf("%w: %w", errNotListed, err)
	}
	for _, id := range boxes {
		if _, ok := c.state.Mailboxes[id.String()]; ok {
			continue
		}
		ch, err := c.verifyChain(id)
		if err != nil || ch.err != nil || len(ch.epochs) == 0 {
			// Created by verifyChain in this call, nothing else holds it.
			delete(c.state.Mailboxes, id.String())
			if err := c.save(); err != nil {
				return err
			}
			c.warn("WARNUNG: %s war auf diesem Gerät noch nicht geöffnet und seine Epochenkette prüft nicht; device lost bearbeitet es nicht und merkt nichts vor.", id)
			continue
		}
		c.mailboxState(id)
		c.warn("Hinweis: %s war auf diesem Gerät noch nicht geöffnet; device lost bearbeitet es wie jedes Postfach dieses Benutzers.", id)
	}
	return nil
}

// openForDeviceLost opens the client directory like Open, but also in the
// states of an interrupted DeviceLost: it returns the client with the old
// key store, the local user.rec and the one of the data directory. Like
// Open it refuses a directory with the marker .incomplete
// (errIncompleteDir, task 20o).
func openForDeviceLost(cfg Config, passphrase []byte) (c *Client, local, remote *store.User, err error) {
	if _, err := os.Stat(cfg.Dir); err != nil {
		return nil, nil, nil, ErrNotRegistered
	}
	if err := refuseIncomplete(cfg.Dir); err != nil {
		return nil, nil, nil, err
	}
	unlock, err := lockClientDir(filepath.Join(cfg.Dir, "lock"))
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if err != nil {
			unlock()
		}
	}()
	st, err := loadState(cfg.statePath())
	if err != nil {
		return nil, nil, nil, err
	}
	me, err := store.ParseID(st.UserID)
	if !st.Registered || err != nil {
		return nil, nil, nil, ErrNotRegistered
	}
	raw, err := store.ReadFileLimited(cfg.userPath(), store.MaxUserFile)
	if err != nil {
		return nil, nil, nil, ErrNotRegistered
	}
	local, err = store.DecodeUser(raw)
	if err != nil || local.ID != me {
		return nil, nil, nil, ErrNotRegistered
	}
	remote, rawRemote, err := cfg.Store.ReadUser(me)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrUserRecord, err)
	}
	c = &Client{cfg: cfg, st: cfg.Store, user: local, me: me, state: st,
		ingest: map[uint32]ingestKey{}, epochKeys: map[epochRef]*store.EpochKeys{}}
	lc, err := openLog(&c.cfg, st, false)
	if err != nil {
		return nil, nil, nil, err
	}
	c.lg = lc
	defer func() {
		if err != nil {
			lc.close()
		}
	}()
	// Once refreshLog (2.7 "bei jedem Sync", task 14b point 12); the key
	// store is not open yet, so no checkpoint is written here: the next
	// Open writes it with the new generation (state.Checkpointed).
	if err := c.refreshLog(); err != nil {
		return nil, nil, nil, err
	}
	// user.rec of the data directory in the log (2.7). After a run
	// interrupted between store.ReplaceUser and its log entry it names
	// the new generation, which is appended on resuming: then the
	// registered user.rec must be the one in the log.
	if err := c.checkUser(me, rawRemote); err != nil {
		if !extendsUser(local, rawRemote) || !errors.Is(err, translog.ErrNotInLog) {
			return nil, nil, nil, err
		}
		if err := c.checkUser(me, raw); err != nil {
			return nil, nil, nil, err
		}
	}
	ksData, err := readKeystore(cfg.keystorePath())
	if err != nil {
		return nil, nil, nil, err
	}
	ks, err := keys.OpenKeystore(ksData, passphrase)
	keys.Wipe(ksData)
	if err != nil {
		return nil, nil, nil, err
	}
	g := local.Generation(ks.Generation)
	if g == nil || !ks.Identity.Public().(ed25519.PublicKey).Equal(g.IdentityPub) || !ks.Unwrap.PublicKey().Equal(g.UnwrapPub) {
		ks.Zero()
		return nil, nil, nil, fmt.Errorf("client: the key store does not hold a generation of the user")
	}
	warnUnconfirmed(cfg, st)
	c.ks, c.unlock = ks, unlock
	return c, local, remote, nil
}

// newGeneration is generation g+1 of DeviceLost: its key store and the
// user.rec that holds it.
type newGeneration struct {
	ks   *keys.Keystore
	user *store.User
	data []byte
}

// nextGeneration derives generation gen = g+1 from seed and returns it
// with the user.rec that holds it. The root of seed must be the user's
// (ErrSeed). If the data directory holds the user.rec of the key store's
// generation g, which must equal the local one, a new certificate is
// signed and user.rec signed again by the root; if it already holds gen
// (a resumed run), its certificate must name exactly the derived keys and
// its earlier generations those of the local user.rec. The root is wiped
// before it returns.
func nextGeneration(c *Client, seed *keys.Seed, local, remote *store.User, gen uint32) (*newGeneration, error) {
	d := keys.DeriveUser(seed)
	defer d.Zero()
	root, err := d.RootKey()
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(root)
	if !local.RootPub.Equal(root.Public()) || !remote.RootPub.Equal(local.RootPub) {
		return nil, ErrSeed
	}
	identity, err := d.IdentityKey(gen)
	if err != nil {
		return nil, err
	}
	unwrap, err := d.UnwrapKey(gen)
	if err != nil {
		keys.Wipe(identity)
		return nil, err
	}
	ks := &keys.Keystore{Generation: gen, Identity: identity, Unwrap: unwrap}
	idPub := identity.Public().(ed25519.PublicKey)
	prev := int(gen - 1)
	// The data directory never holds fewer generations than the client
	// directory (a rolled back user.rec would hide the revocation).
	if len(local.Generations) < prev || len(local.Generations) > len(remote.Generations) ||
		!sameGenerations(local.Generations[:prev], remote.Generations[:min(prev, len(remote.Generations))]) {
		ks.Zero()
		return nil, fmt.Errorf("%w: user.rec of the data directory does not continue the registered one", ErrUserRecord)
	}
	var u *store.User
	switch remote.Current().Gen {
	case gen - 1:
		cert, err := keys.NewGenerationCert(root, gen, idPub, unwrap.PublicKey(), c.cfg.Now().UnixMilli())
		if err != nil {
			ks.Zero()
			return nil, err
		}
		u = &store.User{ID: local.ID, RootPub: local.RootPub, Generations: append(append([]*keys.GenerationCert(nil), remote.Generations...), cert)}
		if err := u.Sign(root); err != nil {
			ks.Zero()
			return nil, err
		}
	case gen:
		g := remote.Current()
		if !g.IdentityPub.Equal(idPub) || !g.UnwrapPub.Equal(unwrap.PublicKey()) {
			ks.Zero()
			return nil, fmt.Errorf("%w: generation %d of user.rec is not derived from this seed", ErrSeed, gen)
		}
		u = remote
	default:
		ks.Zero()
		return nil, fmt.Errorf("%w: user.rec names generation %d, the key store %d", ErrUserRecord, remote.Current().Gen, gen-1)
	}
	data, err := u.Encode()
	if err != nil {
		ks.Zero()
		return nil, err
	}
	return &newGeneration{ks: ks, user: u, data: data}, nil
}

// prepareDeviceLost is step 2 of DeviceLost for mailbox mbx, while the
// generation of the key store is still valid: every own wrap that checks
// is countersigned by the new generation (nks), and folders.gml and the
// index segments of every epoch with access and the metadata this user
// signed are checked, which records them (check records, checkOwnFiles).
// A file that is taken over through an earlier check record is only
// checked here (c.noTakeover): step 4 signs it with g+1, once.
//
// A mailbox that cannot be checked is not skipped silently: a warning
// names it and a fixed cause, and it is marked for the continuation
// (mailboxState.Reissue with the new generation), since its own wraps get
// no wrap-accept of g+1; step 4 and the continuation open them with the
// key store of g, which the seed proves (seedProof). A mailbox whose
// mailbox.rec is not in the data directory (store.ErrNotFound) is not
// marked (step 4 does not mark it either if it is still missing); its
// local state stays. Only mailboxes with a local state are worked on
// here: adoptMemberships adds a mailbox never opened only with a valid
// chain, so a mark always belongs to a remembered or a valid mailbox.
//
// No failure on a file of the data directory stops DeviceLost before the
// revocation (task 09c, 06h finding b): a wrap-accept that cannot be
// written, an index directory, a mail directory or a folder that cannot
// be read, more segments than one run reads. Each is warned about per
// mailbox with a fixed cause, the mailbox is marked, and checked is
// false, which makes the result ErrPartial; the check goes on with the
// other files of the mailbox. A file that was not checked has no check
// record and is not taken over after the revocation (fail closed). Only
// failures on the own local files (state.json) are returned as errors.
func (c *Client) prepareDeviceLost(mbx store.ID, nks *keys.Keystore) (checked bool, err error) {
	ch, err := c.verifyChain(mbx)
	if err != nil || ch.err != nil {
		if _, rerr := c.st.ReadMailbox(mbx); errors.Is(rerr, store.ErrNotFound) {
			c.warn("WARNUNG: %s wird für den Gerätewechsel nicht vorbereitet: mailbox.rec fehlt im Datenverzeichnis.", mbx)
			return true, nil
		}
		cause := "die Epochenkette prüft nicht"
		if err != nil {
			cause = "mailbox.rec ist ungültig oder nicht lesbar"
		}
		c.warn("WARNUNG: %s wird für den Gerätewechsel nicht vorbereitet: %s. Die eigenen Verpackungen werden nicht gegengezeichnet; die Neuausstellung bleibt vorgemerkt (Sync oder device lost erneut ausführen, sobald das Postfach prüft).", mbx, cause)
		c.mailboxState(mbx).Reissue = nks.Generation
		return false, c.save()
	}
	var failed error
	for _, e := range ch.epochs {
		if ch.discarded[e.Number] || !c.ownWrapExists(mbx, e.Number) {
			continue
		}
		k, data, err := c.openOwnWrap(e)
		if err != nil {
			continue
		}
		ref := epochRef{mbx, e.Number}
		c.mu.Lock()
		if c.epochKeys[ref] == nil {
			c.epochKeys[ref] = k
		} else {
			k.Zero()
		}
		c.mu.Unlock()
		if err := c.writeAccept(mbx, e.Number, data, nks); err != nil {
			c.warn("WARNUNG: Die Gegenzeichnung der eigenen Verpackung der Epoche %d von %s für die neue Generation wurde nicht geschrieben: %s.", e.Number, mbx, warnCause(err))
			failed = cmp.Or(failed, err)
		}
		if _, _, _, err := c.foldersAt(ch, e.Number); err != nil {
			c.warn("Hinweis: folders.gml der Epoche %d von %s prüft nicht und wird nicht vermerkt.", e.Number, mbx)
		}
	}
	if err := c.checkOwnFiles(ch); err != nil {
		failed = cmp.Or(failed, err)
	}
	if err := c.saveSeen(); err != nil {
		return false, err
	}
	if failed == nil {
		return true, nil
	}
	c.warn("WARNUNG: %s wurde vor dem Widerruf nicht vollständig geprüft: %s. Der Widerruf wird trotzdem ausgeführt; Dateien, die nicht geprüft wurden, werden danach nicht übernommen. Die Neuausstellung bleibt vorgemerkt.", mbx, warnCause(failed))
	c.mailboxState(mbx).Reissue = nks.Generation
	return false, c.save()
}

// checkOwnFiles is the part of step 2 of DeviceLost for the files that
// readers check one by one (task 09b): every index segment of every epoch
// with access (readSegments records each that checks) and the metadata of
// every mail signed by this user (checkMeta records it). A file that does
// not check is skipped; readSegments warns about it, and so does step 4.
// The records are saved by the caller (saveSeen). A directory that cannot
// be read, or an epoch with more segments than one run reads, does not
// stop the check of the others (task 09c); the first such error is
// returned.
//
// The own segments that check (signed by this user) are noted for step 4
// of the same run (c.checkedOwn, ownFiles, task 09f).
func (c *Client) checkOwnFiles(ch *chain) error {
	mbx := ch.mailbox.ID
	var own *ownFiles
	if c.checkedOwn != nil {
		own = &ownFiles{segments: map[string]uint32{}}
		c.checkedOwn[mbx] = own
	}
	var first error
	for _, e := range ch.epochs {
		if ch.discarded[e.Number] || !c.ownWrapExists(mbx, e.Number) {
			continue
		}
		run, err := c.readSegments(ch, e, false)
		if err == nil && !run.complete {
			err = errSegmentLimit
		}
		first = cmp.Or(first, err)
		if run == nil || own == nil {
			continue
		}
		for _, s := range run.segs {
			if s.signer == c.me {
				own.segments[segmentMemoSum(e.Number, s.ref.Device, s.sum)] = e.Number
			}
		}
	}
	where, err := c.readableMails(mbx)
	first = cmp.Or(first, err)
	for id, folder := range where {
		if signer, _, ok := metaSigner(c.st, mbx, folder, id); ok && signer == c.me {
			c.checkMeta(ch, folder, id)
		}
	}
	return first
}

// ownFiles are the own index segments (signed by this user) of one
// mailbox that step 2 of a DeviceLost run checked (checkOwnFiles, task
// 09f, finding low 2), by the key of the record of their content
// (segmentMemoSum), with their epoch. They live only in memory, for step
// 4 of the same run (missingOwnFiles).
type ownFiles struct {
	segments map[string]uint32
}

// errOwnFileGone is the fixed cause of an own file that this client
// checked before the revocation and that step 4 of DeviceLost did not
// find again (removed, replaced or an older version put back), so it was
// not issued again.
var errOwnFileGone = errors.New("client: an own file checked before the revocation was not found again and not issued again")

// missingOwnFiles is the check of step 4 of a DeviceLost run (task 09f,
// finding low 2: no silent success while a file is hidden) for mailbox
// mbx, after the files signed by a revoked generation were issued again:
//
//   - every own segment that step 2 of the same run checked (ownFiles)
//     must be issued again (the record of its content names a successor:
//     resignSegment, or a merge) or have been found by step 4 (present:
//     then a failure to sign it again is reported already);
//   - every mail whose check record (meta/<id>) still names this user
//     with a revoked generation must be listed and its metadata must
//     check (checkMeta, which also takes them over and signs them again,
//     and which updates the record to the version found): metadata
//     removed or replaced for the whole run are found this way, also
//     without step 2 (a run that continues an interrupted one). Only
//     mails of epochs this user is a user member of with an own wrap
//     count, and none step 4 reported already (reported). A file of an
//     older version than one seen (metaOlder) is not missing (task 09g):
//     as in step 4 itself (task 09f, finding low 3), every reader that
//     saw the newer version rejects it (ErrReplay), and the record, which
//     no check of the older file changes, would make every later
//     DeviceLost end with ErrPartial for as long as the file lies there.
//
// Each file missing is warned about, naming the epoch or the mail ID, and
// the result is errNotReissued, so the mailbox stays marked and DeviceLost
// reports ErrPartial. This never blocks the mark for good: Sync
// (syncGenerations) works without this check, so a file put back is
// issued again there, and one that stays gone leaves nothing signed by
// the revoked generation, which clears the mark (after one Sync). An own
// segment that was hidden for the whole run, step 2 included, is not
// found here: its record cannot tell it from a segment another client
// merged and removed, which is normal. Once it is back, the next Search
// of this client takes it over and signs it again, through its record
// from before the revocation: a segment this client directory wrote has
// that record from the write on (writeSegmentList, noteWritten, task
// 20e), whether this client read it or not; a segment of another client
// directory of this user has it only if this client read it before the
// revocation. A known limit, availability only: the hits are back with
// the next Search.
func (c *Client) missingOwnFiles(ch *chain, where map[store.ID]store.ID, present map[string]bool, reported map[store.ID]bool) error {
	mbx := ch.mailbox.ID
	ms := c.mailboxState(mbx)
	var first error
	if own := c.checkedOwn[mbx]; own != nil {
		names := make([]string, 0, len(own.segments))
		for k := range own.segments {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if m := ms.Checked[k]; m != nil && m.Next != "" || present[k] {
				continue
			}
			c.warn("WARNUNG: Ein eigenes Indexsegment der Epoche %d von %s wurde vor dem Widerruf geprüft, jetzt aber nicht wieder vorgefunden; es wurde nicht neu ausgestellt. Die Neuausstellung bleibt vorgemerkt.", own.segments[k], mbx)
			first = cmp.Or(first, fmt.Errorf("%w: index segment of epoch %d: %w", errNotReissued, own.segments[k], errOwnFileGone))
		}
	}
	stale := func(id store.ID) bool {
		m := ms.Checked[metaMemo(id)]
		return m != nil && m.Signer == c.me.String() && m.Gen < c.ks.Generation
	}
	var ids []store.ID
	for k := range ms.Checked {
		id, err := store.ParseID(strings.TrimPrefix(k, "meta/"))
		if !strings.HasPrefix(k, "meta/") || err != nil || reported[id] || !stale(id) {
			continue
		}
		memo := ms.Mails[id.String()]
		if memo == nil {
			continue
		}
		e, err := ch.usable(memo.Epoch)
		if err != nil || !c.isUserMember(e) || !c.ownWrapExists(mbx, e.Number) {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	for _, id := range ids {
		if folder, ok := where[id]; ok {
			if c.metaOlder(mbx, folder, id) {
				continue
			}
			if _, err := c.checkMeta(ch, folder, id); errors.Is(err, errCrashed) {
				return err
			}
			if !stale(id) {
				continue
			}
		}
		c.warn("WARNUNG: Die Metadaten der Mail %s wurden vor dem Widerruf geprüft, jetzt aber nicht wieder vorgefunden (entfernt oder ersetzt); sie wurden nicht neu ausgestellt. Die Neuausstellung bleibt vorgemerkt.", id)
		first = cmp.Or(first, fmt.Errorf("%w: metadata of mail %s: %w", errNotReissued, id, errOwnFileGone))
	}
	return first
}

// readableMails maps every mail ID of mailbox mbx to the folder that
// holds it, like mailFolders, but a folder directory that cannot be read
// does not hide the mails of the others (task 09c): it returns the mails
// found with the first error.
func (c *Client) readableMails(mbx store.ID) (map[store.ID]store.ID, error) {
	dirs, err := c.st.ListFolders(mbx)
	if err != nil {
		return nil, err
	}
	out := map[store.ID]store.ID{}
	var first error
	for _, d := range dirs {
		ids, err := c.st.ListMails(mbx, d)
		if err != nil {
			first = cmp.Or(first, err)
			continue
		}
		for _, id := range ids {
			out[id] = d
		}
	}
	return out, first
}

// metaSigner returns the user and generation that signed the metadata
// file of mail id, from its trailer and without any check; ok is false if
// the file cannot be read or is not signed by a user.
func metaSigner(st *store.Store, mbx, folder, id store.ID) (store.ID, uint32, bool) {
	data, err := st.ReadMeta(mbx, folder, id)
	if err != nil {
		return store.ID{}, 0, false
	}
	f, err := envelope.Parse(data)
	if err != nil || f.Trailer == nil || f.Trailer.Signer.Type != envelope.SignerUser {
		return store.ID{}, 0, false
	}
	return store.ID(f.Trailer.Signer.ID), f.Trailer.Signer.Gen, true
}

// reissueMetaAndSegments is the part of step 4 of DeviceLost, and of its
// continuation in Sync (syncGenerations), for the metadata and index
// segments of ch that a revoked generation signed (task 09b, 2.2 rule 4):
// reading them takes them over through the check record (checkMeta and
// resignMeta, readSegments and resignSegment), with the current
// generation. Only epochs this user is a user member of are written to.
//
// Unlike in Search, List and Read, a failure here is a failure of the
// mailbox (task 09d, c.reissuing): a segment or metadata file taken over
// that cannot be signed again (errNotReissued), and metadata signed by a
// revoked generation that do not check (a file without a check record
// from before the revocation, ...), each with a warning that names the
// segment or the mail ID and says that it was not issued again; metadata
// that are gone meanwhile are not, and neither is an older version than
// one seen, which every reader rejects anyway (ErrReplay, task 09f), as
// an index segment that fails a check. In a DeviceLost run, an own file
// checked before the revocation that step 4 does not find again is a
// failure as well (missingOwnFiles, task 09f). So are an index
// directory that cannot be read and an epoch with more segments than one
// run reads (task 09c). None of these stops the others: every epoch and
// every mail is worked on, and the first failure is returned, so the
// mailbox stays marked (Reissue) and the result is ErrPartial. A segment
// that fails a check is ignored with a warning, as in every reader, and
// is no failure: anybody with write access to the data directory can put
// such a file there. Spent segments (readSegments) are removed, under the
// mailbox lock the caller's change holds.
func (c *Client) reissueMetaAndSegments(ch *chain, gens genCache) error {
	mbx := ch.mailbox.ID
	c.reissuing = true
	defer func() { c.reissuing = false }()
	var first error
	// present are the contents of the segments that checked, reported the
	// metadata already found not issued again (missingOwnFiles).
	present := map[string]bool{}
	reported := map[store.ID]bool{}
	for _, e := range ch.epochs {
		if ch.discarded[e.Number] || !c.isUserMember(e) || !c.ownWrapExists(mbx, e.Number) {
			continue
		}
		run, err := c.readSegments(ch, e, true)
		if errors.Is(err, errCrashed) {
			return err
		}
		if err == nil && !run.complete {
			err = errSegmentLimit
		}
		if err == nil {
			err = run.notReissued
			for _, s := range run.segs {
				present[segmentMemoSum(e.Number, s.ref.Device, s.sum)] = true
			}
			// Spent files (copies, contents whose successor is there) are
			// removed under the mailbox lock that the change holds, as a
			// merge does: among them a segment signed by the revoked
			// generation whose successor was written and noted before a
			// crash removed it (task 09f).
			for _, r := range run.spent {
				if rerr := c.st.RemoveIndexSegment(mbx, e.Number, r.Device, r.Seq); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
					err = cmp.Or(err, rerr)
				}
			}
		}
		first = cmp.Or(first, err)
	}
	where, err := c.readableMails(mbx)
	first = cmp.Or(first, err)
	ids := make([]store.ID, 0, len(where))
	for id := range where {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	for _, id := range ids {
		folder := where[id]
		signer, gen, ok := metaSigner(c.st, mbx, folder, id)
		if !ok || !c.revokedGen(gens, signer, gen) {
			continue
		}
		_, err := c.checkMeta(ch, folder, id)
		switch {
		case err == nil:
		case errors.Is(err, errCrashed):
			return err
		case c.metaGone(mbx, folder, id):
			// Removed meanwhile: nothing is left to issue again.
		case errors.Is(err, ErrReplay) || c.metaOlder(mbx, folder, id):
			// An older version than one seen, put back (task 09f,
			// finding low 3): every reader that saw the newer one rejects
			// it (Versions), as an index segment that fails a check is
			// ignored; it is warned about and keeps no mark. Signed by a
			// revoked generation, it fails the check record (which names
			// the newer file) before the version is compared, hence the
			// version from its header. If this client checked a newer
			// own version, missingOwnFiles does not report it either
			// (task 09g).
			c.warnRejected(id, "wird nicht neu ausgestellt", fmt.Errorf("%w: %w", ErrReplay, err))
		default:
			c.warnRejected(id, "wird nicht neu ausgestellt", err)
			reported[id] = true
			first = cmp.Or(first, fmt.Errorf("%w: metadata of mail %s: %w", errNotReissued, id, err))
		}
	}
	if c.checkedOwn != nil {
		if err := c.missingOwnFiles(ch, where, present, reported); errors.Is(err, errCrashed) {
			return err
		} else {
			first = cmp.Or(first, err)
		}
	}
	return cmp.Or(c.saveSeen(), first)
}

// metaOlder reports whether the metadata file of mail id in folder names
// in its header a version below the highest this client saw for the mail
// (Versions): a reader that saw the newer one rejects it (ErrReplay),
// whoever signed it. The header is not checked here; a file whose header
// lies fails every reader's check anyway.
func (c *Client) metaOlder(mbx, folder, id store.ID) bool {
	data, err := c.st.ReadMeta(mbx, folder, id)
	if err != nil {
		return false
	}
	f, err := envelope.Parse(data)
	if err != nil || f.Header.Kind != envelope.KindMeta {
		return false
	}
	return f.Header.Version < c.mailboxState(mbx).Versions[id.String()]
}

// metaGone reports whether the metadata file of mail id in folder is no
// longer in the data directory.
func (c *Client) metaGone(mbx, folder, id store.ID) bool {
	_, err := os.Lstat(c.st.MetaFile(mbx, folder, id))
	return errors.Is(err, fs.ErrNotExist)
}

// errRecoveryPending reports that a recovery.wrap signed by the revoked
// generation is not issued again because the recovery record is not
// confirmed on this device.
var errRecoveryPending = fmt.Errorf("%w: recovery.wrap not issued again, the recovery record is not confirmed on this device", ErrRecovery)

// reissue is step 4 of DeviceLost for mailbox mbx (c.ks is the new
// generation, c.prevKs the old one), in two parts that do not depend on
// each other: first the files outside the log (own wraps, wraps of the
// listed recipients and of the recovery recipient, folders.gml), which
// need no recovery record except for recovery.wrap itself, then the epoch
// generation-revoked with the supply, which needs the confirmed recovery
// record if the head names a recovery recipient (resolveMembers). A
// failure of one part does not stop the other; the error joins both, and
// a recovery.wrap left for want of the record is ErrRecovery as well. A
// simulated crash stops at once.
func (c *Client) reissue(mbx store.ID) error {
	recoveryLeft := false
	filesErr := c.mutate(mbx, func(ch *chain) error {
		recoveryLeft = false
		for _, e := range ch.epochs {
			if ch.discarded[e.Number] {
				continue
			}
			if err := c.rewrapOwn(ch, e); err != nil {
				return err
			}
		}
		gens := genCache{}
		for _, e := range ch.epochs {
			if ch.discarded[e.Number] || !c.isUserMember(e) {
				continue
			}
			left, err := c.reissueWraps(ch, e, gens)
			if err != nil {
				return err
			}
			recoveryLeft = recoveryLeft || left
			if err := c.reissueFolders(ch, e, gens); err != nil {
				return err
			}
		}
		return c.reissueMetaAndSegments(ch, gens)
	})
	if errors.Is(filesErr, errCrashed) {
		return filesErr
	}
	epochErr := c.mutate(mbx, func(ch *chain) error {
		head, _ := ch.head()
		if !c.isUserMember(head) {
			c.warn("Hinweis: Für %s legt ein anderes Mitglied die Epoche zur neuen Generation an (dieser Benutzer ist dort kein Mitglied).", mbx)
			return nil
		}
		if m, _ := head.Member(c.me); m.Gen == c.ks.Generation {
			// An earlier run or another member created it already.
			return c.finish(ch)
		}
		// The fixed cause of Q18 (task 14, 06h point 3): a sole user
		// member without a checked folder list cannot create the epoch,
		// and no other member can. TODO(Q18): no way out until Q18 is
		// answered.
		if _, _, err := c.folderList(ch); errors.Is(err, ErrRevoked) && c.soleUserMember(head) {
			return fmt.Errorf("%w: %w", ErrPartial, errNoCheckedFolders)
		}
		return c.immediate(ch, store.ReasonGenerationRevoked, head.Members)
	})
	if errors.Is(epochErr, errCrashed) {
		return epochErr
	}
	if filesErr == nil && epochErr == nil && recoveryLeft {
		return errRecoveryPending
	}
	return errors.Join(filesErr, epochErr)
}

// rewrapOwn seals the own wrap of epoch e again for the current
// generation, from the keys of the old wrap, and countersigns it. A wrap
// that names the current generation already is opened with the new key
// store and checked like every own wrap (signed by a user member of e,
// header at its place, keys equal to epoch.rec: openOwnWrap); only then is
// it left (and countersigned if it is not yet). A file that only claims
// the current generation (planted, or damaged) is sealed again from the
// keys checked in step 2 (c.epochKeys), so it never costs the access to
// the epoch. An epoch this user is not a user member of cannot get a wrap
// signed by it (keysFor accepts only user members), another member does
// it on Sync.
func (c *Client) rewrapOwn(ch *chain, e *store.Epoch) error {
	mbx := ch.mailbox.ID
	data, err := c.st.ReadWrap(mbx, e.Number, c.me)
	if err != nil {
		return nil
	}
	if f, err := envelope.Parse(data); err == nil && len(f.Recipients) == 1 && f.Recipients[0].Gen == c.ks.Generation {
		k, checked, err := c.openOwnWrap(e)
		if err == nil {
			ref := epochRef{mbx, e.Number}
			c.mu.Lock()
			if c.epochKeys[ref] == nil {
				c.epochKeys[ref] = k
			} else {
				k.Zero()
			}
			c.mu.Unlock()
			c.acceptWrap(e, checked)
			return nil
		}
		c.warn("WARNUNG: Die eigene Verpackung der Epoche %d von %s für die neue Generation prüft nicht; sie wird aus den geprüften Schlüsseln neu ausgestellt.", e.Number, mbx)
	}
	if !c.isUserMember(e) {
		c.warn("Hinweis: Die eigene Verpackung der Epoche %d von %s stellt ein Mitglied beim Sync neu aus, sofern sie von einer gültigen Generation signiert ist (dieser Benutzer ist dort kein Mitglied); sonst muss die Freigabe erneut erteilt werden.", e.Number, mbx)
		return nil
	}
	k, err := c.keysFor(ch, e)
	if err != nil {
		c.warn("Hinweis: Die eigene Verpackung der Epoche %d von %s wird nicht neu ausgestellt: sie prüft nicht.", e.Number, mbx)
		return nil
	}
	return c.sealOwn(mbx, e.Number, k, "devicelost-wrap")
}

// sealOwn replaces the own wrap of epoch n of mbx by one of the keys k
// for the current generation, signed by it, and countersigns it; point is
// the name of the simulated crash after the wrap is written.
func (c *Client) sealOwn(mbx store.ID, n uint32, k *store.EpochKeys, point string) error {
	plain, err := k.Encode()
	if err != nil {
		return err
	}
	defer keys.Wipe(plain)
	me := newMember{Member: store.Member{Kind: store.MemberUser, ID: c.me, Gen: c.ks.Generation}, unwrap: c.ks.Unwrap.PublicKey()}
	nd, err := c.sealWrap(mbx, n, me, plain)
	if err != nil {
		return err
	}
	if err := c.st.WriteWrap(mbx, n, c.me, nd); err != nil {
		return err
	}
	if crash(point) {
		return errCrashed
	}
	return c.writeAccept(mbx, n, nd, c.ks)
}

// Wraps issued again for others (device lost, 2.2 point 2; Sync, 2.2
// point 5). The source is never the list of files: a wrap is issued again
// only for a recipient the signed epoch.rec names (users, kind 1, and
// delegates, kind 3; the recovery recipient, kind 2, only with the record
// confirmed on this device), and for a reader of a past period only from
// a template signed by a valid generation (reissueTarget, TODO(Q15)), and
// only after the old wrap checked as its template (checkTemplate): a
// planted file is never a template. The keys
// sealed again are this user's keys of the epoch (keysFor), checked
// against epoch.rec (Matches); the old wrap is not decrypted.

// genInfo is the current generation of a user and its unwrap key, from its
// user.rec, or why it is not available.
type genInfo struct {
	gen uint32
	pub *ecdh.PublicKey
	err error
}

// genCache holds the current generation of each user read during one run,
// so that user.rec is read once per user (currentGeneration).
type genCache map[store.ID]genInfo

func (c *Client) cachedGeneration(gens genCache, id store.ID) (uint32, *ecdh.PublicKey, error) {
	g, ok := gens[id]
	if !ok {
		g.gen, g.pub, g.err = c.currentGeneration(id)
		gens[id] = g
	}
	return g.gen, g.pub, g.err
}

// listedRecipient returns the entry of id in the member list of e as a
// user (kind 1) or delegate (kind 3). A recipient that is not listed is a
// reader of a past period (Share with To, or the epochs before a member
// was added) or no reader at all.
func listedRecipient(e *store.Epoch, id store.ID) (store.Member, bool) {
	for _, m := range e.Members {
		if m.Kind != store.MemberRecovery && m.ID == id {
			return m, true
		}
	}
	return store.Member{}, false
}

// wrapRecipients returns the recipients of the wraps of epoch e other than
// this user, users and delegates: first those of the member list of e,
// then the readers of past periods, whose wrap files are the only trace
// (members/<id>.wrap with an ID the member list does not name).
func (c *Client) wrapRecipients(e *store.Epoch) ([]store.ID, error) {
	var out []store.ID
	for _, m := range e.Members {
		if m.Kind != store.MemberRecovery && m.ID != c.me {
			out = append(out, m.ID)
		}
	}
	dir := filepath.Join(c.st.EpochDir(e.MailboxID, e.Number), "members")
	entries, err := store.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return nil, err
	}
	for _, ent := range entries {
		name := ent.Name()
		if !ent.Type().IsRegular() || !strings.HasSuffix(name, ".wrap") || name == "recovery.wrap" {
			continue
		}
		id, err := store.ParseID(strings.TrimSuffix(name, ".wrap"))
		if err != nil || id == c.me {
			continue
		}
		if _, listed := listedRecipient(e, id); !listed {
			out = append(out, id)
		}
	}
	return out, nil
}

// templateKey resolves the identity key of generation gen of signer for
// checkTemplate and reports whether that generation is revoked.
type templateKey func(signer store.ID, gen uint32) (ed25519.PublicKey, bool, error)

// memberKey is the templateKey of Sync: the key of any generation of the
// signer's user.rec, and whether it is revoked.
func (c *Client) memberKey(signer store.ID, gen uint32) (ed25519.PublicKey, bool, error) {
	g, revoked, err := c.userGen(signer, gen)
	if err != nil {
		return nil, false, err
	}
	return g.IdentityPub, revoked, nil
}

// oldGenKey is the templateKey of DeviceLost: only this user's revoked
// generations whose key stores DeviceLost holds (prevGen: g of the old
// key store, earlier ones derived from the seed), which user.rec already
// names as revoked.
func (c *Client) oldGenKey(signer store.ID, gen uint32) (ed25519.PublicKey, bool, error) {
	p := c.prevGen(gen)
	if p == nil || signer != c.me {
		return nil, false, fmt.Errorf("%w: wrap not signed by a generation of the old key stores", ErrSigner)
	}
	return p.Identity.Public().(ed25519.PublicKey), true, nil
}

// checkTemplate checks the wrap data of epoch e, found at the place of
// recipient id (members/<id>.wrap, or recovery.wrap for type recovery),
// before it serves as the template of a new wrap: the header matches its
// place (kind wrap, mailbox, epoch, file ID id, suite of e), it has exactly
// one recipient of type rt and ID id, and it is signed by a user member
// of e with a generation not below the one the member list names for it,
// verified with the key that key returns. It returns the parsed file and
// whether the signer's generation is revoked.
func checkTemplate(e *store.Epoch, data []byte, rt envelope.RecipientType, id store.ID, key templateKey) (*envelope.File, bool, error) {
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrWrap, err)
	}
	h := f.Header
	if f.Suite != e.Suite || h.Kind != envelope.KindWrap || store.ID(h.MailboxID) != e.MailboxID || h.Epoch != e.Number || store.ID(h.FileID) != id {
		return nil, false, fmt.Errorf("%w: wrap header does not match its location", ErrMismatch)
	}
	if len(f.Recipients) != 1 || f.Recipients[0].Type != rt || store.ID(f.Recipients[0].ID) != id {
		return nil, false, fmt.Errorf("%w: wrap recipient does not match its location", ErrMismatch)
	}
	t := f.Trailer
	if t == nil || t.Signer.Type != envelope.SignerUser {
		return nil, false, fmt.Errorf("%w: wrap not signed by a user", ErrSigner)
	}
	signer := store.ID(t.Signer.ID)
	if m, ok := e.Member(signer); !ok || t.Signer.Gen < m.Gen {
		return nil, false, fmt.Errorf("%w: wrap not signed by a user member of epoch %d", ErrSigner, e.Number)
	}
	pub, revoked, err := key(signer, t.Signer.Gen)
	if err != nil {
		return nil, false, err
	}
	if err := f.VerifySignature(pub, nil); err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrSigner, err)
	}
	return f, revoked, nil
}

// errPastReader marks a reader of a past period whose wrap is no template
// signed by a valid generation (TODO(Q15)): the sharing member shares
// again (Revoke, then Share).
var errPastReader = errors.New("client: reader of a past period without a template of a valid generation")

// errRemovedMember marks a recipient the member list of the epoch names
// but the head of the chain no longer does, whose template is signed by a
// revoked generation: whoever holds that generation's key store (the
// thief) can make such a template for a removed member.
var errRemovedMember = errors.New("client: template of a revoked generation for a recipient the head does not name")

// reissueTarget decides whether the wrap data of epoch e for user id, a
// user, delegate or reader of a past period, may be issued again, and
// returns the member it is issued for: id with the current generation of
// its user.rec. The old wrap must check as the template (checkTemplate
// with key). For a recipient of the member list of e the recipient's
// generation must lie between the listed one and the current one (a wrap
// issued again before names a later generation than the list), and a
// template signed by a revoked generation counts only if head, the head of
// the chain, names the recipient as well (errRemovedMember otherwise): a
// member removed since e is still listed in e, and the thief of a revoked
// generation can sign a template for it. Revoke deletes the wraps of a
// removed member, so it has no genuine one to be issued again. For a
// reader of a past period, who is in no member list, the strictest
// reading holds (TODO(Q15)): the wrap must be signed by a valid (not
// revoked) generation of a user member of e; otherwise errPastReader. No
// wrap-accept counts as proof here: the reader can sign one for any
// file, and a template signed by a revoked generation can be made by
// whoever holds its key store (the thief).
func (c *Client) reissueTarget(head, e *store.Epoch, id store.ID, data []byte, gens genCache, key templateKey) (newMember, error) {
	gen, pub, err := c.cachedGeneration(gens, id)
	if err != nil {
		return newMember{}, err
	}
	f, revoked, err := checkTemplate(e, data, envelope.RecipientUserUnwrap, id, key)
	if err != nil {
		return newMember{}, err
	}
	r := f.Recipients[0]
	m := newMember{Member: store.Member{Kind: store.MemberUser, ID: id, Gen: gen}, unwrap: pub}
	if entry, listed := listedRecipient(e, id); listed {
		if r.Gen < entry.Gen || r.Gen > gen {
			return newMember{}, fmt.Errorf("%w: wrap for generation %d, the member list names %d", ErrMismatch, r.Gen, entry.Gen)
		}
		if revoked {
			if head == nil {
				return newMember{}, errRemovedMember
			}
			if _, still := listedRecipient(head, id); !still {
				return newMember{}, errRemovedMember
			}
		}
		m.Kind = entry.Kind
		return m, nil
	}
	if r.Gen > gen {
		return newMember{}, fmt.Errorf("%w: wrap for generation %d, user.rec names %d", ErrMismatch, r.Gen, gen)
	}
	if revoked {
		return newMember{}, fmt.Errorf("%w: the template is signed by a revoked generation", errPastReader)
	}
	return m, nil
}

// warnNotReissued warns that the wrap of epoch e for id is not issued
// again; it names IDs and numbers only.
func (c *Client) warnNotReissued(e *store.Epoch, id store.ID, err error) {
	if errors.Is(err, errPastReader) {
		c.warn("WARNUNG: Die Verpackung der Epoche %d von %s für %s (Leser eines vergangenen Zeitraums) wird nicht neu ausgestellt: keine Vorlage einer gültigen Generation. Die Freigabe muss erneut erteilt werden (Revoke, dann Share).", e.Number, e.MailboxID, id)
		return
	}
	if errors.Is(err, errRemovedMember) {
		c.warn("WARNUNG: Die Verpackung der Epoche %d von %s für %s wird nicht neu ausgestellt: die Vorlage ist von einer widerrufenen Generation signiert und der Kopf der Kette nennt den Empfänger nicht mehr.", e.Number, e.MailboxID, id)
		return
	}
	c.warn("WARNUNG: Die Verpackung der Epoche %d von %s für %s wird nicht neu ausgestellt: sie ist keine geprüfte Verpackung eines Mitglieds dieser Epoche.", e.Number, e.MailboxID, id)
}

// signedByOldGen is the stale test of DeviceLost: a file signed by this
// user with a generation below the one of the key store.
func (c *Client) signedByOldGen(signer store.ID, gen uint32) bool {
	return signer == c.me && gen < c.ks.Generation
}

// revokedGen reports whether generation gen of signer is older than the
// current one of its user.rec (this user: of the key store): a signature
// of a revoked generation. An unreadable user.rec counts as not revoked,
// so nothing is issued again from it.
func (c *Client) revokedGen(gens genCache, signer store.ID, gen uint32) bool {
	cur, _, err := c.cachedGeneration(gens, signer)
	return err == nil && gen < cur
}

// reissueWraps seals every wrap of epoch e that this user signed with a
// generation of the old key stores again with the current one, for the
// current generation of its recipient (reissueTarget with oldGenKey: the
// old signature is checked with the old key store; such a template is
// signed by a revoked generation, so a recipient of the member list of e
// must be named by the head of the chain as well), and recovery.wrap
// (reissueRecovery). A wrap signed by someone else or already by the
// current generation is left. It reports whether recovery.wrap was left
// for want of the confirmed recovery record or of the epoch keys.
func (c *Client) reissueWraps(ch *chain, e *store.Epoch, gens genCache) (bool, error) {
	mbx := ch.mailbox.ID
	head, _ := ch.head()
	ids, err := c.wrapRecipients(e)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		data, err := c.st.ReadWrap(mbx, e.Number, id)
		if err != nil {
			continue
		}
		f, err := envelope.Parse(data)
		if err != nil || f.Trailer == nil {
			continue
		}
		if t := f.Trailer.Signer; t.Type != envelope.SignerUser || !c.signedByOldGen(store.ID(t.ID), t.Gen) {
			continue
		}
		m, err := c.reissueTarget(head, e, id, data, gens, c.oldGenKey)
		if err != nil {
			c.warnNotReissued(e, id, err)
			continue
		}
		if _, err := c.sealAgain(ch, e, m); err != nil {
			return false, err
		}
		if crash("devicelost-foreign") {
			return false, errCrashed
		}
	}
	_, left, err := c.reissueRecovery(ch, e, c.oldGenKey, c.signedByOldGen, "devicelost-foreign")
	return left, err
}

// reissueRecovery seals recovery.wrap of epoch e again if stale holds for
// its signer (DeviceLost: signed by this user's old generation; Sync:
// signed by a revoked generation): only for the recovery recipient of e,
// or, for an epoch from before it was entered (SetRecovery wraps those as
// well), of the head of the chain, with the record confirmed on this
// device, and only after the old wrap checked as the template (with key),
// which is checked first: a planted file that does not check is never
// counted as left, whether or not the record is confirmed.
// point is the name of the simulated crash after the write. It reports
// whether it wrote the wrap, and whether the wrap was left for want of
// the confirmed record or of the epoch keys (the reissue is then not
// complete; a planted or foreign file is not counted).
func (c *Client) reissueRecovery(ch *chain, e *store.Epoch, key templateKey, stale func(store.ID, uint32) bool, point string) (written, left bool, err error) {
	mbx := ch.mailbox.ID
	data, err := c.st.ReadRecoveryWrap(mbx, e.Number)
	if err != nil {
		return false, false, nil
	}
	f, err := envelope.Parse(data)
	if err != nil || f.Trailer == nil || len(f.Recipients) != 1 {
		return false, false, nil
	}
	if t := f.Trailer.Signer; t.Type != envelope.SignerUser || !stale(store.ID(t.ID), t.Gen) {
		return false, false, nil
	}
	rid := store.ID(f.Recipients[0].ID)
	rm, ok := recoveryMember(e)
	if head, _ := ch.head(); (!ok || rm.ID != rid) && head != nil {
		rm, ok = recoveryMember(head)
	}
	if !ok || rm.ID != rid {
		c.warn("WARNUNG: recovery.wrap der Epoche %d von %s wird nicht neu ausgestellt: der Empfänger ist nicht der Wiederherstellungsempfänger.", e.Number, mbx)
		return false, false, nil
	}
	if f, _, err := checkTemplate(e, data, envelope.RecipientRecovery, rid, key); err != nil || f.Recipients[0].Gen != store.RecoveryGen {
		c.warn("WARNUNG: recovery.wrap der Epoche %d von %s wird nicht neu ausgestellt: sie ist keine geprüfte Verpackung dieser Epoche.", e.Number, mbx)
		return false, false, nil
	}
	p, err := c.confirmedRecovery(mbx, rid)
	if err != nil {
		c.warn("Hinweis: recovery.wrap der Epoche %d von %s wird nicht neu ausgestellt: der Wiederherstellungsempfänger ist auf diesem Gerät nicht bestätigt (ConfirmRecovery, dann Sync).", e.Number, mbx)
		return false, true, nil
	}
	m := newMember{Member: store.Member{Kind: store.MemberRecovery, ID: rid, Gen: store.RecoveryGen}, unwrap: p.UnwrapPub}
	written, err = c.sealAgain(ch, e, m)
	if err != nil || !written {
		return false, err == nil, err
	}
	if crash(point) {
		return true, false, errCrashed
	}
	return true, false, nil
}

// sealAgain replaces the wrap of epoch e for m by one from this user's
// keys of e (keysFor), signed with its current generation, and reports
// whether it did. Without keys it warns (IDs and numbers only) and
// changes nothing.
func (c *Client) sealAgain(ch *chain, e *store.Epoch, m newMember) (bool, error) {
	mbx := ch.mailbox.ID
	k, err := c.keysFor(ch, e)
	if err != nil {
		c.warn("Hinweis: Verpackungen der Epoche %d von %s werden nicht neu ausgestellt: die eigene Verpackung dieser Epoche prüft nicht.", e.Number, mbx)
		return false, nil
	}
	plain, err := k.Encode()
	if err != nil {
		return false, err
	}
	defer keys.Wipe(plain)
	data, err := c.sealWrap(mbx, e.Number, m, plain)
	if err != nil {
		return false, err
	}
	if m.Kind == store.MemberRecovery {
		return true, store.WriteFileAtomic(c.st.RecoveryWrapFile(mbx, e.Number), data)
	}
	return true, c.st.WriteWrap(mbx, e.Number, m.ID, data)
}

// reissueFolders signs folders.gml of epoch e again if a revoked
// generation signed it (this user's old one, or another member's):
// reading it takes it over through the check record (readFolders,
// resignFolders), with the current generation. Step 2 of DeviceLost only
// checked it (c.noTakeover), so it is signed again once.
func (c *Client) reissueFolders(ch *chain, e *store.Epoch, gens genCache) error {
	data, err := c.st.ReadFolders(ch.mailbox.ID, e.Number)
	if err != nil {
		return nil
	}
	f, err := envelope.Parse(data)
	if err != nil || f.Trailer == nil || f.Trailer.Signer.Type != envelope.SignerUser || !c.revokedGen(gens, store.ID(f.Trailer.Signer.ID), f.Trailer.Signer.Gen) {
		return nil
	}
	if _, _, _, err := c.foldersAt(ch, e.Number); err != nil {
		if errors.Is(err, errCrashed) {
			return err
		}
		c.warn("Hinweis: folders.gml der Epoche %d von %s wird nicht neu ausgestellt: sie prüft nicht oder wurde vorher nicht geprüft.", e.Number, ch.mailbox.ID)
	}
	return nil
}

// Other members after a device lost (2.2 point 5, K1 point 4).

// rewrapGenerations issues the wraps of every epoch of ch again that is
// not discarded, that this user is a user member of and that begins no
// later than until (2.2 point 5), each only after the old wrap checked
// as the template (reissueTarget with memberKey):
//   - for a user or delegate the member list of the epoch names, if the
//     wrap is for an older generation than the current one of its
//     user.rec, or is signed by a revoked generation; from a template of
//     a revoked generation only if the head of the chain names the
//     recipient as well (reissueTarget, errRemovedMember);
//   - for a reader of a past period, if the wrap is for an older
//     generation and is signed by a valid one (TODO(Q15));
//   - this user's own wrap, if a revoked generation signed it: from the
//     keys of the epoch (keysFor, which takes such a wrap only with this
//     user's wrap-accept), signed by the current generation (healOwnWrap);
//   - recovery.wrap, if a revoked generation signed it, for the recovery
//     recipient confirmed on this device (reissueRecovery with memberKey).
//
// So every user member heals what a revoked generation signed, its own
// entry as well, and a device lost that could not issue everything (an
// unconfirmed recovery record, DeviceLost) is completed by Sync. It
// reports whether something signed by this user's revoked generation, or
// the own wrap, was left (left: the mark of DeviceLost stays).
func (c *Client) rewrapGenerations(ch *chain, until int64) (left bool, err error) {
	mbx := ch.mailbox.ID
	head, _ := ch.head()
	gens := genCache{}
	revoked := func(signer store.ID, gen uint32) bool { return c.revokedGen(gens, signer, gen) }
	for _, e := range ch.epochs {
		if ch.discarded[e.Number] || e.Begin > until || !c.isUserMember(e) {
			continue
		}
		ownLeft, err := c.healOwnWrap(ch, e, gens)
		if err != nil {
			return false, err
		}
		left = left || ownLeft
		ids, err := c.wrapRecipients(e)
		if err != nil {
			return false, err
		}
		for _, id := range ids {
			data, err := c.st.ReadWrap(mbx, e.Number, id)
			if err != nil {
				continue
			}
			f, err := envelope.Parse(data)
			if err != nil || len(f.Recipients) != 1 {
				continue
			}
			gen, _, err := c.cachedGeneration(gens, id)
			if err != nil {
				continue
			}
			_, listed := listedRecipient(e, id)
			mine, signerRevoked := false, false
			if t := f.Trailer; t != nil && t.Signer.Type == envelope.SignerUser {
				mine = store.ID(t.Signer.ID) == c.me
				signerRevoked = revoked(store.ID(t.Signer.ID), t.Signer.Gen)
			}
			if f.Recipients[0].Gen >= gen && !(listed && signerRevoked) {
				continue
			}
			m, err := c.reissueTarget(head, e, id, data, gens, c.memberKey)
			if err != nil {
				c.warnNotReissued(e, id, err)
				continue
			}
			written, err := c.sealAgain(ch, e, m)
			if err != nil {
				return false, err
			}
			if !written {
				left = left || (listed && mine && signerRevoked)
				continue
			}
			c.warn("Hinweis: Verpackung der Epoche %d von %s für %s auf Generation %d neu ausgestellt.", e.Number, mbx, id, m.Gen)
			if crash("sync-rewrap") {
				return false, errCrashed
			}
		}
		written, recLeft, err := c.reissueRecovery(ch, e, c.memberKey, revoked, "sync-rewrap")
		if err != nil {
			return false, err
		}
		left = left || recLeft
		if written {
			c.warn("Hinweis: recovery.wrap der Epoche %d von %s neu ausgestellt.", e.Number, mbx)
		}
	}
	return left, nil
}

// healOwnWrap is the own part of rewrapGenerations for epoch e: a wrap
// for this user signed by a revoked generation (this user's or another
// member's) is sealed again from the keys of the epoch, which keysFor
// takes from it only with this user's wrap-accept of the current
// generation (2.2 rule 4), signed by the current generation and
// countersigned. It reports whether the own wrap was left although it
// needs a new one: it is for an older generation of this user (only
// DeviceLost with the old key store, or another member, can seal it
// again), or it is signed by this user's revoked generation and does not
// check.
func (c *Client) healOwnWrap(ch *chain, e *store.Epoch, gens genCache) (bool, error) {
	mbx := ch.mailbox.ID
	data, err := c.st.ReadWrap(mbx, e.Number, c.me)
	if err != nil {
		return false, nil
	}
	f, err := envelope.Parse(data)
	if err != nil || len(f.Recipients) != 1 || f.Trailer == nil {
		return false, nil
	}
	if f.Recipients[0].Gen < c.ks.Generation {
		return true, nil
	}
	t := f.Trailer.Signer
	if t.Type != envelope.SignerUser || !c.revokedGen(gens, store.ID(t.ID), t.Gen) {
		return false, nil
	}
	k, err := c.keysFor(ch, e)
	if err != nil {
		c.warn("Hinweis: Die eigene Verpackung der Epoche %d von %s ist von einer widerrufenen Generation signiert und prüft nicht; sie wird nicht neu ausgestellt.", e.Number, mbx)
		return store.ID(t.ID) == c.me, nil
	}
	if err := c.sealOwn(mbx, e.Number, k, "sync-rewrap"); err != nil {
		return false, err
	}
	c.warn("Hinweis: Die eigene Verpackung der Epoche %d von %s war von einer widerrufenen Generation signiert; sie wurde neu ausgestellt.", e.Number, mbx)
	return false, nil
}

// staleGeneration reports whether head names a user or delegate with an
// older generation than the current one of its user.rec: that member
// revoked the generation (device lost), and the epochs of the supply that
// name it must be discarded by an immediate epoch (K1 point 4). others is
// about the other members, own about this user's entry compared with the
// key store: a device lost that could not create the epoch (ErrPartial)
// is completed by Sync.
func (c *Client) staleGeneration(head *store.Epoch) (others, own bool) {
	for _, m := range head.Members {
		if m.Kind == store.MemberRecovery {
			continue
		}
		if gen, _, err := c.currentGeneration(m.ID); err == nil && gen > m.Gen {
			if m.ID == c.me {
				own = true
			} else {
				others = true
			}
		}
	}
	return others, own
}

// syncGenerations is the part of Sync for generations revoked by members
// (2.2 point 5, K1 point 4), for a user member of the head of ch: the
// wraps of revoked generations are replaced, and if the head still names
// a revoked generation, an epoch generation-revoked with immediate effect
// and the supply after it are created. It reports whether it created an
// epoch (and committed the head).
//
// The mark of an incomplete DeviceLost (mailboxState.Reissue) is cleared
// only when nothing of this user's revoked generation is left (no own
// wrap and no wrap it signed is still open, rewrapGenerations) and the
// head no longer names this user with a revoked generation (task 06h
// finding 2): either it did not, or the epoch generation-revoked was just
// created. If only this user's entry is stale and this client cannot read
// folders.gml of the newest epoch with access, the epoch cannot be created
// here: while another user member is in the head, that member creates it
// (a hint, the mark stays); if this user is the only user member, nobody
// else can, and Sync reports ErrPartial with a fixed cause (the mark
// stays), so that the user runs device lost again.
//
// While the mailbox is marked, the metadata and index segments signed by
// a revoked generation are issued again as in step 4
// (reissueMetaAndSegments, task 09d): a failure keeps the mark and is
// returned as partial (ErrPartial), after which Sync still creates the
// supply; err is a failure that stops it.
func (c *Client) syncGenerations(ch *chain, now time.Time) (done bool, partial, err error) {
	head, _ := ch.head()
	others, own := c.staleGeneration(head)
	stale := others || own
	var blocked error
	hinted := false
	if stale {
		// The epoch needs folders.gml of the newest epoch with access
		// (createEpoch). Without it (the own wraps are still for the
		// revoked generation, or folders.gml was signed by a revoked
		// generation and not checked before) this client cannot create
		// the epoch, whose entry is stale (task 14, 06h point 3: a fixed
		// cause, also when another member's entry is stale, never the
		// text of the error). Nor does it create a supply then: the
		// epoch generation-revoked of another member discards it (K1
		// point 4), and the supply needs the same folder list.
		if _, _, err := c.folderList(ch); err != nil {
			stale = false
			blocked = c.blockedGeneration(ch, head, own, err)
			hinted = blocked == nil
		}
	}
	until := int64(1<<63 - 1)
	if stale {
		// The supply after now is discarded right below.
		until = now.UnixMilli()
	}
	left, err := c.rewrapGenerations(ch, until)
	if err != nil && hinted && !errors.Is(err, errCrashed) {
		// Without access to the newest epoch the wraps of the other
		// members are not issued again either: a fixed cause, no raw
		// error text (task 14, 06h point 3).
		c.warn("WARNUNG: Die Verpackungen anderer Mitglieder von %s werden nicht neu ausgestellt: %s.", ch.mailbox.ID, warnCause(err))
		return true, nil, fmt.Errorf("%w: mailbox %s: the wraps of other members are not issued again without access to the newest epoch", ErrPartial, ch.mailbox.ID)
	}
	if err != nil {
		return false, nil, err
	}
	if stale {
		c.warn("Hinweis: Ein Mitglied von %s hat eine Generation widerrufen; eine neue Epoche beginnt sofort.", ch.mailbox.ID)
		if err := c.immediate(ch, store.ReasonGenerationRevoked, head.Members); err != nil {
			return true, nil, err
		}
	}
	ms := c.mailboxState(ch.mailbox.ID)
	// The continuation of DeviceLost for the metadata and index segments
	// signed by a revoked generation (task 09d): as in step 4, a file
	// taken over that is not issued again keeps the mark and makes the
	// result ErrPartial, which does not stop the supply.
	if ms.Reissue != 0 {
		err := c.reissueMetaAndSegments(ch, genCache{})
		if errors.Is(err, errCrashed) {
			return false, nil, err
		}
		if err != nil {
			left = true
			c.warn("WARNUNG: Die Dateien von %s wurden nicht vollständig neu ausgestellt; die Vormerkung bleibt. Abhilfe: das Hindernis beseitigen, dann Sync oder device lost erneut ausführen.", ch.mailbox.ID)
			partial = fmt.Errorf("%w: files of mailbox %s not issued again (%w); Sync or device lost run again completes it", ErrPartial, ch.mailbox.ID, err)
		}
	}
	// own && !stale: the head still names this user's revoked generation.
	if !left && !(own && !stale) && ms.Reissue != 0 {
		ms.Reissue = 0
		if err := c.save(); err != nil {
			return stale, nil, err
		}
	}
	if blocked != nil {
		return false, nil, errors.Join(blocked, partial)
	}
	return stale || hinted, partial, nil
}

// errNoCheckedFolders is the fixed cause of a sole user member who cannot
// create the epoch generation-revoked because folders.gml of the newest
// epoch with access is signed by a revoked generation that this client
// did not check before the revocation (2.2 point 4): there is no checked
// folder list of the epoch, and no member can help. TODO(Q18): the way
// out (taking over the unchecked list after an explicit confirmation, or
// an empty list) is built only once Q18 is answered; until then the
// state is reported as it is, without a remedy.
var errNoCheckedFolders = errors.New("no checked folder list of the epoch; no remedy at present, see Q18")

// blockedGeneration reports why the epoch generation-revoked of ch cannot
// be created by this client (folderList failed with err), with a fixed
// cause and remedy: a warning, and ErrPartial if this user is the only
// user member who could create it (another member can do it otherwise,
// and a hint says so). own reports that the head names this user's own
// revoked generation.
func (c *Client) blockedGeneration(ch *chain, head *store.Epoch, own bool, err error) error {
	mbx := ch.mailbox.ID
	whose := "einen Benutzer"
	if own {
		whose = "diesen Benutzer"
	}
	if errors.Is(err, ErrRevoked) {
		if c.soleUserMember(head) {
			c.warn("WARNUNG: %s nennt %s noch mit einer widerrufenen Generation, und dieser Benutzer ist das einzige Mitglied, das Epochen anlegen kann. Die Epoche zur neuen Generation kann nicht angelegt werden: keine geprüfte Ordnerliste der Epoche (folders.gml ist von einer widerrufenen Generation signiert und wurde vorher nicht geprüft); derzeit keine Abhilfe, siehe Q18.", mbx, whose)
			return fmt.Errorf("%w: mailbox %s still names a revoked generation and has no other user member: %w", ErrPartial, mbx, errNoCheckedFolders)
		}
		c.warn("Hinweis: %s nennt %s noch mit einer widerrufenen Generation; ohne geprüfte Ordnerliste der Epoche legt ein anderes Mitglied die Epoche zur neuen Generation an.", mbx, whose)
		return nil
	}
	if c.soleUserMember(head) {
		c.warn("WARNUNG: %s nennt %s noch mit einer widerrufenen Generation, und dieser Benutzer ist das einzige Mitglied, das Epochen anlegen kann; ohne Zugriff auf die neueste Epoche (%s) kann die Epoche zur neuen Generation nicht angelegt werden. Abhilfe: device lost erneut ausführen.", mbx, whose, warnCause(err))
		return fmt.Errorf("%w: mailbox %s still names a revoked generation and has no other user member; without access to the newest epoch the epoch generation-revoked cannot be created; run device lost again", ErrPartial, mbx)
	}
	c.warn("Hinweis: %s nennt %s noch mit einer widerrufenen Generation; ohne Zugriff auf die neueste Epoche (%s) legt ein anderes Mitglied die Epoche zur neuen Generation an.", mbx, whose, warnCause(err))
	return nil
}

// soleUserMember reports whether this user is the only user member (kind
// 1) of head: only user members create epochs (K2 rule 1), so no one
// else can create the epoch generation-revoked for it.
func (c *Client) soleUserMember(head *store.Epoch) bool {
	for _, m := range head.Members {
		if m.Kind == store.MemberUser && m.ID != c.me {
			return false
		}
	}
	return true
}
