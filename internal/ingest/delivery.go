package ingest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
)

const journalName = "journal.rec"

// crashHook simulates a process crash at a named point. It is nil in
// production and set only by tests of this package: when it returns true,
// the operation stops immediately and leaves everything as a killed
// process would (no cleanup, no rollback).
var crashHook func(point string) bool

// errCrashed is returned after a simulated crash.
var errCrashed = errors.New("ingest: simulated crash")

func crash(point string) bool { return crashHook != nil && crashHook(point) }

// monthIndex is year*12+month in UTC.
func monthIndex(t time.Time) int {
	t = t.UTC()
	return t.Year()*12 + int(t.Month()) - 1
}

// target is one recipient mailbox of a delivery.
type target struct {
	mbx       *store.Mailbox
	epoch     *store.Epoch
	headHash  [32]byte // SHA-256 of the head epoch.rec when the epoch was chosen
	fallback  bool
	addresses []string
	mailID    store.ID
	dir       string // spool/<txn>/<mailbox-id>
	file      *os.File
	hash      hash.Hash
	writer    *envelope.Writer
	mailHash  [32]byte
}

// verifyChain reads and verifies the epoch chain of a mailbox from epoch
// 1 to the head of mailbox.rec like the client does it (store.Chain:
// links, members, discards; signatures by members; log). It returns the
// chain and the SHA-256 of the head epoch.rec. A chain verified before is
// taken from the cache only if every file it was verified from is
// unchanged (chainCache). Epochs beyond the head of mailbox.rec are not
// used; one that exists is noted in the log (only IDs). The caller holds
// the mailbox lock (K8).
func (in *Ingest) verifyChain(mbx *store.Mailbox) (*store.Chain, [32]byte, error) {
	links, head, ok := in.cachedChain(mbx)
	if !ok {
		entry, err := in.verifyChainFull(mbx)
		if err != nil {
			in.chains.drop(mbx.ID)
			return nil, head, err
		}
		in.chains.put(mbx.ID, entry)
		links, head = entry.chain, entry.headHash
	}
	if _, err := os.Lstat(in.st.EpochFile(mbx.ID, mbx.Epoch+1)); err == nil {
		in.log.Info("ingest ignored an epoch beyond the head of mailbox.rec", "mailbox", mbx.ID.String(), "head", mbx.Epoch, "epoch", mbx.Epoch+1)
	}
	return links, head, nil
}

// verifyChainFull verifies the chain without the cache and returns it
// with what the verification relied on.
func (in *Ingest) verifyChainFull(mbx *store.Mailbox) (*chainEntry, error) {
	entry := &chainEntry{head: mbx.Epoch, chain: store.NewChain()}
	for n := uint32(1); n <= mbx.Epoch; n++ {
		e, data, err := in.st.ReadEpoch(mbx.ID, n)
		if err != nil {
			return nil, err
		}
		if err := entry.chain.Add(e, data); err != nil {
			return nil, err
		}
		uk, err := in.userKey(e.SignerID, e.SignerGen, data)
		if err != nil {
			return nil, err
		}
		if err := e.VerifySignature(uk.pub); err != nil {
			return nil, err
		}
		// TODO(phase3-translog): epoch.rec included in the log (2.7).
		if err := in.cfg.Log.CheckEpoch(e.MailboxID, e.Number, data); err != nil {
			return nil, err
		}
		entry.headHash = store.EpochHash(data)
		entry.epochs = append(entry.epochs, epochCheck{hash: entry.headHash, signer: e.SignerID, gen: e.SignerGen, userHash: uk.hash, revoked: uk.revoked})
	}
	if entry.chain.Head() == nil {
		return nil, fmt.Errorf("ingest: no epoch")
	}
	return entry, nil
}

// usableAt reports whether the server may encrypt a mail received at ms
// (milliseconds) for epoch e (2.4 lead time rules 1 and 2): a planned
// epoch from its begin on, an epoch with immediate effect from five
// minutes before its begin on.
func usableAt(e *store.Epoch, ms int64) bool {
	if e.Reason.Immediate() {
		return e.Begin-store.ImmediateLead.Milliseconds() <= ms
	}
	return e.Begin <= ms
}

// chooseEpoch returns the epoch a mail received at t is encrypted for
// (2.4, DECISIONS D50, K8): out of the verified chain from epoch 1 to the
// head of mailbox.rec, the highest epoch that is not discarded and usable
// at t (usableAt). An immediate epoch whose begin is further in the future
// is not used, and that is noted in the log. If the chosen epoch began in
// an earlier month, the supply of epochs ran out; the server keeps using
// it and notes that. It also returns the SHA-256 of the head epoch.rec.
// The caller holds the mailbox lock and read mailbox.rec under it (K8).
func (in *Ingest) chooseEpoch(mbx *store.Mailbox, t time.Time) (*store.Epoch, bool, [32]byte, error) {
	links, head, err := in.verifyChain(mbx)
	if err != nil {
		return nil, false, head, err
	}
	ms := t.UnixMilli()
	var chosen *store.Epoch
	for n := uint32(1); n <= mbx.Epoch; n++ {
		if links.Discarded(n) {
			// 2.4 rule 3: a discarded epoch is never used.
			continue
		}
		e := links.Epoch(n)
		if usableAt(e, ms) {
			chosen = e
		} else if e.Reason.Immediate() {
			in.log.Info("ingest did not use an immediate epoch that begins after the lead time", "mailbox", mbx.ID.String(), "epoch", n)
		}
	}
	if chosen == nil {
		return nil, false, head, fmt.Errorf("ingest: no epoch has begun")
	}
	return chosen, monthIndex(time.UnixMilli(chosen.Begin)) < monthIndex(t), head, nil
}

// stillValid checks again, under the locks of the commit, that the epoch
// chosen for target t is still the one to use (K8): mailbox.rec points to
// the same head with the same epoch.rec, and the chosen epoch is neither
// discarded nor overtaken by a later epoch usable at the receipt (an
// immediate one from five minutes before its begin on).
func (d *delivery) stillValid(t *target) error {
	in := d.in
	refuse := func(why string) error {
		in.log.Info("ingest refused delivery: the epochs changed during the delivery", "session", d.session, "mailbox", t.mbx.ID.String(), "epoch", t.epoch.Number, "reason", why, "status", 451)
		return smtpd.ErrTemporary
	}
	m, err := in.st.ReadMailbox(t.mbx.ID)
	if err != nil {
		return refuse("mailbox.rec")
	}
	if m.Epoch != t.mbx.Epoch {
		return refuse("head")
	}
	links, head, err := in.verifyChain(m)
	if err != nil {
		return refuse("chain")
	}
	if head != t.headHash {
		return refuse("head")
	}
	n := t.epoch.Number
	if links.Discarded(n) || links.Epoch(n) == nil {
		return refuse("discarded")
	}
	ms := d.received.UnixMilli()
	for k := n + 1; links.Epoch(k) != nil; k++ {
		if !links.Discarded(k) && usableAt(links.Epoch(k), ms) {
			return refuse("overtaken")
		}
	}
	return nil
}

// userKeyResult is the identity key of a signer and what it came from.
type userKeyResult struct {
	pub     []byte
	hash    [32]byte // SHA-256 of user.rec
	revoked bool     // the generation is not the current one
}

// userKey returns the identity key of generation gen of a user for the
// signature of a logged record.
func (in *Ingest) userKey(id store.ID, gen uint32, logged []byte) (userKeyResult, error) {
	var res userKeyResult
	u, raw, err := in.st.ReadUser(id)
	if err != nil {
		return res, err
	}
	// TODO(phase3-translog): user.rec included in the log (2.7).
	if err := in.cfg.Log.CheckUser(id, raw); err != nil {
		return res, err
	}
	g := u.Generation(gen)
	if g == nil {
		return res, fmt.Errorf("ingest: unknown generation %d", gen)
	}
	// TODO(phase3-translog): generation valid only from its log entry on (2.2 rule 3).
	if err := in.cfg.Log.CheckGeneration(id, gen); err != nil {
		return res, err
	}
	if gen != u.Current().Gen {
		res.revoked = true
		// TODO(phase3-translog): logged before the revocation (2.2 rule 4, S13).
		if err := in.cfg.Log.CheckRevokedSignature(id, gen, logged); err != nil {
			return res, err
		}
	}
	res.pub, res.hash = g.IdentityPub, sha256.Sum256(raw)
	return res, nil
}

// delivery is one message being received.
type delivery struct {
	in       *Ingest
	session  string
	from     string
	received time.Time
	txnDir   string
	targets  []*target

	header     bytes.Buffer // captured header, at most MaxHeaderBytes
	headerDone bool         // header end seen or limit reached
	headerOK   bool         // header complete within the limit
	size       int64
	crashed    bool
	done       bool
	keepSpool  bool // an undo failed: the journal must survive for Recover
}

// Begin implements smtpd.Backend (5.2 step 2): it groups the recipients
// by mailbox (each mailbox once), chooses the epoch at the time of DATA
// and opens one encryption writer per mailbox into spool/.
func (in *Ingest) Begin(s smtpd.Session, from string, rcpts []string) (smtpd.Delivery, error) {
	now := in.now()
	byMailbox := map[store.ID][]string{}
	var order []store.ID
	for _, r := range rcpts {
		id, addr, err := in.lookup(r)
		if err != nil {
			return nil, err
		}
		if _, ok := byMailbox[id]; !ok {
			order = append(order, id)
		}
		if !contains(byMailbox[id], addr) {
			byMailbox[id] = append(byMailbox[id], addr)
		}
	}
	txn, err := store.NewID(nil)
	if err != nil {
		return nil, smtpd.ErrTemporary
	}
	d := &delivery{in: in, session: s.ID, from: from, received: now, txnDir: filepath.Join(in.st.SpoolDir(), txn.String())}
	if err := mkdirSpool(d.txnDir); err != nil {
		return nil, diskErr(err)
	}
	for _, id := range order {
		t, err := d.open(id, byMailbox[id])
		if err != nil {
			d.Abort()
			in.log.Info("ingest refused delivery", "session", s.ID, "mailbox", id.String(), "status", 451)
			return nil, err
		}
		d.targets = append(d.targets, t)
	}
	return d, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// diskErr maps "no space left" to the SMTP reply 452.
func diskErr(err error) error {
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return smtpd.ErrDiskFull
	}
	return smtpd.ErrTemporary
}

// mkdirSpool creates a directory in spool/ and sets DirPerm (9.1)
// explicitly, because the umask may remove group bits.
func mkdirSpool(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, store.DirPerm); err != nil {
		os.Remove(dir)
		return err
	}
	return nil
}

// open chooses the epoch for mailbox id and opens the encryption writer
// into spool/. The epoch is chosen under the mailbox lock: mailbox.rec
// and the epochs are opened and read only after the lock is held, so that
// over NFS the cache is checked (K8); the lock is released before the
// data are streamed, and commit checks the choice again.
func (d *delivery) open(id store.ID, addrs []string) (*target, error) {
	in := d.in
	unlock, err := in.st.LockMailbox(id)
	if err != nil {
		return nil, smtpd.ErrTemporary
	}
	mbx, err := in.st.ReadMailbox(id)
	if err != nil {
		unlock()
		return nil, smtpd.ErrTemporary
	}
	e, fallback, head, err := in.chooseEpoch(mbx, d.received)
	unlock()
	if err != nil {
		return nil, smtpd.ErrTemporary
	}
	mailID, err := store.NewID(nil)
	if err != nil {
		return nil, smtpd.ErrTemporary
	}
	t := &target{mbx: mbx, epoch: e, headHash: head, fallback: fallback, addresses: addrs, mailID: mailID,
		dir: filepath.Join(d.txnDir, id.String()), hash: sha256.New()}
	if err := mkdirSpool(t.dir); err != nil {
		return nil, diskErr(err)
	}
	f, err := os.OpenFile(filepath.Join(t.dir, "mail.gml"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, diskErr(err)
	}
	t.file = f
	// The mail keeps its mode when it is renamed into the mailbox: FilePerm
	// (9.1), set explicitly because of the umask.
	if err := f.Chmod(store.FilePerm); err != nil {
		f.Close()
		return nil, diskErr(err)
	}
	hdr := envelope.Header{Kind: envelope.KindMail, MailboxID: id, Epoch: e.Number, FileID: mailID, Created: d.received.UnixMilli()}
	rcpt := []envelope.Recipient{{Type: envelope.RecipientEpochContent, ID: id, Gen: e.Number, PublicKey: e.ContentPub}}
	w, err := envelope.NewWriter(multiWriter{f, t.hash}, hdr, rcpt, nil)
	if err != nil {
		f.Close()
		return nil, diskErr(err)
	}
	t.writer = w
	return t, nil
}

// multiWriter writes to the file and the hash.
type multiWriter struct {
	f *os.File
	h hash.Hash
}

func (m multiWriter) Write(p []byte) (int, error) {
	n, err := m.f.Write(p)
	m.h.Write(p[:n])
	return n, err
}

// Write implements smtpd.Delivery: the stream goes block by block into
// every mailbox's encryption writer; only the header is kept (at most
// 1 MB) for the metadata and the term list.
func (d *delivery) Write(p []byte) (int, error) {
	if d.crashed || d.done {
		return 0, smtpd.ErrTemporary
	}
	if crash("data") {
		d.crashed = true
		return 0, errCrashed
	}
	d.size += int64(len(p))
	if !d.headerDone {
		d.captureHeader(p)
	}
	for _, t := range d.targets {
		if _, err := t.writer.Write(p); err != nil {
			return 0, diskErr(err)
		}
	}
	return len(p), nil
}

// captureHeader keeps the bytes up to and including the first empty line.
func (d *delivery) captureHeader(p []byte) {
	room := MaxHeaderBytes - d.header.Len()
	take := p
	if len(take) > room {
		take = take[:room]
	}
	start := d.header.Len()
	d.header.Write(take)
	// Search from a little before the new bytes so that a separator split
	// across writes is found.
	from := start - 3
	if from < 0 {
		from = 0
	}
	if i := bytes.Index(d.header.Bytes()[from:], []byte("\r\n\r\n")); i >= 0 {
		d.header.Truncate(from + i + 4)
		d.headerDone, d.headerOK = true, true
		return
	}
	if d.header.Len() >= MaxHeaderBytes {
		// Larger than 1 MB: not evaluated (5.2). The mail stays marked
		// unprocessed until a client handles it.
		d.headerDone = true
		wipe(d.header.Bytes())
		d.header.Reset()
	}
}

// Abort implements smtpd.Delivery.
func (d *delivery) Abort() {
	if d.crashed || d.done {
		return
	}
	d.done = true
	for _, t := range d.targets {
		if t.file != nil {
			t.file.Close()
		}
	}
	wipe(d.header.Bytes())
	if d.keepSpool {
		return
	}
	os.RemoveAll(d.txnDir)
	store.SyncDir(d.in.st.SpoolDir())
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Commit implements smtpd.Delivery (5.2 steps 3 and 4). Every file is
// written to spool/ first. Then, under the locks of all recipient
// mailboxes, a journal of the renames is written, the files are renamed
// into the mailboxes and the journal is removed. The removal is the
// commit: after a crash before it, Recover undoes the renames, so a mail
// is either completely in every mailbox or in none (DECISIONS D52).
func (d *delivery) Commit() error {
	if d.crashed || d.done {
		return smtpd.ErrTemporary
	}
	err := d.commit()
	if errors.Is(err, errCrashed) {
		d.crashed = true
		return smtpd.ErrTemporary
	}
	if err != nil {
		d.Abort()
		d.in.log.Info("ingest delivery failed", "session", d.session, "status", 451, "size", d.size)
		return err
	}
	d.done = true
	os.RemoveAll(d.txnDir)
	store.SyncDir(d.in.st.SpoolDir())
	return nil
}

func (d *delivery) commit() error {
	in := d.in
	// Finish the mail files.
	for _, t := range d.targets {
		if err := t.writer.Close(); err != nil {
			return diskErr(err)
		}
		if err := t.file.Sync(); err != nil {
			return diskErr(err)
		}
		if err := t.file.Close(); err != nil {
			return diskErr(err)
		}
		t.file = nil
		copy(t.mailHash[:], t.hash.Sum(nil))
	}
	var fields headerFields
	parsed := false
	if d.headerOK {
		fields, parsed = parseHeader(d.header.Bytes())
	}
	// Metadata and marker per mailbox (step 3).
	for _, t := range d.targets {
		if err := d.writeMeta(t, &fields, parsed); err != nil {
			return err
		}
		if err := d.writeMarker(t); err != nil {
			return err
		}
	}
	if err := store.SyncDir(d.txnDir); err != nil {
		return diskErr(err)
	}
	if crash("spooled") {
		return errCrashed
	}

	ids := make([]store.ID, 0, len(d.targets))
	for _, t := range d.targets {
		ids = append(ids, t.mbx.ID)
	}
	unlock, err := in.st.LockMailboxes(ids)
	if err != nil {
		return smtpd.ErrTemporary
	}
	defer unlock()
	// K8: the epochs may have changed while the data were received. Under
	// the locks, before anything is moved into a mailbox, the choice of
	// every target is checked again; if it no longer holds, the delivery
	// fails with 451 and the sender retries.
	for _, t := range d.targets {
		if err := d.stillValid(t); err != nil {
			return err
		}
	}

	// The journal lists every rename, marker first, then metadata, then
	// the mail, so that a reader never sees a mail without metadata.
	var moves []store.Move
	var abs [][2]string
	for _, t := range d.targets {
		id := t.mbx.ID
		pairs := [][2]string{
			{filepath.Join(t.dir, "marker.gml"), in.st.PendingFile(id, t.epoch.Number, t.mailID)},
			{filepath.Join(t.dir, "meta.gml"), in.st.MetaFile(id, t.mbx.Inbox, t.mailID)},
			{filepath.Join(t.dir, "mail.gml"), in.st.MailFile(id, t.mbx.Inbox, t.mailID)},
		}
		for _, p := range pairs {
			src, err1 := in.st.Rel(p[0])
			dst, err2 := in.st.Rel(p[1])
			if err1 != nil || err2 != nil {
				return smtpd.ErrTemporary
			}
			moves = append(moves, store.Move{Src: src, Dst: dst})
			abs = append(abs, p)
		}
	}
	jdata, err := store.EncodeJournal(moves)
	if err != nil {
		return smtpd.ErrTemporary
	}
	if err := store.CreateFileAtomic(filepath.Join(d.txnDir, journalName), jdata); err != nil {
		return diskErr(err)
	}
	if crash("journal") {
		return errCrashed
	}
	for i, p := range abs {
		if err := store.MkdirAll(filepath.Dir(p[1])); err != nil {
			return d.undo(abs[:i], err)
		}
		if _, err := os.Lstat(p[1]); !errors.Is(err, fs.ErrNotExist) {
			return d.undo(abs[:i], fmt.Errorf("ingest: target exists"))
		}
		if err := store.RenameDurable(p[0], p[1]); err != nil {
			return d.undo(abs[:i], err)
		}
		if crash(fmt.Sprintf("moved-%d", i+1)) {
			return errCrashed
		}
	}
	// Commit point.
	if err := store.RemoveDurable(filepath.Join(d.txnDir, journalName)); err != nil {
		return d.undo(abs, err)
	}
	if crash("committed") {
		return errCrashed
	}
	for _, t := range d.targets {
		if t.fallback {
			d.noteFallback(t)
		}
		in.log.Info("ingest delivered", "session", d.session, "mailbox", t.mbx.ID.String(), "mail", t.mailID.String(), "epoch", t.epoch.Number, "size", d.size)
	}
	// Preprocessing (5.2 step 5): the header goes to the queue once per
	// mailbox; the term list replaces the marker later.
	if parsed {
		for _, t := range d.targets {
			in.queue.enqueue(job{mailbox: t.mbx.ID, epoch: t.epoch.Number, metaPub: t.epoch.MetaPub, mail: t.mailID, received: d.received, header: d.header.Bytes(), from: d.from, rcpts: t.addresses})
		}
	}
	wipe(d.header.Bytes())
	d.header.Reset()
	return nil
}

// undo reverses the renames done so far after an error (not a crash) and
// returns err mapped to an SMTP error.
func (d *delivery) undo(done [][2]string, err error) error {
	for _, p := range done {
		if rerr := store.RemoveDurable(p[1]); rerr != nil {
			// Leave the journal in spool/; Recover finishes the rollback.
			d.keepSpool = true
		}
	}
	return diskErr(err)
}

// writeMeta seals the metadata for the meta key of the epoch, signed with
// the ingest key (5.2 step 3, section 7).
func (d *delivery) writeMeta(t *target, f *headerFields, parsed bool) error {
	m := &store.MailMeta{
		Version: 1, MailID: t.mailID, Received: d.received.UnixMilli(), MailHash: t.mailHash,
		Size: uint32(d.size), Folder: t.mbx.Inbox, EnvelopeFrom: store.CleanText(d.from, store.MaxAddressLen),
		Recipients: t.addresses, HeadersParsed: parsed,
	}
	if parsed {
		m.From, m.To, m.Cc, m.Subject, m.Date, m.MessageID, m.Attachment = f.from, f.to, f.cc, f.subject, f.date, f.messageID, f.attachment
	}
	plain, err := m.Encode()
	if err != nil {
		return smtpd.ErrTemporary
	}
	defer wipe(plain)
	extra, err := m.SignedExtra(t.mbx.ID, t.epoch.Number)
	if err != nil {
		return smtpd.ErrTemporary
	}
	hdr := envelope.Header{Kind: envelope.KindMeta, MailboxID: t.mbx.ID, Epoch: t.epoch.Number, FileID: t.mailID, Created: d.received.UnixMilli(), Version: m.Version}
	data, err := envelope.Seal(
		hdr,
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: t.mbx.ID, Gen: t.epoch.Number, PublicKey: t.epoch.MetaPub}},
		plain,
		&envelope.SealOptions{Signer: d.in.ingestSigner(extra)},
	)
	if err != nil {
		return smtpd.ErrTemporary
	}
	path := filepath.Join(t.dir, "meta.gml")
	if err := store.CreateFileAtomic(path, data); err != nil {
		return diskErr(err)
	}
	if crash("meta-written") {
		return errCrashed
	}
	// Section 7: the server checks its own signature on the bytes written,
	// without keys, before the mail goes anywhere near the journal.
	if err := d.in.selfCheck(path, hdr, t.mailHash); err != nil {
		return fmt.Errorf("%w: %w", smtpd.ErrTemporary, err)
	}
	return nil
}

// writeMarker seals the "unprocessed" marker for pending/ (5.2 step 3).
func (d *delivery) writeMarker(t *target) error {
	p := &store.Pending{MailboxID: t.mbx.ID, Epoch: t.epoch.Number, Entries: []store.PendingEntry{{MailID: t.mailID, Unprocessed: true}}}
	data, hdr, err := d.in.sealPending(p, t.mailID, t.epoch, d.received.UnixMilli())
	if err != nil {
		return smtpd.ErrTemporary
	}
	path := filepath.Join(t.dir, "marker.gml")
	if err := store.CreateFileAtomic(path, data); err != nil {
		return diskErr(err)
	}
	if crash("marker-written") {
		return errCrashed
	}
	// Section 7: self-check of the marker's signature, as for the metadata.
	if err := d.in.selfCheck(path, hdr, [32]byte{}); err != nil {
		return fmt.Errorf("%w: %w", smtpd.ErrTemporary, err)
	}
	return nil
}

func (in *Ingest) ingestSigner(extra []byte) *envelope.Signer {
	return &envelope.Signer{Type: envelope.SignerIngest, Gen: in.cfg.IngestGen, Key: in.signer, Extra: extra}
}

// sealPending seals a term list or marker with file ID id and returns it
// with the header it sealed. created is the receipt of the (earliest)
// mail the file covers: the client applies the epoch rule of 2.4 to it,
// and a term list written after a newer epoch began is still valid for
// mails received before (TODO(ask): 3.1 does not define created for kind
// pending; this is the reading the client checks).
func (in *Ingest) sealPending(p *store.Pending, id store.ID, e *store.Epoch, created int64) ([]byte, envelope.Header, error) {
	hdr := envelope.Header{Kind: envelope.KindPending, MailboxID: p.MailboxID, Epoch: p.Epoch, FileID: id, Created: created}
	plain, err := p.Encode()
	if err != nil {
		return nil, hdr, err
	}
	defer wipe(plain)
	data, err := envelope.Seal(
		hdr,
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: p.MailboxID, Gen: p.Epoch, PublicKey: e.MetaPub}},
		plain,
		&envelope.SealOptions{Signer: in.ingestSigner(pendingSignedExtra(hdr))},
	)
	return data, hdr, err
}

// noteFallback records that the last epoch was used past its month
// (2.4). The caller holds the mailbox lock.
func (d *delivery) noteFallback(t *target) {
	in := d.in
	ms := d.received.UnixMilli()
	n, err := in.st.ReadNote(t.mbx.ID)
	if err != nil || n == nil || n.Epoch != t.epoch.Number {
		n = &store.EpochNote{MailboxID: t.mbx.ID, Epoch: t.epoch.Number, First: ms}
	}
	if ms > n.Last {
		n.Last = ms
	}
	n.Count++
	if err := in.st.WriteNote(n); err != nil {
		in.log.Info("ingest could not write the epoch note", "mailbox", t.mbx.ID.String())
		return
	}
	in.log.Info("ingest used the last epoch past its month", "mailbox", t.mbx.ID.String(), "epoch", t.epoch.Number, "count", n.Count)
}
