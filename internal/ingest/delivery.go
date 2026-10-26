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
	fallback  bool
	addresses []string
	mailID    store.ID
	dir       string // spool/<txn>/<mailbox-id>
	file      *os.File
	hash      hash.Hash
	writer    *envelope.Writer
	mailHash  [32]byte
}

// chooseEpoch returns the epoch a mail received at t is encrypted for
// (2.4, DECISIONS D50): the highest epoch whose begin is not after t. Its
// signature is verified with the signer's user.rec. If that epoch began
// in an earlier month, the supply of epochs ran out; the server keeps
// using it and notes that.
func (in *Ingest) chooseEpoch(mbx *store.Mailbox, t time.Time) (*store.Epoch, bool, error) {
	ms := t.UnixMilli()
	for n := mbx.Epoch; n >= 1; n-- {
		e, _, err := in.st.ReadEpoch(mbx.ID, n)
		if err != nil {
			return nil, false, err
		}
		if e.Begin > ms {
			continue
		}
		u, _, err := in.st.ReadUser(e.SignerID)
		if err != nil {
			return nil, false, err
		}
		g := u.Generation(e.SignerGen)
		if g == nil {
			return nil, false, fmt.Errorf("ingest: epoch %d signed by an unknown generation", n)
		}
		if err := e.VerifySignature(g.IdentityPub); err != nil {
			return nil, false, err
		}
		return e, monthIndex(time.UnixMilli(e.Begin)) < monthIndex(t), nil
	}
	return nil, false, fmt.Errorf("ingest: no epoch has begun")
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
	if err := os.Mkdir(d.txnDir, 0o700); err != nil {
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

func (d *delivery) open(id store.ID, addrs []string) (*target, error) {
	in := d.in
	mbx, err := in.st.ReadMailbox(id)
	if err != nil {
		return nil, smtpd.ErrTemporary
	}
	e, fallback, err := in.chooseEpoch(mbx, d.received)
	if err != nil {
		return nil, smtpd.ErrTemporary
	}
	mailID, err := store.NewID(nil)
	if err != nil {
		return nil, smtpd.ErrTemporary
	}
	t := &target{mbx: mbx, epoch: e, fallback: fallback, addresses: addrs, mailID: mailID,
		dir: filepath.Join(d.txnDir, id.String()), hash: sha256.New()}
	if err := os.Mkdir(t.dir, 0o700); err != nil {
		return nil, diskErr(err)
	}
	f, err := os.OpenFile(filepath.Join(t.dir, "mail.gml"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, diskErr(err)
	}
	t.file = f
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
			in.queue.enqueue(job{mailbox: t.mbx.ID, epoch: t.epoch.Number, metaPub: t.epoch.MetaPub, mail: t.mailID, received: d.received, header: d.header.Bytes()})
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
	data, err := envelope.Seal(
		envelope.Header{Kind: envelope.KindMeta, MailboxID: t.mbx.ID, Epoch: t.epoch.Number, FileID: t.mailID, Created: d.received.UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: t.mbx.ID, Gen: t.epoch.Number, PublicKey: t.epoch.MetaPub}},
		plain,
		&envelope.SealOptions{Signer: d.in.ingestSigner(extra)},
	)
	if err != nil {
		return smtpd.ErrTemporary
	}
	if err := store.CreateFileAtomic(filepath.Join(t.dir, "meta.gml"), data); err != nil {
		return diskErr(err)
	}
	return nil
}

// writeMarker seals the "unprocessed" marker for pending/ (5.2 step 3).
func (d *delivery) writeMarker(t *target) error {
	p := &store.Pending{MailboxID: t.mbx.ID, Epoch: t.epoch.Number, Entries: []store.PendingEntry{{MailID: t.mailID, Unprocessed: true}}}
	data, err := d.in.sealPending(p, t.mailID, t.epoch)
	if err != nil {
		return smtpd.ErrTemporary
	}
	if err := store.CreateFileAtomic(filepath.Join(t.dir, "marker.gml"), data); err != nil {
		return diskErr(err)
	}
	return nil
}

func (in *Ingest) ingestSigner(extra []byte) *envelope.Signer {
	return &envelope.Signer{Type: envelope.SignerIngest, Gen: in.cfg.IngestGen, Key: in.signer, Extra: extra}
}

// sealPending seals a term list or marker with file ID id.
func (in *Ingest) sealPending(p *store.Pending, id store.ID, e *store.Epoch) ([]byte, error) {
	plain, err := p.Encode()
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	return envelope.Seal(
		envelope.Header{Kind: envelope.KindPending, MailboxID: p.MailboxID, Epoch: p.Epoch, FileID: id, Created: in.now().UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: p.MailboxID, Gen: p.Epoch, PublicKey: e.MetaPub}},
		plain,
		&envelope.SealOptions{Signer: in.ingestSigner(nil)},
	)
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
