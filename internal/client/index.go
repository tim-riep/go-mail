package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
)

// Index segments (6.2, K5).
//
// A client that indexes reads pending/<n>/ of every epoch it is a user
// member of, writes the marks of the terms as a new immutable segment
// index/<n>/<device-id>-<seq>.gml (kind index, sealed for the meta key of
// the epoch, signed with its identity) and only then deletes the pending
// files it processed. Several clients write their own segments, never the
// same file; readers merge the hits of all segments per mark and drop
// duplicate mail IDs. From MergeThreshold segments on, the next client
// merges them under the mailbox lock into one (or more, if one would be
// larger than rec.MaxRecordSize) and deletes the old ones after the new
// one is written.

// MergeThreshold is the number of segments of one epoch from which a
// client merges them (6.2, K5 point 4).
const MergeThreshold = 16

// maxSegmentAttempts bounds the search for a free sequence number.
const maxSegmentAttempts = 64

// segmentBudget is the size limit of the encoding of one segment, below
// rec.MaxRecordSize with room for the record framing.
const segmentBudget = rec.MaxRecordSize - 4096

// postingSize is an upper bound of the encoding of one posting with n
// mail IDs inside the segment record.
func postingSize(n int) int { return 96 + 16*n }

// mark returns the search mark of term in an epoch (6.1):
// HMAC-SHA256(index key of the epoch, term).
func mark(k *store.EpochKeys, term string) [32]byte {
	h := hmac.New(sha256.New, k.Index[:])
	h.Write([]byte(term))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// postings maps marks to sets of mail IDs.
type postings map[[32]byte]map[store.ID]bool

func (p postings) add(mk [32]byte, id store.ID) {
	s := p[mk]
	if s == nil {
		s = map[store.ID]bool{}
		p[mk] = s
	}
	s[id] = true
}

// segments splits p into index segments of mailbox mbx and epoch n
// within the limits of store (marks per segment, IDs per mark, size of
// the encoding): the IDs of a mark beyond store.MaxPostingIDs go to
// further segments.
func (p postings) segments(mbx store.ID, n uint32) []*store.IndexSegment {
	marks := make([][32]byte, 0, len(p))
	for mk := range p {
		marks = append(marks, mk)
	}
	sort.Slice(marks, func(i, j int) bool { return bytes.Compare(marks[i][:], marks[j][:]) < 0 })
	// Round r holds the r-th chunk of IDs of every mark, marks ascending.
	var rounds [][]store.Posting
	for _, mk := range marks {
		ids := make([]store.ID, 0, len(p[mk]))
		for id := range p[mk] {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
		for r := 0; len(ids) > 0; r++ {
			take := min(len(ids), store.MaxPostingIDs)
			if r == len(rounds) {
				rounds = append(rounds, nil)
			}
			rounds[r] = append(rounds[r], store.Posting{Mark: mk, MailIDs: ids[:take]})
			ids = ids[take:]
		}
	}
	var out []*store.IndexSegment
	for _, round := range rounds {
		cur, size := &store.IndexSegment{MailboxID: mbx, Epoch: n}, 0
		for _, ps := range round {
			s := postingSize(len(ps.MailIDs))
			if len(cur.Postings) > 0 && (len(cur.Postings) >= store.MaxPostings || size+s > segmentBudget) {
				out = append(out, cur)
				cur, size = &store.IndexSegment{MailboxID: mbx, Epoch: n}, 0
			}
			cur.Postings = append(cur.Postings, ps)
			size += s
		}
		if len(cur.Postings) > 0 {
			out = append(out, cur)
		}
	}
	return out
}

// device returns the device ID of this client directory and creates it
// on first use (6.2: <device-id> in the name of a segment).
func (c *Client) device() (store.ID, error) {
	if c.state.Device != "" {
		id, err := store.ParseID(c.state.Device)
		if err != nil {
			return store.ID{}, fmt.Errorf("client: damaged device ID in the state file")
		}
		return id, nil
	}
	id, err := store.NewID(nil)
	if err != nil {
		return store.ID{}, err
	}
	c.state.Device = id.String()
	if err := c.save(); err != nil {
		c.state.Device = ""
		return store.ID{}, err
	}
	return id, nil
}

// mailFolders maps every mail ID of the mailbox to the folder that holds
// it (all folder directories).
func (c *Client) mailFolders(mbx store.ID) (map[store.ID]store.ID, error) {
	dirs, err := c.st.ListFolders(mbx)
	if err != nil {
		return nil, err
	}
	out := map[store.ID]store.ID{}
	for _, d := range dirs {
		ids, err := c.st.ListMails(mbx, d)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			out[id] = d
		}
	}
	return out, nil
}

// pendingMeta loads and checks the metadata of mail id named by an
// unprocessed entry of a pending file of epoch e (6.2 step 2). The
// metadata must belong to e. A mail whose metadata are not (yet) there is
// skipped without warning: the server moves the marker before the
// metadata into the mailbox (DECISIONS D52).
func (c *Client) pendingMeta(ch *chain, e *store.Epoch, id store.ID, where map[store.ID]store.ID) (*Mail, error) {
	folder, ok := where[id]
	if !ok {
		return nil, fmt.Errorf("%w: mail of a pending entry", ErrNotFound)
	}
	m, err := c.checkMeta(ch, folder, id)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			c.warnRejected(id, "wird nicht indexiert", err)
		}
		return nil, err
	}
	if m.Epoch != e.Number {
		err := fmt.Errorf("%w: pending entry of epoch %d for a mail of epoch %d", ErrMismatch, e.Number, m.Epoch)
		c.warnRejected(id, "wird nicht indexiert", err)
		return nil, err
	}
	return m, nil
}

// Index processes pending/ of mailbox mbx (6.2, K5) and returns the
// number of entries (mails) it put into new segments. For every epoch of
// the verified chain that is not discarded and that this client is a user
// member of (only their segments are accepted by readers), it opens every
// pending file with the checks of OpenPending, takes the terms of each
// entry, or for an entry marked unprocessed derives them from the checked
// metadata (metaTerms), computes the marks with the index key of
// the epoch and writes them as new segments. Only then does it delete
// the pending files it processed completely (K5 point 2). A pending file
// that fails a check, or one of whose entries cannot be processed, stays
// and is warned about. Afterwards it merges the segments of the epoch if
// there are MergeThreshold or more.
//
// The versions of the metadata it checked are saved before any segment
// is written (task 09, addendum).
func (c *Client) Index(mbx store.ID) (int, error) {
	if err := c.writable(); err != nil {
		return 0, err
	}
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return 0, err
	}
	dev, err := c.device()
	if err != nil {
		return 0, err
	}
	var where map[store.ID]store.ID
	total := 0
	var first error
	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	for _, e := range ch.epochs {
		// A former member whose wraps were removed has no access any
		// more; that is not an error.
		if ch.discarded[e.Number] || !c.isUserMember(e) || !c.ownWrapExists(mbx, e.Number) {
			continue
		}
		n, err := c.indexEpoch(ch, e, dev, &where)
		total += n
		note(err)
		note(c.mergeSegments(ch, e, dev))
	}
	note(c.saveSeen())
	if first == nil {
		first = ch.err
	}
	return total, first
}

// indexEpoch indexes pending/<n>/ of epoch e (see Index).
func (c *Client) indexEpoch(ch *chain, e *store.Epoch, dev store.ID, where *map[store.ID]store.ID) (int, error) {
	mbx := ch.mailbox.ID
	files, err := c.st.ListPending(mbx, e.Number)
	if err != nil || len(files) == 0 {
		return 0, err
	}
	k, err := c.keysFor(ch, e)
	if err != nil {
		return 0, err
	}
	p := postings{}
	var done []store.ID
	count := 0
	for _, file := range files {
		pf, err := c.openPending(ch, e, file)
		if err != nil {
			continue // warned; the file stays
		}
		type item struct {
			id    store.ID
			terms []string
		}
		items := make([]item, 0, len(pf.Entries))
		complete := true
		for _, en := range pf.Entries {
			terms := en.Terms
			if en.Unprocessed {
				if *where == nil {
					if *where, err = c.mailFolders(mbx); err != nil {
						return 0, err
					}
				}
				m, err := c.pendingMeta(ch, e, en.MailID, *where)
				if err != nil {
					complete = false
					break
				}
				terms = metaTerms(m.Meta)
			}
			items = append(items, item{en.MailID, terms})
		}
		if !complete {
			continue // the file stays until every entry can be processed
		}
		for _, it := range items {
			for _, t := range it.terms {
				p.add(mark(k, t), it.id)
			}
		}
		count += len(items)
		done = append(done, file)
	}
	if len(done) == 0 {
		return 0, nil
	}
	// Nothing derived from metadata versions leaves this operation before
	// those versions are saved.
	if err := c.saveSeen(); err != nil {
		return 0, err
	}
	if _, err := c.writeSegments(ch, e, dev, p); err != nil {
		return 0, err
	}
	if crash("index-written") {
		return 0, errCrashed
	}
	for _, file := range done {
		if err := store.RemoveDurable(c.st.PendingFile(mbx, e.Number, file)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return count, err
		}
	}
	return count, nil
}

// writeSegments writes p as new segments of epoch e with fresh sequence
// numbers of device dev and returns their references; nothing if p is
// empty.
func (c *Client) writeSegments(ch *chain, e *store.Epoch, dev store.ID, p postings) ([]store.IndexSegmentRef, error) {
	if len(p) == 0 {
		return nil, nil
	}
	mbx := ch.mailbox.ID
	ms := c.mailboxState(mbx)
	if ms.IndexSeq == nil {
		ms.IndexSeq = map[string]uint64{}
	}
	key := fmt.Sprint(e.Number)
	seq := max(ms.IndexSeq[key], 1)
	// The sequence number is checked against the files there (another
	// copy of this client directory, or a state file that was not saved).
	refs, err := c.st.ListIndexSegments(mbx, e.Number)
	if err != nil {
		return nil, err
	}
	for _, r := range refs {
		if r.Device == dev && r.Seq >= seq {
			seq = r.Seq + 1
		}
	}
	var written []store.IndexSegmentRef
	for _, seg := range p.segments(mbx, e.Number) {
		plain, err := store.EncodeIndexSegment(seg)
		if err != nil {
			return written, err
		}
		data, err := envelope.Seal(
			envelope.Header{Kind: envelope.KindIndex, MailboxID: mbx, Epoch: e.Number, FileID: dev, Created: c.cfg.Now().UnixMilli()},
			[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: mbx, Gen: e.Number, PublicKey: e.MetaPub}},
			plain, &envelope.SealOptions{Signer: c.signer()})
		keys.Wipe(plain)
		if err != nil {
			return written, err
		}
		for attempt := 1; ; attempt++ {
			err = c.st.WriteIndexSegment(mbx, e.Number, dev, seq, data)
			if !errors.Is(err, store.ErrExists) || attempt >= maxSegmentAttempts {
				break
			}
			seq++
		}
		if err != nil {
			return written, err
		}
		written = append(written, store.IndexSegmentRef{Device: dev, Seq: seq})
		seq++
		ms.IndexSeq[key] = seq
	}
	return written, c.save()
}

// readSegment opens and checks index/<n>/<device>-<seq>.gml of epoch e
// (6.2, K5): kind index, mailbox and epoch of its location, file ID equal
// to the device ID of its name (TODO(ask): 3.1 "file_id gleich der ID im
// Dateinamen"; the sequence number is not bound into the file), suite of
// the epoch, signed by a user member (kind 1) of e with the current
// generation of its user.rec (TODO(S13): strictest reading, as for
// wraps), sealed for the meta key of e, content for mailbox and epoch.
func (c *Client) readSegment(ch *chain, e *store.Epoch, ref store.IndexSegmentRef) (*store.IndexSegment, error) {
	mbx := ch.mailbox.ID
	data, err := c.st.ReadIndexSegment(mbx, e.Number, ref.Device, ref.Seq)
	if err != nil {
		return nil, err
	}
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, err
	}
	h := f.Header
	if h.Kind != envelope.KindIndex || h.MailboxID != mbx || h.Epoch != e.Number || h.FileID != ref.Device {
		return nil, fmt.Errorf("%w: segment header does not match its location", ErrMismatch)
	}
	k, err := c.keysFor(ch, e)
	if err != nil {
		return nil, err
	}
	_, plain, err := envelope.Open(data, envelope.OpenOptions{
		ExpectedSuite: e.Suite,
		Key:           envelope.RecipientKey{Type: envelope.RecipientEpochMeta, ID: mbx, Gen: e.Number, PrivateKey: k.Meta},
		ResolveSigner: func(r envelope.SignerRef) (ed25519.PublicKey, error) {
			if r.Type != envelope.SignerUser {
				return nil, ErrSigner
			}
			if _, ok := e.Member(store.ID(r.ID)); !ok {
				return nil, fmt.Errorf("%w: segment signed by a user who is not a user member of epoch %d", ErrSigner, e.Number)
			}
			return c.userKey(store.ID(r.ID), r.Gen, nil)
		},
	})
	if err != nil {
		return nil, signerErr(err)
	}
	defer keys.Wipe(plain)
	return store.DecodeIndexSegment(mbx, e.Number, plain)
}

// segment is a checked segment with its reference.
type segment struct {
	ref store.IndexSegmentRef
	seg *store.IndexSegment
}

// readSegments opens every segment of epoch e; a segment that fails a
// check is ignored with a warning that names only the file.
func (c *Client) readSegments(ch *chain, e *store.Epoch) ([]segment, error) {
	refs, err := c.st.ListIndexSegments(ch.mailbox.ID, e.Number)
	if err != nil {
		return nil, err
	}
	out := make([]segment, 0, len(refs))
	for _, ref := range refs {
		seg, err := c.readSegment(ch, e, ref)
		if err != nil {
			c.warn("WARNUNG: Indexsegment %s-%d der Epoche %d von %s wird ignoriert: %s.", ref.Device, ref.Seq, e.Number, ch.mailbox.ID, warnCause(err))
			continue
		}
		out = append(out, segment{ref, seg})
	}
	return out, nil
}

// lookup returns the mail IDs of mark mk in seg.
func lookup(seg *store.IndexSegment, mk [32]byte) []store.ID {
	ps := seg.Postings
	i := sort.Search(len(ps), func(i int) bool { return bytes.Compare(ps[i].Mark[:], mk[:]) >= 0 })
	if i < len(ps) && ps[i].Mark == mk {
		return ps[i].MailIDs
	}
	return nil
}

// mergeSegments merges the segments of epoch e into new ones when there
// are MergeThreshold or more (6.2, K5 point 4): under the mailbox lock it
// reads every segment, unites the hits per mark without duplicate mail
// IDs, writes the result as new segments of this device and deletes the
// merged segments only after that. A segment that fails a check is
// neither merged nor deleted.
func (c *Client) mergeSegments(ch *chain, e *store.Epoch, dev store.ID) error {
	mbx := ch.mailbox.ID
	refs, err := c.st.ListIndexSegments(mbx, e.Number)
	if err != nil || len(refs) < MergeThreshold {
		return err
	}
	if !c.skipLock {
		unlock, err := c.st.LockMailbox(mbx)
		if err != nil {
			return err
		}
		defer unlock()
	}
	segs, err := c.readSegments(ch, e)
	if err != nil {
		return err
	}
	if len(segs) < 2 {
		return nil
	}
	p := postings{}
	for _, s := range segs {
		for _, ps := range s.seg.Postings {
			for _, id := range ps.MailIDs {
				p.add(ps.Mark, id)
			}
		}
	}
	written, err := c.writeSegments(ch, e, dev, p)
	if err != nil {
		return err
	}
	if crash("index-merged") {
		return errCrashed
	}
	for _, s := range segs {
		fresh := false
		for _, w := range written {
			fresh = fresh || w == s.ref
		}
		if fresh {
			continue
		}
		if err := c.st.RemoveIndexSegment(mbx, e.Number, s.ref.Device, s.ref.Seq); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
