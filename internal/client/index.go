package client

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
//
// Growth of state.json (task 09g, Q22 variant A). A reader keeps one
// check record per segment content it accepts (segmentMemo, about 300
// bytes), never removes one (D84 (2)) and only changes one in place
// (supersede, noteResult). Nobody without a key makes a client write a
// record for a copy of a content (one record per content), for a pending
// file put back while a segment holds its postings, or for a content
// this client merged or issued again before (spent, or used without
// counting for a merge while its successor is not there). What is left
// is bounded per Sync, epoch and device, and grows linearly with the
// Syncs. Measured with one Sync per round (TestGrowthMeasured09g,
// TestAttack09fForcedMergesDevices), with the rounds until state.json
// reaches 64 MiB, the limit of Open, at one Sync every five minutes:
//
//   - A pending file put back after the segment that holds its postings
//     was removed (also pending/ and index/ restored from a backup): the
//     entries are indexed again, so that they stay searchable, one new
//     segment per epoch and Sync: +300 bytes per round and epoch, on the
//     writer and on every member that reads it; 224,000 rounds, 777
//     days, per epoch attacked.
//   - Forced merges: an attacker keeps every segment that ever appears
//     and shows each device the latest merge results of the others (and
//     no result of its own). A device merges again when that saves
//     MergeThreshold-1 segments (mergeSegments), and each merge is a new
//     content for every other device. With results of one segment that
//     takes 17 devices that index the mailbox: 1 and 9 devices merge in
//     the first round only (+0 afterwards); 17 devices +4,471 bytes per
//     round on each device (263 per device), 15,000 rounds, 52 days.
//     With results of two segments (more than store.MaxPostingIDs mails
//     of one term in the epoch, such as month:): 9 devices +4,842 bytes
//     per round (48 days), 17 devices +9,050 bytes (26 days). The growth
//     per round is about 300 bytes times the devices times the segments
//     of a result, so a large epoch with many devices reaches 64 MiB
//     sooner: per device and segment of a result about 270 bytes per
//     round (126,000 to 255,000 rounds, 440 to 890 days, measured).
//   - Copies, pending files put back while their segment is there, and
//     index/<n>/ rolled back to before a merge: +0.

// MergeThreshold is the number of segments of one epoch from which a
// client merges them (6.2, K5 point 4).
const MergeThreshold = 16

// mergeHook is called by tests in mergeSegments right before the mailbox
// lock is taken, to hold the lock elsewhere. It is nil in production.
var mergeHook func()

// resignHook is called by tests in resignSegment right before the mailbox
// lock is taken, to hold the lock elsewhere or to change the segment. It
// is nil in production.
var resignHook func()

// Limits of one run of readSegments, per mailbox and epoch (task 09c).
// readSegments holds every segment it accepts in memory until the caller
// is done, and a segment may be as large as rec.MaxRecordSize (4 MiB);
// the number of segments in index/<n>/ is not bounded by anybody but the
// writers, and anybody with write access to the data directory can add
// files there (copies of valid segments under new sequence numbers, Q11,
// or files that do not check). A run reads at most maxReadSegments files
// and at most maxReadBytes bytes of them; the rest is left for a later
// run, with a warning, and Search reports ErrPartial.
//
// The values: members merge from MergeThreshold (16) segments on, and a
// merge writes as few segments as the postings need (each up to
// segmentBudget), so a mailbox in normal use has some tens of segments
// per epoch. 256 MiB of segments hold about 16 million postings of one
// mail ID (16 bytes each), for one epoch, i.e. about one million mails at
// fifteen terms each; 4096 segments are 256 times MergeThreshold, room
// for many devices that index without merging. Both bound the memory of
// one run to 256 MiB plus the decoded postings, and the time to 4096
// decryptions and signature checks. They are variables only so that
// tests can lower them.
var (
	maxReadSegments       = 4096
	maxReadBytes    int64 = 256 << 20
)

// errSegmentLimit is the fixed cause of an epoch with more index segments
// than one run reads (maxReadSegments, maxReadBytes).
var errSegmentLimit = errors.New("client: more index segments in the epoch than one run reads")

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
// number of entries (mails) of the pending files it processed. For every
// epoch of the verified chain that is not discarded and that this client
// is a user member of (only their segments are accepted by readers), it
// opens every pending file with the checks of OpenPending, takes the
// terms of each entry, or for an entry marked unprocessed derives them
// from the checked metadata (metaTerms), computes the marks with the
// index key of the epoch and writes those that no segment of the epoch
// holds yet as new segments; only then does it delete the pending files
// it processed completely (K5 point 2). Every entry that checks is
// indexed, however often it comes (task 09g): a pending file put back
// whose postings a segment holds writes nothing, and one whose segment is
// gone (removed, or index/ restored from a backup) writes its postings
// again, so restored data stays searchable. A pending file that fails a
// check, or one of whose entries cannot be processed, stays and is warned
// about. Afterwards it merges the segments of the epoch (mergeSegments).
//
// The versions of the metadata it checked are saved before any segment
// is written (task 09, addendum). An epoch with more segments than one
// run reads (maxReadSegments, maxReadBytes) is merged in parts, with a
// warning each time (task 09c).
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
	// Postings that a segment of the epoch holds already are not written
	// again (task 09d): a pending file put back after it was processed,
	// or processed by another client too, makes no new segment, and so
	// no new check record in any reader, as long as the segment that
	// holds its postings is there.
	run, err := c.readSegments(ch, e, false)
	if err != nil {
		return 0, err
	}
	for _, s := range run.segs {
		for _, ps := range s.seg.Postings {
			ids := p[ps.Mark]
			if ids == nil {
				continue
			}
			for _, id := range ps.MailIDs {
				delete(ids, id)
			}
			if len(ids) == 0 {
				delete(p, ps.Mark)
			}
		}
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

// segmentFile is a segment this client wrote: its reference and the
// SHA-256 of its file.
type segmentFile struct {
	ref store.IndexSegmentRef
	sum [32]byte
}

// writeSegments writes p as new segments of epoch e with fresh sequence
// numbers of device dev and returns their references and hashes; nothing
// if p is empty.
func (c *Client) writeSegments(ch *chain, e *store.Epoch, dev store.ID, p postings) ([]segmentFile, error) {
	return c.writeSegmentList(ch, e, dev, p.segments(ch.mailbox.ID, e.Number))
}

// writeSegmentList writes segs (postings.segments) as new segments of
// epoch e with fresh sequence numbers of device dev (writeSegments).
func (c *Client) writeSegmentList(ch *chain, e *store.Epoch, dev store.ID, segs []*store.IndexSegment) ([]segmentFile, error) {
	if len(segs) == 0 {
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
	var written []segmentFile
	for _, seg := range segs {
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
		written = append(written, segmentFile{store.IndexSegmentRef{Device: dev, Seq: seq}, sha256.Sum256(data)})
		seq++
		ms.IndexSeq[key] = seq
	}
	return written, c.save()
}

// readSegment checks data, the file index/<n>/<device>-<seq>.gml of
// epoch e (6.2, K5): kind index, mailbox and epoch of its location, file
// ID equal to the device ID of its name (TODO(ask): 3.1 "file_id gleich
// der ID im Dateinamen"; the sequence number is not bound into the file,
// Q11), suite of the epoch, signed by a user member (kind 1) of e, sealed
// for the meta key of e, content for mailbox and epoch. The signature
// counts with the current generation of the signer's user.rec, or with a
// revoked one if this client's check record names exactly this file and
// was made before the revocation the log shows (2.2 rule 4, S13, task
// 09b; checkedBefore): taken reports that. The record is the one of the
// content (segmentMemo), or one in the format before task 09c for the
// file at this place (oldSegmentMemo) if it names exactly this content
// (task 09d). Without such a record the segment is rejected
// (errNotChecked). A segment that checks with a valid generation is
// recorded (noteCheckedLater), under its epoch, device and content
// (segmentMemo, task 09c): a copy of it under another sequence number
// finds the same record and adds none. signer is the user who signed it.
func (c *Client) readSegment(ch *chain, e *store.Epoch, ref store.IndexSegmentRef, data []byte) (seg *store.IndexSegment, signer store.ID, taken bool, err error) {
	mbx := ch.mailbox.ID
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, store.ID{}, false, err
	}
	h := f.Header
	if h.Kind != envelope.KindIndex || h.MailboxID != mbx || h.Epoch != e.Number || h.FileID != ref.Device {
		return nil, store.ID{}, false, fmt.Errorf("%w: segment header does not match its location", ErrMismatch)
	}
	k, err := c.keysFor(ch, e)
	if err != nil {
		return nil, store.ID{}, false, err
	}
	var gen uint32
	// envelope.Open wraps the error of the resolver with %v; its cause is
	// kept for the warning (as openUserMetaChecked does).
	var resolveErr error
	_, plain, err := envelope.Open(data, envelope.OpenOptions{
		ExpectedSuite: e.Suite,
		Key:           envelope.RecipientKey{Type: envelope.RecipientEpochMeta, ID: mbx, Gen: e.Number, PrivateKey: k.Meta},
		ResolveSigner: func(r envelope.SignerRef) (pub ed25519.PublicKey, err error) {
			defer func() { resolveErr = err }()
			if r.Type != envelope.SignerUser {
				return nil, ErrSigner
			}
			if _, ok := e.Member(store.ID(r.ID)); !ok {
				return nil, fmt.Errorf("%w: segment signed by a user who is not a user member of epoch %d", ErrSigner, e.Number)
			}
			signer, gen = store.ID(r.ID), r.Gen
			pub, err = c.userKey(signer, gen, nil)
			if !errors.Is(err, ErrRevoked) {
				return pub, err
			}
			// A file outside the log (2.2 rule 4): only through this
			// client's check record from before the revocation.
			// The record of the content, or one in the format before
			// task 09c for the file at this place that names exactly
			// this content (task 09d, finding low 3).
			if !c.checkedBefore(mbx, segmentMemo(e.Number, ref.Device, data), data, signer, gen) &&
				!c.checkedBefore(mbx, oldSegmentMemo(e.Number, ref), data, signer, gen) {
				return nil, fmt.Errorf("%w: %w", errNotChecked, err)
			}
			taken = true
			return c.revokedKey(signer, gen)
		},
	})
	if err != nil {
		if resolveErr != nil {
			return nil, store.ID{}, false, fmt.Errorf("%w: %w", signerErr(err), resolveErr)
		}
		return nil, store.ID{}, false, signerErr(err)
	}
	defer keys.Wipe(plain)
	seg, err = store.DecodeIndexSegment(mbx, e.Number, plain)
	if err != nil {
		return nil, store.ID{}, false, err
	}
	if !taken {
		c.noteCheckedLater(mbx, segmentMemo(e.Number, ref.Device, data), data, signer, gen)
	}
	return seg, signer, taken, nil
}

// segment is a checked segment with its reference, the SHA-256 of its
// file and its signer.
type segment struct {
	ref    store.IndexSegmentRef
	seg    *store.IndexSegment
	sum    [32]byte
	signer store.ID
	// counts reports whether the segment counts for MergeThreshold: every
	// segment that checks, except a content this client merged or issued
	// again before whose successor is not among the segments of the run
	// (restored, task 09f).
	counts bool
}

// segmentRun is what one run of readSegments found in an epoch.
type segmentRun struct {
	// segs are the segments that checked, one per content.
	segs []segment
	// complete is false if the epoch held more than one run reads
	// (maxReadSegments, maxReadBytes); warned.
	complete bool
	// spent are the files whose postings are in a segment of segs:
	// byte-equal copies of a segment used in the same run, and contents
	// this client issued again or merged before (checkMemo.Next) whose
	// successor is among segs, with their copies. They are not used;
	// mergeSegments removes them. A copy of a file that fails a check is
	// not spent: it stays, like the file (D79 (1)).
	spent []store.IndexSegmentRef
	// notReissued is the first failure to sign a taken over segment
	// again while c.reissuing (step 4 of DeviceLost and its
	// continuation, task 09d); warned.
	notReissued error
}

// errResign is the fixed cause of a file taken over that could not be
// signed again (resignSegment, resignMeta): the new file, the mailbox
// lock or the state could not be written.
var errResign = errors.New("client: signing again failed: the new file, the mailbox lock or the state could not be written")

// errNotReissued is the fixed cause of a file signed by a revoked
// generation that step 4 of DeviceLost or its continuation did not issue
// again (task 09d): the mailbox stays marked and the result is
// ErrPartial.
var errNotReissued = errors.New("client: a file signed by a revoked generation was not issued again")

// readSegments opens the segments of epoch e; a segment that fails a
// check is ignored with a warning that names only the file.
//
// Each content is used once per run (task 09d): a file that is byte for
// byte the same as one accepted before in this run (the same device,
// since file_id is bound into the file) is not checked again and not
// used, with the warning of Q11 (the sequence number is not bound into
// the file, TODO(ask) Q11). A copy counts as done only if that file was
// accepted: if it was rejected, the next file with the same content is
// checked (task 09e), since a record in the format before task 09c
// counts only for the file at its place. Such copies are ignored rather
// than removed here: removing them takes nothing from an attacker, who
// puts them back at no cost, while every Search and List would write to
// the data directory; mergeSegments removes them under the mailbox lock.
//
// A content whose check record says that this client issued it again or
// merged it (checkMemo.Next, segmentSuperseded) is held back until every
// other file of the run is read (task 09f, finding low 1). It is spent,
// with a warning, only if its successor is among the segments of the run
// that check: directly, or through the records of successors this client
// merged on, and for a successor of several segments only if every one of
// them is (successors.used, task 09g); its postings are in the successor
// then, so neither it nor a copy is signed again or merged again (task
// 09d). If the successor is not there, or only in part (the index
// directory was rolled back to before a merge, or a segment of the
// successor was removed), the content is checked
// like any other file and, if it checks, used, with a warning, so that
// its postings are not lost; but it does not count for MergeThreshold
// (segment.counts), so files put back never make this client merge, and
// its record, marked already, does not grow. The next merge takes it in
// and marks it with the new successor.
//
// With takeover, a segment signed by a revoked generation that this
// client checked before the revocation is signed again (resignSegment).
// If that fails, a warning says so; in Search, List and Read the checked
// segment is used as it is and a later run signs it again (task 09c);
// in step 4 of DeviceLost and its continuation (c.reissuing) the failure
// is notReissued, which makes the mailbox incomplete (task 09d). Without
// takeover the caller does that (mergeSegments writes every segment it
// reads anew). Step 2 of DeviceLost never takes over (c.noTakeover).
//
// One run reads at most maxReadSegments files and maxReadBytes bytes of
// the epoch (task 09c); complete is false, with a warning naming the
// epoch and a fixed cause, if there were more. The error is only that of
// listing the directory or a simulated crash.
func (c *Client) readSegments(ch *chain, e *store.Epoch, takeover bool) (*segmentRun, error) {
	mbx := ch.mailbox.ID
	refs, err := c.st.ListIndexSegments(mbx, e.Number)
	if err != nil {
		return nil, err
	}
	run := &segmentRun{complete: true}
	if len(refs) > maxReadSegments {
		refs, run.complete = refs[:maxReadSegments], false
	}
	run.segs = make([]segment, 0, len(refs))
	type copyKey struct {
		dev  store.ID
		hash [32]byte
	}
	// first is, per content, the file of this run whose postings are
	// used (accepted, or in a successor), or else the last one checked
	// and rejected (task 09e).
	type firstFile struct {
		ref  store.IndexSegmentRef
		used bool
	}
	first := map[copyKey]*firstFile{}
	// held are the contents this client issued again or merged before,
	// with their copies, decided once every other file is read.
	type heldFile struct {
		ref    store.IndexSegmentRef
		data   []byte
		sum    [32]byte
		copies []store.IndexSegmentRef
	}
	var held []*heldFile
	heldBy := map[copyKey]*heldFile{}
	// use takes a segment that checked: signed again if taken over, then
	// added to the run.
	use := func(ref store.IndexSegmentRef, data []byte, sum [32]byte, seg *store.IndexSegment, signer store.ID, taken, counts bool) error {
		if taken && takeover && !c.noTakeover {
			if err := c.resignSegment(ch, e, ref, seg, data); errors.Is(err, errCrashed) {
				return err
			} else if err != nil && c.reissuing {
				c.warn("WARNUNG: Indexsegment %s-%d der Epoche %d von %s war von einer widerrufenen Generation signiert und wurde nicht neu ausgestellt: %s. Die Neuausstellung bleibt vorgemerkt.", ref.Device, ref.Seq, e.Number, mbx, warnCause(err))
				run.notReissued = cmp.Or(run.notReissued, fmt.Errorf("%w: index segment %s-%d of epoch %d: %w", errNotReissued, ref.Device, ref.Seq, e.Number, err))
			} else if err != nil {
				c.warn("WARNUNG: Indexsegment %s-%d der Epoche %d von %s war von einer widerrufenen Generation signiert und wurde nicht neu signiert: %s. Es wird geprüft verwendet; ein späterer Lauf holt die Neusignatur nach.", ref.Device, ref.Seq, e.Number, mbx, warnCause(err))
			}
		}
		run.segs = append(run.segs, segment{ref: ref, seg: seg, sum: sum, signer: signer, counts: counts})
		return nil
	}
	var read int64
	for _, ref := range refs {
		data, err := c.st.ReadIndexSegment(mbx, e.Number, ref.Device, ref.Seq)
		if err != nil {
			c.warn("WARNUNG: Indexsegment %s-%d der Epoche %d von %s wird ignoriert: %s.", ref.Device, ref.Seq, e.Number, mbx, warnCause(err))
			continue
		}
		if read += int64(len(data)); read > maxReadBytes {
			run.complete = false
			break
		}
		sum := sha256.Sum256(data)
		ck := copyKey{ref.Device, sum}
		if h := heldBy[ck]; h != nil {
			h.copies = append(h.copies, ref)
			continue
		}
		ff, ok := first[ck]
		switch {
		case ok && ff.used:
			c.warn("WARNUNG: Indexsegment %s-%d der Epoche %d von %s ist byte-gleich mit %s-%d desselben Geräts (die Laufnummer ist nicht in der Datei gebunden); es wird in diesem Lauf nicht noch einmal verarbeitet.", ref.Device, ref.Seq, e.Number, mbx, ff.ref.Device, ff.ref.Seq)
			run.spent = append(run.spent, ref)
			continue
		case ok:
			// The file of this content checked before in this run was
			// rejected: a record in the format before task 09c counts
			// only for the file at its place (oldSegmentMemo), so a copy
			// at another place must not hide the file at the recorded
			// place (task 09e). This file is checked as well; it adds no
			// record the first did not (records are per content), and
			// the files of one run are bounded by maxReadSegments.
			c.warn("WARNUNG: Indexsegment %s-%d der Epoche %d von %s ist byte-gleich mit %s-%d desselben Geräts (die Laufnummer ist nicht in der Datei gebunden); jene Datei wurde abgelehnt, diese wird geprüft.", ref.Device, ref.Seq, e.Number, mbx, ff.ref.Device, ff.ref.Seq)
			ff.ref = ref
		default:
			ff = &firstFile{ref: ref}
			first[ck] = ff
		}
		if c.segmentSuperseded(mbx, e.Number, ref, sum) {
			h := &heldFile{ref: ref, data: data, sum: sum}
			held = append(held, h)
			heldBy[ck] = h
			continue
		}
		seg, signer, taken, err := c.readSegment(ch, e, ref, data)
		if err != nil {
			c.warn("WARNUNG: Indexsegment %s-%d der Epoche %d von %s wird ignoriert: %s.", ref.Device, ref.Seq, e.Number, mbx, warnCause(err))
			continue
		}
		ff.used = true
		if err := use(ref, data, sum, seg, signer, taken, true); err != nil {
			return nil, err
		}
	}
	if len(held) > 0 {
		// Every held content is checked, so that a successor that is
		// itself held (merged on later, its own successor gone) counts as
		// there; the records do not change (recordChecked keeps a marked
		// record).
		type checked struct {
			seg    *store.IndexSegment
			signer store.ID
			taken  bool
			err    error
		}
		results := make([]checked, len(held))
		succ := c.successorsOf(mbx, e.Number)
		there := map[string]bool{}
		for _, s := range run.segs {
			there[hex.EncodeToString(s.sum[:16])] = true
		}
		for i, h := range held {
			seg, signer, taken, err := c.readSegment(ch, e, h.ref, h.data)
			results[i] = checked{seg, signer, taken, err}
			if err == nil {
				there[hex.EncodeToString(h.sum[:16])] = true
			}
		}
		for i, h := range held {
			ref := h.ref
			if succ.used(c.segmentNext(mbx, e.Number, ref, h.sum), there) {
				c.warn("WARNUNG: Indexsegment %s-%d der Epoche %d von %s wird ignoriert: sein Inhalt wurde von diesem Client bereits neu ausgestellt oder zusammengefasst (eine Kopie oder eine wieder eingespielte Datei); seine Einträge stehen im Nachfolger.", ref.Device, ref.Seq, e.Number, mbx)
				run.spent = append(run.spent, ref)
				run.spent = append(run.spent, h.copies...)
				continue
			}
			r := results[i]
			if r.err != nil {
				c.warn("WARNUNG: Indexsegment %s-%d der Epoche %d von %s wird ignoriert: %s.", ref.Device, ref.Seq, e.Number, mbx, warnCause(r.err))
				continue
			}
			c.warn("WARNUNG: Indexsegment %s-%d der Epoche %d von %s wurde von diesem Client bereits zusammengefasst oder neu ausgestellt, der Nachfolger fehlt aber; es wird verwendet, zählt nicht für das Zusammenfassen und wird beim nächsten Zusammenfassen übernommen.", ref.Device, ref.Seq, e.Number, mbx)
			run.spent = append(run.spent, h.copies...)
			if err := use(ref, h.data, h.sum, r.seg, r.signer, r.taken, false); err != nil {
				return nil, err
			}
		}
	}
	if !run.complete {
		c.warn("WARNUNG: Die Epoche %d von %s hat mehr Indexsegmente, als ein Lauf liest (höchstens %d Dateien und %d MiB); die übrigen werden in diesem Lauf nicht gelesen, Suche und Indexierung sind unvollständig.", e.Number, mbx, maxReadSegments, maxReadBytes>>20)
	}
	return run, nil
}

// resignSegment signs segment seg (file data at ref) of epoch e again
// after readSegment took it over (it was signed by a revoked generation
// and this client's check record from before the revocation names the
// file, 2.2 rule 4): under the mailbox lock, while the file is still
// data, its postings are written as a new segment of this device (signed
// by this user; several if they do not fit into one under this client's
// limits, each noted as a part of the result, noteResult), then the
// check record of the content is marked as issued again (supersede, task
// 09d) and saved, and only then is the old file removed (K5 point 4). A
// copy of the content that turns up later is ignored (readSegments), so
// a content is signed again once, however many copies there are. Only a
// user member of e whose key store holds its current generation and that
// may write does it; otherwise the segment is used as it is. In step 4 of DeviceLost and its continuation
// (c.reissuing) a key store whose generation is not the current one by
// user.rec and the log, and a file replaced or removed before the lock
// is taken, are errors (notIssued, task 09e): the caller reports the
// segment as not issued again.
func (c *Client) resignSegment(ch *chain, e *store.Epoch, ref store.IndexSegmentRef, seg *store.IndexSegment, data []byte) error {
	mbx := ch.mailbox.ID
	if c.writable() != nil || c.ks == nil || !c.isUserMember(e) {
		return nil
	}
	if err := c.ownGenValid(); err != nil {
		// In step 4 of DeviceLost and its continuation the segment is
		// not issued again (task 09e); elsewhere it is used as it is.
		return c.notIssued(err)
	}
	dev, err := c.device()
	if err != nil {
		return fmt.Errorf("%w: %w", errResign, err)
	}
	p := postings{}
	for _, ps := range seg.Postings {
		for _, id := range ps.MailIDs {
			p.add(ps.Mark, id)
		}
	}
	if resignHook != nil {
		resignHook()
	}
	changed := false
	err = c.withMailboxLock(mbx, func() error {
		cur, err := c.st.ReadIndexSegment(mbx, e.Number, ref.Device, ref.Seq)
		if err != nil || !bytes.Equal(cur, data) {
			// Removed or replaced meanwhile: the next read checks it.
			changed = true
			return nil
		}
		written, err := c.writeSegments(ch, e, dev, p)
		if err != nil {
			return err
		}
		if crash("segment-resigned") {
			return errCrashed
		}
		next := c.noteResult(mbx, e.Number, dev, written)
		if c.supersede(mbx, e.Number, ref.Device, sha256.Sum256(data), next) || len(written) > 1 {
			if err := c.saveSeen(); err != nil {
				return err
			}
		}
		if crash("segment-superseded") {
			return errCrashed
		}
		if err := c.st.RemoveIndexSegment(mbx, e.Number, ref.Device, ref.Seq); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		c.warn("Hinweis: Indexsegment %s-%d der Epoche %d von %s war von einer widerrufenen Generation signiert; es wurde übernommen und neu signiert.", ref.Device, ref.Seq, e.Number, mbx)
		return nil
	})
	if err != nil && !errors.Is(err, errCrashed) {
		return fmt.Errorf("%w: %w", errResign, err)
	}
	if err == nil && changed {
		// In step 4 of DeviceLost and its continuation a file swapped for
		// a moment (and put back afterwards) must not pass for issued
		// again (task 09e): the mailbox stays marked.
		return c.notIssued(errChanged)
	}
	return err
}

// errChanged is the fixed cause of a file taken over that was replaced
// or removed between reading and taking the mailbox lock, so that it was
// not signed again (resignSegment, resignMeta).
var errChanged = errors.New("client: the file was replaced or removed between reading and taking the mailbox lock")

// errOwnGen is the fixed cause of a file taken over that was not signed
// again because the current generation of this user's key store is not
// valid by its user.rec and the log (ownGenValid).
var errOwnGen = errors.New("client: the current generation of this user is not confirmed by its user.rec and the log")

// ownGenValid reports whether the generation of this client's key store
// is the current, logged generation of this user (userGen): only then
// does it sign a file taken over again. The error of userGen, or
// errOwnGen if the generation is not the current one.
func (c *Client) ownGenValid() error {
	_, revoked, err := c.userGen(c.me, c.ks.Generation)
	if err != nil {
		return fmt.Errorf("%w: %w", errOwnGen, err)
	}
	if revoked {
		return errOwnGen
	}
	return nil
}

// notIssued is the result of resignSegment and resignMeta for a file
// taken over that they do not sign again for cause: nil in Search, List
// and Read, where the checked file is used as it is and a later run
// signs it again (task 09c); in step 4 of DeviceLost and its continuation
// (c.reissuing) an error with cause, which the caller reports as not
// issued again (errNotReissued), so the mailbox stays marked and the
// result is ErrPartial (task 09e: no silent exits).
func (c *Client) notIssued(cause error) error {
	if !c.reissuing {
		return nil
	}
	return cause
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

// mergeSegments merges the segments of epoch e into new ones (6.2, K5
// point 4): under the mailbox lock it reads every segment, unites the
// hits per mark without duplicate mail IDs, writes the result as new
// segments of this device and deletes the merged segments only after
// that. A segment that fails a check is neither merged nor deleted.
//
// Only different segments that check count (task 09d): a file that fails
// a check, a byte-equal copy of another segment, a content this client
// issued again or merged before whose successor is there (spent, see
// readSegments) and one whose successor is not there (segment.counts
// false, task 09f) do not, so that nobody without a key makes this client
// merge again what it merged before by putting files back into
// index/<n>/. A content of the last kind is still merged with the others
// when a merge takes place.
//
// A merge takes place if it saves at least MergeThreshold-1 segments
// (task 09g): the segments that count, less the segments the merge would
// write. For a result of one segment, as in normal use, that is a merge
// from MergeThreshold segments on (K5 point 4). A result is several
// segments if it does not fit into one (more than store.MaxPostingIDs
// mail IDs of one mark, such as month: in an epoch of more than 4096
// mails, or more than segmentBudget bytes), and each of them counts:
// without this rule a result of MergeThreshold segments or more would
// count for a merge by itself, and every Index of every member would
// merge it again, each time with new segments and new check records in
// every reader. With it, such an epoch is merged again after
// MergeThreshold-1 new segments, as a small one.
//
// After the result is written, its name (resultID) is noted: for a
// result of several segments in the record of each of them (noteResult,
// checkMemo.Part), and in the record of every merged content as its
// successor (supersede: changed in place, it does not grow). The state
// is saved, and only then are the merged segments removed, together with
// the spent files, whose postings are in a segment read. If no merge
// takes place, the spent files are removed all the same (under the lock)
// and nothing is written.
//
// The limits of tasks 09e and 09f on the postings of the own last merge
// result (mailboxState.Merged, MergedResult) are gone (task 09g, Q22
// variant A): after the result was removed they held back every merge for
// good (09e), or bounded nothing once it was removed (09f). What
// segments put back can still make a client merge is bounded per Index
// and device; see the comment at the top of this file.
//
// With more segments than one run reads (warned), the segments read are
// counted and merged, and the rest is left for the next run; the limits
// (4096 files, 256 MiB) are far above MergeThreshold.
func (c *Client) mergeSegments(ch *chain, e *store.Epoch, dev store.ID) error {
	mbx := ch.mailbox.ID
	refs, err := c.st.ListIndexSegments(mbx, e.Number)
	if err != nil || len(refs) < MergeThreshold {
		return err
	}
	if mergeHook != nil {
		mergeHook()
	}
	if !c.skipLock {
		unlock, err := c.st.LockMailbox(mbx)
		if err != nil {
			return err
		}
		defer unlock()
	}
	// A segment taken over (signed by a revoked generation, checked
	// before the revocation) is written anew with all others below.
	run, err := c.readSegments(ch, e, false)
	if err != nil {
		return err
	}
	remove := func(refs []store.IndexSegmentRef) error {
		for _, r := range refs {
			if err := c.st.RemoveIndexSegment(mbx, e.Number, r.Device, r.Seq); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	}
	counted := 0
	for _, s := range run.segs {
		if s.counts {
			counted++
		}
	}
	if counted < MergeThreshold {
		return remove(run.spent)
	}
	p := postings{}
	for _, s := range run.segs {
		for _, ps := range s.seg.Postings {
			for _, id := range ps.MailIDs {
				p.add(ps.Mark, id)
			}
		}
	}
	result := p.segments(mbx, e.Number)
	if counted-len(result) < MergeThreshold-1 {
		return remove(run.spent)
	}
	written, err := c.writeSegmentList(ch, e, dev, result)
	if err != nil {
		return err
	}
	if crash("index-merged") {
		return errCrashed
	}
	next := c.noteResult(mbx, e.Number, dev, written)
	var merged []store.IndexSegmentRef
	for _, s := range run.segs {
		fresh := false
		for _, w := range written {
			fresh = fresh || w.ref == s.ref
		}
		if fresh {
			continue
		}
		c.supersede(mbx, e.Number, s.ref.Device, s.sum, next)
		merged = append(merged, s.ref)
	}
	// The marks are saved before any merged segment is removed.
	if err := c.saveSeen(); err != nil {
		return err
	}
	if crash("index-merge-noted") {
		return errCrashed
	}
	return remove(append(merged, run.spent...))
}

// resultDomain separates the name of a result of several segments
// (resultID) from every other use of SHA-256 in the client.
const resultDomain = "go-mail index result v1\x00"

// resultID returns the name of a result of a merge or of a new signature
// that consists of the segments with the SHA-256 sums: for one segment
// the first 128 bits (hex) of its SHA-256, as since task 09d; for several
// the first 128 bits (hex) of the SHA-256 over resultDomain and their
// sums in ascending order (task 09g), a name of fixed size that only the
// whole set of segments has. "" for none.
func resultID(sums [][32]byte) string {
	switch len(sums) {
	case 0:
		return ""
	case 1:
		return hex.EncodeToString(sums[0][:16])
	}
	sorted := append([][32]byte(nil), sums...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i][:], sorted[j][:]) < 0 })
	h := sha256.New()
	h.Write([]byte(resultDomain))
	for _, s := range sorted {
		h.Write(s[:])
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// noteResult returns the name of the result written (resultID), which
// the caller notes as the successor of what it took in (supersede). For
// a result of several segments it notes in the check record of each that
// it is a part of that result (checkMemo.Part, task 09g, finding N1 of
// 09f): the record that the first check of the segment would make (this
// client sealed it with the current generation of its key store; a
// record that is there keeps its fields), with the name. So a content is
// spent only while every part of its successor is there (readSegments,
// successors.used). These records are made once per segment this client
// writes, as readers make one for each, not per file put back. The
// caller saves the state.
func (c *Client) noteResult(mbx store.ID, n uint32, dev store.ID, written []segmentFile) string {
	sums := make([][32]byte, 0, len(written))
	for _, w := range written {
		sums = append(sums, w.sum)
	}
	id := resultID(sums)
	if len(written) < 2 || c.ks == nil {
		return id
	}
	ms := c.mailboxState(mbx)
	if ms.Checked == nil {
		ms.Checked = map[string]*checkMemo{}
	}
	for _, w := range written {
		key := segmentMemoSum(n, dev, w.sum)
		m := ms.Checked[key]
		if m == nil {
			m = &checkMemo{Hash: hex.EncodeToString(w.sum[:]), Signer: c.me.String(), Gen: c.ks.Generation, Tree: c.treeSize()}
			ms.Checked[key] = m
		}
		m.Part = id
	}
	c.dirty = true
	return id
}
