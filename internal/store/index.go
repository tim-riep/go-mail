package store

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tim-riep/go-mail/internal/rec"
)

// Limits of index segments (6.2, K5).
const (
	MaxPostings         = 16384   // marks in one segment
	MaxPostingIDs       = 4096    // mail IDs of one mark in one segment
	MaxIndexSegmentFile = 4 << 20 // encrypted segment file
)

// PostingSchema is one mark of an index segment and the IDs of the mails
// that carry it: mail_ids is the concatenation of the 16-byte IDs in
// ascending order.
var PostingSchema = rec.MustSchema("gomail/v1/rec/posting",
	bytes32(1, "mark", true),
	rec.Field{Num: 2, Name: "mail_ids", Kind: rec.Bytes, MaxLen: MaxPostingIDs * 16, Required: true},
)

// IndexSegmentSchema is the plaintext of index/<n>/<device-id>-<seq>.gml
// (6.2, K5): mailbox, epoch and the postings, marks in ascending order.
// The file is sealed for the meta key of the epoch and signed by the
// client as kind index; segments are immutable.
var IndexSegmentSchema = rec.MustSchema("gomail/v1/rec/index-segment",
	id16(1, "mailbox_id", true),
	rec.Field{Num: 2, Name: "epoch", Kind: rec.U32, Required: true},
	rec.Field{Num: 3, Name: "postings", Kind: rec.List, Elem: PostingSchema, MaxCount: MaxPostings, Required: true},
)

// Posting is one mark with its mail IDs.
type Posting struct {
	Mark    [32]byte
	MailIDs []ID // strictly ascending
}

// IndexSegment is the content of one index segment.
type IndexSegment struct {
	MailboxID ID
	Epoch     uint32
	Postings  []Posting // strictly ascending by mark
}

func (seg *IndexSegment) check() error {
	if seg.MailboxID.IsZero() || seg.Epoch == 0 {
		return fmt.Errorf("%w: index segment without mailbox or epoch", ErrRecord)
	}
	if len(seg.Postings) == 0 || len(seg.Postings) > MaxPostings {
		return fmt.Errorf("%w: %d postings", ErrRecord, len(seg.Postings))
	}
	for i, p := range seg.Postings {
		if i > 0 && bytes.Compare(seg.Postings[i-1].Mark[:], p.Mark[:]) >= 0 {
			return fmt.Errorf("%w: marks not strictly ascending", ErrRecord)
		}
		if len(p.MailIDs) == 0 || len(p.MailIDs) > MaxPostingIDs {
			return fmt.Errorf("%w: %d mail ids of one mark", ErrRecord, len(p.MailIDs))
		}
		for j, id := range p.MailIDs {
			if id.IsZero() || j > 0 && bytes.Compare(p.MailIDs[j-1][:], id[:]) >= 0 {
				return fmt.Errorf("%w: mail ids not strictly ascending", ErrRecord)
			}
		}
	}
	return nil
}

// EncodeIndexSegment returns the canonical encoding of seg. A segment
// whose encoding exceeds rec.MaxRecordSize is rejected; the caller splits
// it.
func EncodeIndexSegment(seg *IndexSegment) ([]byte, error) {
	if err := seg.check(); err != nil {
		return nil, err
	}
	list := make([]*rec.Record, 0, len(seg.Postings))
	for _, p := range seg.Postings {
		ids := make([]byte, 0, 16*len(p.MailIDs))
		for _, id := range p.MailIDs {
			ids = append(ids, id[:]...)
		}
		list = append(list, rec.New(PostingSchema).SetBytes(1, p.Mark[:]).SetBytes(2, ids))
	}
	data, err := rec.New(IndexSegmentSchema).SetBytes(1, seg.MailboxID[:]).SetU32(2, seg.Epoch).SetList(3, list).Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecord, err)
	}
	return data, nil
}

// DecodeIndexSegment decodes the plaintext of an index segment and checks
// that it belongs to mailbox mbx and epoch.
func DecodeIndexSegment(mbx ID, epoch uint32, data []byte) (*IndexSegment, error) {
	r, err := rec.Decode(IndexSegmentSchema, data)
	if err != nil {
		return nil, err
	}
	seg := &IndexSegment{MailboxID: idFromBytes(r.Bytes(1)), Epoch: r.U32(2)}
	list := r.List(3)
	seg.Postings = make([]Posting, 0, len(list))
	for _, e := range list {
		raw := e.Bytes(2)
		if len(raw)%16 != 0 {
			return nil, fmt.Errorf("%w: mail ids are not a multiple of 16 bytes", ErrRecord)
		}
		p := Posting{MailIDs: make([]ID, len(raw)/16)}
		copy(p.Mark[:], e.Bytes(1))
		for i := range p.MailIDs {
			copy(p.MailIDs[i][:], raw[16*i:])
		}
		seg.Postings = append(seg.Postings, p)
	}
	if err := seg.check(); err != nil {
		return nil, err
	}
	if seg.MailboxID != mbx || seg.Epoch != epoch {
		return nil, fmt.Errorf("%w: index segment of another mailbox or epoch", ErrRecord)
	}
	return seg, nil
}

// IndexSegmentRef names one segment file of an epoch.
type IndexSegmentRef struct {
	Device ID
	Seq    uint64
}

// IndexDir is mailboxes/<id>/index/<n>.
func (s *Store) IndexDir(id ID, n uint32) string {
	return filepath.Join(s.MailboxDir(id), "index", epochDir(n))
}

// IndexSegmentFile is index/<n>/<device-id>-<seq>.gml, seq in decimal
// without leading zeros (section 4, 6.2).
func (s *Store) IndexSegmentFile(id ID, n uint32, device ID, seq uint64) string {
	return filepath.Join(s.IndexDir(id, n), device.String()+"-"+strconv.FormatUint(seq, 10)+".gml")
}

// WriteIndexSegment creates a segment; segments are immutable, so an
// existing one is never replaced (ErrExists).
func (s *Store) WriteIndexSegment(id ID, n uint32, device ID, seq uint64, data []byte) error {
	if err := MkdirAll(s.IndexDir(id, n)); err != nil {
		return err
	}
	return CreateFileAtomic(s.IndexSegmentFile(id, n, device, seq), data)
}

// ReadIndexSegment reads an encrypted segment file of at most
// MaxIndexSegmentFile bytes.
func (s *Store) ReadIndexSegment(id ID, n uint32, device ID, seq uint64) ([]byte, error) {
	return ReadFileLimited(s.IndexSegmentFile(id, n, device, seq), MaxIndexSegmentFile)
}

// RemoveIndexSegment deletes a segment (after merging, K5 point 4).
func (s *Store) RemoveIndexSegment(id ID, n uint32, device ID, seq uint64) error {
	return RemoveDurable(s.IndexSegmentFile(id, n, device, seq))
}

// ListIndexSegments returns the segments of epoch n sorted by device and
// sequence number. Other files (fulltext.gml, temporary files, names that
// are not canonical) are ignored.
func (s *Store) ListIndexSegments(id ID, n uint32) ([]IndexSegmentRef, error) {
	entries, err := os.ReadDir(s.IndexDir(id, n))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []IndexSegmentRef
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".gml")
		if !ok || !e.Type().IsRegular() || len(name) < IDLen+2 || name[IDLen] != '-' {
			continue
		}
		device, err := ParseID(name[:IDLen])
		if err != nil {
			continue
		}
		seq, err := strconv.ParseUint(name[IDLen+1:], 10, 64)
		if err != nil || strconv.FormatUint(seq, 10) != name[IDLen+1:] {
			continue
		}
		out = append(out, IndexSegmentRef{Device: device, Seq: seq})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Device != out[j].Device {
			return string(out[i].Device[:]) < string(out[j].Device[:])
		}
		return out[i].Seq < out[j].Seq
	})
	return out, nil
}
