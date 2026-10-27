package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/tim-riep/go-mail/internal/rec"
)

func mark(i int) [32]byte {
	var m [32]byte
	binary.BigEndian.PutUint32(m[:], uint32(i)+1)
	return m
}

func mailIDs(n, from int) []ID {
	ids := make([]ID, n)
	for i := range ids {
		binary.BigEndian.PutUint32(ids[i][:], uint32(from+i)+1)
	}
	return ids
}

func TestIndexSegment(t *testing.T) {
	seg := &IndexSegment{MailboxID: ID{1}, Epoch: 2, Postings: []Posting{
		{Mark: mark(0), MailIDs: mailIDs(3, 0)}, {Mark: mark(1), MailIDs: mailIDs(1, 5)},
	}}
	data, err := EncodeIndexSegment(seg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("gomail/v1/rec/index-segment\x00")) {
		t.Fatal("record type")
	}
	got, err := DecodeIndexSegment(ID{1}, 2, data)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := EncodeIndexSegment(got); !bytes.Equal(again, data) {
		t.Fatal("segment not byte-identical")
	}
	if len(got.Postings) != 2 || got.Postings[0].MailIDs[2] != seg.Postings[0].MailIDs[2] || got.Postings[1].Mark != mark(1) {
		t.Fatal("decoded segment")
	}
	if _, err := DecodeIndexSegment(ID{2}, 2, data); !errors.Is(err, ErrRecord) {
		t.Fatal("segment of another mailbox")
	}
	if _, err := DecodeIndexSegment(ID{1}, 3, data); !errors.Is(err, ErrRecord) {
		t.Fatal("segment of another epoch")
	}
	// The largest posting is valid, one more ID is not.
	big := &IndexSegment{MailboxID: ID{1}, Epoch: 2, Postings: []Posting{{Mark: mark(0), MailIDs: mailIDs(MaxPostingIDs, 0)}}}
	bd, err := EncodeIndexSegment(big)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIndexSegment(ID{1}, 2, bd); err != nil {
		t.Fatal(err)
	}
	// Many postings fit until the encoding reaches rec.MaxRecordSize.
	many := &IndexSegment{MailboxID: ID{1}, Epoch: 2}
	for i := 0; i < 10000; i++ {
		many.Postings = append(many.Postings, Posting{Mark: mark(i), MailIDs: mailIDs(1, i)})
	}
	if _, err := EncodeIndexSegment(many); err != nil {
		t.Fatalf("10000 postings: %v", err)
	}
	for i := 10000; i < MaxPostings; i++ {
		many.Postings = append(many.Postings, Posting{Mark: mark(i), MailIDs: mailIDs(1, i)})
	}
	if _, err := EncodeIndexSegment(many); !errors.Is(err, ErrRecord) || !errors.Is(err, rec.ErrTooLong) {
		t.Fatalf("segment above MaxRecordSize: %v", err)
	}
	tooMany := &IndexSegment{MailboxID: ID{1}, Epoch: 2, Postings: append(many.Postings, Posting{Mark: mark(MaxPostings), MailIDs: mailIDs(1, 0)})}
	for name, bad := range map[string]*IndexSegment{
		"no mailbox":      {Epoch: 2, Postings: seg.Postings},
		"epoch 0":         {MailboxID: ID{1}, Postings: seg.Postings},
		"no postings":     {MailboxID: ID{1}, Epoch: 2},
		"too many":        tooMany,
		"too many ids":    {MailboxID: ID{1}, Epoch: 2, Postings: []Posting{{Mark: mark(0), MailIDs: mailIDs(MaxPostingIDs+1, 0)}}},
		"no ids":          {MailboxID: ID{1}, Epoch: 2, Postings: []Posting{{Mark: mark(0)}}},
		"zero id":         {MailboxID: ID{1}, Epoch: 2, Postings: []Posting{{Mark: mark(0), MailIDs: []ID{{}, {1}}}}},
		"duplicate id":    {MailboxID: ID{1}, Epoch: 2, Postings: []Posting{{Mark: mark(0), MailIDs: []ID{{1}, {1}}}}},
		"ids descending":  {MailboxID: ID{1}, Epoch: 2, Postings: []Posting{{Mark: mark(0), MailIDs: []ID{{2}, {1}}}}},
		"duplicate mark":  {MailboxID: ID{1}, Epoch: 2, Postings: []Posting{{Mark: mark(0), MailIDs: mailIDs(1, 0)}, {Mark: mark(0), MailIDs: mailIDs(1, 1)}}},
		"marks unordered": {MailboxID: ID{1}, Epoch: 2, Postings: []Posting{{Mark: mark(1), MailIDs: mailIDs(1, 0)}, {Mark: mark(0), MailIDs: mailIDs(1, 1)}}},
	} {
		if _, err := EncodeIndexSegment(bad); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s encoded: %v", name, err)
		}
	}
	// The decoder applies the same rules, and the IDs are whole.
	posting := func(m [32]byte, ids []byte) *rec.Record {
		return rec.New(PostingSchema).SetBytes(1, m[:]).SetBytes(2, ids)
	}
	segment := func(ps ...*rec.Record) []byte {
		return mustEncode(t, rec.New(IndexSegmentSchema).SetBytes(1, (&ID{1})[:]).SetU32(2, 2).SetList(3, ps))
	}
	id1, id2 := ID{1}, ID{2}
	for name, enc := range map[string][]byte{
		"partial id":     segment(posting(mark(0), make([]byte, 17))),
		"no ids":         segment(posting(mark(0), nil)),
		"no postings":    segment(),
		"duplicate mark": segment(posting(mark(0), id1[:]), posting(mark(0), id2[:])),
		"ids descending": segment(posting(mark(0), append(id2[:], id1[:]...))),
		"zero mailbox":   mustEncode(t, rec.New(IndexSegmentSchema).SetBytes(1, make([]byte, 16)).SetU32(2, 2).SetList(3, []*rec.Record{posting(mark(0), id1[:])})),
	} {
		if _, err := DecodeIndexSegment(ID{1}, 2, enc); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s decoded: %v", name, err)
		}
	}
	if _, err := rec.New(PostingSchema).SetBytes(1, make([]byte, 32)).SetBytes(2, make([]byte, MaxPostingIDs*16+16)).Encode(); err == nil {
		t.Fatal("posting above MaxPostingIDs encoded")
	}
	if _, err := DecodeIndexSegment(ID{1}, 2, append(data, 0)); err == nil {
		t.Fatal("trailing byte")
	}
}

func TestIndexSegmentFiles(t *testing.T) {
	s, _ := Init(t.TempDir())
	mbx, dev, dev2 := ID{9}, ID{3}, ID{1}
	if refs, err := s.ListIndexSegments(mbx, 1); err != nil || refs != nil {
		t.Fatal("segments of a new epoch")
	}
	if s.IndexSegmentFile(mbx, 1, dev, 0) != filepath.Join(s.MailboxDir(mbx), "index", "1", dev.String()+"-0.gml") ||
		filepath.Base(s.IndexSegmentFile(mbx, 1, dev, 120)) != dev.String()+"-120.gml" {
		t.Fatal("path of a segment")
	}
	for _, r := range []IndexSegmentRef{{dev, 10}, {dev, 2}, {dev2, 7}, {dev, 0}} {
		if err := s.WriteIndexSegment(mbx, 1, r.Device, r.Seq, []byte(strconv.FormatUint(r.Seq, 10))); err != nil {
			t.Fatal(err)
		}
	}
	// Segments are immutable.
	if err := s.WriteIndexSegment(mbx, 1, dev, 2, []byte("x")); !errors.Is(err, ErrExists) {
		t.Fatal("segment replaced")
	}
	if b, err := s.ReadIndexSegment(mbx, 1, dev, 2); err != nil || string(b) != "2" {
		t.Fatal("read segment")
	}
	// Other names are ignored: fulltext.gml, leading zeros, signs, other
	// suffixes, upper case, temporary files, directories.
	dir := s.IndexDir(mbx, 1)
	for _, n := range []string{"fulltext.gml", dev.String() + "-01.gml", dev.String() + "-+1.gml", dev.String() + "--1.gml",
		dev.String() + "-1.rec", dev.String() + "-.gml", dev.String() + "1.gml", "abc-1.gml", tmpPrefix + "x",
		dev.String() + "-18446744073709551616.gml"} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	MkdirAll(filepath.Join(dir, dev.String()+"-99.gml"))
	refs, err := s.ListIndexSegments(mbx, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []IndexSegmentRef{{dev2, 7}, {dev, 0}, {dev, 2}, {dev, 10}}
	if len(refs) != len(want) {
		t.Fatalf("segments %v", refs)
	}
	for i := range want {
		if refs[i] != want[i] {
			t.Fatalf("segments %v", refs)
		}
	}
	if err := s.RemoveIndexSegment(mbx, 1, dev, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadIndexSegment(mbx, 1, dev, 2); !errors.Is(err, ErrNotFound) {
		t.Fatal("removed segment")
	}
	if err := s.RemoveIndexSegment(mbx, 1, dev, 2); err != nil {
		t.Fatal("removing a missing segment")
	}
	// The read limit of 4 MiB.
	f, _ := os.Create(s.IndexSegmentFile(mbx, 1, dev, 50))
	f.Truncate(MaxIndexSegmentFile + 1)
	f.Close()
	if _, err := s.ReadIndexSegment(mbx, 1, dev, 50); !errors.Is(err, ErrTooLarge) {
		t.Fatal("segment above the limit")
	}
	os.RemoveAll(dir)
	os.WriteFile(dir, nil, 0o600)
	if _, err := s.ListIndexSegments(mbx, 1); err == nil {
		t.Fatal("index directory is a file")
	}
	if err := s.WriteIndexSegment(mbx, 1, dev, 1, nil); err == nil {
		t.Fatal("segment written below a file")
	}
}
