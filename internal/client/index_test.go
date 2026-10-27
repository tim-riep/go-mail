package client_test

import (
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// send delivers a raw message from the envelope sender from to
// a@example.org.
func (f *fixture) send(t *testing.T, from, msg string) {
	t.Helper()
	d, err := f.in.Begin(smtpd.Session{ID: "t"}, from, []string{"a@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	d.Write([]byte(msg))
	if err := d.Commit(); err != nil {
		t.Fatal(err)
	}
}

// header returns a message with From addr and Subject and Message-ID
// subject.
func header(addr, subject string) string {
	return "From: Rechnung <" + addr + ">\r\nTo: a@example.org\r\nSubject: " + subject +
		"\r\nMessage-ID: <" + subject + "@sender.example>\r\n\r\nbody\r\n"
}

func (f *fixture) flush(t *testing.T) {
	t.Helper()
	if err := f.in.Flush(); err != nil {
		t.Fatal(err)
	}
}

// subjects returns the sorted subjects of mails ("-" for a mail whose
// header was not evaluated).
func subjects(list []*client.Mail) string {
	var out []string
	for _, m := range list {
		s := m.Meta.Subject
		if !m.Meta.HeadersParsed {
			s = "-"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func search(t *testing.T, c *client.Client, mbx store.ID, q, since string) string {
	t.Helper()
	list, err := c.Search(mbx, q, client.SearchOptions{Since: since})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	seen := map[store.ID]bool{}
	for _, m := range list {
		if seen[m.ID] {
			t.Fatalf("mail %s found twice", m.ID)
		}
		seen[m.ID] = true
	}
	return subjects(list)
}

func pendingCount(t *testing.T, env *testenv.Env, mbx store.ID, n uint32) int {
	t.Helper()
	ids, err := env.Store.ListPending(mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	return len(ids)
}

func segmentCount(t *testing.T, env *testenv.Env, mbx store.ID, n uint32) int {
	t.Helper()
	refs, err := env.Store.ListIndexSegments(mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	return len(refs)
}

// TestIndexAndSearchTwoEpochs indexes and searches over two epochs with
// term lists and unprocessed markers (6.2, 6.3, K5).
func TestIndexAndSearchTwoEpochs(t *testing.T) {
	f := newFixture(t)
	// Epoch 1: r1 and n1 as a term list, u1 with a header the server
	// cannot evaluate (marker, envelope only).
	f.send(t, "bounce@lieferant.de", header("Rechnung@Lieferant.DE", "r1"))
	f.send(t, "x@other.example", header("news@other.example", "n1"))
	f.flush(t)
	f.send(t, "rechnung@lieferant.de", "X-Broken: no end of header\r\n")
	// Epoch 2 (begins on November 1): r3 as a term list, r4 as a marker
	// whose header was evaluated but not yet turned into a term list.
	f.env.Clock.Set(time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC))
	f.send(t, "bounce@lieferant.de", header("rechnung@lieferant.de", "r3"))
	f.flush(t)
	f.send(t, "bounce@lieferant.de", header("rechnung@lieferant.de", "r4"))
	if pendingCount(t, f.env, f.mbx, 1) != 2 || pendingCount(t, f.env, f.mbx, 2) != 2 {
		t.Fatal("pending files before indexing")
	}
	c := f.u.Client
	check := func(stage string) {
		t.Helper()
		for _, tc := range []struct{ q, since, want string }{
			{"from:rechnung@lieferant.de", "", "-,r1,r3,r4"},
			{"  FROM:Rechnung@Lieferant.de ", "", "-,r1,r3,r4"},
			{"fromdomain:lieferant.de", "2026-11", "r3,r4"},
			{"from:rechnung@lieferant.de", "2026-12", ""},
			{"day:2026-10-26", "", "-,n1,r1"},
			{"month:2026-11", "", "r3,r4"},
			{"to:a@example.org", "", "-,n1,r1,r3,r4"},
			{"thread:<r4@sender.example>", "", "r4"},
			{"thread:<r1@sender.example>", "", "r1"},
			{"has:attachment", "", ""},
			{"from:nobody@lieferant.de", "", ""},
		} {
			if got := search(t, c, f.mbx, tc.q, tc.since); got != tc.want {
				t.Fatalf("%s: search %d: got %q, want %q", stage, len(tc.q), got, tc.want)
			}
		}
	}
	check("before indexing")
	n, err := c.Index(f.mbx)
	if err != nil || n != 5 {
		t.Fatalf("index: %d entries: %v", n, err)
	}
	if pendingCount(t, f.env, f.mbx, 1) != 0 || pendingCount(t, f.env, f.mbx, 2) != 0 {
		t.Fatal("pending files left after indexing")
	}
	if segmentCount(t, f.env, f.mbx, 1) != 1 || segmentCount(t, f.env, f.mbx, 2) != 1 {
		t.Fatal("one segment per epoch expected")
	}
	check("after indexing")
	// A new process reads the segments as well.
	c = f.env.Reopen(f.u)
	check("after a restart")
	if n, err := c.Index(f.mbx); err != nil || n != 0 {
		t.Fatalf("second index: %d: %v", n, err)
	}
	// The same term has different marks in different epochs (6.3).
	m1, err1 := c.TermMark(f.mbx, 1, "from:rechnung@lieferant.de")
	m2, err2 := c.TermMark(f.mbx, 2, "from:rechnung@lieferant.de")
	if err1 != nil || err2 != nil || m1 == m2 {
		t.Fatal("marks of two epochs for the same term must differ")
	}
	segs, err := c.Segments(f.mbx, 2)
	if err != nil || len(segs) != 1 {
		t.Fatal(err)
	}
	for _, p := range segs[0].Postings {
		if p.Mark == m1 {
			t.Fatal("mark of epoch 1 in a segment of epoch 2")
		}
	}
	// Sync indexes too.
	f.send(t, "bounce@lieferant.de", header("rechnung@lieferant.de", "r5"))
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if pendingCount(t, f.env, f.mbx, 2) != 0 || segmentCount(t, f.env, f.mbx, 2) != 2 {
		t.Fatal("sync did not index")
	}
	if got := search(t, c, f.mbx, "fromdomain:lieferant.de", "2026-11"); got != "r3,r4,r5" {
		t.Fatalf("after sync: %q", got)
	}
}

func TestSearchArguments(t *testing.T) {
	f := newFixture(t)
	for _, q := range []string{"", "subject:secret", "from:", "from:   ", "has:attachments", "secret"} {
		if _, err := f.u.Client.Search(f.mbx, q, client.SearchOptions{}); !errors.Is(err, client.ErrQuery) {
			t.Fatalf("query %d accepted: %v", len(q), err)
		} else if q != "" && strings.Contains(err.Error(), q) {
			t.Fatal("the error carries the term")
		}
	}
	for _, s := range []string{"2026", "2026-13", "26-01", "2026-01-01"} {
		if _, err := f.u.Client.Search(f.mbx, "has:attachment", client.SearchOptions{Since: s}); !errors.Is(err, client.ErrArgument) {
			t.Fatalf("since %q accepted: %v", s, err)
		}
	}
	if _, err := f.u.Client.Search(store.ID{1}, "has:attachment", client.SearchOptions{}); err == nil {
		t.Fatal("unknown mailbox")
	}
}

// TestIndexTwoClients: two clients index the same pending entries; the
// duplicate hits are merged when reading (K5 point 3).
func TestIndexTwoClients(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.send(t, "s@x.example", header("s@x.example", "m2"))
	f.flush(t)
	mbox, _ := f.env.Store.ReadMailbox(f.mbx)
	ep := uint32(0)
	for n := uint32(1); n <= mbox.Epoch; n++ {
		if pendingCount(t, f.env, f.mbx, n) > 0 {
			ep = n
		}
	}
	if ep == 0 {
		t.Fatal("no pending file")
	}
	// Both clients see the same pending files: they are put back after
	// alice processed them.
	ids, _ := f.env.Store.ListPending(f.mbx, ep)
	saved := map[store.ID][]byte{}
	for _, id := range ids {
		saved[id], _ = f.env.Store.ReadPending(f.mbx, ep, id)
	}
	if n, err := f.u.Client.Index(f.mbx); err != nil || n != 2 {
		t.Fatalf("alice: %d: %v", n, err)
	}
	for id, data := range saved {
		store.WriteFileAtomic(f.env.Store.PendingFile(f.mbx, ep, id), data)
	}
	if n, err := bob.Client.Index(f.mbx); err != nil || n != 2 {
		t.Fatalf("bob: %d: %v", n, err)
	}
	refs, _ := f.env.Store.ListIndexSegments(f.mbx, ep)
	if len(refs) != 2 || refs[0].Device == refs[1].Device {
		t.Fatalf("segments %+v", refs)
	}
	for _, c := range []*client.Client{f.u.Client, bob.Client} {
		if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1,m2" {
			t.Fatalf("search: %q", got)
		}
	}
	// The device ID stays the same across restarts, and the next segment
	// of a device gets the next sequence number.
	dev, _ := f.u.Client.Device()
	f.send(t, "s@x.example", header("s@x.example", "m3"))
	f.flush(t)
	c := f.env.Reopen(f.u)
	if d, _ := c.Device(); d != dev {
		t.Fatal("device ID changed")
	}
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	refs, _ = f.env.Store.ListIndexSegments(f.mbx, ep)
	seqs := map[uint64]bool{}
	for _, r := range refs {
		if r.Device == dev {
			seqs[r.Seq] = true
		}
	}
	if len(refs) != 3 || !seqs[1] || !seqs[2] {
		t.Fatalf("segments after a restart %+v", refs)
	}
	// A sequence number taken by a file the state does not know (a copy of
	// the client directory) is skipped.
	segData, _ := f.env.Store.ReadIndexSegment(f.mbx, ep, dev, 1)
	if err := f.env.Store.WriteIndexSegment(f.mbx, ep, dev, 7, segData); err != nil {
		t.Fatal(err)
	}
	f.send(t, "s@x.example", header("s@x.example", "m4"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Store.ReadIndexSegment(f.mbx, ep, dev, 8); err != nil {
		t.Fatalf("next sequence number after a foreign file: %v", err)
	}
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1,m2,m3,m4" {
		t.Fatalf("search: %q", got)
	}
	// The copy under another sequence number is a valid segment of the
	// same device: accepted, its hits merged.
	if warned(f.env, "Indexsegment") {
		t.Fatal("a copied segment of the same device is warned about")
	}
}

// TestIndexMerge: from 16 segments of an epoch on, the next client merges
// them under the mailbox lock and deletes the old ones only after the new
// one is written (6.2, K5 point 4).
func TestIndexMerge(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	crashed := false
	for i := 0; i < client.MergeThreshold; i++ {
		f.send(t, "s@x.example", header("s@x.example", "m"+string(rune('a'+i))))
		f.flush(t)
		if i == client.MergeThreshold-1 {
			client.SetCrashHook(t, func(p string) bool {
				if p == "index-merged" && !crashed {
					crashed = true
					return true
				}
				return false
			})
		}
		if _, err := c.Index(f.mbx); err != nil && !errors.Is(err, client.ErrCrashed) {
			t.Fatal(err)
		}
		if i < client.MergeThreshold-1 && segmentCount(t, f.env, f.mbx, 1) != i+1 {
			t.Fatalf("segments after %d runs", i+1)
		}
	}
	if !crashed {
		t.Fatal("no merge")
	}
	// The merged segment is written, the old ones are still there.
	if n := segmentCount(t, f.env, f.mbx, 1); n != client.MergeThreshold+1 {
		t.Fatalf("%d segments after a crash during the merge", n)
	}
	want := "ma,mb,mc,md,me,mf,mg,mh,mi,mj,mk,ml,mm,mn,mo,mp"
	if got := search(t, c, f.mbx, "to:a@example.org", ""); got != want {
		t.Fatalf("after the crash: %q", got)
	}
	// The next run merges again and deletes every old segment.
	if n, err := c.Index(f.mbx); err != nil || n != 0 {
		t.Fatalf("index: %d: %v", n, err)
	}
	if n := segmentCount(t, f.env, f.mbx, 1); n != 1 {
		t.Fatalf("%d segments after the merge", n)
	}
	if got := search(t, c, f.mbx, "to:a@example.org", ""); got != want {
		t.Fatalf("after the merge: %q", got)
	}
	segs, err := c.Segments(f.mbx, 1)
	if err != nil || len(segs) != 1 {
		t.Fatal(err)
	}
	mk, _ := c.TermMark(f.mbx, 1, "to:a@example.org")
	for _, p := range segs[0].Postings {
		if p.Mark == mk && len(p.MailIDs) != client.MergeThreshold {
			t.Fatalf("%d mail IDs for the mark", len(p.MailIDs))
		}
	}
}

// TestIndexCrashAfterSegment: a crash after the segment is written and
// before pending/ is cleaned leaves both; the next run indexes again and
// the duplicate hits are merged (K5 point 2 and 3).
func TestIndexCrashAfterSegment(t *testing.T) {
	f := newFixture(t)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	client.SetCrashHook(t, func(p string) bool { return p == "index-written" })
	if _, err := f.u.Client.Index(f.mbx); !errors.Is(err, client.ErrCrashed) {
		t.Fatal(err)
	}
	if pendingCount(t, f.env, f.mbx, 1) != 1 || segmentCount(t, f.env, f.mbx, 1) != 1 {
		t.Fatal("segment first, then pending")
	}
	client.SetCrashHook(t, nil)
	if n, err := f.u.Client.Index(f.mbx); err != nil || n != 1 {
		t.Fatalf("%d: %v", n, err)
	}
	if pendingCount(t, f.env, f.mbx, 1) != 0 || segmentCount(t, f.env, f.mbx, 1) != 2 {
		t.Fatal("second run")
	}
	if got := search(t, f.u.Client, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("search: %q", got)
	}
}

// sealSegment seals seg as an index segment of header epoch n and file
// ID dev for the meta key of epoch e, signed by signer.
func sealSegment(t *testing.T, env *testenv.Env, signer *testenv.User, e *store.Epoch, n uint32, dev store.ID, seg *store.IndexSegment) []byte {
	t.Helper()
	plain, err := store.EncodeIndexSegment(seg)
	if err != nil {
		t.Fatal(err)
	}
	ks := env.Keystore(signer)
	defer ks.Zero()
	data, err := envelope.Seal(envelope.Header{Kind: envelope.KindIndex, MailboxID: e.MailboxID, Epoch: n, FileID: dev, Created: env.Clock.Now().UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: e.MailboxID, Gen: e.Number, PublicKey: e.MetaPub}}, plain,
		&envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerUser, ID: signer.ID, Gen: ks.Generation, Key: ks.Identity}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestSegmentRejected: a segment of a user who is not a user member of
// the epoch, one for another epoch, and one whose file ID does not match
// its name are ignored with a warning.
func TestSegmentRejected(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	c := f.u.Client
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := c.List(f.mbx, store.ID{})
	victim := list[0].ID
	e1, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	e2, _, _ := f.env.Store.ReadEpoch(f.mbx, 2)
	mk, _ := c.TermMark(f.mbx, 1, "from:evil@x.example")
	seg := &store.IndexSegment{MailboxID: f.mbx, Epoch: 1, Postings: []store.Posting{{Mark: mk, MailIDs: []store.ID{victim}}}}
	dev, _ := c.Device()
	bobDev, _ := store.NewID(nil)
	other, _ := store.NewID(nil)
	cases := []struct {
		name string
		dev  store.ID
		data []byte
	}{
		{"non-member", bobDev, sealSegment(t, f.env, bob, e1, 1, bobDev, seg)},
		{"other epoch", dev, sealSegment(t, f.env, f.u, e2, 2, dev, &store.IndexSegment{MailboxID: f.mbx, Epoch: 2, Postings: seg.Postings})},
		{"header epoch", dev, sealSegment(t, f.env, f.u, e1, 2, dev, seg)},
		{"file id", other, sealSegment(t, f.env, f.u, e1, 1, dev, seg)},
		{"content epoch", dev, sealSegment(t, f.env, f.u, e1, 1, dev, &store.IndexSegment{MailboxID: f.mbx, Epoch: 2, Postings: seg.Postings})},
		{"garbage", dev, []byte("not a segment")},
	}
	for i, tc := range cases {
		if err := f.env.Store.WriteIndexSegment(f.mbx, 1, tc.dev, uint64(100+i), tc.data); err != nil {
			t.Fatal(err)
		}
		f.env.Warnings.Take()
		if got := search(t, c, f.mbx, "from:evil@x.example", ""); got != "" {
			t.Fatalf("%s: forged hit %q", tc.name, got)
		}
		if !warned(f.env, "wird ignoriert") {
			t.Fatalf("%s: no warning", tc.name)
		}
		os.Remove(f.env.Store.IndexSegmentFile(f.mbx, 1, tc.dev, uint64(100+i)))
	}
	// The same segment signed by alice, a user member, is accepted.
	if err := f.env.Store.WriteIndexSegment(f.mbx, 1, dev, 50, sealSegment(t, f.env, f.u, e1, 1, dev, seg)); err != nil {
		t.Fatal(err)
	}
	if got := search(t, c, f.mbx, "from:evil@x.example", ""); got != "m1" {
		t.Fatalf("segment of a member: %q", got)
	}
	// A hit for a mail of another epoch is not shown.
	mk2, _ := c.TermMark(f.mbx, 2, "from:evil2@x.example")
	f.env.Clock.Set(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	if err := f.env.Store.WriteIndexSegment(f.mbx, 2, dev, 1, sealSegment(t, f.env, f.u, e2, 2, dev,
		&store.IndexSegment{MailboxID: f.mbx, Epoch: 2, Postings: []store.Posting{{Mark: mk2, MailIDs: []store.ID{victim}}}})); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:evil2@x.example", ""); got != "" || !warned(f.env, "anderen Epoche") {
		t.Fatalf("hit of another epoch: %q", got)
	}
}

func TestSplitSegments(t *testing.T) {
	mbx := store.ID{1}
	// 3 marks with 5000 IDs each: the IDs beyond MaxPostingIDs go to a
	// second segment.
	out := client.SplitPostings(mbx, 3, 5000)
	if len(out) != 2 || len(out[0]) != 3 || out[0][0] != store.MaxPostingIDs || out[1][0] != 5000-store.MaxPostingIDs {
		t.Fatalf("split by IDs: %v", out)
	}
	// More marks than one segment holds.
	out = client.SplitPostings(mbx, store.MaxPostings+5, 1)
	total := 0
	for _, s := range out {
		if len(s) > store.MaxPostings {
			t.Fatal("too many marks in one segment")
		}
		total += len(s)
	}
	if len(out) < 2 || total != store.MaxPostings+5 {
		t.Fatal("split by marks")
	}
	// Larger than rec.MaxRecordSize in total.
	out = client.SplitPostings(mbx, 20, store.MaxPostingIDs)
	if len(out) < 2 {
		t.Fatal("split by size")
	}
	total = 0
	for _, s := range out {
		total += len(s)
	}
	if total != 20 {
		t.Fatal("postings lost")
	}
}

// TestIndexSkips: a client opened with the recovery key does not index,
// a pending file that fails its checks stays, and an entry whose
// metadata are missing keeps its file.
func TestIndexSkips(t *testing.T) {
	f := newFixture(t)
	f.send(t, "s@x.example", "X-Broken: no end of header\r\n")
	list, _ := f.u.Client.List(f.mbx, store.ID{})
	if len(list) != 1 {
		t.Fatal("mail")
	}
	inbox := f.inbox(t)
	meta, _ := f.env.Store.ReadMeta(f.mbx, inbox, list[0].ID)
	os.Remove(f.env.Store.MetaFile(f.mbx, inbox, list[0].ID))
	if n, err := f.u.Client.Index(f.mbx); err != nil || n != 0 || pendingCount(t, f.env, f.mbx, 1) != 1 {
		t.Fatalf("marker without metadata: %d: %v", n, err)
	}
	store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, inbox, list[0].ID), meta)
	// A forged pending file stays and is warned about.
	e1, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	bad := f.forgePending(t, e1, testenv.Start.Add(-time.Hour))
	f.env.Warnings.Take()
	if n, err := f.u.Client.Index(f.mbx); err != nil || n != 1 {
		t.Fatalf("%d: %v", n, err)
	}
	if ids, _ := f.env.Store.ListPending(f.mbx, 1); len(ids) != 1 || ids[0] != bad {
		t.Fatal("the forged pending file must stay, the marker go")
	}
	if !warned(f.env, "wird nicht verarbeitet") {
		t.Fatal("no warning")
	}
}
