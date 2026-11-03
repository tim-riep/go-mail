package client_test

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 09e: the term list that replaces a marker indexed before
// is still indexed (since task 09g every entry is, with what no segment
// holds); step 4 of device lost has no silent exits; a
// copy at another place does not hide a segment whose record is in the
// format before task 09c; segments merged by other clients and put back
// make no client merge the same postings again. The verifier's tests of
// task 09d keep their names, turned around.

// reply is a reply to <root@sender.example>: its term list holds
// thread:<root@sender.example>, the terms derived from its metadata
// (marker) thread:<re1@sender.example> (TODO(Q12)).
const reply = "From: Rechnung <s@x.example>\r\nTo: a@example.org\r\nSubject: re1\r\n" +
	"Message-ID: <re1@sender.example>\r\nIn-Reply-To: <root@sender.example>\r\n" +
	"References: <root@sender.example>\r\n\r\nbody\r\n"

// pendingFiles returns the pending files of epoch n of mbx with their
// contents.
func pendingFiles(t *testing.T, env *testenv.Env, mbx store.ID, n uint32) map[store.ID][]byte {
	t.Helper()
	ids, err := env.Store.ListPending(mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	out := map[store.ID][]byte{}
	for _, id := range ids {
		data, err := env.Store.ReadPending(mbx, n, id)
		if err != nil {
			t.Fatal(err)
		}
		out[id] = data
	}
	return out
}

// mailMemos returns the memos of the mails of mbx in state.json of dir.
func mailMemos(t *testing.T, dir string, mbx store.ID) map[string]any {
	t.Helper()
	mails, _ := readState(t, dir, mbx)["mails"].(map[string]any)
	return mails
}

// TestAttack09dIndexedMarkerFirst (finding medium, the verifier's test,
// turned around): ingest moves the marker of a reply into pending/ (5.2
// step 3), the client indexes it from the metadata, then ingest writes
// the term list (5.2 step 5). The term list is indexed all the same: the
// reply is found under the root of its thread, and the term list writes
// only what no segment holds. Since task 09g nothing is noted per mail.
func TestAttack09dIndexedMarkerFirst(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	f.send(t, "s@x.example", reply)
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatalf("index of the marker: %d %v", n, err)
	}
	dev, _ := c.Device()
	if mine := ownSegments(t, f.env, f.mbx, 1, dev); len(mine) != 1 {
		t.Fatalf("segments after the marker: %v", mine)
	}
	if got := search(t, c, f.mbx, "thread:<root@sender.example>", ""); got != "" {
		t.Fatalf("the marker gave thread:<root>: %q", got)
	}
	f.flush(t)
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatalf("index of the term list: %d %v", n, err)
	}
	if n := pendingCount(t, f.env, f.mbx, 1); n != 0 {
		t.Fatalf("pending files left: %d", n)
	}
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "thread:<root@sender.example>", ""); got != "re1" {
		t.Fatalf("the reply is not found under the root of its thread: %q", got)
	}
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "re1" {
		t.Fatalf("from: %q", got)
	}
	// The term list wrote one segment, with the postings no segment held.
	mine := ownSegments(t, f.env, f.mbx, 1, dev)
	if len(mine) != 2 {
		t.Fatalf("segments after the term list: %v", mine)
	}
	segs, err := c.Segments(f.mbx, 1)
	if err != nil {
		t.Fatal(err)
	}
	from, _ := c.TermMark(f.mbx, 1, "from:s@x.example")
	held := 0
	for _, s := range segs {
		for _, ps := range s.Postings {
			if ps.Mark == from {
				held++
			}
		}
	}
	if held != 1 {
		t.Fatalf("from: held by %d segments", held)
	}
	c.Close()
	for _, v := range mailMemos(t, f.u.Dir, f.mbx) {
		if m := v.(map[string]any); m["indexed"] != nil || m["indexed_terms"] != nil {
			t.Fatalf("memo noted as indexed: %v", m)
		}
	}
}

// TestPendingReplayAfterDeletionKinds (finding medium, turned around in
// task 09g): as TestPendingReplayAfterDeletion, for a mail whose marker
// was indexed before its term list. The attacker removes the segments
// that hold the mail and puts the marker back before one Sync and the
// term list before the next, 20 rounds: each is indexed again, no
// pending file is left, the mail is found under the root of its thread
// after each term list, and state.json grows by at most roundBound per
// round (the record of the new segment).
func TestPendingReplayAfterDeletionKinds(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	f.send(t, "s@x.example", reply)
	marker := pendingFiles(t, f.env, f.mbx, 1)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	f.flush(t)
	terms := pendingFiles(t, f.env, f.mbx, 1)
	if len(marker) == 0 || len(terms) == 0 {
		t.Fatalf("pending files: %d markers, %d term lists", len(marker), len(terms))
	}
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := search(t, c, f.mbx, "thread:<root@sender.example>", ""); got != "re1" {
		t.Fatal(got)
	}
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	dev, _ := c.Device()
	base := stateSize(t, f.u.Dir)
	prev := base
	const rounds = 20
	for r := 0; r < rounds; r++ {
		for _, ref := range ownSegments(t, f.env, f.mbx, 1, dev) {
			if err := f.env.Store.RemoveIndexSegment(f.mbx, 1, ref.Device, ref.Seq); err != nil {
				t.Fatal(err)
			}
		}
		put := marker
		if r%2 == 1 {
			put = terms
		}
		for id, data := range put {
			if err := store.WriteFileAtomic(f.env.Store.PendingFile(f.mbx, 1, id), data); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.Sync(); err != nil {
			t.Fatal(err)
		}
		if mine := ownSegments(t, f.env, f.mbx, 1, dev); len(mine) != 1 {
			t.Fatalf("round %d: segments %v", r, mine)
		}
		if n := pendingCount(t, f.env, f.mbx, 1); n != 0 {
			t.Fatalf("round %d: %d pending files left", r, n)
		}
		if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "re1" {
			t.Fatalf("round %d: %q", r, got)
		}
		if r%2 == 1 {
			if got := search(t, c, f.mbx, "thread:<root@sender.example>", ""); got != "re1" {
				t.Fatalf("round %d: thread: %q", r, got)
			}
		}
		now := stateSize(t, f.u.Dir)
		if now-prev > roundBound {
			t.Fatalf("round %d: state.json +%d bytes", r, now-prev)
		}
		prev = now
	}
	t.Logf("state.json +%d bytes after %d rounds (segments removed, marker and term list put back in turn)", stateSize(t, f.u.Dir)-base, rounds)
}

// TestMarkerAfterTermList (finding medium, turned around in task 09g): a
// client that saw the term list of a mail first indexes its marker put
// back later once the segment is gone: the marker gives the terms derived
// from the metadata (here thread: of the own Message-ID, TODO(Q12)). With
// the segment of the term list there, the marker writes only what that
// segment does not hold. Nothing is noted per mail.
func TestMarkerAfterTermList(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	f.send(t, "s@x.example", reply)
	marker := pendingFiles(t, f.env, f.mbx, 1)
	f.flush(t)
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatalf("index: %d %v", n, err)
	}
	dev, _ := c.Device()
	put := func() {
		for id, data := range marker {
			if err := store.WriteFileAtomic(f.env.Store.PendingFile(f.mbx, 1, id), data); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The segment of the term list is there: only thread: of the own
	// Message-ID is new.
	put()
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if mine := ownSegments(t, f.env, f.mbx, 1, dev); len(mine) != 2 {
		t.Fatalf("the marker after the term list: %v", mine)
	}
	if got := search(t, c, f.mbx, "thread:<re1@sender.example>", ""); got != "re1" {
		t.Fatalf("thread: of the own Message-ID: %q", got)
	}
	for _, ref := range ownSegments(t, f.env, f.mbx, 1, dev) {
		if err := f.env.Store.RemoveIndexSegment(f.mbx, 1, ref.Device, ref.Seq); err != nil {
			t.Fatal(err)
		}
	}
	put()
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if mine := ownSegments(t, f.env, f.mbx, 1, dev); len(mine) != 1 {
		t.Fatalf("the marker after the segments were removed: %v", mine)
	}
	if n := pendingCount(t, f.env, f.mbx, 1); n != 0 {
		t.Fatalf("%d pending files left", n)
	}
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "re1" {
		t.Fatalf("from: %q", got)
	}
	c.Close()
	for _, v := range mailMemos(t, f.u.Dir, f.mbx) {
		if m := v.(map[string]any); m["indexed"] != nil || m["indexed_terms"] != nil {
			t.Fatalf("noted: %v", m)
		}
	}
}

// TestIndexedLegacyRecord (finding medium, turned around in task 09g): a
// memo of tasks 09d to 09f that notes a mail as indexed is read and kept
// as it is, and ignored: the term list of the mail, put back with its
// segment gone, is indexed each time.
func TestIndexedLegacyRecord(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	f.send(t, "s@x.example", reply)
	f.flush(t)
	terms := pendingFiles(t, f.env, f.mbx, 1)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := c.List(f.mbx, store.ID{})
	if len(list) != 1 {
		t.Fatalf("%d mails", len(list))
	}
	dev, _ := c.Device()
	c.Close()
	editState(t, f.u.Dir, f.mbx, func(ms map[string]any) {
		m := ms["mails"].(map[string]any)[list[0].ID.String()].(map[string]any)
		m["indexed"], m["indexed_terms"] = 1, 1
	})
	c = f.env.Reopen(f.u)
	for round := 0; round < 2; round++ {
		for _, ref := range ownSegments(t, f.env, f.mbx, 1, dev) {
			if err := f.env.Store.RemoveIndexSegment(f.mbx, 1, ref.Device, ref.Seq); err != nil {
				t.Fatal(err)
			}
		}
		for id, data := range terms {
			if err := store.WriteFileAtomic(f.env.Store.PendingFile(f.mbx, 1, id), data); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		if mine := ownSegments(t, f.env, f.mbx, 1, dev); len(mine) != 1 {
			t.Fatalf("round %d: segments %v", round, mine)
		}
		if got := search(t, c, f.mbx, "thread:<root@sender.example>", ""); got != "re1" {
			t.Fatalf("round %d: %q", round, got)
		}
	}
	c.Close()
	m := mailMemos(t, f.u.Dir, f.mbx)[list[0].ID.String()].(map[string]any)
	if m["indexed"] != float64(1) || m["indexed_terms"] != float64(1) {
		t.Fatalf("legacy fields not kept: %v", m)
	}
}

// TestAttack09dStep4ReplacedMeanwhile (finding low 1, the verifier's test,
// turned around): in step 4 of device lost the segment taken over is
// replaced (or removed) between reading and taking the mailbox lock, and
// put back afterwards. DeviceLost reports ErrPartial, the mailbox stays
// marked, the warning names the segment, "nicht neu ausgestellt" and the
// cause; Sync completes the reissue and carol finds the mail.
func TestAttack09dStep4ReplacedMeanwhile(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(fmt.Sprint("removed=", removed), func(t *testing.T) {
			f := newFixture(t)
			_, carol := threeMembers(t, f)
			f.send(t, "s@x.example", header("s@x.example", "m1"))
			f.flush(t)
			if _, err := f.u.Client.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			if got := search(t, f.u.Client, f.mbx, "from:s@x.example", ""); got != "m1" {
				t.Fatal(got)
			}
			list, _ := f.u.Client.List(f.mbx, store.ID{})
			n := list[0].Epoch
			refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
			seg := refs[0]
			p := f.env.Store.IndexSegmentFile(f.mbx, n, seg.Device, seg.Seq)
			orig := mustRead(t, p)
			swapped := false
			client.SetResignHook(t, func() {
				if swapped {
					return
				}
				swapped = true
				if removed {
					os.Remove(p)
				} else {
					os.WriteFile(p, []byte("junk"), 0o644)
				}
			})
			f.env.Clock.Advance(time.Minute)
			f.u.Client.Close()
			f.env.Warnings.Take()
			gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
			if err := os.WriteFile(p, orig, 0o644); err != nil {
				t.Fatal(err)
			}
			if !swapped || gen != 2 || !errors.Is(err, client.ErrPartial) || !strings.Contains(err.Error(), "not issued again") {
				t.Fatalf("DeviceLost: gen %d err %v (swapped %v)", gen, err, swapped)
			}
			warningWith(t, f.env.Warnings.Take(), fmt.Sprintf("%s-%d", seg.Device, seg.Seq), "nicht neu ausgestellt", "ersetzt oder entfernt")
			if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
				t.Fatalf("mailbox not marked: %d", r)
			}
			client.SetResignHook(t, nil)
			c := f.env.Reopen(f.u)
			if err := c.Sync(); err != nil {
				t.Fatalf("Sync: %v", err)
			}
			c.Close()
			if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
				t.Fatalf("mark after Sync: %d", r)
			}
			cc := f.env.Reopen(carol)
			if err := cc.Sync(); err != nil {
				t.Fatal(err)
			}
			if got := search(t, cc, f.mbx, "from:s@x.example", ""); got != "m1" {
				t.Fatalf("carol: %q %v", got, f.env.Warnings.Take())
			}
		})
	}
}

// TestDeviceLostStep4MetaReplacedMeanwhile (finding low 1, metadata): the
// metadata alice flagged with generation 1 are replaced for a moment
// while step 4 signs them again (resignMetaHook): ErrPartial, the mailbox
// stays marked, the warning names the mail; Sync completes it.
func TestDeviceLostStep4MetaReplacedMeanwhile(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	if _, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"seen"}, nil); err != nil {
		t.Fatal(err)
	}
	path := f.env.Store.MetaFile(f.mbx, f.inbox(t), a.ID)
	orig := mustRead(t, path)
	once := false
	client.SetResignMetaHook(t, func() {
		if once {
			return
		}
		once = true
		if err := os.WriteFile(path, []byte("junk"), 0o644); err != nil {
			t.Error(err)
		}
	})
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
	if err := os.WriteFile(path, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	if !once || gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("DeviceLost: %d %v", gen, err)
	}
	warningWith(t, f.env.Warnings.Take(), a.ID.String(), "nicht neu ausgestellt", "ersetzt oder entfernt")
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("mailbox not marked: %d", r)
	}
	client.SetResignMetaHook(t, nil)
	c := f.env.Reopen(f.u)
	if err := c.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if s, g, v := signerOf(t, f, a.ID); s != f.u.ID || g != 2 || v != 3 {
		t.Fatalf("not issued again: %s %d %d", s, g, v)
	}
	c.Close()
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
		t.Fatalf("mark after Sync: %d", r)
	}
}

// genLog answers ErrNotInLog for CheckGeneration of one generation of
// one user while armed.
type genLog struct {
	translog.Log
	user  store.ID
	gen   uint32
	armed *bool
}

func (l *genLog) CheckGeneration(user store.ID, gen uint32) error {
	if *l.armed && user == l.user && gen == l.gen {
		return fmt.Errorf("%w: test", translog.ErrNotInLog)
	}
	return l.Log.CheckGeneration(user, gen)
}

// TestDeviceLostStep4OwnGenNotConfirmed (finding low 1, userGen): while
// step 4 signs alice's segments and metadata again, the log does not
// confirm her new generation for a moment (armed by the hook of the first
// segment signed again). The second segment and the metadata are not
// issued again: ErrPartial, the mailbox stays marked, the warnings name
// them and the cause; Sync completes the reissue.
func TestDeviceLostStep4OwnGenNotConfirmed(t *testing.T) {
	f := newFixture(t)
	_, carol := threeMembers(t, f)
	c := f.u.Client
	for _, s := range []string{"m1", "m2"} {
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := c.List(f.mbx, store.ID{})
	n := list[0].Epoch
	if _, err := c.SetFlags(f.mbx, list[0].ID, []string{"seen"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"m1", "m2"} {
		if got := search(t, c, f.mbx, "from:"+s+"@x.example", ""); got != s {
			t.Fatal(got)
		}
	}
	dev, _ := c.Device()
	old := ownSegments(t, f.env, f.mbx, n, dev)
	if len(old) != 2 {
		t.Fatalf("segments %v", old)
	}
	armed := false
	client.SetLogHook(t, func(l translog.Log) translog.Log { return &genLog{Log: l, user: f.u.ID, gen: 2, armed: &armed} })
	client.SetResignHook(t, func() { armed = true })
	f.env.Clock.Advance(time.Minute)
	c.Close()
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
	armed = false
	client.SetResignHook(t, nil)
	if gen != 2 || !errors.Is(err, client.ErrPartial) || !strings.Contains(err.Error(), "not issued again") {
		t.Fatalf("DeviceLost: %d %v", gen, err)
	}
	w := f.env.Warnings.Take()
	warningWith(t, w, fmt.Sprintf("%s-%d", old[1].Device, old[1].Seq), "nicht neu ausgestellt", "nicht bestätigt")
	warningWith(t, w, list[0].ID.String(), "nicht neu ausgestellt", "nicht bestätigt")
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("mailbox not marked: %d", r)
	}
	c = f.env.Reopen(f.u)
	if err := c.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	c.Close()
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
		t.Fatalf("mark after Sync: %d", r)
	}
	if s, g, _ := signerOf(t, f, list[0].ID); s != f.u.ID || g != 2 {
		t.Fatalf("metadata not issued again: %s %d", s, g)
	}
	cc := f.env.Reopen(carol)
	if err := cc.Sync(); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"m1", "m2"} {
		if got := search(t, cc, f.mbx, "from:"+s+"@x.example", ""); got != s {
			t.Fatalf("carol, %s: %q %v", s, got, f.env.Warnings.Take())
		}
	}
}

// TestDeviceLostStep4MetaVersionLimit (finding low 1, MaxUint32): alice's
// metadata with the highest version, signed by generation 1, cannot be
// signed again: step 4 reports it (ErrPartial, mark, warning with the
// mail ID and the cause) instead of passing it over; Search and List
// use them as checked.
func TestDeviceLostStep4MetaVersionLimit(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	f.forgeVersion(t, f.u, a.Meta, a.Epoch, math.MaxUint32, nil)
	if !listed(t, f.u.Client, f.mbx, a.ID) {
		t.Fatal("not listed")
	}
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
	if gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("DeviceLost: %d %v", gen, err)
	}
	warningWith(t, f.env.Warnings.Take(), a.ID.String(), "nicht neu ausgestellt", "erschöpft")
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("mailbox not marked: %d", r)
	}
	c := f.env.Reopen(f.u)
	if !listed(t, c, f.mbx, a.ID) {
		t.Fatalf("not listed: %v", f.env.Warnings.Take())
	}
	if s, g, v := signerOf(t, f, a.ID); s != f.u.ID || g != 1 || v != math.MaxUint32 {
		t.Fatalf("metadata changed: %s %d %d", s, g, v)
	}
}

// TestAttack09dReissueSilentStaleUserRec (finding low 1, the verifier's
// test, turned around): the user.rec of before the revocation put back
// while alice's mailbox is marked makes Sync fail; it neither clears the
// mark nor passes the segment over. With the current user.rec back, Sync
// completes the reissue and carol finds the mail.
func TestAttack09dReissueSilentStaleUserRec(t *testing.T) {
	f := newFixture(t)
	_, carol := threeMembers(t, f)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	if _, err := f.u.Client.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if got := search(t, f.u.Client, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatal(got)
	}
	list, _ := f.u.Client.List(f.mbx, store.ID{})
	n := list[0].Epoch
	dev, _ := f.u.Client.Device()
	oldUser := mustRead(t, f.env.Store.UserFile(f.u.ID))
	for s := uint64(2); s <= 80; s++ {
		if err := os.MkdirAll(f.env.Store.IndexSegmentFile(f.mbx, n, dev, s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	if _, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words); !errors.Is(err, client.ErrPartial) {
		t.Fatalf("DeviceLost: %v", err)
	}
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("precondition: mailbox not marked: %d", r)
	}
	for s := uint64(2); s <= 80; s++ {
		os.RemoveAll(f.env.Store.IndexSegmentFile(f.mbx, n, dev, s))
	}
	newUser := mustRead(t, f.env.Store.UserFile(f.u.ID))
	c := f.env.Reopen(f.u)
	if err := os.WriteFile(f.env.Store.UserFile(f.u.ID), oldUser, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(); err == nil {
		t.Fatal("Sync with the old user.rec succeeded")
	}
	c.Close()
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("mark cleared with the old user.rec: %d", r)
	}
	if err := os.WriteFile(f.env.Store.UserFile(f.u.ID), newUser, 0o644); err != nil {
		t.Fatal(err)
	}
	c = f.env.Reopen(f.u)
	if err := c.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	c.Close()
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
		t.Fatalf("mark after Sync: %d", r)
	}
	cc := f.env.Reopen(carol)
	if err := cc.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := search(t, cc, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("carol: %q %v", got, f.env.Warnings.Take())
	}
}

// TestAttack09dOldMemoShadowCopy (finding low 2, the verifier's test): a
// record in the format before task 09c counts only for the file at its
// place. A copy of bob's segment under a lower sequence number is checked
// first and rejected; the file at the recorded place, byte-equal, is
// checked as well and taken over, so alice keeps the hit. state.json
// grows by the copy no more than without it (records are per content).
func TestAttack09dOldMemoShadowCopy(t *testing.T) {
	growth := map[bool]int64{}
	for _, attack := range []bool{false, true} {
		t.Run(fmt.Sprint("attack=", attack), func(t *testing.T) {
			f := newFixture(t)
			bob, _ := threeMembers(t, f)
			f.send(t, "s@x.example", header("s@x.example", "m1"))
			f.flush(t)
			if _, err := bob.Client.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			list, _ := f.u.Client.List(f.mbx, store.ID{})
			n := list[0].Epoch
			refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
			if len(refs) != 1 || refs[0].Seq == 0 {
				t.Fatalf("segments %v", refs)
			}
			bobSeg := refs[0]
			data, err := f.env.Store.ReadIndexSegment(f.mbx, n, bobSeg.Device, bobSeg.Seq)
			if err != nil {
				t.Fatal(err)
			}
			if got := search(t, f.u.Client, f.mbx, "from:s@x.example", ""); got != "m1" {
				t.Fatal(got)
			}
			f.u.Client.Close()
			key := client.SegmentMemoKey(n, bobSeg.Device, data)
			editState(t, f.u.Dir, f.mbx, func(ms map[string]any) {
				checked := ms["checked"].(map[string]any)
				m := checked[key]
				delete(checked, key)
				checked[fmt.Sprintf("index/%d/%s-%d", n, bobSeg.Device, bobSeg.Seq)] = m
			})
			f.env.Rotate(bob)
			if attack {
				if err := f.env.Store.WriteIndexSegment(f.mbx, n, bobSeg.Device, 0, data); err != nil {
					t.Fatal(err)
				}
			}
			base := stateSize(t, f.u.Dir)
			c := f.env.Reopen(f.u)
			f.env.Warnings.Take()
			if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
				t.Fatalf("alice lost the hit of bob's segment at its recorded place: %q %v", got, f.env.Warnings.Take())
			}
			w := f.env.Warnings.Take()
			if attack {
				warningWith(t, w, fmt.Sprintf("%s-1", bobSeg.Device), "jene Datei wurde abgelehnt")
			}
			warningWith(t, w, fmt.Sprintf("%s-%d", bobSeg.Device, bobSeg.Seq), "neu signiert")
			c.Close()
			growth[attack] = stateSize(t, f.u.Dir) - base
		})
	}
	// The resign marks the old record and adds the one of alice's
	// segment; the copy adds nothing.
	t.Logf("state.json without the copy %+d, with it %+d bytes", growth[false], growth[true])
	if growth[true] != growth[false] {
		t.Fatalf("the copy changed the growth: %v", growth)
	}
}

// TestAttack09dGrowthCombo (the verifier's test of task 09d, regression):
// an attacker keeps every pending file and every segment that ever
// appeared (alice and bob index in turns, both merge) and before every
// round puts all of them back, at their places, under fresh sequence
// numbers, under the other devices, and the pending files in other
// epochs too. state.json of alice and bob does not grow after the first
// round, and alice finds every mail.
func TestAttack09dGrowthCombo(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	clients := []struct {
		name string
		dir  string
		c    *client.Client
	}{{"alice", f.u.Dir, f.u.Client}, {"bob", bob.Dir, bob.Client}}
	type file struct {
		path string
		data []byte
	}
	var pend []file
	segs := map[string][]byte{}
	snapPending := func() {
		eps, _ := f.env.Store.ListPendingEpochs(f.mbx)
		for _, n := range eps {
			for id, d := range pendingFiles(t, f.env, f.mbx, n) {
				pend = append(pend, file{f.env.Store.PendingFile(f.mbx, n, id), d})
			}
		}
	}
	snapSegs := func() {
		for n := uint32(1); n <= 40; n++ {
			refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
			for _, r := range refs {
				p := f.env.Store.IndexSegmentFile(f.mbx, n, r.Device, r.Seq)
				if d, err := os.ReadFile(p); err == nil {
					segs[p] = d
				}
			}
		}
	}
	for i := 0; i < 40; i++ {
		if i == 20 {
			f.env.Clock.Set(time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC))
		}
		f.send(t, "s@x.example", header("s@x.example", fmt.Sprintf("m%d", i)))
		if i%3 != 0 {
			f.flush(t)
		}
		snapPending()
		if _, err := clients[i%2].c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		snapSegs()
	}
	devs := map[store.ID]bool{}
	for p := range segs {
		if id, err := store.ParseID(filepath.Base(p)[:26]); err == nil {
			devs[id] = true
		}
	}
	replay := func(round int) {
		for _, p := range pend {
			os.MkdirAll(filepath.Dir(p.path), 0o755)
			os.WriteFile(p.path, p.data, 0o644)
			for _, other := range []string{"1", "2", "9", "10"} {
				q := filepath.Join(filepath.Dir(filepath.Dir(p.path)), other, filepath.Base(p.path))
				if _, err := os.Stat(filepath.Dir(q)); err == nil {
					os.WriteFile(q, p.data, 0o644)
				}
			}
		}
		k := 0
		for p, d := range segs {
			os.WriteFile(p, d, 0o644)
			dir, base := filepath.Dir(p), filepath.Base(p)
			os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%d.gml", base[:26], 100000+round*1000+k)), d, 0o644)
			for dv := range devs {
				os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%d.gml", dv, 200000+round*1000+k)), d, 0o644)
			}
			k++
		}
	}
	var base [2]int64
	for round := 0; round < 8; round++ {
		replay(round)
		for _, c := range clients {
			if _, err := c.c.Index(f.mbx); err != nil {
				t.Logf("%s index: %v", c.name, err)
			}
			if _, err := c.c.Search(f.mbx, "from:s@x.example", client.SearchOptions{}); err != nil {
				t.Logf("%s search: %v", c.name, err)
			}
		}
		f.env.Warnings.Take()
		if round == 1 {
			base = [2]int64{stateSize(t, f.u.Dir), stateSize(t, bob.Dir)}
		}
	}
	a, b := stateSize(t, f.u.Dir)-base[0], stateSize(t, bob.Dir)-base[1]
	t.Logf("state.json after round 1: alice %+d, bob %+d bytes", a, b)
	if a > stateBound || b > stateBound {
		t.Fatalf("state.json grew after round 1: alice %+d, bob %+d", a, b)
	}
	list, err := f.u.Client.Search(f.mbx, "from:s@x.example", client.SearchOptions{})
	if err != nil || len(list) != 40 {
		t.Fatalf("alice finds %d of 40 (%v)", len(list), err)
	}
}

// TestForeignMergesPutBack (finding low 3, turned around in task 09g):
// segments that other clients merged are not marked in alice's records,
// and copies of one content from different clients differ in their
// bytes. Alice merged the postings of 16 mails; then 16 segments of other
// devices (bob's merge results, here written directly), each with
// postings alice merged before, are put back, in two sets and in rounds.
// Without the limit of 09e/09f they count for MergeThreshold, and alice
// merges each set once (the first round of each set): one new segment,
// and state.json grows by the records of the contents read and written,
// at most (MergeThreshold+1)*roundBound. From then on each set is spent
// (its successor leads to her latest result): no merge, no growth. A new
// mail is merged as before.
func TestForeignMergesPutBack(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	c := f.u.Client
	dev, _ := c.Device()
	var ids []store.ID
	var n uint32
	for i := 0; i < client.MergeThreshold; i++ {
		s := fmt.Sprintf("m%02d", i)
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := c.List(f.mbx, store.ID{})
	n = list[0].Epoch
	for _, m := range list {
		ids = append(ids, m.ID)
	}
	merged := ownSegments(t, f.env, f.mbx, n, dev)
	if len(merged) != 1 || segmentCount(t, f.env, f.mbx, n) != 1 {
		t.Fatalf("alice did not merge: %v", merged)
	}
	e, _, err := f.env.Store.ReadEpoch(f.mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	mk, err := c.TermMark(f.mbx, n, "fromdomain:x.example")
	if err != nil {
		t.Fatal(err)
	}
	// Two sets of 16 foreign segments, each with postings alice merged.
	type foreign struct {
		dev  store.ID
		data []byte
	}
	sets := make([][]foreign, 2)
	for s := range sets {
		for i := 0; i < client.MergeThreshold; i++ {
			d, _ := store.NewID(nil)
			seg := &store.IndexSegment{MailboxID: f.mbx, Epoch: n, Postings: []store.Posting{{Mark: mk, MailIDs: []store.ID{ids[(i+s)%len(ids)]}}}}
			sets[s] = append(sets[s], foreign{d, sealSegment(t, f.env, bob, e, n, d, seg)})
		}
	}
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	var sizes []int64
	for r := 0; r < 6; r++ {
		for _, x := range sets[r%2] {
			if err := f.env.Store.WriteIndexSegment(f.mbx, n, x.dev, 1, x.data); err != nil && !errors.Is(err, store.ErrExists) {
				t.Fatal(err)
			}
		}
		f.env.Warnings.Take()
		before, prev := stateSize(t, f.u.Dir), ownSegments(t, f.env, f.mbx, n, dev)
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		mine := ownSegments(t, f.env, f.mbx, n, dev)
		if len(mine) != 1 || (r < 2) != (mine[0] != prev[0]) {
			t.Fatalf("round %d: alice's segments %v, before %v", r, mine, prev)
		}
		if grown := stateSize(t, f.u.Dir) - before; grown > (client.MergeThreshold+1)*roundBound {
			t.Fatalf("round %d: state.json +%d bytes", r, grown)
		}
		sizes = append(sizes, stateSize(t, f.u.Dir))
		// The attacker removes them again (as a merge by another
		// client would).
		for _, x := range sets[r%2] {
			f.env.Store.RemoveIndexSegment(f.mbx, n, x.dev, 1)
		}
	}
	t.Logf("state.json after each round: %v", sizes)
	// Round 2 makes the record of the result of round 1, once.
	for r := 3; r < len(sizes); r++ {
		if sizes[r] != sizes[2] {
			t.Fatalf("grew after the first round of each set: %v", sizes)
		}
	}
	if got := search(t, c, f.mbx, "from:m00@x.example", ""); got != "m00" {
		t.Fatal(got)
	}
	// A spent set and a new mail: the set is removed under the lock and
	// makes no merge; the new mail is found next to alice's result.
	latest := ownSegments(t, f.env, f.mbx, n, dev)
	for _, x := range sets[0] {
		if err := f.env.Store.WriteIndexSegment(f.mbx, n, x.dev, 1, x.data); err != nil && !errors.Is(err, store.ErrExists) {
			t.Fatal(err)
		}
	}
	f.send(t, "new@x.example", header("new@x.example", "new"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if mine := ownSegments(t, f.env, f.mbx, n, dev); len(mine) != 2 || mine[0] != latest[0] || segmentCount(t, f.env, f.mbx, n) != 2 {
		t.Fatalf("spent set: %v, %d segments", mine, segmentCount(t, f.env, f.mbx, n))
	}
	if got := search(t, c, f.mbx, "from:new@x.example", ""); got != "new" {
		t.Fatal(got)
	}
	if got := search(t, c, f.mbx, "from:m00@x.example", ""); got != "m00" {
		t.Fatal(got)
	}
}
