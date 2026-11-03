package client_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 09b: S13 for metadata and index segments, pinned test
// gaps of task 09, the warnings of Search and of duplicate segments, and
// the file hash in the memo of a mail.

// threeMembers shares the fixture's mailbox with bob and carol (user
// members) and returns them; mails delivered afterwards belong to an
// epoch that names all three.
func threeMembers(t *testing.T, f *fixture) (bob, carol *testenv.User) {
	t.Helper()
	bob = f.env.NewUser("bob")
	carol = f.env.NewUser("carol")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	f.env.Share(f.u, f.mbx, carol, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	return bob, carol
}

// signerOf returns the signer of the metadata of mail id and their
// version.
func signerOf(t *testing.T, f *fixture, id store.ID) (store.ID, uint32, uint32) {
	t.Helper()
	data, err := f.env.Store.ReadMeta(f.mbx, f.inbox(t), id)
	if err != nil {
		t.Fatal(err)
	}
	pf := parse(t, data)
	if pf.Trailer == nil || pf.Trailer.Signer.Type != envelope.SignerUser {
		t.Fatal("metadata not signed by a user")
	}
	return store.ID(pf.Trailer.Signer.ID), pf.Trailer.Signer.Gen, pf.Header.Version
}

// listed reports whether mail id is in the inbox list of c.
func listed(t *testing.T, c *client.Client, mbx, id store.ID) bool {
	t.Helper()
	list, err := c.List(mbx, store.ID{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range list {
		if m.ID == id {
			return true
		}
	}
	return false
}

// setTree sets the tree size of the check record key of mbx in the state
// of the client directory dir (the client must be closed).
func setTree(t *testing.T, dir string, mbx store.ID, key string, tree int64) {
	t.Helper()
	editState(t, dir, mbx, func(ms map[string]any) {
		checked, _ := ms["checked"].(map[string]any)
		m, ok := checked[key].(map[string]any)
		if !ok {
			t.Fatalf("no check record %s", key)
		}
		if tree == 0 {
			delete(m, "tree")
		} else {
			m["tree"] = tree
		}
	})
}

// TestMetaTakeover (point 2): bob sets flags (version 2, signed by his
// generation 1) and rotates. Alice had listed the mail before the
// revocation: she keeps listing it and signs it again (version 3). Carol
// had not seen version 2: she gets a warning naming only the mail ID, and
// the mail is not listed, until alice's version 3 is there. A check
// record that claims a tree holding the revocation, or one without a
// tree, does not count, nor does one for another file of the same signer
// and generation (a version 3 bob's generation 1 signed after alice's
// check: what a thief with the lost device could write).
func TestMetaTakeover(t *testing.T) {
	for _, v := range []string{"takeover", "after-revocation", "no-tree", "other-file"} {
		t.Run(v, func(t *testing.T) {
			f := newFixture(t)
			bob, carol := threeMembers(t, f)
			a := f.deliver(t, "a", "x")
			if !listed(t, carol.Client, f.mbx, a.ID) {
				t.Fatal("carol does not list version 1")
			}
			v2, err := bob.Client.SetFlags(f.mbx, a.ID, []string{"flagged"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !listed(t, f.u.Client, f.mbx, a.ID) {
				t.Fatal("alice does not list version 2")
			}
			want := uint32(2)
			if v == "other-file" {
				f.forgeVersion(t, bob, v2.Meta, a.Epoch, 3, func(m *store.MailMeta) { m.Flags = 1 })
				want = 3
			}
			f.env.Rotate(bob)
			if v == "after-revocation" || v == "no-tree" {
				f.u.Client.Close()
				tree := int64(0)
				if v == "after-revocation" {
					tree = 1 << 40
				}
				setTree(t, f.u.Dir, f.mbx, "meta/"+a.ID.String(), tree)
			}
			// Carol: no check record.
			cc := f.env.Reopen(carol)
			f.env.Warnings.Take()
			if listed(t, cc, f.mbx, a.ID) {
				t.Fatal("carol lists metadata of a revoked generation she did not check")
			}
			w := f.env.Warnings.Take()
			warningWith(t, w, a.ID.String(), "vorher nicht geprüft")
			for _, s := range w {
				if strings.Contains(s, "vorher nicht geprüft") && strings.Contains(s, f.mbx.String()) {
					t.Fatalf("the warning names more than the mail: %s", s)
				}
			}
			ac := f.env.Reopen(f.u)
			f.env.Warnings.Take()
			ok := listed(t, ac, f.mbx, a.ID)
			w = f.env.Warnings.Take()
			if v != "takeover" {
				if ok {
					t.Fatalf("%s: alice took over with a record that does not count", v)
				}
				warningWith(t, w, a.ID.String(), "vorher nicht geprüft")
				if s, _, ver := signerOf(t, f, a.ID); s != bob.ID || ver != want {
					t.Fatal("the file was changed")
				}
				return
			}
			if !ok {
				t.Fatalf("alice, with a check record: not listed (%q)", w)
			}
			warningWith(t, w, a.ID.String(), "übernommen und neu signiert")
			if s, g, ver := signerOf(t, f, a.ID); s != f.u.ID || g != 1 || ver != 3 {
				t.Fatalf("not signed again by alice: %s gen %d version %d", s, g, ver)
			}
			m, _, err := ac.Read(f.mbx, a.ID)
			if err != nil || m.Meta.Version != 3 || client.FlagNames(m.Meta.Flags)[0] != "flagged" {
				t.Fatalf("read after the takeover: %v", err)
			}
			if !listed(t, f.env.Reopen(carol), f.mbx, a.ID) {
				t.Fatalf("carol after the takeover: %q", f.env.Warnings.Take())
			}
		})
	}
}

// TestSegmentTakeover (point 2): bob indexes a mail (his segment, signed
// by his generation 1) and rotates. Alice had searched before the
// revocation: she still finds the mail and signs the segment again (a new
// segment of her device, bob's is removed). Carol had not checked bob's
// segment: a warning names only the segment, and she does not find the
// mail until alice's segment is there. A check record that claims a tree
// holding the revocation does not count.
func TestSegmentTakeover(t *testing.T) {
	for _, v := range []string{"takeover", "after-revocation"} {
		t.Run(v, func(t *testing.T) {
			f := newFixture(t)
			bob, carol := threeMembers(t, f)
			f.send(t, "s@x.example", header("s@x.example", "m1"))
			f.flush(t)
			if n, err := bob.Client.Index(f.mbx); err != nil || n != 1 {
				t.Fatalf("bob indexes: %d %v", n, err)
			}
			list, _ := f.u.Client.List(f.mbx, store.ID{})
			n := list[0].Epoch
			refs, err := f.env.Store.ListIndexSegments(f.mbx, n)
			if err != nil || len(refs) != 1 || pendingCount(t, f.env, f.mbx, n) != 0 {
				t.Fatalf("segments %v %v", refs, err)
			}
			bobSeg := refs[0]
			if got := search(t, f.u.Client, f.mbx, "from:s@x.example", ""); got != "m1" {
				t.Fatalf("alice before: %q", got)
			}
			f.env.Rotate(bob)
			bobData, err := f.env.Store.ReadIndexSegment(f.mbx, n, bobSeg.Device, bobSeg.Seq)
			if err != nil {
				t.Fatal(err)
			}
			key := client.SegmentMemoKey(n, bobSeg.Device, bobData)
			if v == "after-revocation" {
				f.u.Client.Close()
				setTree(t, f.u.Dir, f.mbx, key, 1<<40)
			}
			cc := f.env.Reopen(carol)
			f.env.Warnings.Take()
			if got := search(t, cc, f.mbx, "from:s@x.example", ""); got != "" {
				t.Fatalf("carol finds through a segment of a revoked generation: %q", got)
			}
			segName := fmt.Sprintf("%s-%d", bobSeg.Device, bobSeg.Seq)
			warningWith(t, f.env.Warnings.Take(), segName, "vorher nicht geprüft")
			ac := f.env.Reopen(f.u)
			f.env.Warnings.Take()
			got := search(t, ac, f.mbx, "from:s@x.example", "")
			w := f.env.Warnings.Take()
			if v == "after-revocation" {
				if got != "" {
					t.Fatal("alice took over with a record from after the revocation")
				}
				warningWith(t, w, segName, "vorher nicht geprüft")
				return
			}
			if got != "m1" {
				t.Fatalf("alice, with a check record: %q (%q)", got, w)
			}
			warningWith(t, w, segName, "übernommen und neu signiert")
			refs, _ = f.env.Store.ListIndexSegments(f.mbx, n)
			dev, _ := ac.Device()
			if len(refs) != 1 || refs[0].Device != dev {
				t.Fatalf("segments after the takeover: %v", refs)
			}
			if got := search(t, f.env.Reopen(carol), f.mbx, "from:s@x.example", ""); got != "m1" {
				t.Fatalf("carol after the takeover: %q", got)
			}
		})
	}
}

// TestDeviceLostReissuesMetaAndSegments (point 2): alice sets flags and
// indexes with generation 1, then loses her device. device lost signs her
// metadata (version 3) and her segment again with generation 2; nothing
// falls out of List or Search.
func TestDeviceLostReissuesMetaAndSegments(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	c := f.u.Client
	if _, err := c.SetFlags(f.mbx, a.ID, []string{"seen"}, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Index(f.mbx); err != nil || n != 2 {
		t.Fatalf("index: %d %v", n, err)
	}
	refs, _ := f.env.Store.ListIndexSegments(f.mbx, a.Epoch)
	if len(refs) != 1 {
		t.Fatalf("segments %v", refs)
	}
	f.env.Clock.Advance(time.Minute)
	gen := f.env.DeviceLost(f.u)
	if gen != 2 {
		t.Fatalf("generation %d", gen)
	}
	if s, g, ver := signerOf(t, f, a.ID); s != f.u.ID || g != 2 || ver != 3 {
		t.Fatalf("metadata: %s gen %d version %d", s, g, ver)
	}
	after, _ := f.env.Store.ListIndexSegments(f.mbx, a.Epoch)
	if len(after) != 1 || after[0] == refs[0] {
		t.Fatalf("segment not issued again: %v", after)
	}
	data, err := f.env.Store.ReadIndexSegment(f.mbx, a.Epoch, after[0].Device, after[0].Seq)
	if err != nil {
		t.Fatal(err)
	}
	if tr := parse(t, data).Trailer; tr == nil || store.ID(tr.Signer.ID) != f.u.ID || tr.Signer.Gen != 2 {
		t.Fatal("segment not signed by generation 2")
	}
	c = f.env.Reopen(f.u)
	f.env.Warnings.Take()
	if !listed(t, c, f.mbx, a.ID) {
		t.Fatalf("mail fell out of List: %q", f.env.Warnings.Take())
	}
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "a,m1" {
		t.Fatalf("mail fell out of Search: %q (%q)", got, f.env.Warnings.Take())
	}
	for _, w := range f.env.Warnings.Take() {
		if strings.Contains(w, "widerrufenen") {
			t.Fatalf("warning after device lost: %s", w)
		}
	}
}

// TestVerifyIndexSavesSeenBeforeSegment (point 3a, after the verifier's
// test of the same name): Index saves the versions it checked before it
// writes a segment; if that save fails, no segment is written and
// pending/ stays.
func TestVerifyIndexSavesSeenBeforeSegment(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	f.send(t, "s@x.example", header("s@x.example", "first"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil { // creates the device ID
		t.Fatal(err)
	}
	f.send(t, "s@x.example", "X-Broken: no end of header\r\n") // marker: metadata are checked
	failed := false
	client.SetSaveHook(t, func(dirty bool) error {
		if dirty {
			failed = true
			return errors.New("save failed")
		}
		return nil
	})
	if n, err := c.Index(f.mbx); err == nil || !failed {
		t.Fatalf("index without a saved state succeeded: %d %v", n, err)
	}
	if segmentCount(t, f.env, f.mbx, 1) != 1 {
		t.Fatal("segment written although the versions were not saved")
	}
	if pendingCount(t, f.env, f.mbx, 1) != 1 {
		t.Fatal("pending removed")
	}
	client.SetSaveHook(t, nil)
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatalf("index after repair: %d %v", n, err)
	}
}

// TestVerifySegmentRevokedGeneration (point 3b): a segment signed by a
// user member with a generation revoked before this client checked it is
// rejected (2.2 rule 4, files outside the log).
func TestVerifySegmentRevokedGeneration(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	c := f.u.Client
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := c.List(f.mbx, store.ID{})
	victim := list[0].ID
	n := list[0].Epoch
	e, _, _ := f.env.Store.ReadEpoch(f.mbx, n)
	mk, _ := c.TermMark(f.mbx, n, "from:evil@x.example")
	seg := &store.IndexSegment{MailboxID: f.mbx, Epoch: n, Postings: []store.Posting{{Mark: mk, MailIDs: []store.ID{victim}}}}
	bobDev, _ := store.NewID(nil)
	data := sealSegment(t, f.env, bob, e, n, bobDev, seg) // bob, generation 1
	f.env.Rotate(bob)                                     // generation 1 revoked
	if err := f.env.Store.WriteIndexSegment(f.mbx, n, bobDev, 1, data); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:evil@x.example", ""); got != "" {
		t.Fatalf("segment of a revoked generation accepted: %q", got)
	}
	warningWith(t, f.env.Warnings.Take(), bobDev.String(), "wird ignoriert", "vorher nicht geprüft")
}

// TestVerifySetFlagsHeader (point 3c): with the clock 48 hours after the
// receipt, the new metadata version keeps created equal to the receipt.
func TestVerifySetFlagsHeader(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	f.env.Clock.Advance(48 * time.Hour)
	m, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"answered"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := f.env.Store.ReadMeta(f.mbx, f.inbox(t), a.ID)
	pf := parse(t, data)
	if pf.Header.Created != a.Meta.Received || pf.Header.Version != 2 || m.Meta.Version != 2 || m.Meta.Received != a.Meta.Received {
		t.Fatalf("header %+v", pf.Header)
	}
	if pf.Trailer == nil || pf.Trailer.Signer.Type != envelope.SignerUser {
		t.Fatal("trailer")
	}
}

// forgePendingFor writes a marker of epoch e naming mail id (unprocessed),
// signed by the ingest key.
func (f *fixture) forgePendingFor(t *testing.T, e *store.Epoch, id store.ID, created time.Time) store.ID {
	t.Helper()
	fid, _ := store.NewID(nil)
	p := &store.Pending{MailboxID: f.mbx, Epoch: e.Number, Entries: []store.PendingEntry{{MailID: id, Unprocessed: true}}}
	plain, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	data, err := envelope.Seal(envelope.Header{Kind: envelope.KindPending, MailboxID: f.mbx, Epoch: e.Number, FileID: fid, Created: created.UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: f.mbx, Gen: e.Number, PublicKey: e.MetaPub}}, plain,
		&envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerIngest, Gen: 1, Key: f.env.IngestKey}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MkdirAll(f.env.Store.PendingDir(f.mbx, e.Number)); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateFileAtomic(f.env.Store.PendingFile(f.mbx, e.Number, fid), data); err != nil {
		t.Fatal(err)
	}
	return fid
}

// TestVerifyPendingEntryOtherEpoch (point 3d): a pending entry of epoch 2
// naming a mail of epoch 1 is not indexed; the file stays with a warning.
func TestVerifyPendingEntryOtherEpoch(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	c := f.u.Client
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	e2, _, _ := f.env.Store.ReadEpoch(f.mbx, 2)
	f.env.Clock.Set(time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC))
	fid := f.forgePendingFor(t, e2, a.ID, f.env.Clock.Now())
	f.env.Warnings.Take()
	if n, err := c.Index(f.mbx); err != nil || n != 0 {
		t.Fatalf("index: %d %v", n, err)
	}
	if ids, _ := f.env.Store.ListPending(f.mbx, 2); len(ids) != 1 || ids[0] != fid {
		t.Fatal("the file must stay")
	}
	warningWith(t, f.env.Warnings.Take(), a.ID.String(), "wird nicht indexiert")
	if segmentCount(t, f.env, f.mbx, 2) != 0 {
		t.Fatal("segment written for epoch 2")
	}
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "a" {
		t.Fatalf("search: %q", got)
	}
}

// TestMergeUnderLock (point 3e): the merge of segments waits for the
// mailbox lock. The test holds the lock from the hook right before the
// merge takes it; Index must not finish while the lock is held, and
// merges once it is released.
func TestMergeUnderLock(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	for i := 0; i < client.MergeThreshold-1; i++ {
		f.send(t, "s@x.example", header("s@x.example", "m"+string(rune('a'+i))))
		f.flush(t)
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
	}
	if n := segmentCount(t, f.env, f.mbx, 1); n != client.MergeThreshold-1 {
		t.Fatalf("%d segments", n)
	}
	f.send(t, "s@x.example", header("s@x.example", "mz"))
	f.flush(t)
	done := make(chan struct{})
	heldDuringIndex := make(chan bool, 1)
	segsWhileHeld := make(chan int, 1)
	client.SetMergeHook(t, func() {
		unlock, err := f.env.Store.LockMailbox(f.mbx)
		if err != nil {
			t.Error(err)
			return
		}
		go func() {
			select {
			case <-done:
				heldDuringIndex <- false // Index finished while the lock was held
			case <-time.After(500 * time.Millisecond):
				heldDuringIndex <- true
			}
			segsWhileHeld <- segmentCount(t, f.env, f.mbx, 1)
			unlock()
		}()
	})
	var err error
	go func() {
		_, err = c.Index(f.mbx)
		close(done)
	}()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if !<-heldDuringIndex {
		t.Fatal("the merge did not wait for the mailbox lock")
	}
	if n := <-segsWhileHeld; n != client.MergeThreshold {
		t.Fatalf("%d segments while the lock was held", n)
	}
	if n := segmentCount(t, f.env, f.mbx, 1); n != 1 {
		t.Fatalf("%d segments after the merge", n)
	}
}

// TestSearchWarnsHiddenFolder (point 4, after the verifier's
// TestAttackHideMailFromSearch): an indexed mail moved by the server into
// a folder directory that folders.gml does not name is not shown by
// Search, and a warning names the mail ID, as in List.
func TestSearchWarnsHiddenFolder(t *testing.T) {
	f := newFixture(t)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	c := f.u.Client
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := c.List(f.mbx, store.ID{})
	if len(list) != 1 {
		t.Fatal("baseline list")
	}
	id, inbox := list[0].ID, f.inbox(t)
	hidden, _ := store.NewID(nil)
	if err := store.MkdirAll(f.env.Store.MailDir(f.mbx, hidden)); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]string{
		{f.env.Store.MailFile(f.mbx, inbox, id), f.env.Store.MailFile(f.mbx, hidden, id)},
		{f.env.Store.MetaFile(f.mbx, inbox, id), f.env.Store.MetaFile(f.mbx, hidden, id)},
	} {
		if err := store.WriteFileAtomic(p[1], mustRead(t, p[0])); err != nil {
			t.Fatal(err)
		}
		if err := store.RemoveDurable(p[0]); err != nil {
			t.Fatal(err)
		}
	}
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "" {
		t.Fatalf("mail in a hidden folder shown: %q", got)
	}
	w := f.env.Warnings.Take()
	warningWith(t, w, id.String(), "nicht in folders.gml")
	for _, s := range w {
		if strings.Contains(s, id.String()) && strings.Contains(s, hidden.String()) {
			t.Fatalf("the warning names more than the mail: %s", s)
		}
	}
}

// TestSegmentCopyWarns (point 4, after the verifier's
// TestAttackSeqDuplication): a segment copied byte for byte to another
// sequence number of the same device is processed once (task 09d; it has
// no other hits), with a warning (the sequence number is not bound into
// the file, Q11).
func TestSegmentCopyWarns(t *testing.T) {
	f := newFixture(t)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	c := f.u.Client
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	dev, _ := c.Device()
	data, err := f.env.Store.ReadIndexSegment(f.mbx, 1, dev, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.env.Store.WriteIndexSegment(f.mbx, 1, dev, 999, data); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("search after duplication: %q", got)
	}
	warningWith(t, f.env.Warnings.Take(), fmt.Sprintf("%s-999", dev), fmt.Sprintf("%s-1 ", dev), "byte-gleich")
}

// TestMetaFileHash (point 5): the memo of a mail names the SHA-256 of the
// metadata file of the highest version seen; another valid file with the
// same version is ErrMetaChanged.
func TestMetaFileHash(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	c := f.u.Client
	m, err := c.SetFlags(f.mbx, a.ID, []string{"seen"}, nil)
	if err != nil || m.Meta.Version != 2 {
		t.Fatal(err)
	}
	// A second version 2, validly signed by alice, with other flags.
	f.forgeVersion(t, f.u, m.Meta, a.Epoch, 2, func(x *store.MailMeta) { x.Flags = 4 })
	f.env.Warnings.Take()
	if _, _, err := c.Read(f.mbx, a.ID); !errors.Is(err, client.ErrMetaChanged) {
		t.Fatalf("same version, other file: %v", err)
	}
	warningWith(t, f.env.Warnings.Take(), a.ID.String())
	// A new process remembers it as well.
	if _, _, err := f.env.Reopen(f.u).Read(f.mbx, a.ID); !errors.Is(err, client.ErrMetaChanged) {
		t.Fatalf("after reopening: %v", err)
	}
	// A higher version is accepted again.
	f.forgeVersion(t, f.u, m.Meta, a.Epoch, 3, func(x *store.MailMeta) { x.Flags = 4 })
	if got, _, err := f.u.Client.Read(f.mbx, a.ID); err != nil || got.Meta.Version != 3 {
		t.Fatalf("version 3: %v", err)
	}
}
