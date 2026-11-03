package client_test

import (
	"encoding/json"
	"errors"
	"fmt"
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

// Tests of task 09c: check records of segments bound to their content,
// the limit of one run of readSegments, device lost not blocked by files
// of the data directory, signing again that fails, and the pinned test
// gaps of task 09b (tree boundary, resignSegment).

// stateSize returns the size of state.json in the client directory dir.
func stateSize(t *testing.T, dir string) int64 {
	t.Helper()
	fi, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// TestAttack09bStateGrowthSegmentCopies (finding high, the verifier's
// test of the same name, turned around): an attacker with write access
// to the data directory only (no key) copies one valid index segment to
// 1000 fresh sequence numbers, lets alice search, removes the copies and
// does it again, three times. The copies share the check record of the
// segment (epoch, device, SHA-256 of the file): state.json grows by at
// most a fixed amount that does not depend on the number of copies. The
// warning of Q11 about byte-equal segments stays.
func TestAttack09bStateGrowthSegmentCopies(t *testing.T) {
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
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatal(got)
	}
	base := stateSize(t, f.u.Dir)
	const per = 1000
	// bound is the fixed amount state.json may grow by over all rounds:
	// nothing of the copies is remembered; it leaves room for numbers
	// that change with the log (sizes and times).
	const bound = 512
	seq := uint64(1000)
	for round := 0; round < 3; round++ {
		var written []uint64
		for i := 0; i < per; i++ {
			seq++
			if err := f.env.Store.WriteIndexSegment(f.mbx, 1, dev, seq, data); err != nil {
				t.Fatal(err)
			}
			written = append(written, seq)
		}
		f.env.Warnings.Take()
		if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
			t.Fatal(got)
		}
		warningWith(t, f.env.Warnings.Take(), fmt.Sprintf("%s-%d", dev, seq), fmt.Sprintf("byte-gleich mit %s-1", dev))
		for _, s := range written {
			if err := f.env.Store.RemoveIndexSegment(f.mbx, 1, dev, s); err != nil {
				t.Fatal(err)
			}
		}
		grown := stateSize(t, f.u.Dir) - base
		t.Logf("round %d: state.json +%d bytes after %d copies", round, grown, (round+1)*per)
		if grown > bound {
			t.Fatalf("state.json grew by %d bytes after %d copies", grown, (round+1)*per)
		}
	}
	// A new process finds the same record, and the copies under a fresh
	// client directory state do not count twice either.
	c = f.env.Reopen(f.u)
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatal(got)
	}
	if grown := stateSize(t, f.u.Dir) - base; grown > bound {
		t.Fatalf("state.json grew by %d bytes", grown)
	}
}

// TestStateGrowthLegitimate measures what state.json grows by through
// legitimate writes (task 09c), per mail: listed for the first time
// (memo and version of its metadata), indexed in its own run and found by
// a search (the check record of the new segment), flags set once (the
// check record of version 2); and per merge of segments (the check
// record of the merged segment, less what the records of the merged
// segments lose when they are marked, task 09d). The numbers are logged;
// the bounds are generous upper limits of the measurement.
func TestStateGrowthLegitimate(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	f.send(t, "s0@x.example", header("s0@x.example", "w0"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	const rounds = 10
	var listed, indexed, flagged, merged int64
	// grow runs step and adds the growth of state.json to *sum.
	grow := func(sum *int64, step func()) {
		before := stateSize(t, f.u.Dir)
		step()
		*sum += stateSize(t, f.u.Dir) - before
	}
	searchAll := func() {
		if _, err := c.Search(f.mbx, "fromdomain:x.example", client.SearchOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < rounds; i++ {
		s := fmt.Sprintf("m%d", i)
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		var id store.ID
		grow(&listed, func() {
			list, err := c.List(f.mbx, store.ID{})
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range list {
				if m.Meta.Subject == s {
					id = m.ID
				}
			}
		})
		grow(&indexed, func() {
			if n, err := c.Index(f.mbx); err != nil || n != 1 {
				t.Fatalf("index: %d %v", n, err)
			}
			searchAll()
		})
		grow(&flagged, func() {
			if _, err := c.SetFlags(f.mbx, id, []string{"seen"}, nil); err != nil {
				t.Fatal(err)
			}
		})
		// Up to MergeThreshold different segments (only different
		// segments that check count, task 09d); Index merges them into
		// one new segment, Search checks it.
		refs, err := f.env.Store.ListIndexSegments(f.mbx, 1)
		if err != nil || len(refs) == 0 {
			t.Fatal(err)
		}
		for n := len(refs); n < client.MergeThreshold; n++ {
			if _, err := c.WriteSegment(f.mbx, 1, fmt.Sprintf("from:fill%d-%d@x.example", i, n), id); err != nil {
				t.Fatal(err)
			}
		}
		searchAll() // records the new segments
		grow(&merged, func() {
			if _, err := c.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			if n := segmentCount(t, f.env, f.mbx, 1); n != 1 {
				t.Fatalf("%d segments after the merge", n)
			}
			searchAll()
		})
	}
	t.Logf("state.json: %d bytes per mail listed, %d per mail indexed in its own run, %d per flag change, %d per merge",
		listed/rounds, indexed/rounds, flagged/rounds, merged/rounds)
	for name, v := range map[string]int64{"listed": listed, "indexed": indexed, "flagged": flagged, "merged": merged} {
		if v/rounds > 1024 {
			t.Fatalf("%s: %d bytes", name, v/rounds)
		}
	}
}

// TestSegmentReadLimit (finding high): one run of readSegments reads at
// most maxReadSegments files and maxReadBytes bytes of an epoch. Search
// beyond either limit returns what it found with ErrPartial and a
// warning with the fixed cause; Index warns and merges the segments it
// read (if MergeThreshold different ones check), the rest stays for the
// next run.
func TestSegmentReadLimit(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	var sizes []int64
	dev, _ := c.Device()
	for i, s := range []string{"m1", "m2", "m3"} {
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		if n, err := c.Index(f.mbx); err != nil || n != 1 {
			t.Fatalf("index %s: %d %v", s, n, err)
		}
		data, err := f.env.Store.ReadIndexSegment(f.mbx, 1, dev, uint64(i+1))
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, int64(len(data)))
	}
	client.SetSegmentLimits(t, 3, sizes[0]+sizes[1]+sizes[2])
	if got := search(t, c, f.mbx, "fromdomain:x.example", ""); got != "m1,m2,m3" {
		t.Fatalf("within the limits: %q", got)
	}
	for _, lim := range []struct {
		name  string
		files int
		bytes int64
	}{
		{"files", 2, 1 << 30},
		{"bytes", 100, sizes[0] + sizes[1] + sizes[2] - 1},
	} {
		client.SetSegmentLimits(t, lim.files, lim.bytes)
		f.env.Warnings.Take()
		list, err := c.Search(f.mbx, "fromdomain:x.example", client.SearchOptions{})
		if !errors.Is(err, client.ErrPartial) {
			t.Fatalf("%s: search beyond the limit: %v", lim.name, err)
		}
		if got := subjects(list); got != "m1,m2" {
			t.Fatalf("%s: %q", lim.name, got)
		}
		w := f.env.Warnings.Take()
		warningWith(t, w, "Epoche 1 von "+f.mbx.String(), "mehr Indexsegmente, als ein Lauf liest")
	}
	// Index: MergeThreshold+4 different segments, MergeThreshold read
	// per run: the ones read are merged, the rest stays for later.
	list, err := c.List(f.mbx, store.ID{})
	if err != nil || len(list) != 3 {
		t.Fatal(err)
	}
	for s := 4; s <= client.MergeThreshold+4; s++ {
		if _, err := c.WriteSegment(f.mbx, 1, fmt.Sprintf("from:fill%d@x.example", s), list[s%3].ID); err != nil {
			t.Fatal(err)
		}
	}
	client.SetSegmentLimits(t, client.MergeThreshold, 1<<30)
	f.env.Warnings.Take()
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	warningWith(t, f.env.Warnings.Take(), "Epoche 1 von "+f.mbx.String(), "mehr Indexsegmente, als ein Lauf liest")
	if n := segmentCount(t, f.env, f.mbx, 1); n != 4+1 {
		t.Fatalf("%d segments after a merge of %d", n, client.MergeThreshold)
	}
	client.SetSegmentLimits(t, 4096, 256<<20)
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "fromdomain:x.example", ""); got != "m1,m2,m3" {
		t.Fatalf("after the merge: %q", got)
	}
	for s := 4; s <= client.MergeThreshold+4; s++ {
		if got := search(t, c, f.mbx, fmt.Sprintf("from:fill%d@x.example", s), ""); got != list[s%3].Meta.Subject {
			t.Fatalf("fill %d after the merge: %q", s, got)
		}
	}
}

// readState returns the memory of mbx in state.json of the client
// directory dir.
func readState(t *testing.T, dir string, mbx store.ID) map[string]any {
	t.Helper()
	var st map[string]any
	if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "state.json")), &st); err != nil {
		t.Fatal(err)
	}
	boxes, _ := st["mailboxes"].(map[string]any)
	ms, _ := boxes[mbx.String()].(map[string]any)
	return ms
}

// deviceLostNotBlocked (finding medium, after the verifier's
// TestAttack09bDeviceLostBlockedByIndexDir and ...ByAccept): an attacker
// with write access to the data directory puts a regular file where
// index/<n>/ or mail/ of the victim's mailbox belongs, a directory where
// members/<me>.accept belongs, a file in place of mailboxes/, or more
// segments in index/<n>/ than one run reads. Step 2 of device lost fails
// on that file; the revocation runs anyway: user.rec with generation 2
// is in the log, DeviceLost returns generation 2 with ErrPartial, a
// warning names the mailbox (or the listing) with a fixed cause, and the
// mailbox is marked. In the variants "...-gone" the attacker removes the
// obstacle right after step 2: step 4 completes the mailbox, and still
// the result is ErrPartial and the mark stays, since step 2 did not check
// every file.
func deviceLostNotBlocked(t *testing.T, variants ...string) {
	for _, where := range variants {
		t.Run(where, func(t *testing.T) {
			f := newFixture(t)
			a := f.deliver(t, "a", "x")
			f.send(t, "s@x.example", header("s@x.example", "m1"))
			f.flush(t)
			if _, err := f.u.Client.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			fileAt := func(p string) {
				if err := os.RemoveAll(p); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want := "nicht vollständig geprüft"
			var undo func()
			switch where {
			case "index", "index-gone":
				p := f.env.Store.IndexDir(f.mbx, a.Epoch)
				if err := os.Rename(p, p+".aside"); err != nil {
					t.Fatal(err)
				}
				fileAt(p)
				undo = func() {
					if err := os.Remove(p); err != nil {
						t.Error(err)
					}
					if err := os.Rename(p+".aside", p); err != nil {
						t.Error(err)
					}
				}
			case "mail":
				fileAt(filepath.Dir(f.env.Store.MailDir(f.mbx, f.inbox(t))))
			case "accept", "accept-gone":
				p := filepath.Join(f.env.Store.EpochDir(f.mbx, a.Epoch), "members", f.u.ID.String()+".accept")
				if err := os.RemoveAll(p); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(p, "x"), 0o755); err != nil {
					t.Fatal(err)
				}
				undo = func() {
					if err := os.RemoveAll(p); err != nil {
						t.Error(err)
					}
				}
			case "limit":
				client.SetSegmentLimits(t, 0, 1<<30)
			case "mailboxes":
				p := f.env.Store.Path("mailboxes")
				if err := os.Rename(p, p+".aside"); err != nil {
					t.Fatal(err)
				}
				fileAt(p)
				want = "nicht aufgelistet"
			}
			if strings.HasSuffix(where, "-gone") {
				client.SetCrashHook(t, func(p string) bool {
					if p == "devicelost-prepared" {
						undo()
					}
					return false
				})
			}
			f.env.Clock.Advance(time.Minute)
			f.u.Client.Close()
			f.env.Warnings.Take()
			gen, dlErr := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
			t.Logf("%s: DeviceLost gen %d err %v", where, gen, dlErr)
			if gen != 2 || !errors.Is(dlErr, client.ErrPartial) {
				t.Fatalf("DeviceLost: %d %v", gen, dlErr)
			}
			warningWith(t, f.env.Warnings.Take(), want)
			f.env.MustPublishHead()
			ents, err := f.env.LogOperator().Lookup(translog.KindUser, f.u.ID[:])
			if err != nil {
				t.Fatal(err)
			}
			logged := false
			for _, e := range ents {
				logged = logged || e.Seq == 2
			}
			if !logged {
				t.Fatal("the revocation is not in the log")
			}
			if u, _, err := f.env.Store.ReadUser(f.u.ID); err != nil || u.Current().Gen != 2 {
				t.Fatalf("user.rec: %v", err)
			}
			if r, _ := readState(t, f.u.Dir, f.mbx)["reissue"].(float64); r != 2 {
				t.Fatalf("mailbox not marked: %v", r)
			}
			if strings.HasSuffix(where, "-gone") && strings.Contains(dlErr.Error(), "not issued again") {
				t.Fatalf("step 4 did not complete after the obstacle was gone: %v", dlErr)
			}
			// The client opens with generation 2.
			f.env.Reopen(f.u)
		})
	}
}

// TestAttack09bDeviceLostBlockedByIndexDir: index/<n>/ or mail/ of the
// mailbox is a regular file, or index/<n>/ holds more segments than one
// run reads (deviceLostNotBlocked).
func TestAttack09bDeviceLostBlockedByIndexDir(t *testing.T) {
	deviceLostNotBlocked(t, "index", "mail", "limit", "index-gone")
}

// TestAttack09bDeviceLostBlockedByAccept: members/<me>.accept of the
// epoch is a directory (deviceLostNotBlocked).
func TestAttack09bDeviceLostBlockedByAccept(t *testing.T) {
	deviceLostNotBlocked(t, "accept", "accept-gone")
}

// TestDeviceLostBlockedByMailboxes: mailboxes/ of the data directory is
// a regular file, so the memberships cannot be listed
// (deviceLostNotBlocked).
func TestDeviceLostBlockedByMailboxes(t *testing.T) {
	deviceLostNotBlocked(t, "mailboxes")
}

// TestDeviceLostUnreadableFolder (finding medium): a folder directory
// that cannot be read (an attacker who owns the data directory removes
// its permissions) does not keep step 2 from checking the metadata in
// the other folders: alice's version 2, whose check record she does not
// have yet, is checked in step 2 and signed again with generation 2.
// A process that reads every directory (root with CAP_DAC_OVERRIDE)
// skips it; it runs as another user, or as root without that capability
// (setpriv --inh-caps=-dac_override,-dac_read_search
// --bounding-set=-dac_override,-dac_read_search).
func TestDeviceLostUnreadableFolder(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	if _, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"seen"}, nil); err != nil {
		t.Fatal(err)
	}
	f.u.Client.Close()
	editState(t, f.u.Dir, f.mbx, func(ms map[string]any) {
		checked, _ := ms["checked"].(map[string]any)
		delete(checked, "meta/"+a.ID.String())
	})
	// A folder directory that sorts before the inbox.
	var low store.ID
	dir := f.env.Store.MailDir(f.mbx, low)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	if _, err := os.ReadDir(dir); err == nil {
		t.Skip("this process reads every directory")
	}
	f.env.Clock.Advance(time.Minute)
	gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
	if gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("DeviceLost: %d %v", gen, err)
	}
	if s, g, v := signerOf(t, f, a.ID); s != f.u.ID || g != 2 || v != 3 {
		t.Fatalf("metadata not signed again: %s %d %d", s, g, v)
	}
}

// TestAttack09bSearchFailsOnResignWrite (finding low 1, the verifier's
// test of the same name, turned around): alice checked bob's segment
// before bob's revocation; an attacker blocks the next sequence numbers
// of alice's device with directories, so that signing the segment again
// fails. Search warns and returns the hits of the checked segment, which
// stays; once the obstacle is gone, the next Search signs it again.
func TestAttack09bSearchFailsOnResignWrite(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	if _, err := bob.Client.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := f.u.Client.List(f.mbx, store.ID{})
	n := list[0].Epoch
	if got := search(t, f.u.Client, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatal(got)
	}
	f.env.Rotate(bob)
	dev, _ := f.u.Client.Device()
	for s := uint64(1); s <= 70; s++ {
		if err := os.MkdirAll(f.env.Store.IndexSegmentFile(f.mbx, n, dev, s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	c := f.env.Reopen(f.u)
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("search: %q", got)
	}
	warningWith(t, f.env.Warnings.Take(), "nicht neu signiert", "späterer Lauf")
	refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
	if len(refs) != 1 || refs[0].Device == dev {
		t.Fatalf("segments: %v", refs)
	}
	for s := uint64(1); s <= 70; s++ {
		os.Remove(f.env.Store.IndexSegmentFile(f.mbx, n, dev, s))
	}
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("search: %q", got)
	}
	warningWith(t, f.env.Warnings.Take(), "übernommen und neu signiert")
	refs, _ = f.env.Store.ListIndexSegments(f.mbx, n)
	if len(refs) != 1 || refs[0].Device != dev {
		t.Fatalf("segments after the takeover: %v", refs)
	}
}

// TestListResignMetaFails (finding low 1 for resignMeta): alice checked
// bob's version 2 before his revocation; the mailbox lock cannot be
// taken (a directory in place of the lock file), so writing version 3
// fails. List warns and lists the checked mail; the next List after the
// obstacle is gone signs it again.
func TestListResignMetaFails(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	a := f.deliver(t, "a", "x")
	if _, err := bob.Client.SetFlags(f.mbx, a.ID, []string{"flagged"}, nil); err != nil {
		t.Fatal(err)
	}
	if !listed(t, f.u.Client, f.mbx, a.ID) {
		t.Fatal("alice v2")
	}
	f.env.Rotate(bob)
	lock := filepath.Join(f.env.Store.MailboxDir(f.mbx), "lock")
	if err := os.RemoveAll(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(lock, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := f.env.Reopen(f.u)
	f.env.Warnings.Take()
	if !listed(t, c, f.mbx, a.ID) {
		t.Fatalf("not listed: %q", f.env.Warnings.Take())
	}
	warningWith(t, f.env.Warnings.Take(), a.ID.String(), "nicht neu signiert", "späterer Lauf")
	if s, _, v := signerOf(t, f, a.ID); s != bob.ID || v != 2 {
		t.Fatal("the file was changed")
	}
	m, _, err := c.Read(f.mbx, a.ID)
	if err != nil || m.Meta.Version != 2 {
		t.Fatalf("read: %v", err)
	}
	if err := os.RemoveAll(lock); err != nil {
		t.Fatal(err)
	}
	if !listed(t, c, f.mbx, a.ID) {
		t.Fatal("not listed")
	}
	if s, g, v := signerOf(t, f, a.ID); s != f.u.ID || g != 1 || v != 3 {
		t.Fatalf("not signed again: %s %d %d", s, g, v)
	}
}

// TestAttack09bMetaChangedNoRecovery (finding low 2, the verifier's test
// of the same name, pinned): alice saw her own version
// 3; the file now holds another valid version 3 (carol's). Alice gets
// ErrMetaChanged and cannot write version 4 herself (strictest reading of
// task 09b point 5, see the package comment); once carol writes version
// 4, alice lists the mail again.
func TestAttack09bMetaChangedNoRecovery(t *testing.T) {
	f := newFixture(t)
	_, carol := threeMembers(t, f)
	a := f.deliver(t, "a", "x")
	m, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"seen"}, nil)
	if err != nil || m.Meta.Version != 2 {
		t.Fatal(err)
	}
	if m3, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"flagged"}, nil); err != nil || m3.Meta.Version != 3 {
		t.Fatal(err)
	}
	f.forgeVersion(t, carol, m.Meta, a.Epoch, 3, func(x *store.MailMeta) { x.Flags = 4 })
	if _, _, err := f.u.Client.Read(f.mbx, a.ID); !errors.Is(err, client.ErrMetaChanged) {
		t.Fatalf("read: %v", err)
	}
	if listed(t, f.u.Client, f.mbx, a.ID) {
		t.Fatal("listed")
	}
	if _, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"answered"}, nil); !errors.Is(err, client.ErrMetaChanged) {
		t.Fatalf("alice wrote over the other version 3: %v", err)
	}
	if _, err := f.env.Reopen(carol).SetFlags(f.mbx, a.ID, []string{"answered"}, nil); err != nil {
		t.Fatal(err)
	}
	if !listed(t, f.env.Reopen(f.u), f.mbx, a.ID) {
		t.Fatal("not listed after carol's version 4")
	}
}

// TestAttack09bTreeBoundary (point 3a, the verifier's test of the same
// name): the check record counts exactly when the
// revocation entry (index R) is not in the tree the record names: tree R
// counts, tree R+1 does not, nor does R+2; R-1 counts.
func TestAttack09bTreeBoundary(t *testing.T) {
	for _, d := range []int64{-1, 0, 1, 2} {
		t.Run(fmt.Sprint(d), func(t *testing.T) {
			f := newFixture(t)
			bob, _ := threeMembers(t, f)
			a := f.deliver(t, "a", "x")
			if _, err := bob.Client.SetFlags(f.mbx, a.ID, []string{"flagged"}, nil); err != nil {
				t.Fatal(err)
			}
			if !listed(t, f.u.Client, f.mbx, a.ID) {
				t.Fatal("alice v2")
			}
			f.env.Rotate(bob)
			f.env.MustPublishHead()
			ents, err := f.env.LogOperator().Lookup(translog.KindUser, bob.ID[:])
			if err != nil {
				t.Fatal(err)
			}
			r := int64(-1)
			for _, e := range ents {
				if e.Seq == 2 {
					r = e.Index
				}
			}
			if r < 0 {
				t.Fatal("no revocation entry")
			}
			f.u.Client.Close()
			setTree(t, f.u.Dir, f.mbx, "meta/"+a.ID.String(), r+d)
			ac := f.env.Reopen(f.u)
			got := listed(t, ac, f.mbx, a.ID)
			if want := d <= 0; got != want {
				t.Fatalf("revocation index %d, record tree %d: taken over %v", r, r+d, got)
			}
			if s, _, _ := signerOf(t, f, a.ID); (s == f.u.ID) != got {
				t.Fatalf("tree %d: signed again %v, taken over %v", r+d, s == f.u.ID, got)
			}
		})
	}
}

// segmentTakeoverFixture: bob indexes a mail, alice checks his segment
// by a search, bob rotates. It returns the fixture, the epoch, bob's
// segment and alice's client, opened again (a new process, so that the
// next search takes the segment over).
func segmentTakeoverFixture(t *testing.T) (*fixture, uint32, store.IndexSegmentRef, *client.Client) {
	t.Helper()
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	if _, err := bob.Client.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := f.u.Client.List(f.mbx, store.ID{})
	n := list[0].Epoch
	refs, err := f.env.Store.ListIndexSegments(f.mbx, n)
	if err != nil || len(refs) != 1 {
		t.Fatalf("segments %v %v", refs, err)
	}
	if got := search(t, f.u.Client, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatal(got)
	}
	if _, err := f.u.Client.Device(); err != nil {
		t.Fatal(err)
	}
	f.env.Rotate(bob)
	c := f.env.Reopen(f.u)
	f.env.Warnings.Take()
	return f, n, refs[0], c
}

// TestResignSegmentHoldsLock (point 3b, task 09d finding low 4):
// resignSegment takes the mailbox lock before it writes. The test takes
// the lock in the hook right before resignSegment takes it, and releases
// it from the hook that runs right before withMailboxLock waits for it:
// the client asked for the lock while the test held it, and nothing was
// written before it got it (checked inside the lock at the crash point
// "segment-resigned", after the new segment is written). No time window.
func TestResignSegmentHoldsLock(t *testing.T) {
	f, n, bobSeg, c := segmentTakeoverFixture(t)
	var unlock func()
	held, asked := false, false
	var whileHeld []store.IndexSegmentRef
	client.SetResignHook(t, func() {
		u, err := f.env.Store.LockMailbox(f.mbx)
		if err != nil {
			t.Error(err)
			return
		}
		unlock, held = u, true
	})
	client.SetLockHook(t, func(mbx store.ID) {
		if mbx != f.mbx || !held {
			return
		}
		asked = true
		whileHeld, _ = f.env.Store.ListIndexSegments(f.mbx, n)
		held = false
		unlock()
	})
	heldAtWrite := false
	client.SetCrashHook(t, func(p string) bool {
		if p == "segment-resigned" {
			heldAtWrite = held
		}
		return false
	})
	got, err := c.Search(f.mbx, "from:s@x.example", client.SearchOptions{})
	if held {
		unlock()
	}
	if err != nil || subjects(got) != "m1" {
		t.Fatalf("search: %q %v", subjects(got), err)
	}
	if !asked {
		t.Fatal("resignSegment did not ask for the mailbox lock while it was held")
	}
	if heldAtWrite {
		t.Fatal("resignSegment wrote while the test held the mailbox lock")
	}
	if len(whileHeld) != 1 || whileHeld[0] != bobSeg {
		t.Fatalf("segments while the lock was held: %v", whileHeld)
	}
	dev, _ := c.Device()
	if refs, _ := f.env.Store.ListIndexSegments(f.mbx, n); len(refs) != 1 || refs[0].Device != dev {
		t.Fatalf("segments after the takeover: %v", refs)
	}
}

// TestResignSegmentNewBeforeOld (point 3b): resignSegment writes the new
// segment before it removes the old one: a crash in between leaves both,
// and the mail is still found.
func TestResignSegmentNewBeforeOld(t *testing.T) {
	f, n, bobSeg, c := segmentTakeoverFixture(t)
	hits := 0
	client.SetCrashHook(t, func(p string) bool {
		if p == "segment-resigned" {
			hits++
			return hits == 1
		}
		return false
	})
	if _, err := c.Search(f.mbx, "from:s@x.example", client.SearchOptions{}); !errors.Is(err, client.ErrCrashed) {
		t.Fatalf("no crash: %v", err)
	}
	client.SetCrashHook(t, nil)
	dev, _ := c.Device()
	refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
	old, fresh := false, false
	for _, r := range refs {
		old = old || r == bobSeg
		fresh = fresh || r.Device == dev
	}
	if !old || !fresh || len(refs) != 2 {
		t.Fatalf("segments after the crash: %v", refs)
	}
	f.env.Warnings.Take()
	if got := search(t, f.env.Reopen(f.u), f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("after the crash: %q (%q)", got, f.env.Warnings.Take())
	}
}

// TestResignSegmentComparesBytes (point 3b): resignSegment replaces the
// segment only while the file is byte for byte the one checked. Another
// file at its place (written between the check and the lock) is neither
// removed nor signed again.
func TestResignSegmentComparesBytes(t *testing.T) {
	f, n, bobSeg, c := segmentTakeoverFixture(t)
	other := []byte("another file at the place of the segment")
	client.SetResignHook(t, func() {
		if err := os.WriteFile(f.env.Store.IndexSegmentFile(f.mbx, n, bobSeg.Device, bobSeg.Seq), other, 0o644); err != nil {
			t.Error(err)
		}
	})
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("search: %q", got)
	}
	refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
	if len(refs) != 1 || refs[0] != bobSeg {
		t.Fatalf("segments: %v", refs)
	}
	data, err := os.ReadFile(f.env.Store.IndexSegmentFile(f.mbx, n, bobSeg.Device, bobSeg.Seq))
	if err != nil || string(data) != string(other) {
		t.Fatalf("the other file was replaced: %v", err)
	}
	for _, w := range f.env.Warnings.Take() {
		if strings.Contains(w, "übernommen und neu signiert") {
			t.Fatalf("taken over: %s", w)
		}
	}
}
