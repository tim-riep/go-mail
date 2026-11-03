package client_test

import (
	"bytes"
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
)

// Tests of task 09d: a content signed again or merged once, however many
// copies or files put back there are; no merge and no segment that
// nobody without a key can force; step 4 of device lost and its
// continuation report a file not issued again; the pinned test gaps of
// task 09c.

// stateBound is the fixed amount state.json may grow by over all rounds
// of an attack in these tests: nothing of the copies, files put back or
// merges forced is remembered; it leaves room for numbers that change
// with the log (sizes and times).
const stateBound = 512

// ownSegments returns the segments of epoch n of mbx written by device
// dev.
func ownSegments(t *testing.T, env *testenv.Env, mbx store.ID, n uint32, dev store.ID) []store.IndexSegmentRef {
	t.Helper()
	refs, err := env.Store.ListIndexSegments(mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.IndexSegmentRef
	for _, r := range refs {
		if r.Device == dev {
			out = append(out, r)
		}
	}
	return out
}

// countWith returns the number of warnings that hold every part.
func countWith(warnings []string, parts ...string) int {
	n := 0
	for _, w := range warnings {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(w, p)
		}
		if ok {
			n++
		}
	}
	return n
}

// TestAttack09cStateGrowthResignCopies (finding high, the verifier's test
// of the same name, turned around): bob loses a device after alice
// checked his segment B. The attacker (write access to the data
// directory, no key) puts 1000 copies of B under new sequence numbers
// before alice's first search after the revocation, and 1000 more before
// each of three further rounds. Alice signs the content of B again once:
// the copies in the same run are not processed again (Q11 warning), and
// later copies find the record of B marked as issued again and are
// ignored. state.json grows by at most a fixed amount, alice writes one
// segment in all, and the search finds the mail exactly once.
func TestAttack09cStateGrowthResignCopies(t *testing.T) {
	f, n, bobSeg, c := segmentTakeoverFixture(t)
	B, err := f.env.Store.ReadIndexSegment(f.mbx, n, bobSeg.Device, bobSeg.Seq)
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := c.Device()
	const per = 1000
	seq := uint64(100000)
	copies := func() []uint64 {
		var written []uint64
		for i := 0; i < per; i++ {
			seq++
			if err := f.env.Store.WriteIndexSegment(f.mbx, n, bobSeg.Device, seq, B); err != nil {
				t.Fatal(err)
			}
			written = append(written, seq)
		}
		return written
	}
	written := copies()
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatal(got)
	}
	w := f.env.Warnings.Take()
	if k := countWith(w, "übernommen und neu signiert"); k != 1 {
		t.Fatalf("signed again %d times in the first run", k)
	}
	warningWith(t, w, fmt.Sprintf("%s-%d", bobSeg.Device, seq), "byte-gleich", "nicht noch einmal verarbeitet")
	if mine := ownSegments(t, f.env, f.mbx, n, dev); len(mine) != 1 {
		t.Fatalf("alice wrote %d segments", len(mine))
	}
	// Her next search reads (and records) her new segment.
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatal(got)
	}
	base := stateSize(t, f.u.Dir)
	for round := 0; round < 3; round++ {
		for _, s := range written {
			if err := f.env.Store.RemoveIndexSegment(f.mbx, n, bobSeg.Device, s); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		}
		written = copies()
		f.env.Warnings.Take()
		for i := 0; i < 2; i++ {
			if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
				t.Fatal(got)
			}
		}
		w := f.env.Warnings.Take()
		if k := countWith(w, "übernommen und neu signiert"); k != 0 {
			t.Fatalf("round %d: signed again %d times", round, k)
		}
		warningWith(t, w, "bereits neu ausgestellt oder zusammengefasst")
		if mine := ownSegments(t, f.env, f.mbx, n, dev); len(mine) != 1 {
			t.Fatalf("round %d: alice has %d segments", round, len(mine))
		}
		grown := stateSize(t, f.u.Dir) - base
		t.Logf("round %d: state.json +%d bytes after %d copies", round, grown, (round+2)*per)
		if grown > stateBound {
			t.Fatalf("state.json grew by %d bytes", grown)
		}
	}
	// A new process remembers the mark.
	c = f.env.Reopen(f.u)
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatal(got)
	}
	if k := countWith(f.env.Warnings.Take(), "übernommen und neu signiert"); k != 0 {
		t.Fatalf("signed again after reopening: %d", k)
	}
	if grown := stateSize(t, f.u.Dir) - base; grown > stateBound {
		t.Fatalf("state.json grew by %d bytes", grown)
	}
}

// TestResignedMetaReplay (finding high, metadata): bob sets flags
// (version 2), alice lists it, bob rotates, alice signs it again (version
// 3). Bob's version 2 put back again and again is neither listed nor
// signed again, and state.json does not grow: the record of the mail
// (one per mail, metaMemo) names version 3 now, and even a record that
// still named version 2 would not do, since version 2 is older than the
// version seen (Versions, ErrReplay). Version 3 put back is listed again.
func TestResignedMetaReplay(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	a := f.deliver(t, "a", "x")
	if _, err := bob.Client.SetFlags(f.mbx, a.ID, []string{"flagged"}, nil); err != nil {
		t.Fatal(err)
	}
	if !listed(t, f.u.Client, f.mbx, a.ID) {
		t.Fatal("alice v2")
	}
	path := f.env.Store.MetaFile(f.mbx, f.inbox(t), a.ID)
	v2 := mustRead(t, path)
	memoV2 := readState(t, f.u.Dir, f.mbx)["checked"].(map[string]any)["meta/"+a.ID.String()]
	f.env.Rotate(bob)
	c := f.env.Reopen(f.u)
	if !listed(t, c, f.mbx, a.ID) {
		t.Fatal("not listed")
	}
	if s, _, v := signerOf(t, f, a.ID); s != f.u.ID || v != 3 {
		t.Fatalf("not signed again: %s %d", s, v)
	}
	v3 := mustRead(t, path)
	base := stateSize(t, f.u.Dir)
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(path, v2, 0o644); err != nil {
			t.Fatal(err)
		}
		f.env.Warnings.Take()
		if listed(t, c, f.mbx, a.ID) {
			t.Fatal("replayed version 2 listed")
		}
		// The record of the mail names version 3 now.
		warningWith(t, f.env.Warnings.Take(), a.ID.String(), "vorher nicht geprüft")
		if s, _, v := signerOf(t, f, a.ID); s != bob.ID || v != 2 {
			t.Fatalf("the replayed file was signed again: %s %d", s, v)
		}
	}
	if grown := stateSize(t, f.u.Dir) - base; grown != 0 {
		t.Fatalf("state.json grew by %d bytes", grown)
	}
	// Even a record that still named version 2 would not take it over
	// again: version 2 is older than the version 3 seen (ErrReplay).
	c.Close()
	editState(t, f.u.Dir, f.mbx, func(ms map[string]any) {
		ms["checked"].(map[string]any)["meta/"+a.ID.String()] = memoV2
	})
	c = f.env.Reopen(f.u)
	f.env.Warnings.Take()
	if listed(t, c, f.mbx, a.ID) {
		t.Fatal("replayed version 2 listed")
	}
	warningWith(t, f.env.Warnings.Take(), a.ID.String(), "ältere Version")
	if s, _, v := signerOf(t, f, a.ID); s != bob.ID || v != 2 {
		t.Fatalf("the replayed file was signed again: %s %d", s, v)
	}
	if err := os.WriteFile(path, v3, 0o644); err != nil {
		t.Fatal(err)
	}
	if !listed(t, c, f.mbx, a.ID) {
		t.Fatal("version 3 not listed")
	}
}

// TestAttack09cDeviceLostStep4SilentResign (finding medium 1, the
// verifier's test of the same name, turned around): an attacker blocks
// the next sequence numbers of alice's device with directories, so that
// step 4 of device lost cannot sign her segment again. DeviceLost
// returns generation 2 with ErrPartial, the mailbox is marked, and a
// warning names the segment and says that it was not issued again (not
// "Prüfung fehlgeschlagen"). Once the obstacle is gone, Sync issues it
// again and clears the mark, and carol, who never checked the old
// segment, finds the mail.
func TestAttack09cDeviceLostStep4SilentResign(t *testing.T) {
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
	old := ownSegments(t, f.env, f.mbx, n, dev)
	if len(old) != 1 {
		t.Fatalf("segments %v", old)
	}
	for s := uint64(2); s <= 80; s++ {
		if err := os.MkdirAll(f.env.Store.IndexSegmentFile(f.mbx, n, dev, s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
	if gen != 2 || !errors.Is(err, client.ErrPartial) || !strings.Contains(err.Error(), "not issued again") {
		t.Fatalf("DeviceLost: %d %v", gen, err)
	}
	w := f.env.Warnings.Take()
	seg := fmt.Sprintf("%s-%d", old[0].Device, old[0].Seq)
	warningWith(t, w, seg, "nicht neu ausgestellt", "geschrieben werden")
	for _, x := range w {
		if strings.Contains(x, seg) && strings.Contains(x, "Prüfung fehlgeschlagen") {
			t.Fatalf("the warning names a failed check: %s", x)
		}
	}
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("mailbox not marked: %d", r)
	}
	c := f.env.Reopen(f.u)
	// The obstacle stays: Sync reports it again, the mark stays.
	f.env.Warnings.Take()
	if err := c.Sync(); !errors.Is(err, client.ErrPartial) {
		t.Fatalf("Sync with the obstacle: %v", err)
	}
	warningWith(t, f.env.Warnings.Take(), seg, "nicht neu ausgestellt")
	c.Close()
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("mark after Sync with the obstacle: %d", r)
	}
	for s := uint64(2); s <= 80; s++ {
		if err := os.Remove(f.env.Store.IndexSegmentFile(f.mbx, n, dev, s)); err != nil {
			t.Fatal(err)
		}
	}
	c = f.env.Reopen(f.u)
	if err := c.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	c.Close()
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
		t.Fatalf("mark after Sync: %d", r)
	}
	now := ownSegments(t, f.env, f.mbx, n, dev)
	if len(now) != 1 || now[0] == old[0] {
		t.Fatalf("segment not issued again: %v", now)
	}
	data, err := f.env.Store.ReadIndexSegment(f.mbx, n, now[0].Device, now[0].Seq)
	if err != nil {
		t.Fatal(err)
	}
	if tr := parse(t, data).Trailer; tr == nil || store.ID(tr.Signer.ID) != f.u.ID || tr.Signer.Gen != 2 {
		t.Fatal("segment not signed by generation 2")
	}
	cc := f.env.Reopen(carol)
	if err := cc.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := search(t, cc, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("carol: %q", got)
	}
}

// TestDeviceLostStep4MetaResignFails (finding medium 1, metadata): alice
// set flags with generation 1; in step 4 the metadata file is a
// directory for a moment (resignMetaHook), so writing version 3 fails.
// DeviceLost reports ErrPartial, marks the mailbox and warns with the
// mail ID that it was not issued again; Sync completes it once the file
// is back.
func TestDeviceLostStep4MetaResignFails(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	if _, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"seen"}, nil); err != nil {
		t.Fatal(err)
	}
	path := f.env.Store.MetaFile(f.mbx, f.inbox(t), a.ID)
	once := false
	client.SetResignMetaHook(t, func() {
		if once {
			return
		}
		once = true
		if err := os.Rename(path, path+".aside"); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Error(err)
		}
	})
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
	if gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("DeviceLost: %d %v", gen, err)
	}
	warningWith(t, f.env.Warnings.Take(), a.ID.String(), "nicht neu ausgestellt", "geschrieben werden")
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("mailbox not marked: %d", r)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".aside", path); err != nil {
		t.Fatal(err)
	}
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

// TestDeviceLostStep4MetaGone (finding medium 1, changed by task 09f,
// finding low 2): metadata that are removed while step 4 signs them again
// (resignMetaHook) were checked in step 2 of the same run, so DeviceLost
// does not report success: ErrPartial, mark and a warning with the mail
// ID. They stay gone, so the next Sync finds nothing signed by the
// revoked generation and clears the mark.
func TestDeviceLostStep4MetaGone(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	if _, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"seen"}, nil); err != nil {
		t.Fatal(err)
	}
	path := f.env.Store.MetaFile(f.mbx, f.inbox(t), a.ID)
	client.SetResignMetaHook(t, func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
	})
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	f.env.Warnings.Take()
	if gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words); gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("DeviceLost: %d %v", gen, err)
	}
	warningWith(t, f.env.Warnings.Take(), a.ID.String(), "nicht wieder vorgefunden")
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("mailbox not marked: %d", r)
	}
	client.SetResignMetaHook(t, nil)
	c := f.env.Reopen(f.u)
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
		t.Fatalf("mark after Sync: %d", r)
	}
}

// TestDeviceLostStep4MetaCheckFails (finding medium 1, checkMeta; turned
// around in task 09g): after the revocation (crash hook
// "devicelost-logged", before step 4) the attacker puts another file in
// place of alice's version 3, which she has seen and checked in step 2.
//
//   - "other": a file of the same version 3 with other flags, signed by
//     her old generation (from another copy of her client directory).
//     Step 4 cannot issue it again (its check record names her version
//     3): ErrPartial, mark, and a warning with the mail ID that it is not
//     issued again. A file of the version seen is not older (metaOlder
//     compares with "<").
//   - "older": her version 2. Every reader that saw version 3 rejects it
//     (ErrReplay); step 4 warns about it and does not count it as not
//     issued again (task 09f, finding low 3), and since task 09g
//     missingOwnFiles does not either: no ErrPartial, no mark, and a
//     second DeviceLost with the file still there ends without
//     ErrPartial as well.
func TestDeviceLostStep4MetaCheckFails(t *testing.T) {
	for _, variant := range []string{"other", "older"} {
		t.Run(variant, func(t *testing.T) {
			f := newFixture(t)
			a := f.deliver(t, "a", "x")
			if _, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"seen"}, nil); err != nil {
				t.Fatal(err)
			}
			path := f.env.Store.MetaFile(f.mbx, f.inbox(t), a.ID)
			v2 := mustRead(t, path)
			// A copy of alice's client directory that has seen version 2.
			copyDir := filepath.Join(t.TempDir(), "alice2")
			if err := os.CopyFS(copyDir, os.DirFS(f.u.Dir)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"flagged"}, nil); err != nil {
				t.Fatal(err)
			}
			v3 := mustRead(t, path)
			put := v2
			if variant == "other" {
				if err := os.WriteFile(path, v2, 0o644); err != nil {
					t.Fatal(err)
				}
				other, err := client.Open(f.env.ClientConfig(copyDir), testenv.Passphrase)
				if err != nil {
					t.Fatal(err)
				}
				m, err := other.SetFlags(f.mbx, a.ID, []string{"answered"}, nil)
				other.Close()
				if err != nil || m.Meta.Version != 3 {
					t.Fatalf("other version 3: %v", err)
				}
				put = mustRead(t, path)
				if bytes.Equal(put, v3) {
					t.Fatal("the same file")
				}
				if err := os.WriteFile(path, v3, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			client.SetCrashHook(t, func(p string) bool {
				if p == "devicelost-logged" {
					if err := os.WriteFile(path, put, 0o644); err != nil {
						t.Error(err)
					}
				}
				return false
			})
			f.env.Clock.Advance(time.Minute)
			f.u.Client.Close()
			f.env.Warnings.Take()
			gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
			w := f.env.Warnings.Take()
			warningWith(t, w, a.ID.String(), "wird nicht neu ausgestellt")
			if variant == "other" {
				if gen != 2 || !errors.Is(err, client.ErrPartial) {
					t.Fatalf("DeviceLost: %d %v", gen, err)
				}
				if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
					t.Fatalf("mailbox not marked: %d", r)
				}
				return
			}
			if gen != 2 || err != nil {
				t.Fatalf("DeviceLost: %d %v", gen, err)
			}
			if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
				t.Fatalf("mailbox marked: %d", r)
			}
			if countWith(w, "nicht wieder vorgefunden") != 0 {
				t.Fatalf("an older version counted as missing: %q", w)
			}
			f.env.Clock.Advance(time.Minute)
			if gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words); gen != 3 || err != nil {
				t.Fatalf("second DeviceLost with the older version there: %d %v", gen, err)
			}
		})
	}
}

// TestDeviceLostStep4IndexUnreadable (finding low 2): index/<n>/ becomes
// a regular file after step 2 (crash hook "devicelost-logged"). Step 4
// does not stop there: the metadata alice signed are issued again with
// generation 2, and the failure on the index makes the result ErrPartial
// and marks the mailbox. Once the directory is back, Sync issues the
// segment again and clears the mark.
func TestDeviceLostStep4IndexUnreadable(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	if _, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"seen"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.u.Client.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	dev, _ := f.u.Client.Device()
	old := ownSegments(t, f.env, f.mbx, a.Epoch, dev)
	if len(old) != 1 {
		t.Fatalf("segments %v", old)
	}
	dir := f.env.Store.IndexDir(f.mbx, a.Epoch)
	client.SetCrashHook(t, func(p string) bool {
		if p == "devicelost-logged" {
			if err := os.Rename(dir, dir+".aside"); err != nil {
				t.Error(err)
			}
			if err := os.WriteFile(dir, []byte("x"), 0o644); err != nil {
				t.Error(err)
			}
		}
		return false
	})
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
	if gen != 2 || !errors.Is(err, client.ErrPartial) || !strings.Contains(err.Error(), "not issued again") {
		t.Fatalf("DeviceLost: %d %v", gen, err)
	}
	warningWith(t, f.env.Warnings.Take(), f.mbx.String(), "nicht vollständig neu ausgestellt")
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("mailbox not marked: %d", r)
	}
	if s, g, v := signerOf(t, f, a.ID); s != f.u.ID || g != 2 || v != 3 {
		t.Fatalf("metadata not issued again after the index failed: %s %d %d", s, g, v)
	}
	client.SetCrashHook(t, nil)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir+".aside", dir); err != nil {
		t.Fatal(err)
	}
	c := f.env.Reopen(f.u)
	if err := c.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	c.Close()
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
		t.Fatalf("mark after Sync: %d", r)
	}
	if now := ownSegments(t, f.env, f.mbx, a.Epoch, dev); len(now) != 1 || now[0] == old[0] {
		t.Fatalf("segment not issued again: %v", now)
	}
}

// TestDeviceLostUnlistedOnly (finding low 2): bob is a member of no
// mailbox, and mailboxes/ of the data directory is a regular file. The
// only failure is that the mailboxes cannot be listed: the revocation
// runs, and the result is ErrPartial for that reason alone.
func TestDeviceLostUnlistedOnly(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	p := f.env.Store.Path("mailboxes")
	if err := os.Rename(p, p+".aside"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	bob.Client.Close()
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(f.env.ClientConfig(bob.Dir), testenv.Passphrase, bob.Words)
	if gen != 2 || !errors.Is(err, client.ErrPartial) || !strings.Contains(err.Error(), "cannot be listed") {
		t.Fatalf("DeviceLost: %d %v", gen, err)
	}
	warningWith(t, f.env.Warnings.Take(), "nicht aufgelistet")
}

// TestListResignMetaGone (finding low 2): alice checked bob's version 2
// before his revocation; while she signs it again, the file is removed
// (resignMetaHook). The mail is gone: List does not list it, and the
// warning names the missing file, not a signature left for later.
func TestListResignMetaGone(t *testing.T) {
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
	path := f.env.Store.MetaFile(f.mbx, f.inbox(t), a.ID)
	client.SetResignMetaHook(t, func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
	})
	c := f.env.Reopen(f.u)
	f.env.Warnings.Take()
	if listed(t, c, f.mbx, a.ID) {
		t.Fatal("a mail whose metadata are gone is listed")
	}
	w := f.env.Warnings.Take()
	warningWith(t, w, a.ID.String(), "Datei fehlt")
	if k := countWith(w, "nicht neu signiert"); k != 0 {
		t.Fatalf("warned as a signature left for later: %q", w)
	}
}

// TestSegmentMemoPerContent (finding low 1): bob writes two different
// segments, alice checks both, bob rotates. Each segment has its own
// check record (per content): alice takes over both and finds both
// mails.
func TestSegmentMemoPerContent(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	for _, s := range []string{"m1", "m2"} {
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		if n, err := bob.Client.Index(f.mbx); err != nil || n != 1 {
			t.Fatalf("bob indexes %s: %d %v", s, n, err)
		}
	}
	list, _ := f.u.Client.List(f.mbx, store.ID{})
	n := list[0].Epoch
	bobDev, _ := bob.Client.Device()
	if segs := ownSegments(t, f.env, f.mbx, n, bobDev); len(segs) != 2 {
		t.Fatalf("bob's segments: %v", segs)
	}
	if got := search(t, f.u.Client, f.mbx, "fromdomain:x.example", ""); got != "m1,m2" {
		t.Fatal(got)
	}
	f.env.Rotate(bob)
	c := f.env.Reopen(f.u)
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "fromdomain:x.example", ""); got != "m1,m2" {
		t.Fatalf("after bob's revocation: %q (%q)", got, f.env.Warnings.Take())
	}
	if k := countWith(f.env.Warnings.Take(), "übernommen und neu signiert"); k != 2 {
		t.Fatalf("%d segments taken over", k)
	}
	if segs := ownSegments(t, f.env, f.mbx, n, bobDev); len(segs) != 0 {
		t.Fatalf("bob's segments left: %v", segs)
	}
}

// TestOldSegmentMemo (finding low 3): a check record in the format before
// task 09c (index/<n>/<device>-<seq>) names the SHA-256 of the file it
// was made for. Alice's record of bob's segment is in that format, here
// twice (the copy attack of task 09b left one per sequence number). After
// bob's revocation she takes over the segment at its place through it,
// without a new record, and signs it again once: the records in the old
// format are marked, so a copy under the other recorded sequence number
// is ignored, and a copy under a sequence number without a record is not
// taken over.
func TestOldSegmentMemo(t *testing.T) {
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
	if len(refs) != 1 {
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
	dev, _ := f.u.Client.Device()
	f.u.Client.Close()
	key := client.SegmentMemoKey(n, bobSeg.Device, data)
	oldKey := func(seq uint64) string { return fmt.Sprintf("index/%d/%s-%d", n, bobSeg.Device, seq) }
	editState(t, f.u.Dir, f.mbx, func(ms map[string]any) {
		checked := ms["checked"].(map[string]any)
		m := checked[key]
		delete(checked, key)
		checked[oldKey(bobSeg.Seq)] = m
		checked[oldKey(500)] = m
	})
	f.env.Rotate(bob)
	c := f.env.Reopen(f.u)
	base := stateSize(t, f.u.Dir)
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("not taken over through the old record: %q (%q)", got, f.env.Warnings.Take())
	}
	if k := countWith(f.env.Warnings.Take(), "übernommen und neu signiert"); k != 1 {
		t.Fatalf("%d takeovers", k)
	}
	if mine := ownSegments(t, f.env, f.mbx, n, dev); len(mine) != 1 {
		t.Fatalf("alice's segments %v", mine)
	}
	// A copy under the other recorded number, at the old place, and under
	// a number without a record.
	for _, round := range []struct {
		seq  uint64
		want string
	}{{500, "bereits neu ausgestellt"}, {bobSeg.Seq, "bereits neu ausgestellt"}, {777, "vorher nicht geprüft"}} {
		if err := f.env.Store.WriteIndexSegment(f.mbx, n, bobSeg.Device, round.seq, data); err != nil {
			t.Fatal(err)
		}
		f.env.Warnings.Take()
		if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
			t.Fatal(got)
		}
		w := f.env.Warnings.Take()
		if k := countWith(w, "übernommen und neu signiert"); k != 0 {
			t.Fatalf("a copy under %d was taken over again: %q", round.seq, w)
		}
		warningWith(t, w, fmt.Sprintf("%s-%d ", bobSeg.Device, round.seq), round.want)
		if err := f.env.Store.RemoveIndexSegment(f.mbx, n, bobSeg.Device, round.seq); err != nil {
			t.Fatal(err)
		}
	}
	if mine := ownSegments(t, f.env, f.mbx, n, dev); len(mine) != 1 {
		t.Fatalf("alice's segments %v", mine)
	}
	// One record for alice's new segment; the old ones changed in place.
	if grown := stateSize(t, f.u.Dir) - base; grown > stateBound {
		t.Fatalf("state.json grew by %d bytes", grown)
	}
	c.Close()
	ms := readState(t, f.u.Dir, f.mbx)
	checked := ms["checked"].(map[string]any)
	for _, s := range []uint64{bobSeg.Seq, 500} {
		m, _ := checked[oldKey(s)].(map[string]any)
		if m == nil || m["next"] == nil || m["signer"] != nil {
			t.Fatalf("old record %d not marked: %v", s, m)
		}
	}
	if _, ok := checked[key]; ok {
		t.Fatal("a record of the content was made")
	}
	// The mark of a record in the old format holds only for the content
	// it names: another valid segment at the same place (bob, with his
	// new generation) is used.
	e, _, err := f.env.Store.ReadEpoch(f.mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	c = f.env.Reopen(f.u)
	mk, err := c.TermMark(f.mbx, n, "from:other@x.example")
	if err != nil {
		t.Fatal(err)
	}
	other := sealSegment(t, f.env, bob, e, n, bobSeg.Device, &store.IndexSegment{MailboxID: f.mbx, Epoch: n, Postings: []store.Posting{{Mark: mk, MailIDs: []store.ID{list[0].ID}}}})
	if err := f.env.Store.WriteIndexSegment(f.mbx, n, bobSeg.Device, bobSeg.Seq, other); err != nil {
		t.Fatal(err)
	}
	if got := search(t, c, f.mbx, "from:other@x.example", ""); got != "m1" {
		t.Fatalf("another content at the marked place: %q (%q)", got, f.env.Warnings.Take())
	}
}

// TestAttack09cStateGrowthForcedMerge (finding medium 2, the verifier's
// test of the same name, turned around): 14 files with canonical names
// and garbage content, and before every Sync a copy of the one valid
// segment. Neither counts for MergeThreshold: no merge, no new segment;
// after 100 Syncs state.json has grown by at most a fixed amount.
func TestAttack09cStateGrowthForcedMerge(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	dev, _ := c.Device()
	var junk store.ID
	junk[0] = 0xff
	for s := 1; s <= client.MergeThreshold-2; s++ {
		if err := os.WriteFile(f.env.Store.IndexSegmentFile(f.mbx, 1, junk, uint64(s)), []byte("junk"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatal(got)
	}
	mine := ownSegments(t, f.env, f.mbx, 1, dev)
	if len(mine) != 1 {
		t.Fatalf("segments %v", mine)
	}
	data, err := f.env.Store.ReadIndexSegment(f.mbx, 1, dev, mine[0].Seq)
	if err != nil {
		t.Fatal(err)
	}
	// The first Sync records folders.gml of every epoch, as it would
	// without any attack.
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	base := stateSize(t, f.u.Dir)
	const rounds = 100
	for r := 0; r < rounds; r++ {
		if err := f.env.Store.WriteIndexSegment(f.mbx, 1, dev, mine[0].Seq+1000+uint64(r), data); err != nil {
			t.Fatal(err)
		}
		f.env.Warnings.Take()
		if err := c.Sync(); err != nil {
			t.Fatal(err)
		}
		if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
			t.Fatal(got)
		}
		if now := ownSegments(t, f.env, f.mbx, 1, dev); len(now) != 1 || now[0] != mine[0] {
			t.Fatalf("round %d: merged or copy left: %v", r, now)
		}
	}
	grown := stateSize(t, f.u.Dir) - base
	t.Logf("state.json +%d bytes after %d Syncs", grown, rounds)
	if grown > stateBound {
		t.Fatalf("state.json grew by %d bytes", grown)
	}
}

// TestAttack09cStateGrowthForcedMergeReplay (finding medium 2, variant):
// alice indexes 16 mails in 16 runs, the 16th merges the segments. The
// attacker keeps every segment the merge consumed and every pending
// file, and puts all of them back before each of 100 Syncs. The merged
// segments are marked in alice's records (merged, not grown): they are
// ignored, start no merge and are removed; the pending entries are in
// the merged segment already and make no new segment. state.json grows
// by at most a fixed amount, and the search finds every mail once.
func TestAttack09cStateGrowthForcedMergeReplay(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	dev, _ := c.Device()
	pending := map[store.ID][]byte{}
	segs := map[store.IndexSegmentRef][]byte{}
	snapSegs := func() {
		refs, err := f.env.Store.ListIndexSegments(f.mbx, 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range refs {
			data, err := f.env.Store.ReadIndexSegment(f.mbx, 1, r.Device, r.Seq)
			if err != nil {
				t.Fatal(err)
			}
			segs[r] = data
		}
	}
	client.SetMergeHook(t, snapSegs)
	var want []string
	for i := 0; i < client.MergeThreshold; i++ {
		s := fmt.Sprintf("m%02d", i)
		want = append(want, s)
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		ids, err := f.env.Store.ListPending(f.mbx, 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			pending[id], _ = f.env.Store.ReadPending(f.mbx, 1, id)
		}
		if n, err := c.Index(f.mbx); err != nil || n != 1 {
			t.Fatalf("index %s: %d %v", s, n, err)
		}
	}
	client.SetMergeHook(t, nil)
	if len(segs) != client.MergeThreshold || segmentCount(t, f.env, f.mbx, 1) != 1 {
		t.Fatalf("%d segments kept, %d now", len(segs), segmentCount(t, f.env, f.mbx, 1))
	}
	merged := ownSegments(t, f.env, f.mbx, 1, dev)
	all := strings.Join(want, ",")
	if got := search(t, c, f.mbx, "fromdomain:x.example", ""); got != all {
		t.Fatal(got)
	}
	// The first Sync records folders.gml of every epoch, as it would
	// without any attack.
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	base := stateSize(t, f.u.Dir)
	const rounds = 100
	for r := 0; r < rounds; r++ {
		for ref, data := range segs {
			if err := f.env.Store.WriteIndexSegment(f.mbx, 1, ref.Device, ref.Seq, data); err != nil && !errors.Is(err, store.ErrExists) {
				t.Fatal(err)
			}
		}
		for id, data := range pending {
			if err := store.WriteFileAtomic(f.env.Store.PendingFile(f.mbx, 1, id), data); err != nil {
				t.Fatal(err)
			}
		}
		f.env.Warnings.Take()
		if err := c.Sync(); err != nil {
			t.Fatal(err)
		}
		if r == 0 {
			warningWith(t, f.env.Warnings.Take(), "bereits neu ausgestellt oder zusammengefasst")
		}
		if now := ownSegments(t, f.env, f.mbx, 1, dev); len(now) != 1 || now[0] != merged[0] {
			t.Fatalf("round %d: segments %v", r, now)
		}
		if n := pendingCount(t, f.env, f.mbx, 1); n != 0 {
			t.Fatalf("round %d: %d pending files left", r, n)
		}
		if got := search(t, c, f.mbx, "fromdomain:x.example", ""); got != all {
			t.Fatalf("round %d: %q", r, got)
		}
	}
	grown := stateSize(t, f.u.Dir) - base
	t.Logf("state.json +%d bytes after %d Syncs with %d segments and %d pending files put back", grown, rounds, len(segs), len(pending))
	if grown > stateBound {
		t.Fatalf("state.json grew by %d bytes", grown)
	}
}

// TestMergeCountsDistinctValid (finding medium 2): MergeThreshold-1
// different segments (one of Index, the others written directly), a
// byte-equal copy and a file that does not check make MergeThreshold+1
// names but no merge; the copy is removed under the lock, the other file
// stays. One more different segment makes the merge, which removes a
// copy as well.
func TestMergeCountsDistinctValid(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	a := f.deliver(t, "a", "x")
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatalf("index: %d %v", n, err)
	}
	var first store.IndexSegmentRef
	for i := 0; i < client.MergeThreshold-2; i++ {
		ref, err := c.WriteSegment(f.mbx, a.Epoch, fmt.Sprintf("from:s%d@x.example", i), a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = ref
		}
	}
	data, err := f.env.Store.ReadIndexSegment(f.mbx, a.Epoch, first.Device, first.Seq)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.env.Store.WriteIndexSegment(f.mbx, a.Epoch, first.Device, 900, data); err != nil {
		t.Fatal(err)
	}
	var junk store.ID
	junk[0] = 0xfe
	if err := os.WriteFile(f.env.Store.IndexSegmentFile(f.mbx, a.Epoch, junk, 1), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if n := segmentCount(t, f.env, f.mbx, a.Epoch); n != client.MergeThreshold {
		t.Fatalf("%d segments: merged, or the copy was left", n)
	}
	if _, err := f.env.Store.ReadIndexSegment(f.mbx, a.Epoch, first.Device, 900); err == nil {
		t.Fatal("the copy was left")
	}
	// One more different segment, and the copy again: the merge removes
	// it with the merged segments.
	if _, err := c.WriteSegment(f.mbx, a.Epoch, "from:last@x.example", a.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.env.Store.WriteIndexSegment(f.mbx, a.Epoch, first.Device, 901, data); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if n := segmentCount(t, f.env, f.mbx, a.Epoch); n != 2 {
		t.Fatalf("%d segments after the merge (the merged one and the junk)", n)
	}
	for i := 0; i < client.MergeThreshold-2; i++ {
		if got := search(t, c, f.mbx, fmt.Sprintf("from:s%d@x.example", i), ""); got != "a" {
			t.Fatalf("term %d: %q", i, got)
		}
	}
}

// TestReplayUnseenSegmentsOnce (finding medium 2, bound): bob indexes 16
// mails in 16 runs and merges; alice never read his segments. The
// attacker puts bob's 16 merged segments back again and again: they are
// different, valid and unknown to alice, so her next Index merges them
// once (records of 16 contents, marked as merged, and one merged
// segment); from then on they are spent and nothing grows. The growth is
// bounded by the segments members ever wrote, not by the attack.
func TestReplayUnseenSegmentsOnce(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	segs := map[store.IndexSegmentRef][]byte{}
	var n uint32
	client.SetMergeHook(t, func() {
		refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
		for _, r := range refs {
			segs[r], _ = f.env.Store.ReadIndexSegment(f.mbx, n, r.Device, r.Seq)
		}
	})
	for i := 0; i < client.MergeThreshold; i++ {
		s := fmt.Sprintf("m%02d", i)
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		if n == 0 {
			list, _ := bob.Client.List(f.mbx, store.ID{})
			n = list[0].Epoch
		}
		if _, err := bob.Client.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
	}
	client.SetMergeHook(t, nil)
	if len(segs) != client.MergeThreshold || segmentCount(t, f.env, f.mbx, n) != 1 {
		t.Fatalf("%d segments kept", len(segs))
	}
	c := f.u.Client
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := search(t, c, f.mbx, "from:m00@x.example", ""); got != "m00" {
		t.Fatal(got)
	}
	base := stateSize(t, f.u.Dir)
	var sizes []int64
	for r := 0; r < 5; r++ {
		for ref, data := range segs {
			if err := f.env.Store.WriteIndexSegment(f.mbx, n, ref.Device, ref.Seq, data); err != nil && !errors.Is(err, store.ErrExists) {
				t.Fatal(err)
			}
		}
		if err := c.Sync(); err != nil {
			t.Fatal(err)
		}
		if got := search(t, c, f.mbx, "from:m00@x.example", ""); got != "m00" {
			t.Fatal(got)
		}
		sizes = append(sizes, stateSize(t, f.u.Dir)-base)
	}
	t.Logf("state.json over base after each round: %v (%d segments put back each round)", sizes, len(segs))
	for r := 1; r < len(sizes); r++ {
		if sizes[r] != sizes[0] {
			t.Fatalf("grew after the first merge of the unseen segments: %v", sizes)
		}
	}
}

// TestPendingReplayAfterDeletion (finding medium 2, turned around in
// task 09g): the client no longer notes which mails it indexed. An
// attacker who puts a pending file back while the segment that holds its
// mail is there makes no new segment and state.json does not grow
// ("kept"). One who removes the segment first, before each of 20 Syncs
// ("removed"), gets the mail indexed again each time, as after a restore
// from a backup: the mail stays searchable, and state.json grows by the
// record of one new segment per round, no more than roundBound.
func TestPendingReplayAfterDeletion(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(map[bool]string{false: "kept", true: "removed"}[removed], func(t *testing.T) {
			f := newFixture(t)
			c := f.u.Client
			f.send(t, "s@x.example", header("s@x.example", "m1"))
			f.flush(t)
			ids, err := f.env.Store.ListPending(f.mbx, 1)
			if err != nil || len(ids) == 0 {
				t.Fatal(err)
			}
			pending := map[store.ID][]byte{}
			for _, id := range ids {
				pending[id], _ = f.env.Store.ReadPending(f.mbx, 1, id)
			}
			if err := c.Sync(); err != nil {
				t.Fatal(err)
			}
			if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
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
				if removed {
					for _, ref := range ownSegments(t, f.env, f.mbx, 1, dev) {
						if err := f.env.Store.RemoveIndexSegment(f.mbx, 1, ref.Device, ref.Seq); err != nil {
							t.Fatal(err)
						}
					}
				}
				for id, data := range pending {
					if err := store.WriteFileAtomic(f.env.Store.PendingFile(f.mbx, 1, id), data); err != nil {
						t.Fatal(err)
					}
				}
				if err := c.Sync(); err != nil {
					t.Fatal(err)
				}
				if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
					t.Fatalf("round %d: %q", r, got)
				}
				if mine := ownSegments(t, f.env, f.mbx, 1, dev); len(mine) != 1 {
					t.Fatalf("round %d: segments %v", r, mine)
				}
				if n := pendingCount(t, f.env, f.mbx, 1); n != 0 {
					t.Fatalf("round %d: %d pending files left", r, n)
				}
				now := stateSize(t, f.u.Dir)
				if now-prev > roundBound {
					t.Fatalf("round %d: state.json +%d bytes", r, now-prev)
				}
				prev = now
			}
			grown := stateSize(t, f.u.Dir) - base
			t.Logf("state.json +%d bytes after %d rounds (pending file put back before a Sync, segment removed: %v)", grown, rounds, removed)
			if !removed && grown > stateBound || removed && grown == 0 {
				t.Fatalf("state.json grew by %d bytes", grown)
			}
		})
	}
}

// TestIndexedBeforeMetadata (finding medium 2, turned around in task
// 09g): Index no longer makes a memo. A state file of tasks 09d to 09f
// may hold one that Index made before this client checked the metadata of
// the mail (the epoch indexed only); the first List fills it, the field
// stays as it was, and the rules against replay hold for it as before.
func TestIndexedBeforeMetadata(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	a := f.deliver(t, "a", "x")
	c.Close()
	editState(t, f.u.Dir, f.mbx, func(ms map[string]any) {
		delete(ms, "mails")
		delete(ms, "versions")
	})
	c = f.env.Reopen(f.u)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if mails := mailMemos(t, f.u.Dir, f.mbx); len(mails) != 0 {
		t.Fatalf("Index made memos: %v", mails)
	}
	// The memo of a mail as Index of task 09e made it.
	editState(t, f.u.Dir, f.mbx, func(ms map[string]any) {
		ms["mails"] = map[string]any{a.ID.String(): map[string]any{"epoch": 0, "received": 0, "mail_hash": "", "indexed_terms": 1}}
	})
	c = f.env.Reopen(f.u)
	if !listed(t, c, f.mbx, a.ID) {
		t.Fatal("not listed")
	}
	c.Close()
	mails := mailMemos(t, f.u.Dir, f.mbx)
	if len(mails) == 0 {
		t.Fatal("no memos")
	}
	for id, v := range mails {
		m := v.(map[string]any)
		if m["mail_hash"] == "" || id == a.ID.String() && m["indexed_terms"] != float64(1) {
			t.Fatalf("memo of %s not filled, or its field not kept: %v", id, m)
		}
	}
	// The versions and memos noted by List hold: a replayed version 1 is
	// refused.
	path := f.env.Store.MetaFile(f.mbx, f.inbox(t), a.ID)
	v1 := mustRead(t, path)
	c = f.env.Reopen(f.u)
	if _, err := c.SetFlags(f.mbx, a.ID, []string{"seen"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, v1, 0o644); err != nil {
		t.Fatal(err)
	}
	if listed(t, c, f.mbx, a.ID) {
		t.Fatal("replayed version 1 listed")
	}
}

// TestMarkedRecordStays (finding high, guard): a check record marked as
// issued again or merged (checkMemo.Next) is never replaced by a new
// check of the same content; it stays marked, so the content stays spent.
// Readers skip a spent content before they check it, so only a direct
// call reaches the guard in recordChecked.
func TestMarkedRecordStays(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatal(got)
	}
	dev, _ := c.Device()
	mine := ownSegments(t, f.env, f.mbx, 1, dev)
	if len(mine) != 1 {
		t.Fatalf("segments %v", mine)
	}
	data, err := f.env.Store.ReadIndexSegment(f.mbx, 1, dev, mine[0].Seq)
	if err != nil {
		t.Fatal(err)
	}
	key := client.SegmentMemoKey(1, dev, data)
	c.Close()
	editState(t, f.u.Dir, f.mbx, func(ms map[string]any) {
		checked := ms["checked"].(map[string]any)
		m, _ := checked[key].(map[string]any)
		if m == nil {
			t.Fatal("no record of the segment")
		}
		checked[key] = map[string]any{"hash": m["hash"], "next": strings.Repeat("ab", 16)}
	})
	c = f.env.Reopen(f.u)
	if c.RecordChecked(f.mbx, key, data, f.u.ID, 1) {
		t.Fatal("a marked record was replaced by a new check")
	}
	// An unmarked record of another content is still made.
	if !c.RecordChecked(f.mbx, client.SegmentMemoKey(1, dev, []byte("other")), []byte("other"), f.u.ID, 1) {
		t.Fatal("no record of another content")
	}
}
