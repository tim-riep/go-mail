package client_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 09f: the limit of a merge is bound to the own last merge
// result; a content merged or issued again before is spent only while its
// successor is there; step 4 of device lost compares the own files with
// those step 2 checked; an older metadata version put back keeps no mark;
// test gaps of 09e. The verifier's tests of task 09e keep their names
// where the task names them, turned around.

// postingSet builds a valid segment of epoch n of mbx from a posting map.
func postingSet(mbx store.ID, n uint32, p map[[32]byte]map[store.ID]bool) *store.IndexSegment {
	seg := &store.IndexSegment{MailboxID: mbx, Epoch: n}
	for mk, ids := range p {
		ps := store.Posting{Mark: mk}
		for id := range ids {
			ps.MailIDs = append(ps.MailIDs, id)
		}
		sort.Slice(ps.MailIDs, func(i, j int) bool { return bytes.Compare(ps.MailIDs[i][:], ps.MailIDs[j][:]) < 0 })
		seg.Postings = append(seg.Postings, ps)
	}
	sort.Slice(seg.Postings, func(i, j int) bool { return bytes.Compare(seg.Postings[i].Mark[:], seg.Postings[j].Mark[:]) < 0 })
	return seg
}

// TestAttack09eMergedBlock (finding medium, the verifier's test, turned
// around): with the limit of 09e alone, alice never merged again once
// her merged segment was gone, her own segments piled up past the read
// limit (lowered to 40 files here) and the hits of new mails were
// missing. Variant "collude": bob (member, colluding) seals 16 segments
// of garbage postings, alice merges them with the real ones, then her
// merged segments are removed and bob seals one segment with exactly the
// real postings. Variant "delete": no key, alice's merged segment is
// removed once (its hits are lost, as with any deletion). Since task 09g
// there is no such limit: she merges again from MergeThreshold segments
// on, every new mail is found, no search reports ErrPartial, and
// index/<n>/ never holds more than MergeThreshold segments after an
// Index. Neither merged nor merged_result is written any more.
func TestAttack09eMergedBlock(t *testing.T) {
	for _, variant := range []string{"control", "collude", "delete"} {
		t.Run(variant, func(t *testing.T) {
			f := newFixture(t)
			bob, _ := threeMembers(t, f)
			c := f.u.Client
			dev, _ := c.Device()
			perRun := 1
			if variant == "delete" {
				perRun = 5
			}
			k := 0
			for i := 0; i < client.MergeThreshold; i++ {
				for j := 0; j < perRun; j++ {
					s := fmt.Sprintf("old%03d", k)
					k++
					f.send(t, s+"@x.example", header(s+"@x.example", s))
				}
				f.flush(t)
				if _, err := c.Index(f.mbx); err != nil {
					t.Fatal(err)
				}
			}
			list, _ := c.List(f.mbx, store.ID{})
			n := list[0].Epoch
			if got := segmentCount(t, f.env, f.mbx, n); got != 1 {
				t.Fatalf("alice did not merge: %d", got)
			}
			e, _, err := f.env.Store.ReadEpoch(f.mbx, n)
			if err != nil {
				t.Fatal(err)
			}
			real := map[[32]byte]map[store.ID]bool{}
			segs, err := c.Segments(f.mbx, n)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range segs {
				for _, ps := range s.Postings {
					if real[ps.Mark] == nil {
						real[ps.Mark] = map[store.ID]bool{}
					}
					for _, id := range ps.MailIDs {
						real[ps.Mark][id] = true
					}
				}
			}
			switch variant {
			case "collude":
				for i := 0; i < client.MergeThreshold; i++ {
					g := map[[32]byte]map[store.ID]bool{}
					for m := 0; m < 4; m++ {
						var mk [32]byte
						rand.Read(mk[:])
						g[mk] = map[store.ID]bool{}
						// Small enough that the merge saves
						// MergeThreshold-1 segments (task 09g).
						for x := 0; x < 1000; x++ {
							id, _ := store.NewID(nil)
							g[mk][id] = true
						}
					}
					d, _ := store.NewID(nil)
					if err := f.env.Store.WriteIndexSegment(f.mbx, n, d, 1, sealSegment(t, f.env, bob, e, n, d, postingSet(f.mbx, n, g))); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := c.Index(f.mbx); err != nil {
					t.Fatal(err)
				}
				mine := ownSegments(t, f.env, f.mbx, n, dev)
				if segmentCount(t, f.env, f.mbx, n) != len(mine) {
					t.Fatalf("alice did not merge the garbage: %d segments", segmentCount(t, f.env, f.mbx, n))
				}
				for _, r := range mine {
					f.env.Store.RemoveIndexSegment(f.mbx, n, r.Device, r.Seq)
				}
				d, _ := store.NewID(nil)
				if err := f.env.Store.WriteIndexSegment(f.mbx, n, d, 1, sealSegment(t, f.env, bob, e, n, d, postingSet(f.mbx, n, real))); err != nil {
					t.Fatal(err)
				}
				if got := search(t, c, f.mbx, "from:old000@x.example", ""); got != "old000" {
					t.Fatalf("old hit lost: %q", got)
				}
			case "delete":
				for _, r := range ownSegments(t, f.env, f.mbx, n, dev) {
					f.env.Store.RemoveIndexSegment(f.mbx, n, r.Device, r.Seq)
				}
			}
			client.SetSegmentLimits(t, 40, 256<<20)
			const rounds = 50
			most := 0
			for r := 0; r < rounds; r++ {
				s := fmt.Sprintf("new%03d", r)
				f.send(t, s+"@x.example", header(s+"@x.example", s))
				f.flush(t)
				if _, err := c.Index(f.mbx); err != nil {
					t.Fatalf("round %d: %v", r, err)
				}
				most = max(most, segmentCount(t, f.env, f.mbx, n))
			}
			f.env.Warnings.Take()
			for r := 0; r < rounds; r++ {
				s := fmt.Sprintf("new%03d", r)
				l, err := c.Search(f.mbx, "from:"+s+"@x.example", client.SearchOptions{})
				if err != nil || subjects(l) != s {
					t.Fatalf("%s: %q %v", s, subjects(l), err)
				}
			}
			if most > client.MergeThreshold {
				t.Fatalf("%d segments after an Index", most)
			}
			if n := countWith(f.env.Warnings.Take(), "nicht zusammengefasst"); n != 0 {
				t.Fatalf("%d merges held back", n)
			}
			if ms := readState(t, f.u.Dir, f.mbx); ms["merged"] != nil || ms["merged_result"] != nil {
				t.Fatalf("limit of 09e/09f written: %v %v", ms["merged"], ms["merged_result"])
			}
		})
	}
}

// TestMergeAfterOwnResultRejected (the verifier's honest case of 09e):
// bob merges every posting, alice's merged segment included, and then
// his generation is revoked before he issues his files again. Alice
// never checked bob's merged segment, so she rejects it; with the limit
// of 09e she merged no more, since the postings she saw fell below her
// last merge, and 40 index runs left 41 segments. Her result is gone, so
// she merges as usual: index/<n>/ holds at most MergeThreshold segments
// after any of her index runs (K5 point 4).
func TestMergeAfterOwnResultRejected(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	c := f.u.Client
	k := 0
	next := func() string { k++; return fmt.Sprintf("v%03d", k) }
	for b := 0; b < client.MergeThreshold-1; b++ {
		for i := 0; i < 10; i++ {
			s := next()
			f.send(t, s+"@x.example", header(s+"@x.example", s))
		}
		f.flush(t)
		if _, err := bob.Client.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
	}
	s := next()
	f.send(t, s+"@x.example", header(s+"@x.example", s))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := c.List(f.mbx, store.ID{})
	n := list[0].Epoch
	if got := segmentCount(t, f.env, f.mbx, n); got != 1 {
		t.Fatalf("alice did not merge: %d", got)
	}
	for i := 0; i < client.MergeThreshold-1; i++ {
		s := next()
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		if _, err := bob.Client.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
	}
	bdev, _ := bob.Client.Device()
	if got := segmentCount(t, f.env, f.mbx, n); got != 1 || len(ownSegments(t, f.env, f.mbx, n, bdev)) != 1 {
		t.Fatalf("bob did not merge: %d", got)
	}
	f.env.Rotate(bob)
	c = f.env.Reopen(f.u)
	most := 0
	for i := 0; i < 40; i++ {
		s = next()
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		most = max(most, segmentCount(t, f.env, f.mbx, n))
	}
	if most > client.MergeThreshold {
		t.Fatalf("K5 point 4: alice held %d segments without merging", most)
	}
	if n := countWith(f.env.Warnings.Take(), "nicht zusammengefasst"); n != 0 {
		t.Fatalf("%d merges held back", n)
	}
	if got := search(t, c, f.mbx, "from:"+s+"@x.example", ""); got != s {
		t.Fatalf("%s: %q", s, got)
	}
}

// mergeRollback lets alice merge MergeThreshold single-mail segments with
// carol as a further member, and keeps the files of index/<n>/ right
// before the merge (merge hook). It returns the fixture, carol, the
// epoch, the files kept (path to content) and alice's merge result.
func mergeRollback(t *testing.T) (*fixture, *testenv.User, uint32, map[string][]byte, []store.IndexSegmentRef) {
	t.Helper()
	f := newFixture(t)
	_, carol := threeMembers(t, f)
	c := f.u.Client
	saved := map[string][]byte{}
	var n uint32
	client.SetMergeHook(t, func() {
		if len(saved) > 0 || n == 0 {
			return
		}
		refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
		for _, r := range refs {
			p := f.env.Store.IndexSegmentFile(f.mbx, n, r.Device, r.Seq)
			if d, err := os.ReadFile(p); err == nil {
				saved[p] = d
			}
		}
	})
	for i := 0; i < client.MergeThreshold; i++ {
		s := fmt.Sprintf("m%02d", i)
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			list, _ := c.List(f.mbx, store.ID{})
			n = list[0].Epoch
		}
	}
	client.SetMergeHook(t, nil)
	result, err := f.env.Store.ListIndexSegments(f.mbx, n)
	if err != nil || len(result) != 1 || len(saved) != client.MergeThreshold {
		t.Fatalf("no merge: %v, %d saved, %v", result, len(saved), err)
	}
	return f, carol, n, saved, result
}

// rollBack puts index/<n>/ back to the files kept before the merge.
func rollBack(t *testing.T, f *fixture, n uint32, saved map[string][]byte) {
	t.Helper()
	refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
	for _, r := range refs {
		f.env.Store.RemoveIndexSegment(f.mbx, n, r.Device, r.Seq)
	}
	for p, d := range saved {
		if err := os.WriteFile(p, d, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestV09eRollbackOriginals (finding low 1, the verifier's test, turned
// around): index/<n>/ is rolled back to the state right before alice's
// merge (a backup, or anybody with write access): the 16 originals,
// signed by alice's current generation, are back, the merged segment is
// gone. Before task 09f alice removed the originals as merged on her next
// Index, and the hits were gone for every reader. Their successor is not
// there, so alice uses them; carol finds the mails before and after
// alice's Index, and alice removes nothing and writes nothing.
func TestV09eRollbackOriginals(t *testing.T) {
	f, carol, n, saved, _ := mergeRollback(t)
	rollBack(t, f, n, saved)
	f.env.Warnings.Take()
	c := f.u.Client
	if got := search(t, c, f.mbx, "from:m03@x.example", ""); got != "m03" {
		t.Fatalf("alice after the rollback: %q %v", got, f.env.Warnings.Take())
	}
	warningWith(t, f.env.Warnings.Take(), "der Nachfolger fehlt", "zählt nicht")
	if got := search(t, f.env.Reopen(carol), f.mbx, "from:m03@x.example", ""); got != "m03" {
		t.Fatalf("carol after the rollback: %q", got)
	}
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if got := segmentCount(t, f.env, f.mbx, n); got != client.MergeThreshold {
		t.Fatalf("segments after alice's Index: %d", got)
	}
	if got := search(t, f.env.Reopen(carol), f.mbx, "from:m03@x.example", ""); got != "m03" {
		t.Fatalf("carol after alice's Index: %q", got)
	}
}

// TestRollbackOriginalsNoGrowth (finding low 1, "Ein Zurückspielen darf
// dabei nicht wachsen"): the rollback to before the merge is repeated
// five times, each time after alice and carol searched and alice
// indexed. The originals do not count for MergeThreshold, so nobody
// without a key makes alice merge them again: she writes no segment, and
// state.json of alice and carol stays the same from the second round on.
// A legitimate merge later takes the originals in and names the new
// result in their records (changed in place); put back once more, they
// are spent and removed, again without growth.
func TestRollbackOriginalsNoGrowth(t *testing.T) {
	f, carol, n, saved, _ := mergeRollback(t)
	c := f.u.Client
	cc := f.env.Reopen(carol)
	dev, _ := c.Device()
	var sizes [][2]int64
	for r := 0; r < 5; r++ {
		rollBack(t, f, n, saved)
		if got := search(t, c, f.mbx, "from:m05@x.example", ""); got != "m05" {
			t.Fatalf("round %d, alice: %q", r, got)
		}
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		if got := search(t, cc, f.mbx, "from:m05@x.example", ""); got != "m05" {
			t.Fatalf("round %d, carol: %q", r, got)
		}
		if mine := ownSegments(t, f.env, f.mbx, n, dev); len(mine) != client.MergeThreshold {
			t.Fatalf("round %d: alice has %d segments", r, len(mine))
		}
		sizes = append(sizes, [2]int64{stateSize(t, f.u.Dir), stateSize(t, carol.Dir)})
	}
	for r := 2; r < len(sizes); r++ {
		if sizes[r] != sizes[1] {
			t.Fatalf("state.json grew: %v", sizes)
		}
	}
	// A legitimate merge: MergeThreshold new mails.
	for i := 0; i < client.MergeThreshold; i++ {
		s := fmt.Sprintf("p%02d", i)
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
	}
	if got := segmentCount(t, f.env, f.mbx, n); got >= client.MergeThreshold {
		t.Fatalf("no merge with the originals: %d segments", got)
	}
	var before int64
	for r := 0; r < 4; r++ {
		if r == 1 {
			// From here on: the first round read the new result and the
			// memos of the mails searched (legitimate, once).
			before = stateSize(t, f.u.Dir)
		}
		for p, d := range saved {
			if err := os.WriteFile(p, d, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		f.env.Warnings.Take()
		for _, s := range []string{"m05", "p03"} {
			if got := search(t, c, f.mbx, "from:"+s+"@x.example", ""); got != s {
				t.Fatalf("after the merge, %s: %q", s, got)
			}
		}
		warningWith(t, f.env.Warnings.Take(), "bereits neu ausgestellt oder zusammengefasst")
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		if got := segmentCount(t, f.env, f.mbx, n); got >= client.MergeThreshold {
			t.Fatalf("originals put back after the merge stay: %d segments", got)
		}
	}
	if after := stateSize(t, f.u.Dir); after != before {
		t.Fatalf("state.json grew by %d", after-before)
	}
}

// TestSpentThroughLaterMerge (finding low 1): a content alice merged is
// spent while the segment its records lead to is there, also through a
// later merge of hers: the originals of her first merge, put back after
// her second merge (whose result holds the first result), are spent and
// removed, not used again.
func TestSpentThroughLaterMerge(t *testing.T) {
	f, _, n, saved, _ := mergeRollback(t)
	c := f.u.Client
	for i := 0; i < client.MergeThreshold-1; i++ {
		s := fmt.Sprintf("q%02d", i)
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
	}
	if got := segmentCount(t, f.env, f.mbx, n); got != 1 {
		t.Fatalf("no second merge: %d", got)
	}
	for p, d := range saved {
		if err := os.WriteFile(p, d, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:m07@x.example", ""); got != "m07" {
		t.Fatal(got)
	}
	w := f.env.Warnings.Take()
	if countWith(w, "der Nachfolger fehlt") != 0 || countWith(w, "bereits neu ausgestellt oder zusammengefasst") != client.MergeThreshold {
		t.Fatalf("originals not spent through the later merge: %q", w)
	}
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if got := segmentCount(t, f.env, f.mbx, n); got != 1 {
		t.Fatalf("segments: %d", got)
	}
}

// TestSpentThroughHeldSuccessor (finding low 1): alice merged the
// originals into her first result R1 and R1 into a second result R2; R2
// is removed, and R1 and the originals are put back. R1 is held (its
// successor is gone) but checks, so it is used; the originals, whose
// successor R1 is there, are spent and removed, not used next to it.
func TestSpentThroughHeldSuccessor(t *testing.T) {
	f, _, n, saved, result := mergeRollback(t)
	c := f.u.Client
	dev, _ := c.Device()
	r1 := map[string][]byte{}
	for _, r := range result {
		p := f.env.Store.IndexSegmentFile(f.mbx, n, r.Device, r.Seq)
		r1[p] = mustRead(t, p)
	}
	for i := 0; i < client.MergeThreshold-1; i++ {
		s := fmt.Sprintf("q%02d", i)
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
	}
	r2 := ownSegments(t, f.env, f.mbx, n, dev)
	if len(r2) != 1 || r2[0] == result[0] || segmentCount(t, f.env, f.mbx, n) != 1 {
		t.Fatalf("no second merge: %v", r2)
	}
	f.env.Store.RemoveIndexSegment(f.mbx, n, r2[0].Device, r2[0].Seq)
	for _, files := range []map[string][]byte{saved, r1} {
		for p, d := range files {
			if err := os.WriteFile(p, d, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:m07@x.example", ""); got != "m07" {
		t.Fatal(got)
	}
	w := f.env.Warnings.Take()
	if countWith(w, "der Nachfolger fehlt") != 1 || countWith(w, "bereits neu ausgestellt oder zusammengefasst") != client.MergeThreshold {
		t.Fatalf("originals not spent through the held successor: %q", w)
	}
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if mine := ownSegments(t, f.env, f.mbx, n, dev); len(mine) != 1 || mine[0] != result[0] || segmentCount(t, f.env, f.mbx, n) != 1 {
		t.Fatalf("segments after Index: %v, %d", mine, segmentCount(t, f.env, f.mbx, n))
	}
}

// TestMergeLimitNeedsWholeResult (task 09f; since task 09g there is no
// limit at all): alice merges 16 segments of bob whose one mark holds
// more mail IDs than one segment takes, so her result is two segments.
// One of them is removed, and 16 segments with postings of the other one
// are put back: alice merges as usual, and nothing she merged is lost.
func TestMergeLimitNeedsWholeResult(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	c := f.u.Client
	dev, _ := c.Device()
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := c.List(f.mbx, store.ID{})
	n := list[0].Epoch
	e, _, err := f.env.Store.ReadEpoch(f.mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	var mk [32]byte
	rand.Read(mk[:])
	put := func(ids []store.ID) {
		t.Helper()
		d, _ := store.NewID(nil)
		seg := postingSet(f.mbx, n, map[[32]byte]map[store.ID]bool{mk: {}})
		seg.Postings[0].MailIDs = ids
		sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
		if err := f.env.Store.WriteIndexSegment(f.mbx, n, d, 1, sealSegment(t, f.env, bob, e, n, d, seg)); err != nil {
			t.Fatal(err)
		}
	}
	per := (store.MaxPostingIDs + 64) / client.MergeThreshold
	for i := 0; i < client.MergeThreshold; i++ {
		ids := make([]store.ID, per)
		for j := range ids {
			ids[j], _ = store.NewID(nil)
		}
		put(ids)
	}
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	result := ownSegments(t, f.env, f.mbx, n, dev)
	if len(result) != 2 || segmentCount(t, f.env, f.mbx, n) != 2 {
		t.Fatalf("result of the merge: %v, %d segments", result, segmentCount(t, f.env, f.mbx, n))
	}
	// The larger part stays, the smaller one is removed.
	sizeOf := func(r store.IndexSegmentRef) int {
		data, err := f.env.Store.ReadIndexSegment(f.mbx, n, r.Device, r.Seq)
		if err != nil {
			t.Fatal(err)
		}
		return len(data)
	}
	gone := result[0]
	if sizeOf(result[1]) < sizeOf(gone) {
		gone = result[1]
	}
	f.env.Store.RemoveIndexSegment(f.mbx, n, gone.Device, gone.Seq)
	segs, err := c.Segments(f.mbx, n)
	if err != nil || len(segs) != 1 {
		t.Fatal(len(segs), err)
	}
	var kept []store.ID
	for _, ps := range segs[0].Postings {
		if ps.Mark == mk {
			kept = ps.MailIDs
		}
	}
	if len(kept) != store.MaxPostingIDs {
		t.Fatalf("part left holds %d mail IDs of the mark", len(kept))
	}
	for i := 0; i < client.MergeThreshold; i++ {
		put([]store.ID{kept[i]})
	}
	f.env.Warnings.Take()
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if n := countWith(f.env.Warnings.Take(), "nicht zusammengefasst"); n != 0 {
		t.Fatalf("merge held back by the part of the result that is left (%d)", n)
	}
	if mine := ownSegments(t, f.env, f.mbx, n, dev); len(mine) != 1 || segmentCount(t, f.env, f.mbx, n) != 1 {
		t.Fatalf("no merge: %v, %d segments", mine, segmentCount(t, f.env, f.mbx, n))
	}
}

// TestMergedResultPerEpoch (finding low 4, turned around in task 09g):
// a state file of task 09f holds the own last result and the postings
// merged per epoch (merged_result, merged). Since task 09g they are read
// and kept as they are, and ignored: 16 segments of other devices with
// postings of alice's result in epoch A, which is there, are merged, once
// per set; put back again they are spent, and state.json does not grow.
// Each merge of a new set adds at most the records of what it read and
// wrote.
func TestMergedResultPerEpoch(t *testing.T) {
	f := newFixture(t)
	c := f.u.Client
	dev, _ := c.Device()
	run := func(prefix string) (uint32, []*client.Mail) {
		var mails []*client.Mail
		for i := 0; i < client.MergeThreshold; i++ {
			s := fmt.Sprintf("%s%02d", prefix, i)
			f.send(t, s+"@x.example", header(s+"@x.example", s))
			f.flush(t)
			if _, err := c.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
		}
		list, _ := c.List(f.mbx, store.ID{})
		for _, m := range list {
			if strings.HasPrefix(m.Meta.Subject, prefix) {
				mails = append(mails, m)
			}
		}
		if len(mails) != client.MergeThreshold {
			t.Fatalf("%s: %d mails", prefix, len(mails))
		}
		n := mails[0].Epoch
		if got := ownSegments(t, f.env, f.mbx, n, dev); len(got) != 1 || segmentCount(t, f.env, f.mbx, n) != 1 {
			t.Fatalf("%s: no merge in epoch %d: %v", prefix, n, got)
		}
		return n, mails
	}
	a, mails := run("a")
	f.env.Clock.Set(time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC))
	b, _ := run("b")
	if a == b {
		t.Fatalf("one epoch %d", a)
	}
	resultA := ownSegments(t, f.env, f.mbx, a, dev)
	data := mustRead(t, f.env.Store.IndexSegmentFile(f.mbx, a, resultA[0].Device, resultA[0].Seq))
	sum := sha256.Sum256(data)
	// The limit as task 09f noted it: alice's result of A, with more
	// postings than any merge holds.
	legacy := func(ms map[string]any) {
		ms["merged"] = map[string]any{fmt.Sprint(a): uint64(1) << 40}
		ms["merged_result"] = map[string]any{fmt.Sprint(a): []any{hex.EncodeToString(sum[:16])}}
	}
	c.Close()
	editState(t, f.u.Dir, f.mbx, legacy)
	c = f.env.Reopen(f.u)
	e, _, err := f.env.Store.ReadEpoch(f.mbx, a)
	if err != nil {
		t.Fatal(err)
	}
	mk, err := c.TermMark(f.mbx, a, "fromdomain:x.example")
	if err != nil {
		t.Fatal(err)
	}
	type foreign struct {
		dev  store.ID
		data []byte
	}
	var set []foreign
	for i := 0; i < client.MergeThreshold; i++ {
		d, _ := store.NewID(nil)
		seg := &store.IndexSegment{MailboxID: f.mbx, Epoch: a, Postings: []store.Posting{{Mark: mk, MailIDs: []store.ID{mails[i].ID}}}}
		set = append(set, foreign{d, sealSegment(t, f.env, f.u, e, a, d, seg)})
	}
	var sizes []int64
	for r := 0; r < 4; r++ {
		for _, x := range set {
			if err := f.env.Store.WriteIndexSegment(f.mbx, a, x.dev, 1, x.data); err != nil && !errors.Is(err, store.ErrExists) {
				t.Fatal(err)
			}
		}
		before := stateSize(t, f.u.Dir)
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		mine := ownSegments(t, f.env, f.mbx, a, dev)
		if len(mine) != 1 || segmentCount(t, f.env, f.mbx, a) != 1 || r == 0 && mine[0] == resultA[0] {
			t.Fatalf("round %d: %v, %d segments", r, mine, segmentCount(t, f.env, f.mbx, a))
		}
		if grown := stateSize(t, f.u.Dir) - before; grown > (client.MergeThreshold+1)*roundBound {
			t.Fatalf("round %d: state.json +%d bytes", r, grown)
		}
		sizes = append(sizes, stateSize(t, f.u.Dir))
	}
	t.Logf("state.json after each round: %v", sizes)
	for r := 2; r < len(sizes); r++ {
		if sizes[r] != sizes[1] {
			t.Fatalf("grew once the set was spent: %v", sizes)
		}
	}
	c.Close()
	ms := readState(t, f.u.Dir, f.mbx)
	if m, _ := ms["merged"].(map[string]any); m[fmt.Sprint(a)] != float64(1<<40) || len(m) != 1 {
		t.Fatalf("merged not kept as it was: %v", ms["merged"])
	}
	if m, _ := ms["merged_result"].(map[string]any); len(m) != 1 {
		t.Fatalf("merged_result not kept as it was: %v", ms["merged_result"])
	}
	f.env.Reopen(f.u)
}

// TestRemovalAfterMarksSaved (finding low 4, mutations V13, V14 and V18
// of the 09d check): the marks are saved before anything is removed. At
// the point right before the removal, state.json on the disk holds them
// and the files are still there: after a merge, the successor in the
// record of every merged content and the result; after a segment is
// signed again, the successor in the record of the old content; after
// indexing, the mails noted as indexed, with the pending files still in
// place.
func TestRemovalAfterMarksSaved(t *testing.T) {
	t.Run("merge", func(t *testing.T) {
		f := newFixture(t)
		c := f.u.Client
		var n uint32
		seen := false
		client.SetCrashHook(t, func(p string) bool {
			if p != "index-merge-noted" {
				return false
			}
			seen = true
			ms := readState(t, f.u.Dir, f.mbx)
			checked, _ := ms["checked"].(map[string]any)
			marked := 0
			for _, v := range checked {
				if m, _ := v.(map[string]any); m["next"] != nil {
					marked++
				}
			}
			if marked != client.MergeThreshold || ms["merged_result"] != nil {
				t.Errorf("state on the disk before the removal: %d records marked, results %v", marked, ms["merged_result"])
			}
			if got := segmentCount(t, f.env, f.mbx, n); got != client.MergeThreshold+1 {
				t.Errorf("segments before the removal: %d", got)
			}
			return false
		})
		for i := 0; i < client.MergeThreshold; i++ {
			s := fmt.Sprintf("m%02d", i)
			f.send(t, s+"@x.example", header(s+"@x.example", s))
			f.flush(t)
			if _, err := c.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				list, _ := c.List(f.mbx, store.ID{})
				n = list[0].Epoch
			}
		}
		if !seen || segmentCount(t, f.env, f.mbx, n) != 1 {
			t.Fatalf("merge: point reached %v, %d segments", seen, segmentCount(t, f.env, f.mbx, n))
		}
	})
	t.Run("resign", func(t *testing.T) {
		f, n, bobSeg, c := segmentTakeoverFixture(t)
		data := mustRead(t, f.env.Store.IndexSegmentFile(f.mbx, n, bobSeg.Device, bobSeg.Seq))
		key := client.SegmentMemoKey(n, bobSeg.Device, data)
		seen := false
		client.SetCrashHook(t, func(p string) bool {
			if p != "segment-superseded" {
				return false
			}
			seen = true
			checked, _ := readState(t, f.u.Dir, f.mbx)["checked"].(map[string]any)
			if m, _ := checked[key].(map[string]any); m["next"] == nil {
				t.Errorf("record of the old content on the disk before the removal: %v", m)
			}
			if _, err := os.Stat(f.env.Store.IndexSegmentFile(f.mbx, n, bobSeg.Device, bobSeg.Seq)); err != nil {
				t.Errorf("old segment before the removal: %v", err)
			}
			return false
		})
		if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" || !seen {
			t.Fatalf("search: %q, point reached %v", got, seen)
		}
	})
	t.Run("index", func(t *testing.T) {
		// Since task 09g nothing is noted per mail: the segment is
		// written before the pending file is removed (K5 point 2).
		f := newFixture(t)
		f.send(t, "s@x.example", header("s@x.example", "m1"))
		f.flush(t)
		list, _ := f.u.Client.List(f.mbx, store.ID{})
		n := list[0].Epoch
		seen := false
		client.SetCrashHook(t, func(p string) bool {
			if p != "index-written" {
				return false
			}
			seen = true
			if got := segmentCount(t, f.env, f.mbx, n); got != 1 {
				t.Errorf("segments before the removal: %d", got)
			}
			if got := pendingCount(t, f.env, f.mbx, n); got != 1 {
				t.Errorf("pending files before the removal: %d", got)
			}
			return false
		})
		if got, err := f.u.Client.Index(f.mbx); err != nil || got != 1 || !seen {
			t.Fatalf("index: %d %v, point reached %v", got, err, seen)
		}
	})
}

// hideFixture: alice indexes a mail and sets a flag on it (her
// generation signs the segment and the metadata), carol is a member.
func hideFixture(t *testing.T) (*fixture, *testenv.User, *client.Mail, store.IndexSegmentRef) {
	t.Helper()
	f := newFixture(t)
	_, carol := threeMembers(t, f)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	if _, err := f.u.Client.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := f.u.Client.List(f.mbx, store.ID{})
	m, err := f.u.Client.SetFlags(f.mbx, list[0].ID, []string{"seen"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := search(t, f.u.Client, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatal(got)
	}
	refs, _ := f.env.Store.ListIndexSegments(f.mbx, m.Epoch)
	if len(refs) != 1 {
		t.Fatalf("segments %v", refs)
	}
	return f, carol, &client.Mail{ID: list[0].ID, Epoch: m.Epoch}, refs[0]
}

// TestDeviceLostHiddenWholeRun (finding low 2, the verifier's
// TestAttack09eStep4HiddenWholeRun, turned around): no key, no window.
// The attacker puts junk in place of alice's metadata, or removes them,
// for the whole of DeviceLost ("meta", "meta-removed"), or removes her
// segment right after step 2 checked it ("segment"), and puts the file
// back afterwards. Step 4 does not find what alice checked before the
// revocation: no silent success but ErrPartial, the mark and a warning.
// Put back, the next Sync issues it again and clears the mark, and carol
// finds and lists the mail. If the file stays gone ("-gone"), Sync finds
// nothing signed by the revoked generation and clears the mark all the
// same.
func TestDeviceLostHiddenWholeRun(t *testing.T) {
	for _, what := range []string{"meta", "meta-removed", "segment", "meta-gone", "segment-gone"} {
		t.Run(what, func(t *testing.T) {
			f, carol, m, seg := hideFixture(t)
			segment := strings.HasPrefix(what, "segment")
			var p string
			if segment {
				p = f.env.Store.IndexSegmentFile(f.mbx, m.Epoch, seg.Device, seg.Seq)
			} else {
				p = f.env.Store.MetaFile(f.mbx, f.inbox(t), m.ID)
			}
			orig := mustRead(t, p)
			switch what {
			case "meta", "meta-gone":
				if err := os.WriteFile(p, []byte("junk"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "meta-removed":
				os.Remove(p)
			default:
				client.SetCrashHook(t, func(point string) bool {
					if point == "devicelost-prepared" {
						os.Remove(p)
					}
					return false
				})
			}
			f.env.Clock.Advance(time.Minute)
			f.u.Client.Close()
			f.env.Warnings.Take()
			gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
			client.SetCrashHook(t, nil)
			if gen != 2 || !errors.Is(err, client.ErrPartial) {
				t.Fatalf("DeviceLost: %d %v", gen, err)
			}
			want := m.ID.String()
			if segment {
				want = "Indexsegment der Epoche"
			}
			warningWith(t, f.env.Warnings.Take(), want, "nicht wieder vorgefunden", "nicht neu ausgestellt")
			if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
				t.Fatalf("not marked: %d", r)
			}
			gone := strings.HasSuffix(what, "-gone")
			if gone {
				os.Remove(p)
			} else if err := os.WriteFile(p, orig, 0o644); err != nil {
				t.Fatal(err)
			}
			ac := f.env.Reopen(f.u)
			if err := ac.Sync(); err != nil {
				t.Fatalf("alice Sync: %v", err)
			}
			if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
				t.Fatalf("mark after Sync: %d", r)
			}
			if gone {
				return
			}
			cc := f.env.Reopen(carol)
			if err := cc.Sync(); err != nil {
				t.Fatal(err)
			}
			f.env.Warnings.Take()
			if got := search(t, cc, f.mbx, "from:s@x.example", ""); got != "m1" {
				t.Fatalf("carol: %q %v", got, f.env.Warnings.Take())
			}
		})
	}
}

// TestDeviceLostSegmentHiddenWholeRun (finding low 2, known limit): an
// own segment hidden for the whole of DeviceLost, step 2 included, is
// not found missing: its check record cannot tell it from a segment that
// another client merged and removed. DeviceLost succeeds. Once the
// segment is back, alice's next Search takes it over through her record
// from before the revocation and signs it again, and carol finds the
// mail.
func TestDeviceLostSegmentHiddenWholeRun(t *testing.T) {
	f, carol, m, seg := hideFixture(t)
	p := f.env.Store.IndexSegmentFile(f.mbx, m.Epoch, seg.Device, seg.Seq)
	orig := mustRead(t, p)
	os.Remove(p)
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	if _, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words); err != nil {
		t.Fatalf("DeviceLost: %v", err)
	}
	if err := os.WriteFile(p, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	ac := f.env.Reopen(f.u)
	if got := search(t, ac, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("alice: %q", got)
	}
	cc := f.env.Reopen(carol)
	if err := cc.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := search(t, cc, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("carol: %q %v", got, f.env.Warnings.Take())
	}
}

// TestReplayedMetaKeepsNoMark (finding low 3, the verifier's
// TestAttack09eReplayKeepsMark, turned around): no key. An older version
// of alice's metadata, signed by the generation revoked later, is put
// back before or after DeviceLost and left there. Every reader rejects it
// (Versions), as a segment that fails a check; step 4 and Sync warn but
// do not count it as not issued again, so it keeps no mark for good. Put
// back before, it hides the version alice checked last; since task 09g
// DeviceLost does not report that either (missingOwnFiles skips an older
// version), so no DeviceLost ends with ErrPartial for it.
func TestReplayedMetaKeepsNoMark(t *testing.T) {
	for _, when := range []string{"before", "after"} {
		t.Run(when, func(t *testing.T) {
			f := newFixture(t)
			threeMembers(t, f)
			f.send(t, "s@x.example", header("s@x.example", "m1"))
			f.flush(t)
			c := f.u.Client
			list, _ := c.List(f.mbx, store.ID{})
			id := list[0].ID
			if _, err := c.SetFlags(f.mbx, id, []string{"seen"}, nil); err != nil {
				t.Fatal(err)
			}
			p := f.env.Store.MetaFile(f.mbx, f.inbox(t), id)
			old := mustRead(t, p)
			if _, err := c.SetFlags(f.mbx, id, []string{"flagged"}, nil); err != nil {
				t.Fatal(err)
			}
			if when == "before" {
				if err := os.WriteFile(p, old, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			f.env.Clock.Advance(time.Minute)
			c.Close()
			f.env.Warnings.Take()
			_, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words)
			if when == "before" {
				// Her version 3, checked before, is not there; the older
				// version is only warned about (task 09g).
				if err != nil {
					t.Fatalf("DeviceLost: %v", err)
				}
				w := f.env.Warnings.Take()
				warningWith(t, w, id.String(), "wird nicht neu ausgestellt")
				if countWith(w, "nicht wieder vorgefunden") != 0 {
					t.Fatalf("older version counted as missing: %q", w)
				}
			} else if err != nil {
				t.Fatalf("DeviceLost: %v", err)
			} else if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
				t.Fatalf("marked: %d", r)
			}
			if when == "after" {
				if err := os.WriteFile(p, old, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 3; i++ {
				ac := f.env.Reopen(f.u)
				if err := ac.Sync(); err != nil {
					t.Fatalf("Sync %d: %v", i, err)
				}
				if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
					t.Fatalf("Sync %d: marked: %d", i, r)
				}
				ac.Close()
			}
		})
	}
}

// TestReplayedMetaClearsMark (finding low 3): a mailbox marked for
// another reason (a metadata file of alice removed during DeviceLost)
// with an older version of other metadata put back: Sync rejects the
// older version but does not count it as not issued again, so the mark
// is cleared.
func TestReplayedMetaClearsMark(t *testing.T) {
	f := newFixture(t)
	threeMembers(t, f)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.send(t, "t@x.example", header("t@x.example", "m2"))
	f.flush(t)
	c := f.u.Client
	list, _ := c.List(f.mbx, store.ID{})
	if len(list) != 2 {
		t.Fatalf("%d mails", len(list))
	}
	a, b := list[0].ID, list[1].ID
	for _, id := range []store.ID{a, b} {
		if _, err := c.SetFlags(f.mbx, id, []string{"seen"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	pa, pb := f.env.Store.MetaFile(f.mbx, f.inbox(t), a), f.env.Store.MetaFile(f.mbx, f.inbox(t), b)
	oldB := mustRead(t, pb)
	if _, err := c.SetFlags(f.mbx, b, []string{"flagged"}, nil); err != nil {
		t.Fatal(err)
	}
	keepA := mustRead(t, pa)
	os.Remove(pa)
	f.env.Clock.Advance(time.Minute)
	c.Close()
	if _, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words); !errors.Is(err, client.ErrPartial) {
		t.Fatalf("DeviceLost: %v", err)
	}
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("not marked: %d", r)
	}
	if err := os.WriteFile(pa, keepA, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pb, oldB, 0o644); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	ac := f.env.Reopen(f.u)
	if err := ac.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	warningWith(t, f.env.Warnings.Take(), b.String(), "wird nicht neu ausgestellt")
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
		t.Fatalf("mark after Sync: %d", r)
	}
	if s, g, _ := signerOf(t, f, a); s != f.u.ID || g != 2 {
		t.Fatalf("metadata of a not issued again: %s %d", s, g)
	}
}

// TestResignMetaStaleTolerated (finding low 4, mutation N2 of the 09e
// check): Search, List and Read take bob's metadata over (he rotated
// after alice checked them); the file changes between alice's check and
// her replacing it (errStale). They use the metadata as checked, and a
// later run signs them again.
func TestResignMetaStaleTolerated(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	f.send(t, "s@x.example", header("s@x.example", "m1"))
	f.flush(t)
	if _, err := f.u.Client.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := f.u.Client.List(f.mbx, store.ID{})
	id := list[0].ID
	if _, err := bob.Client.SetFlags(f.mbx, id, []string{"flagged"}, nil); err != nil {
		t.Fatal(err)
	}
	if !listed(t, f.u.Client, f.mbx, id) {
		t.Fatal("alice did not check bob's version")
	}
	f.env.Rotate(bob)
	c := f.env.Reopen(f.u)
	p := f.env.Store.MetaFile(f.mbx, f.inbox(t), id)
	orig := mustRead(t, p)
	client.SetResignMetaHook(t, func() {
		if err := os.WriteFile(p, []byte("changed meanwhile"), 0o644); err != nil {
			t.Error(err)
		}
	})
	restore := func() {
		if err := os.WriteFile(p, orig, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "m1" {
		t.Fatalf("search: %q %v", got, f.env.Warnings.Take())
	}
	restore()
	if !listed(t, c, f.mbx, id) {
		t.Fatalf("list: %v", f.env.Warnings.Take())
	}
	restore()
	if m, _, err := c.Read(f.mbx, id); err != nil || m.Meta.Version != 2 {
		t.Fatalf("read: %v", err)
	}
	restore()
	client.SetResignMetaHook(t, nil)
	if !listed(t, c, f.mbx, id) {
		t.Fatal("not listed")
	}
	if s, g, v := signerOf(t, f, id); s != f.u.ID || g != 1 || v != 3 {
		t.Fatalf("not signed again later: %s %d %d", s, g, v)
	}
}

// TestNoResignWithRevokedOwnGeneration (finding low 4, ownGenValid): a
// second process of alice, opened before her generation 1 was revoked,
// takes bob's segment over (bob rotated after alice checked it). Its own
// generation is revoked meanwhile, so it does not sign the segment again:
// the segment is used as it is, and no segment of alice's device is
// written.
func TestNoResignWithRevokedOwnGeneration(t *testing.T) {
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
	dev, _ := f.u.Client.Device()
	f.u.Client.Close()
	dir2 := filepath.Join(t.TempDir(), "alice-2")
	if err := os.MkdirAll(dir2, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(f.u.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || e.Name() == "lock" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir2, e.Name()), mustRead(t, filepath.Join(f.u.Dir, e.Name())), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c2, err := client.Open(f.env.ClientConfig(dir2), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c2.Close)
	// The second process opens the epochs while its generation is valid
	// (the keys stay in its memory).
	if l, err := c2.Search(f.mbx, "from:s@x.example", client.SearchOptions{}); err != nil || subjects(l) != "m1" {
		t.Fatalf("second process: %q %v", subjects(l), err)
	}
	f.env.Rotate(bob)
	f.env.Rotate(f.u)
	f.env.Warnings.Take()
	l, err := c2.Search(f.mbx, "from:s@x.example", client.SearchOptions{})
	if err != nil || subjects(l) != "m1" {
		t.Fatalf("search of the second process: %q %v %v", subjects(l), err, f.env.Warnings.Take())
	}
	if mine := ownSegments(t, f.env, f.mbx, n, dev); len(mine) != 0 {
		t.Fatalf("signed again with a revoked own generation: %v", mine)
	}
	if got := segmentCount(t, f.env, f.mbx, n); got != 1 {
		t.Fatalf("segments: %d", got)
	}
}

// TestReissuingResetAfterSync (finding low 4, mutation V8 of the 09d
// check): the continuation of DeviceLost in Sync sets reissuing only
// while it works; afterwards Search, List and Read are tolerant again.
func TestReissuingResetAfterSync(t *testing.T) {
	f, _, m, _ := hideFixture(t)
	p := f.env.Store.MetaFile(f.mbx, f.inbox(t), m.ID)
	os.Remove(p)
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	if _, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words); !errors.Is(err, client.ErrPartial) {
		t.Fatalf("DeviceLost: %v", err)
	}
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 2 {
		t.Fatalf("not marked: %d", r)
	}
	c := f.env.Reopen(f.u)
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if c.Reissuing() {
		t.Fatal("reissuing still set after Sync")
	}
	if r := reissueMark(t, f.u.Dir, f.mbx); r != 0 {
		t.Fatalf("mark after Sync: %d", r)
	}
}

// TestHonestMarkerMergeTermList (the verifier's honest order of 09e):
// marker, merge, term list, merge again, with a second member indexing in
// between. thread:<root> of the term list is found by alice and bob at
// every step after the term list was indexed by anyone.
func TestHonestMarkerMergeTermList(t *testing.T) {
	for _, who := range []string{"alice", "bob"} {
		t.Run("termlist-by-"+who, func(t *testing.T) {
			f := newFixture(t)
			bob, _ := threeMembers(t, f)
			c := f.u.Client
			f.send(t, "s@x.example", reply)
			if _, err := c.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < client.MergeThreshold; i++ {
				s := fmt.Sprintf("o%02d", i)
				f.send(t, s+"@x.example", header(s+"@x.example", s))
				if _, err := c.Index(f.mbx); err != nil {
					t.Fatal(err)
				}
			}
			f.flush(t)
			ix := c
			if who == "bob" {
				ix = bob.Client
			}
			if _, err := ix.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			check := func(step string) {
				t.Helper()
				for _, cl := range []*client.Client{c, bob.Client} {
					if got := search(t, cl, f.mbx, "thread:<root@sender.example>", ""); got != "re1" {
						t.Errorf("%s: thread:<root> -> %q", step, got)
					}
					if got := search(t, cl, f.mbx, "from:o07@x.example", ""); got != "o07" {
						t.Errorf("%s: from:o07 -> %q", step, got)
					}
				}
			}
			check("after term lists")
			for i := 0; i < client.MergeThreshold+2; i++ {
				s := fmt.Sprintf("p%02d", i)
				f.send(t, s+"@x.example", header(s+"@x.example", s))
				if i%2 == 0 {
					f.flush(t)
				}
				cl := c
				if i%3 == 0 {
					cl = bob.Client
				}
				if _, err := cl.Index(f.mbx); err != nil {
					t.Fatal(err)
				}
			}
			f.flush(t)
			if _, err := c.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			if _, err := bob.Client.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			check("after more merges")
			for i := 0; i < client.MergeThreshold+2; i += 5 {
				s := fmt.Sprintf("p%02d", i)
				if got := search(t, c, f.mbx, "from:"+s+"@x.example", ""); got != s {
					t.Errorf("%s -> %q", s, got)
				}
			}
		})
	}
}
