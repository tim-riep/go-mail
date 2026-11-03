package client_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 09g (Q22, variant A): no mark "indexed" and no limit
// "merged" any more; restored data stay searchable; a content merged
// into a result of several segments is spent only while every part is
// there; a merge must save MergeThreshold-1 segments; what an attacker
// without a key can still make the client write is bounded per round
// and measured here. The verifier's tests of task 09f keep their names.

// roundBound is the fixed amount state.json may grow by in one round of
// an attack that makes the client write one new segment (the check
// record of the new content, about 300 bytes, and numbers that change
// with the log).
const roundBound = 512

// stateLimit is the size from which client.Open refuses state.json
// (store.ReadFileLimited in loadState).
const stateLimit = 64 << 20

// syncsPerDay is the number of Syncs in a day at one Sync every five
// minutes, the rate of the growth measurements (task 09g point 4).
const syncsPerDay = 24 * 60 / 5

// daysTo64MiB returns the days until state.json reaches stateLimit at
// grow bytes per Sync and one Sync every five minutes.
func daysTo64MiB(grow float64) float64 {
	if grow <= 0 {
		return 0
	}
	return stateLimit / grow / syncsPerDay
}

// dirFiles reads every regular file below dir but the lock (relative
// path to bytes).
func dirFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() || d.Name() == "lock" {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr == nil {
			rel, _ := filepath.Rel(dir, p)
			out[rel] = data
		}
		return nil
	})
	return out
}

// putDir makes dir hold exactly files (relative path to bytes).
func putDir(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	for rel := range dirFiles(t, dir) {
		if _, ok := files[rel]; !ok {
			os.Remove(filepath.Join(dir, rel))
		}
	}
	for rel, data := range files {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestHonest09fBackupRestore (the verifier's test of task 09f, finding
// M2; task 09g point 1): five mails are delivered, then backups are
// taken, then alice indexes.
//
//   - "client": alice's client directory is restored from the backup
//     (the disk of the device replaced); the data directory is current.
//   - "data": pending/ and index/ of the mailbox are restored from the
//     backup (the disk of the server replaced); alice's client directory
//     is current. Until task 09g alice took the pending entries as
//     indexed, wrote no segment and removed pending/: the mails stayed
//     listable, but no search of any member found them, for good.
//
// In both, alice's next Index writes what is missing, and alice and
// carol find the mails.
func TestHonest09fBackupRestore(t *testing.T) {
	for _, variant := range []string{"client", "data"} {
		t.Run(variant, func(t *testing.T) {
			f := newFixture(t)
			_, carol := threeMembers(t, f)
			c := f.u.Client
			for i := 0; i < 5; i++ {
				s := fmt.Sprintf("r%d", i)
				f.send(t, s+"@x.example", header(s+"@x.example", s))
			}
			f.flush(t)
			list, err := c.List(f.mbx, store.ID{})
			if err != nil || len(list) != 5 {
				t.Fatalf("list %d %v", len(list), err)
			}
			mdir := f.env.Store.MailboxDir(f.mbx)
			inData := func(rel string) bool {
				return strings.HasPrefix(rel, "pending") || strings.HasPrefix(rel, "index")
			}
			cBackup := dirFiles(t, f.u.Dir)
			pBackup := map[string][]byte{}
			for rel, d := range dirFiles(t, mdir) {
				if inData(rel) {
					pBackup[rel] = d
				}
			}
			if _, err := c.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			if got := search(t, c, f.mbx, "from:r3@x.example", ""); got != "r3" {
				t.Fatalf("before the restore: %q", got)
			}
			switch variant {
			case "client":
				c.Close()
				putDir(t, f.u.Dir, cBackup)
				c = f.env.Reopen(f.u)
			case "data":
				for rel := range dirFiles(t, mdir) {
					if inData(rel) && pBackup[rel] == nil {
						os.Remove(filepath.Join(mdir, rel))
					}
				}
				for rel, d := range pBackup {
					p := filepath.Join(mdir, rel)
					os.MkdirAll(filepath.Dir(p), 0o700)
					if err := os.WriteFile(p, d, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			f.env.Warnings.Take()
			got, err := c.Index(f.mbx)
			if err != nil || got != 5 && variant == "data" {
				t.Fatalf("Index after the restore: %d %v", got, err)
			}
			if n := segmentCount(t, f.env, f.mbx, list[0].Epoch); n == 0 {
				t.Fatal("no segment after the restore")
			}
			cc := f.env.Reopen(carol)
			if _, err := cc.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 5; i++ {
				s := fmt.Sprintf("r%d", i)
				a := search(t, c, f.mbx, "from:"+s+"@x.example", "")
				b := search(t, cc, f.mbx, "from:"+s+"@x.example", "")
				if a != s || b != s {
					t.Fatalf("%s restored: %s lost (alice %q, carol %q)", variant, s, a, b)
				}
			}
		})
	}
}

// bigTermFixture lets alice index one mail and write segs segments of
// per mail IDs each of the term big:term (per at most
// store.MaxPostingIDs). It returns the fixture, the epoch and the mail
// IDs of the term.
func bigTermFixture(t *testing.T, segs, per int) (*fixture, uint32, map[store.ID]bool) {
	t.Helper()
	f := newFixture(t)
	c := f.u.Client
	f.send(t, "a@x.example", header("a@x.example", "a"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := c.List(f.mbx, store.ID{})
	n := list[0].Epoch
	want := map[store.ID]bool{}
	for i := 0; i < segs; i++ {
		ids := make([]store.ID, per)
		for j := range ids {
			ids[j], _ = store.NewID(nil)
			want[ids[j]] = true
		}
		if _, err := c.WriteSegment(f.mbx, n, "big:term", ids...); err != nil {
			t.Fatal(err)
		}
	}
	return f, n, want
}

// countTerm returns how many of want the segments of epoch n hold under
// term.
func countTerm(t *testing.T, c *client.Client, mbx store.ID, n uint32, term string, want map[store.ID]bool) int {
	t.Helper()
	mk, err := c.TermMark(mbx, n, term)
	if err != nil {
		t.Fatal(err)
	}
	segs, err := c.Segments(mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	got := map[store.ID]bool{}
	for _, s := range segs {
		for _, ps := range s.Postings {
			if ps.Mark != mk {
				continue
			}
			for _, id := range ps.MailIDs {
				if want[id] {
					got[id] = true
				}
			}
		}
	}
	return len(got)
}

// keepBeforeMerge sets the merge hook so that it keeps the files of
// index/<n>/ right before the next merge, once.
func keepBeforeMerge(t *testing.T, f *fixture, n uint32) map[string][]byte {
	t.Helper()
	saved := map[string][]byte{}
	client.SetMergeHook(t, func() {
		if len(saved) > 0 {
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
	return saved
}

// putFiles writes files (path to bytes).
func putFiles(t *testing.T, files map[string][]byte) {
	t.Helper()
	for p, d := range files {
		if err := os.WriteFile(p, d, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAttack09fSplitResultSpent (the verifier's test of task 09f,
// finding N1; task 09g point 3): a merge whose result is two segments
// (one mark with more than store.MaxPostingIDs mail IDs). Until task 09g
// the records of the merged contents named only the first segment as
// their successor. One segment of the result is removed and the
// originals are put back (index/<n>/ rolled back to before the merge, or
// the segment removed): the originals are spent only while every segment
// of the result is there. Removing either leaves them in use, and no
// posting is lost, also after alice's next Index.
func TestAttack09fSplitResultSpent(t *testing.T) {
	for _, variant := range []string{"first", "second"} {
		t.Run(variant, func(t *testing.T) {
			f, n, want := bigTermFixture(t, client.MergeThreshold-1, 300)
			c := f.u.Client
			saved := keepBeforeMerge(t, f, n)
			f.send(t, "b@x.example", header("b@x.example", "b"))
			f.flush(t)
			if _, err := c.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			client.SetMergeHook(t, nil)
			res, _ := f.env.Store.ListIndexSegments(f.mbx, n)
			if len(res) != 2 || len(saved) != client.MergeThreshold+1 {
				t.Fatalf("precondition: merge result %v, %d originals kept", res, len(saved))
			}
			if got := countTerm(t, c, f.mbx, n, "big:term", want); got != len(want) {
				t.Fatalf("precondition: %d of %d after the merge", got, len(want))
			}
			// written[0] has the lower sequence number (writeSegments).
			sort.Slice(res, func(i, j int) bool { return res[i].Seq < res[j].Seq })
			gone := res[1]
			if variant == "first" {
				gone = res[0]
			}
			f.env.Store.RemoveIndexSegment(f.mbx, n, gone.Device, gone.Seq)
			putFiles(t, saved)
			f.env.Warnings.Take()
			if got := countTerm(t, c, f.mbx, n, "big:term", want); got != len(want) {
				t.Fatalf("%s removed: %d of %d with the originals back", variant, got, len(want))
			}
			warningWith(t, f.env.Warnings.Take(), "der Nachfolger fehlt")
			if _, err := c.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			if got := countTerm(t, c, f.mbx, n, "big:term", want); got != len(want) {
				t.Fatalf("%s removed: %d of %d after alice's Index", variant, got, len(want))
			}
		})
	}
}

// TestSplitResultWholeSpent (task 09g point 3, control): with both
// segments of a result of two there, the originals put back are spent
// (warned and removed) and every posting is found once.
func TestSplitResultWholeSpent(t *testing.T) {
	f, n, want := bigTermFixture(t, client.MergeThreshold-1, 300)
	c := f.u.Client
	saved := keepBeforeMerge(t, f, n)
	f.send(t, "b@x.example", header("b@x.example", "b"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	client.SetMergeHook(t, nil)
	if got := segmentCount(t, f.env, f.mbx, n); got != 2 {
		t.Fatalf("merge result: %d segments", got)
	}
	base := stateSize(t, f.u.Dir)
	putFiles(t, saved)
	f.env.Warnings.Take()
	if got := countTerm(t, c, f.mbx, n, "big:term", want); got != len(want) {
		t.Fatalf("%d of %d", got, len(want))
	}
	if w := f.env.Warnings.Take(); countWith(w, "bereits neu ausgestellt oder zusammengefasst") != client.MergeThreshold+1 || countWith(w, "der Nachfolger fehlt") != 0 {
		t.Fatalf("originals not spent with the whole result there: %q", w)
	}
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if got := segmentCount(t, f.env, f.mbx, n); got != 2 {
		t.Fatalf("segments after Index: %d", got)
	}
	if grown := stateSize(t, f.u.Dir) - base; grown > stateBound {
		t.Fatalf("state.json +%d bytes", grown)
	}
}

// TestSpentThroughMergedParts (task 09g point 3): the parts of a result
// of two segments (G) are merged later with new segments into a result
// of two segments again (H). The originals of G, put back, are spent
// while both parts of H are there: every part of G leads to H. With one
// part of H removed, they are in use, and nothing is lost.
func TestSpentThroughMergedParts(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint("partial=", partial), func(t *testing.T) {
			f, n, want := bigTermFixture(t, client.MergeThreshold-1, 300)
			c := f.u.Client
			dev, _ := c.Device()
			saved := keepBeforeMerge(t, f, n)
			f.send(t, "b@x.example", header("b@x.example", "b"))
			f.flush(t)
			if _, err := c.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			client.SetMergeHook(t, nil)
			g := ownSegments(t, f.env, f.mbx, n, dev)
			if len(g) != 2 || segmentCount(t, f.env, f.mbx, n) != 2 {
				t.Fatalf("first result: %v", g)
			}
			// A merge needs MergeThreshold-1 segments more than it
			// writes: 15 new ones next to the two parts.
			for i := 0; i < client.MergeThreshold-1; i++ {
				id, _ := store.NewID(nil)
				if _, err := c.WriteSegment(f.mbx, n, fmt.Sprintf("from:n%02d@x.example", i), id); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := c.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			h := ownSegments(t, f.env, f.mbx, n, dev)
			if len(h) != 2 || h[0] == g[0] || h[1] == g[1] || segmentCount(t, f.env, f.mbx, n) != 2 {
				t.Fatalf("second result: %v (first %v)", h, g)
			}
			if partial {
				f.env.Store.RemoveIndexSegment(f.mbx, n, h[1].Device, h[1].Seq)
			}
			putFiles(t, saved)
			f.env.Warnings.Take()
			if got := countTerm(t, c, f.mbx, n, "big:term", want); got != len(want) {
				t.Fatalf("%d of %d with the originals back", got, len(want))
			}
			w := f.env.Warnings.Take()
			spent := countWith(w, "bereits neu ausgestellt oder zusammengefasst")
			if !partial && spent != client.MergeThreshold+1 || partial && spent != 0 {
				t.Fatalf("originals spent: %d (%q)", spent, w)
			}
			if _, err := c.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
			if got := countTerm(t, c, f.mbx, n, "big:term", want); got != len(want) {
				t.Fatalf("%d of %d after alice's Index", got, len(want))
			}
		})
	}
}

// TestLargeResultNotMergedAgain (task 09g, rule of the savings): a
// merge result of more than MergeThreshold segments (one mark with more
// than MergeThreshold*store.MaxPostingIDs mail IDs) counts for a merge by
// itself. Without the rule that a merge must save MergeThreshold-1
// segments, every Index would merge it again, each time new segments and
// new check records, also without any attack. With it, nothing is merged
// again until MergeThreshold-1 new segments are there, and state.json
// does not grow meanwhile.
func TestLargeResultNotMergedAgain(t *testing.T) {
	f, n, want := bigTermFixture(t, 2*client.MergeThreshold-1, 2200)
	c := f.u.Client
	dev, _ := c.Device()
	f.send(t, "b@x.example", header("b@x.example", "b"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	result := ownSegments(t, f.env, f.mbx, n, dev)
	k := len(result)
	if k <= client.MergeThreshold || segmentCount(t, f.env, f.mbx, n) != k {
		t.Fatalf("result of %d segments, %d in all", k, segmentCount(t, f.env, f.mbx, n))
	}
	if got := countTerm(t, c, f.mbx, n, "big:term", want); got != len(want) {
		t.Fatalf("%d of %d", got, len(want))
	}
	base := stateSize(t, f.u.Dir)
	for r := 0; r < 3; r++ {
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		if now := ownSegments(t, f.env, f.mbx, n, dev); len(now) != k || now[0] != result[0] {
			t.Fatalf("round %d: merged again: %v", r, now)
		}
	}
	if grown := stateSize(t, f.u.Dir) - base; grown != 0 {
		t.Fatalf("state.json +%d bytes", grown)
	}
	// MergeThreshold-2 new segments: no merge yet; one more: merge.
	for i := 0; i < client.MergeThreshold-1; i++ {
		id, _ := store.NewID(nil)
		if _, err := c.WriteSegment(f.mbx, n, fmt.Sprintf("from:n%02d@x.example", i), id); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		merged := ownSegments(t, f.env, f.mbx, n, dev)[0] != result[0]
		if merged != (i == client.MergeThreshold-2) {
			t.Fatalf("after %d new segments: merged %v, %d segments", i+1, merged, segmentCount(t, f.env, f.mbx, n))
		}
	}
	if got := countTerm(t, c, f.mbx, n, "big:term", want); got != len(want) {
		t.Fatalf("%d of %d after the merge", got, len(want))
	}
}

// TestHeldCopiesRemoved (task 09g point 6, test gap of 09f "copies of
// contents used again"): index/<n>/ is rolled back to before alice's
// merge, and a byte-equal copy of one original lies under another
// sequence number. The originals are used (their successor is gone) and
// stay; the copy is not used a second time and is removed under the
// lock.
func TestHeldCopiesRemoved(t *testing.T) {
	f, _, n, saved, _ := mergeRollback(t)
	rollBack(t, f, n, saved)
	var first string
	for p := range saved {
		if first == "" || p < first {
			first = p
		}
	}
	base := filepath.Base(first)
	dev, err := store.ParseID(base[:strings.LastIndex(base, "-")])
	if err != nil {
		t.Fatal(err)
	}
	if err := f.env.Store.WriteIndexSegment(f.mbx, n, dev, 900, saved[first]); err != nil {
		t.Fatal(err)
	}
	c := f.u.Client
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Store.ReadIndexSegment(f.mbx, n, dev, 900); err == nil {
		t.Fatal("the copy of a content used again stays")
	}
	if got := segmentCount(t, f.env, f.mbx, n); got != client.MergeThreshold {
		t.Fatalf("%d segments", got)
	}
	for i := 0; i < client.MergeThreshold; i++ {
		s := fmt.Sprintf("m%02d", i)
		if got := search(t, c, f.mbx, "from:"+s+"@x.example", ""); got != s {
			t.Fatalf("%s: %q", s, got)
		}
	}
}

// TestAttack09fForcedMergesDevices (the verifier's test of task 09f,
// finding M1; task 09g point 4, measurement): an attacker with write
// access to the data directory and no key keeps every segment that ever
// appears and, before device d of D runs Index, leaves in index/<n>/
// every content that d has not merged, but one segment of d's latest
// result. Each device is a client directory of alice of its own. A
// device merges the latest results of the other devices once they save
// MergeThreshold-1 segments: (D-1)*k - k >= MergeThreshold-1 for results
// of k segments. Then every round makes every device merge again, and
// state.json of every device grows by the records of the (D-1)*k new
// contents it reads and the k it writes, about D*k*300 bytes per round;
// below that the merges stop after the first round.
//
// The test measures the growth per round of device 0 and the days until
// 64 MiB at one Sync every five minutes, and checks it: at most
// D*k*roundBound per round, the merges stop when the rule above says so,
// and the growth per round and device leaves at least 30 days.
func TestAttack09fForcedMergesDevices(t *testing.T) {
	type tc struct {
		devices, per int // devices; originals: MergeThreshold-1 segments of per mail IDs of one term and two more
	}
	cases := []tc{{1, 1}, {9, 1}, {17, 1}, {9, 300}, {17, 300}}
	if testing.Short() {
		cases = []tc{{1, 1}, {9, 1}, {17, 1}}
	}
	for _, x := range cases {
		t.Run(fmt.Sprintf("devices%d_per%d", x.devices, x.per), func(t *testing.T) {
			f, n, _ := bigTermFixture(t, client.MergeThreshold-1, x.per)
			files := func(dev *store.ID) map[string][]byte {
				refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
				out := map[string][]byte{}
				for _, r := range refs {
					if dev != nil && r.Device != *dev {
						continue
					}
					p := f.env.Store.IndexSegmentFile(f.mbx, n, r.Device, r.Seq)
					if d, err := os.ReadFile(p); err == nil {
						out[p] = d
					}
				}
				return out
			}
			clear := func() {
				refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
				for _, r := range refs {
					f.env.Store.RemoveIndexSegment(f.mbx, n, r.Device, r.Seq)
				}
			}
			// One more segment makes MergeThreshold+1 originals: a merge
			// into two segments (per 300) saves MergeThreshold-1.
			id, _ := store.NewID(nil)
			if _, err := f.u.Client.WriteSegment(f.mbx, n, "from:b@x.example", id); err != nil {
				t.Fatal(err)
			}
			originals := files(nil)
			if len(originals) != client.MergeThreshold+1 {
				t.Fatalf("precondition: %d originals", len(originals))
			}
			type device struct {
				dir string
				c   *client.Client
				id  store.ID
			}
			devs := make([]*device, x.devices)
			for i := range devs {
				dir := filepath.Join(t.TempDir(), "dev")
				if err := os.CopyFS(dir, os.DirFS(f.u.Dir)); err != nil {
					t.Fatal(err)
				}
				var st map[string]any
				p := filepath.Join(dir, "state.json")
				if err := json.Unmarshal(mustRead(t, p), &st); err != nil {
					t.Fatal(err)
				}
				delete(st, "device")
				d, _ := json.Marshal(st)
				if err := os.WriteFile(p, d, 0o600); err != nil {
					t.Fatal(err)
				}
				c, err := client.Open(f.env.ClientConfig(dir), testenv.Passphrase)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(c.Close)
				id, err := c.Device()
				if err != nil {
					t.Fatal(err)
				}
				devs[i] = &device{dir, c, id}
			}
			pool := map[string][]byte{}
			for p, d := range originals {
				pool[p] = d
			}
			mergedBy := make([]map[string]bool, x.devices)
			latest := make([]map[string][]byte, x.devices)
			for d := range mergedBy {
				mergedBy[d] = map[string]bool{}
			}
			var sizes []int64
			var merges []int
			k := 0
			const rounds = 5
			for r := 0; r < rounds; r++ {
				m := 0
				for d, dv := range devs {
					clear()
					shown := map[string][]byte{}
					var skip []string
					for p := range latest[d] {
						skip = append(skip, p)
					}
					sort.Strings(skip)
					for p, data := range pool {
						if mergedBy[d][p] || len(skip) > 0 && p == skip[0] {
							continue
						}
						shown[p] = data
					}
					putFiles(t, shown)
					if _, err := dv.c.Index(f.mbx); err != nil {
						t.Fatalf("round %d device %d: %v", r, d, err)
					}
					own := files(&dv.id)
					fresh := false
					for p := range own {
						if pool[p] == nil {
							fresh = true
						}
					}
					if fresh {
						for p := range shown {
							mergedBy[d][p] = true
						}
						for p, data := range own {
							pool[p] = data
						}
						latest[d] = own
						k = max(k, len(own))
						m++
					}
				}
				f.env.Warnings.Take()
				merges = append(merges, m)
				sizes = append(sizes, stateSize(t, devs[0].dir))
			}
			per := float64(sizes[rounds-1]-sizes[rounds-3]) / 2
			days := daysTo64MiB(per)
			t.Logf("MEASURE forced merges: %d devices, results of %d segments: merges per round %v, state.json of device 0 per round %v, +%.0f B per round (%.0f B per round and device), %s",
				x.devices, k, merges, sizes, per, per/float64(x.devices), roundsTo64MiB(per))
			// With results of one segment a device needs MergeThreshold
			// other results: fewer devices merge only in the first round.
			if x.per == 1 && x.devices <= client.MergeThreshold && merges[rounds-1] != 0 {
				t.Fatalf("merges per round %v (%d devices)", merges, x.devices)
			}
			if per > float64(x.devices*k*roundBound) {
				t.Fatalf("+%.0f B per round, more than %d devices * %d segments * %d", per, x.devices, k, roundBound)
			}
			if per > 0 && days*float64(x.devices) < 30 {
				t.Fatalf("%.1f days to 64 MiB per device", days*float64(x.devices))
			}
		})
	}
}

// roundsTo64MiB describes the rounds and days until state.json reaches
// 64 MiB at grow bytes per round (one round per Sync, one Sync every five
// minutes).
func roundsTo64MiB(grow float64) string {
	if grow <= 0 {
		return "no growth"
	}
	return fmt.Sprintf("%.0f rounds to 64 MiB, %.0f days", stateLimit/grow, daysTo64MiB(grow))
}

// TestAttack09fRevokedReinject (the verifier's test of task 09f, roles
// (a) and (b); regression): bob's segment X, signed by his generation 1
// and checked by alice before the revocation, is taken over and signed
// again by alice (X'), which marks X. The attacker removes X' and puts X
// back, five times: X is held, its successor is not there, so it is
// checked like any file; the record no longer proves the check before
// the revocation, so X is rejected: no new signature by alice, no growth
// of state.json, carol rejects it as well.
func TestAttack09fRevokedReinject(t *testing.T) {
	f := newFixture(t)
	bob, carol := threeMembers(t, f)
	f.send(t, "b1@x.example", header("b1@x.example", "b1"))
	f.flush(t)
	if _, err := bob.Client.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	list, _ := f.u.Client.List(f.mbx, store.ID{})
	n := list[0].Epoch
	bdev, _ := bob.Client.Device()
	xs := ownSegments(t, f.env, f.mbx, n, bdev)
	if len(xs) != 1 {
		t.Fatalf("bob's segments %v", xs)
	}
	xp := f.env.Store.IndexSegmentFile(f.mbx, n, xs[0].Device, xs[0].Seq)
	x := mustRead(t, xp)
	if got := search(t, f.u.Client, f.mbx, "from:b1@x.example", ""); got != "b1" {
		t.Fatal(got)
	}
	f.env.Rotate(bob)
	c := f.env.Reopen(f.u)
	if got := search(t, c, f.mbx, "from:b1@x.example", ""); got != "b1" {
		t.Fatalf("takeover: %q", got)
	}
	dev, _ := c.Device()
	if mine := ownSegments(t, f.env, f.mbx, n, dev); len(mine) != 1 || len(ownSegments(t, f.env, f.mbx, n, bdev)) != 0 {
		t.Fatalf("no resign: alice %v", mine)
	}
	var sizes []int64
	for r := 0; r < 5; r++ {
		for _, m := range ownSegments(t, f.env, f.mbx, n, dev) {
			f.env.Store.RemoveIndexSegment(f.mbx, n, m.Device, m.Seq)
		}
		if err := os.WriteFile(xp, x, 0o644); err != nil {
			t.Fatal(err)
		}
		f.env.Warnings.Take()
		got := search(t, c, f.mbx, "from:b1@x.example", "")
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		if got != "" || len(ownSegments(t, f.env, f.mbx, n, dev)) != 0 {
			t.Fatalf("round %d: X used or signed again: %q, %v", r, got, ownSegments(t, f.env, f.mbx, n, dev))
		}
		sizes = append(sizes, stateSize(t, f.u.Dir))
	}
	if got := search(t, f.env.Reopen(carol), f.mbx, "from:b1@x.example", ""); got != "" {
		t.Fatalf("carol used X: %q", got)
	}
	if sizes[len(sizes)-1] != sizes[0] {
		t.Fatalf("growth: %v", sizes)
	}
}

// TestGrowthMeasured09g (task 09g point 4, measurement): what an
// attacker without a key makes one device of alice write per round (one
// Sync each), with the rounds and days until state.json reaches 64 MiB at
// one Sync every five minutes. Each is checked against a fixed bound per
// round.
//
//   - pending-kept: alice's pending file put back, its segment there: +0.
//   - pending-removed: the segment removed and the pending file put
//     back: the mail is indexed again, one new segment and its record.
//   - copies: 100 byte-equal copies of her segment under new sequence
//     numbers: +0 (one record per content, task 09c).
//   - rollback: index/<n>/ rolled back to before her merge (originals
//     back, result removed): the originals are used without counting, +0.
func TestGrowthMeasured09g(t *testing.T) {
	for _, what := range []string{"pending-kept", "pending-removed", "copies", "rollback"} {
		t.Run(what, func(t *testing.T) {
			var f *fixture
			var n uint32
			var round func()
			switch what {
			case "rollback":
				var saved map[string][]byte
				f, _, n, saved, _ = mergeRollback(t)
				round = func() { rollBack(t, f, n, saved) }
			default:
				f = newFixture(t)
				f.send(t, "s@x.example", header("s@x.example", "m1"))
				f.flush(t)
				n = 1
				pending := pendingFiles(t, f.env, f.mbx, n)
				if err := f.u.Client.Sync(); err != nil {
					t.Fatal(err)
				}
				dev, _ := f.u.Client.Device()
				mine := ownSegments(t, f.env, f.mbx, n, dev)
				if len(mine) != 1 {
					t.Fatalf("segments %v", mine)
				}
				data := mustRead(t, f.env.Store.IndexSegmentFile(f.mbx, n, dev, mine[0].Seq))
				seq := uint64(1000)
				round = func() {
					switch what {
					case "copies":
						for i := 0; i < 100; i++ {
							seq++
							if err := f.env.Store.WriteIndexSegment(f.mbx, n, dev, seq, data); err != nil {
								t.Fatal(err)
							}
						}
						return
					case "pending-removed":
						for _, r := range ownSegments(t, f.env, f.mbx, n, dev) {
							f.env.Store.RemoveIndexSegment(f.mbx, n, r.Device, r.Seq)
						}
					}
					for id, d := range pending {
						if err := store.WriteFileAtomic(f.env.Store.PendingFile(f.mbx, n, id), d); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			c := f.u.Client
			sync := func() {
				if err := c.Sync(); err != nil {
					t.Fatal(err)
				}
				if _, err := c.Search(f.mbx, "fromdomain:x.example", client.SearchOptions{}); err != nil {
					t.Fatal(err)
				}
				f.env.Warnings.Take()
			}
			sync()
			const rounds = 20
			// The first round may make records once (the folder list of
			// a new head, memos of mails searched first).
			round()
			sync()
			base := stateSize(t, f.u.Dir)
			for r := 0; r < rounds; r++ {
				round()
				sync()
			}
			per := float64(stateSize(t, f.u.Dir)-base) / rounds
			t.Logf("MEASURE %s: +%.0f B per round, %s", what, per, roundsTo64MiB(per))
			bound := 0.0
			if what == "pending-removed" {
				bound = roundBound
			}
			if per > bound || what == "pending-removed" && per == 0 {
				t.Fatalf("+%.0f B per round, bound %.0f", per, bound)
			}
		})
	}
}

// TestSplitResultPartRecordMissing (task 09g point 3, guard): the name of
// a result of several segments is checked against the records of its
// parts (resultID over their hashes). If the record of a part is missing
// (a state file edited or put together from older copies), the result is
// unknown and never spent: with the other part there and the originals
// put back, no posting is lost.
func TestSplitResultPartRecordMissing(t *testing.T) {
	f, n, want := bigTermFixture(t, client.MergeThreshold-1, 300)
	c := f.u.Client
	dev, _ := c.Device()
	saved := keepBeforeMerge(t, f, n)
	f.send(t, "b@x.example", header("b@x.example", "b"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	client.SetMergeHook(t, nil)
	res := ownSegments(t, f.env, f.mbx, n, dev)
	if len(res) != 2 || segmentCount(t, f.env, f.mbx, n) != 2 {
		t.Fatalf("merge result: %v", res)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Seq < res[j].Seq })
	gone := mustRead(t, f.env.Store.IndexSegmentFile(f.mbx, n, dev, res[1].Seq))
	key := client.SegmentMemoKey(n, dev, gone)
	f.env.Store.RemoveIndexSegment(f.mbx, n, dev, res[1].Seq)
	c.Close()
	editState(t, f.u.Dir, f.mbx, func(ms map[string]any) {
		checked := ms["checked"].(map[string]any)
		if m, _ := checked[key].(map[string]any); m["part"] == nil {
			t.Fatalf("record of the part: %v", m)
		}
		delete(checked, key)
	})
	c = f.env.Reopen(f.u)
	putFiles(t, saved)
	if got := countTerm(t, c, f.mbx, n, "big:term", want); got != len(want) {
		t.Fatalf("%d of %d with the originals back", got, len(want))
	}
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	if got := countTerm(t, c, f.mbx, n, "big:term", want); got != len(want) {
		t.Fatalf("%d of %d after alice's Index", got, len(want))
	}
}
