package client_test

import (
	"fmt"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of task 20b point 8: the saving rule of mergeSegments (D91 (5))
// for results of several segments with 32 and more segments counted. A
// merge takes place when counted - len(result) >= MergeThreshold-1; a
// rule "merge from 2*MergeThreshold counted segments on" (mutation V6 of
// the check of 09g) must break one of them.

// largeResult builds an epoch whose merge result holds k >= 18 segments
// of alice's device (one term with more than 17*store.MaxPostingIDs mail
// IDs), adds extra different segments of one mail ID each and runs Index
// once. It returns the fixture, the epoch, k, the result before the new
// segments and the mail IDs of the big term.
func largeResult(t *testing.T, extra int) (f *fixture, n uint32, k int, result []store.IndexSegmentRef, want map[store.ID]bool) {
	t.Helper()
	// 33 segments of 2200 IDs: 72,600 IDs of big:term, 18 segments.
	f, n, want = bigTermFixture(t, 2*client.MergeThreshold+1, 2200)
	c := f.u.Client
	dev, _ := c.Device()
	f.send(t, "b@x.example", header("b@x.example", "b"))
	f.flush(t)
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	result = ownSegments(t, f.env, f.mbx, n, dev)
	k = len(result)
	if k < client.MergeThreshold+2 || segmentCount(t, f.env, f.mbx, n) != k {
		t.Fatalf("result of %d segments, %d in all", k, segmentCount(t, f.env, f.mbx, n))
	}
	for i := 0; i < extra; i++ {
		id, _ := store.NewID(nil)
		if _, err := c.WriteSegment(f.mbx, n, fmt.Sprintf("from:n%02d@x.example", i), id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	return f, n, k, result, want
}

// stillThere reports whether every segment of result is still in the
// epoch.
func stillThere(t *testing.T, f *fixture, n uint32, result []store.IndexSegmentRef) bool {
	t.Helper()
	refs, err := f.env.Store.ListIndexSegments(f.mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	there := map[store.IndexSegmentRef]bool{}
	for _, r := range refs {
		there[r] = true
	}
	for _, r := range result {
		if !there[r] {
			return false
		}
	}
	return true
}

// TestMergeSavingBelowThreshold: a result of k >= 18 segments and
// MergeThreshold-2 new ones: 32 or more segments count, but a merge would
// save only MergeThreshold-2 of them, so none takes place, also in
// further runs.
func TestMergeSavingBelowThreshold(t *testing.T) {
	extra := client.MergeThreshold - 2
	f, n, k, result, want := largeResult(t, extra)
	if k+extra < 2*client.MergeThreshold {
		t.Fatalf("only %d segments count", k+extra)
	}
	for r := 0; r < 2; r++ {
		if r > 0 {
			if _, err := f.u.Client.Index(f.mbx); err != nil {
				t.Fatal(err)
			}
		}
		if got := segmentCount(t, f.env, f.mbx, n); got != k+extra || !stillThere(t, f, n, result) {
			t.Fatalf("run %d: merged although it saves %d segments: %d segments", r, extra, got)
		}
	}
	if got := countTerm(t, f.u.Client, f.mbx, n, "big:term", want); got != len(want) {
		t.Fatalf("%d of %d", got, len(want))
	}
}

// TestMergeSavingAtThreshold: a result of k >= 18 segments and
// MergeThreshold-1 new ones: the merge saves MergeThreshold-1 segments
// and takes place; the new result has k segments and holds every mail
// ID.
func TestMergeSavingAtThreshold(t *testing.T) {
	extra := client.MergeThreshold - 1
	f, n, k, result, want := largeResult(t, extra)
	dev, _ := f.u.Client.Device()
	now := ownSegments(t, f.env, f.mbx, n, dev)
	if stillThere(t, f, n, result) || len(now) != k || segmentCount(t, f.env, f.mbx, n) != k {
		t.Fatalf("not merged at a saving of %d: %d own segments, %d in all, result of %d", extra, len(now), segmentCount(t, f.env, f.mbx, n), k)
	}
	if got := countTerm(t, f.u.Client, f.mbx, n, "big:term", want); got != len(want) {
		t.Fatalf("%d of %d after the merge", got, len(want))
	}
}
