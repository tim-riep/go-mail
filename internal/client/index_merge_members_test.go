package client_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
)

// Proof tests of the specification check of task 09f, taken over by task
// 20b point 8 and adapted to task 09g (D91). The third test of that check
// (a merge result of several segments, index/<n>/ rolled back to the
// originals with only the first result segment kept) is covered by
// TestAttack09fSplitResultSpent and not repeated here.

// TestIndexTwoMembersHonest: honest operation with two members that
// index in turns (three rounds each) while new mails arrive. After every
// Index, index/<n>/ holds at most MergeThreshold segments, no merge is
// held back, merges take place, and both members find every mail.
func TestIndexTwoMembersHonest(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	alice := f.u.Client
	const rounds = 70
	most, merges, prev := 0, 0, -1
	var n uint32
	for r := 0; r < rounds; r++ {
		s := fmt.Sprintf("h%03d", r)
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		c := alice
		if (r/3)%2 == 1 {
			c = bob.Client
		}
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatalf("round %d: %v", r, err)
		}
		if n == 0 {
			list, _ := alice.List(f.mbx, store.ID{})
			n = list[0].Epoch
		}
		cnt := segmentCount(t, f.env, f.mbx, n)
		if prev >= 0 && cnt < prev {
			merges++
		}
		prev = cnt
		most = max(most, cnt)
	}
	if k := countWith(f.env.Warnings.Take(), "nicht zusammengefasst"); k != 0 {
		t.Fatalf("%d merges held back", k)
	}
	if most > client.MergeThreshold {
		t.Fatalf("%d segments after an Index", most)
	}
	if merges < 3 {
		t.Fatalf("only %d merges", merges)
	}
	for r := 0; r < rounds; r++ {
		s := fmt.Sprintf("h%03d", r)
		if got := search(t, alice, f.mbx, "from:"+s+"@x.example", ""); got != s {
			t.Fatalf("alice %s: %q", s, got)
		}
		if got := search(t, bob.Client, f.mbx, "from:"+s+"@x.example", ""); got != s {
			t.Fatalf("bob %s: %q", s, got)
		}
	}
}

// TestMergedRevokedOriginalsNotTakenOver (D91 (2), D84 (2)): alice
// merges bob's segments, signed by his generation 1 and checked by her
// while it was valid. Bob's generation 1 is revoked, alice's result is
// removed and bob's originals are put back. Their records name a
// successor that is gone, so they are checked like any file, and the
// record no longer proves a check before the revocation: they are not
// accepted, and alice signs none of them again.
func TestMergedRevokedOriginalsNotTakenOver(t *testing.T) {
	f := newFixture(t)
	bob, _ := threeMembers(t, f)
	alice := f.u.Client
	var n uint32
	saved := map[string][]byte{}
	bdev, _ := bob.Client.Device()
	client.SetMergeHook(t, func() {
		if len(saved) > 0 || n == 0 {
			return
		}
		refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
		for _, r := range refs {
			if r.Device != bdev {
				continue
			}
			p := f.env.Store.IndexSegmentFile(f.mbx, n, r.Device, r.Seq)
			if d, err := os.ReadFile(p); err == nil {
				saved[p] = d
			}
		}
	})
	for i := 0; i < client.MergeThreshold; i++ {
		s := fmt.Sprintf("r%02d", i)
		f.send(t, s+"@x.example", header(s+"@x.example", s))
		f.flush(t)
		c := bob.Client
		if i == client.MergeThreshold-1 {
			c = alice
		}
		if _, err := c.Index(f.mbx); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			list, _ := alice.List(f.mbx, store.ID{})
			n = list[0].Epoch
		}
		if c == bob.Client {
			// alice checks bob's segment while generation 1 is valid.
			search(t, alice, f.mbx, "from:"+s+"@x.example", "")
		}
	}
	client.SetMergeHook(t, nil)
	if segmentCount(t, f.env, f.mbx, n) != 1 || len(saved) == 0 {
		t.Fatalf("alice did not merge bob's segments: %d, %d saved", segmentCount(t, f.env, f.mbx, n), len(saved))
	}
	f.env.Clock.Advance(time.Minute)
	f.env.Rotate(bob)
	alice = f.env.Reopen(f.u)
	// Rolled back: alice's result gone, bob's originals (generation 1)
	// back.
	refs, _ := f.env.Store.ListIndexSegments(f.mbx, n)
	for _, r := range refs {
		f.env.Store.RemoveIndexSegment(f.mbx, n, r.Device, r.Seq)
	}
	for p, d := range saved {
		if err := os.WriteFile(p, d, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f.env.Warnings.Take()
	segs, err := alice.Segments(f.mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 0 {
		t.Fatalf("%d of %d merged contents signed by a revoked generation accepted after their successor vanished", len(segs), len(saved))
	}
	if _, err := alice.Search(f.mbx, "from:r00@x.example", client.SearchOptions{}); err != nil {
		t.Fatal(err)
	}
	adev, _ := alice.Device()
	if mine := ownSegments(t, f.env, f.mbx, n, adev); len(mine) != 0 {
		t.Fatalf("alice signed a restored revoked content again: %v", mine)
	}
}
