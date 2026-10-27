package translog

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// Tests of task 14b (translog side): a larger checkpoint signed before
// the reference head (point 1), an older head in heads/ (point 2, see
// also TestHeadRules) and an audit index whose tables do not cover the
// reference size (point 7).

// TestCheckpointLargerEarlier (point 1): a checkpoint larger than the
// reference head is ErrPending while its time is not before the
// reference head's, and ErrConsistency (entries withheld from this
// client) when it was signed before it.
func TestCheckpointLargerEarlier(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.mustAppend(KindUser, newUser(t).rec(t, 1))
	e.head()
	c, v := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	last := v.Last
	for _, x := range []struct {
		time int64
		want error
	}{
		{last.Time - 1, ErrConsistency},
		{0, ErrConsistency},
		{last.Time, ErrPending},
		{last.Time + 1, ErrPending},
	} {
		err := v.CheckCheckpoint(testOrigin, last.Size+1, last.Hash, x.time, nil)
		if !errors.Is(err, x.want) {
			t.Fatalf("time %d: %v", x.time, err)
		}
		if x.want == ErrConsistency && errors.Is(err, ErrPending) {
			t.Fatalf("time %d: both verdicts", x.time)
		}
	}
}

// TestCheckOlderHead (point 2): the verdicts of CheckOlderHead directly.
func TestCheckOlderHead(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.mustAppend(KindUser, newUser(t).rec(t, 1))
	small := e.head()
	small.Note = sign(t, small, e.all()...)
	e.mustAppend(KindUser, newUser(t).rec(t, 1))
	e.now = e.now.Add(time.Minute)
	e.head()
	c, v := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	proof, err := c.ConsistencyProof(small.Size, v.Last.Size)
	if err != nil {
		t.Fatal(err)
	}
	vc := *v
	if err := vc.CheckOlderHead(small, proof); err != nil {
		t.Fatalf("older head: %v", err)
	}
	if err := vc.CheckOlderHead(small, nil); !errors.Is(err, ErrConsistency) {
		t.Fatalf("older head without proof: %v", err)
	}
	if err := vc.CheckOlderHead(v.Last, nil); !errors.Is(err, ErrHead) {
		t.Fatalf("not older: %v", err)
	}
	nolast := vc
	nolast.Last = nil
	if err := nolast.CheckOlderHead(small, proof); !errors.Is(err, ErrHead) {
		t.Fatalf("without a reference head: %v", err)
	}
	later := *small
	later.Time = v.Last.Time + 1
	later.Note = sign(t, &later, e.all()...)
	if err := vc.CheckOlderHead(&later, proof); !errors.Is(err, ErrConsistency) {
		t.Fatalf("older head signed after the reference head: %v", err)
	}
	unsigned := *small
	unsigned.Note = sign(t, small, e.signer)
	if err := vc.CheckOlderHead(&unsigned, proof); !errors.Is(err, ErrWitness) {
		t.Fatalf("without witnesses: %v", err)
	}
}

// TestRefreshOlderHeadWithheld (point 2): with an older head in heads/
// the Pending rules still apply to the reference head: an own entry
// beyond it is withheld once the reference head is newer than the
// append by more than HeadInterval, and stale after MaxPendingHeadAge.
func TestRefreshOlderHeadWithheld(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.mustAppend(KindUser, newUser(t).rec(t, 1))
	e.head()
	e.mustAppend(KindUser, newUser(t).rec(t, 1))
	e.now = e.now.Add(time.Minute)
	big := e.head()
	c, v := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(KindUser, newUser(t).rec(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.path(HeadPath(big.Size))); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrOlderHead) || len(v.Pending) != 1 {
		t.Fatalf("older head with a pending entry: %v %v", err, v.Pending)
	}
	e.now = e.now.Add(MaxPendingHeadAge + time.Minute)
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrStale) || errors.Is(err, ErrOlderHead) {
		t.Fatalf("older head, pending entry, stale reference head: %v", err)
	}
}

// TestIndexEmptyTablesRebuilt (point 7): an audit index with the size
// and root of the reference head but empty tables is discarded and
// rebuilt when the client log is opened: Lookup finds the entries again.
func TestIndexEmptyTablesRebuilt(t *testing.T) {
	e := newEnv(t, 1, 1)
	u := newUser(t)
	e.mustAppend(KindUser, u.rec(t, 1))
	e.head()
	v := e.verifier()
	idx := t.TempDir() + "/index.json"
	l, err := Open(Options{Store: e.st, Verifier: v, IndexFile: idx})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	var full map[string]json.RawMessage
	if err := json.Unmarshal(data, &full); err != nil {
		t.Fatal(err)
	}
	emptied := map[string]json.RawMessage{"version": full["version"], "anchor": full["anchor"], "size": full["size"], "root": full["root"]}
	b, _ := json.Marshal(emptied)
	if err := os.WriteFile(idx, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &state{}
	if err := json.Unmarshal(b, s); err != nil {
		t.Fatal(err)
	}
	if err := s.checkStructure(); !errors.Is(err, ErrConsistency) {
		t.Fatalf("empty tables accepted: %v", err)
	}
	l2, err := Open(Options{Store: e.st, Verifier: v, IndexFile: idx})
	if err != nil {
		t.Fatal(err)
	}
	ents, err := l2.Lookup(KindUser, u.id[:])
	if err != nil || len(ents) != 1 {
		t.Fatalf("lookup after the rebuild: %d %v", len(ents), err)
	}
	if after, _ := os.ReadFile(idx); string(after) == string(b) {
		t.Fatal("index not rebuilt")
	}
}
