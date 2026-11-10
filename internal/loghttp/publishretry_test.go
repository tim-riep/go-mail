package loghttp

// Task 25 C2: Tick retries a failed publication before it signs a new
// candidate (N1 of the review of 25 C), and candidate.merge takes over
// new lines only together with a note that note.Sign built (N2).

import (
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/translog"
)

// faultOp counts PublishHead and can fail it or refuse SignHead.
type faultOp struct {
	translog.Operator
	publish     atomic.Int64
	failPublish atomic.Bool
	refuseSign  atomic.Bool
}

func (f *faultOp) PublishHead(h *translog.Head) error {
	f.publish.Add(1)
	if f.failPublish.Load() {
		return errors.New("injected I/O error")
	}
	return f.Operator.PublishHead(h)
}

func (f *faultOp) SignHead(s note.Signer, now time.Time) (*translog.Head, error) {
	if f.refuseSign.Load() {
		return nil, translog.ErrConsistency
	}
	return f.Operator.SignHead(s, now)
}

// faultEnv is an environment with three witnesses, a quorum of two and
// a server over faultOp with a MinGap of one second.
func faultEnv(t *testing.T) (*env, *faultOp) {
	t.Helper()
	e := newEnv(t, 3, 2)
	e.grow(2)
	f := &faultOp{Operator: e.op}
	cfg := e.config()
	cfg.Log = f
	cfg.MinGap = time.Second
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	e.http.Close()
	e.http = httptest.NewServer(srv)
	t.Cleanup(e.http.Close)
	return e, f
}

// TestTickPublishesBeforeNewCandidate: the merge that reaches the quorum
// fails to publish (an injected error of PublishHead); the next Tick,
// after MinGap, signs a new candidate (the log grew) or drops it
// (SignHead refuses). Tick retries the publication before that, so the
// head with the quorum is published with all its lines.
func TestTickPublishesBeforeNewCandidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		next func(e *env, f *faultOp)
		size func(size int64) int64 // of the candidate after Tick, 0 for none
	}{
		{"grown", func(e *env, f *faultOp) { e.grow(1) }, func(size int64) int64 { return size + 1 }},
		{"sign refused", func(e *env, f *faultOp) { f.refuseSign.Store(true) }, func(int64) int64 { return 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, f := faultEnv(t)
			e.srv.Tick()
			size := e.srv.Candidate().Size
			if err := e.poll(0); err != nil {
				t.Fatal(err)
			}
			f.failPublish.Store(true)
			if err := e.poll(1); err != nil {
				t.Fatal(err)
			}
			f.failPublish.Store(false)
			if e.headFile(size) != nil {
				t.Fatal("published despite the injected failure")
			}
			if !strings.Contains(e.logs.String(), "publication refused") {
				t.Fatal("no refusal logged")
			}
			calls := f.publish.Load()
			tc.next(e, f)
			e.clk.add(2 * time.Second)
			e.srv.Tick()
			var got int64
			if c := e.srv.Candidate(); c != nil {
				got = c.Size
			}
			if want := tc.size(size); got != want {
				t.Fatalf("candidate after Tick: size %d, want %d", got, want)
			}
			if n := f.publish.Load(); n != calls+1 {
				t.Fatalf("Tick called PublishHead %d times, want 1", n-calls)
			}
			b := e.headFile(size)
			if b == nil {
				t.Fatalf("quorum of size %d reached, publication failed once, candidate replaced: never published", size)
			}
			h, err := e.openHead(b)
			if err != nil || h.Size != size || len(h.Sigs) != 3 {
				t.Fatalf("published head: %v", err)
			}
		})
	}
}

// TestMergeFailureKeepsCandidate: a line that makes note.Sign fail (its
// key hash does not match its signature bytes; note.Open never yields
// one, so the test calls merge directly) leaves the candidate's lines
// and note as they were, and the next valid line still merges and
// reaches the quorum.
func TestMergeFailureKeepsCandidate(t *testing.T) {
	e := newEnv(t, 3, 2)
	e.grow(2)
	e.srv.Tick()
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	size := e.srv.Candidate().Size
	bad := note.Signature{Name: "bad-witness", Hash: 1, Base64: base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 2, 9, 9})}
	e.srv.mu.Lock()
	c := e.srv.cand
	before, cos := string(c.note), len(c.cos)
	added, err := c.merge([]note.Signature{bad})
	after, cosAfter := string(c.note), len(c.cos)
	e.srv.mu.Unlock()
	if err == nil || added {
		t.Fatalf("merge of a malformed line: added %v, %v", added, err)
	}
	if after != before || cosAfter != cos {
		t.Fatalf("failed merge changed the candidate: %d lines (was %d), note changed %v", cosAfter, cos, after != before)
	}
	if err := e.poll(1); err != nil {
		t.Fatalf("valid line after a failed merge: %v", err)
	}
	if h, err := e.openHead(e.headFile(size)); err != nil || len(h.Sigs) != 3 {
		t.Fatalf("published head: %v", err)
	}
	if n := len(e.srv.Candidate().Sigs); n != 3 {
		t.Fatalf("candidate: %d lines", n)
	}
	// One line per key also within one call (note.Open already drops a
	// repeated line of a key, so only a direct call shows it).
	dup := note.Signature{Name: "dup-witness", Hash: 7, Base64: base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 7, 1, 2, 3})}
	e.srv.mu.Lock()
	added, err = e.srv.cand.merge([]note.Signature{dup, dup})
	e.srv.mu.Unlock()
	if err != nil || !added {
		t.Fatalf("merge of a new line twice: added %v, %v", added, err)
	}
	if n := len(e.srv.Candidate().Sigs); n != 4 {
		t.Fatalf("candidate after a line twice: %d lines, want 4", n)
	}
}
