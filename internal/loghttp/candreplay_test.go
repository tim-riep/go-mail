package loghttp

// Task 25 C (N2 of the review of 24 D2): POST /cosign with the
// candidate's own note, which anybody can fetch with GET /head, calls
// PublishHead only when the body adds a line, also below the quorum.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/witness"
)

// TestReplayCandidateBelowQuorum: replays of the candidate's note (and of
// the note of a witness already merged) below the quorum and after it
// are answered 200 without a call of PublishHead and without a log line
// of the publication; a new line calls it once, and Tick retries a
// publication below the quorum.
func TestReplayCandidateBelowQuorum(t *testing.T) {
	e := newEnv(t, 3, 2)
	e.grow(2)
	cnt := &countingOp{Operator: e.op}
	cfg := e.config()
	cfg.Log = cnt
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	e.http.Close()
	e.http = httptest.NewServer(srv)
	t.Cleanup(e.http.Close)
	srv.Tick()
	if n := cnt.publish.Load(); n != 0 {
		t.Fatalf("PublishHead called %d times without cosignature", n)
	}
	waiting := func() int { return strings.Count(e.logs.String(), "waiting for cosignatures") }

	// Witness a: one line, below the quorum of two.
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	if n, w := cnt.publish.Load(), waiting(); n != 1 || w != 1 {
		t.Fatalf("first line: PublishHead %d, waiting %d", n, w)
	}
	size := srv.Candidate().Size
	if e.headFile(size) != nil {
		t.Fatal("published below the quorum")
	}
	replay := func(what string, want int64, wantWaiting int) {
		t.Helper()
		body := srv.Candidate().Note
		for i := 0; i < 20; i++ {
			if r := e.do(http.MethodPost, witness.PathCosign, witness.ContentType, body); r.Code != http.StatusOK || r.Body.String() != "stored\n" {
				t.Fatalf("%s: %d %q", what, r.Code, r.Body.String())
			}
		}
		if n, w := cnt.publish.Load(), waiting(); n != want || w != wantWaiting {
			t.Fatalf("%s: PublishHead %d (want %d), waiting %d (want %d)", what, n, want, w, wantWaiting)
		}
	}
	replay("below the quorum", 1, 1)
	// The same witness again: its line is merged already.
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	if n := cnt.publish.Load(); n != 1 {
		t.Fatalf("known line: PublishHead %d", n)
	}
	// Tick retries the publication below the quorum.
	srv.Tick()
	if n, w := cnt.publish.Load(), waiting(); n != 2 || w != 2 {
		t.Fatalf("Tick: PublishHead %d, waiting %d", n, w)
	}
	// Witness b reaches the quorum: one call, published.
	if err := e.poll(1); err != nil {
		t.Fatal(err)
	}
	if n := cnt.publish.Load(); n != 3 || e.headFile(size) == nil {
		t.Fatalf("quorum: PublishHead %d, published %v", n, e.headFile(size) != nil)
	}
	replay("published", 3, 2)
	srv.Tick()
	if n := cnt.publish.Load(); n != 3 {
		t.Fatalf("Tick after the publication: PublishHead %d", n)
	}
}
