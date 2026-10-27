package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/translog"
)

// sigLines returns the signature lines of a signed note.
func sigLines(t testing.TB, msg []byte) []string {
	t.Helper()
	i := bytes.LastIndex(msg, []byte("\n\n"))
	if i < 0 {
		t.Fatalf("not a signed note: %q", msg)
	}
	return strings.Split(strings.TrimSuffix(string(msg[i+2:]), "\n"), "\n")
}

// checkBody checks a cosign body: exactly the log signature and the
// witness's cosignature, both valid, over text.
func (f *fixture) checkBody(body []byte, size int64) {
	f.t.Helper()
	lines := sigLines(f.t, body)
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "— "+translog.LogSignerName+" ") || !strings.HasPrefix(lines[1], "— witness.test ") {
		f.t.Fatalf("cosign body has lines %q", lines)
	}
	n, err := note.Open(body, note.VerifierList(mustVerifier(f.t, f.log.vkey), mustVerifier(f.t, f.vkey)))
	if err != nil || len(n.Sigs) != 2 {
		f.t.Fatalf("cosign body does not verify: %v", err)
	}
	h, err := translog.ParseHeadText([]byte(n.Text))
	if err != nil || h.Size != size {
		f.t.Fatalf("cosigned size %v, want %d (%v)", h, size, err)
	}
}

func TestPoll(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// No head yet: nothing to do.
	if err := f.w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if f.st().Head != nil || f.srv.postCount() != 0 {
		t.Fatal("state or post without a head")
	}

	// First head: trust on first use, no proof requested.
	f.publish(3)
	if err := f.w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if f.srv.postCount() != 1 || proofs(f.srv) != 0 {
		t.Fatalf("posts %d, proofs %d", f.srv.postCount(), proofs(f.srv))
	}
	f.checkBody(f.srv.lastPost(), 3)
	st := f.st()
	if st.Origin != testOrigin || st.Head == nil || st.Head.Size != 3 || st.Fork {
		t.Fatalf("state %+v", st)
	}
	stored := readFile(t, f.w.path(headExt))
	if !bytes.Equal(stored, f.srv.lastPost()) || !bytes.Equal(st.Head.Note, stored) {
		t.Fatal("stored head differs from the posted one")
	}
	for p, mode := range map[string]os.FileMode{f.w.path(headExt): 0o600, f.state: 0o700} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: mode %v, want %v", filepath.Base(p), fi.Mode().Perm(), mode)
		}
	}

	// The candidate now carries the cosignature: nothing is posted again.
	if err := f.w.Poll(ctx); err != nil || f.srv.postCount() != 1 {
		t.Fatalf("re-posted an unchanged head: %v, %d", err, f.srv.postCount())
	}

	// Growth with a consistency proof.
	f.clk.add(time.Minute)
	f.publish(4)
	if err := f.w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if f.srv.postCount() != 2 || proofs(f.srv) != 1 {
		t.Fatalf("posts %d, proofs %d", f.srv.postCount(), proofs(f.srv))
	}
	f.checkBody(f.srv.lastPost(), 7)

	// Re-signature of the same size for freshness (time >= stored).
	f.clk.add(time.Hour)
	f.srv.setCandidate(f.log.head(t, 7, f.clk.ms()))
	if err := f.w.Poll(ctx); err != nil || f.srv.postCount() != 3 || proofs(f.srv) != 1 {
		t.Fatalf("refresh: %v, posts %d, proofs %d", err, f.srv.postCount(), proofs(f.srv))
	}
	if f.st().Head.Time != f.clk.ms() {
		t.Fatal("refresh not stored")
	}

	// The state survives a restart.
	f.restart()
	if st := f.st(); st.Head == nil || st.Head.Size != 7 || st.Head.Time != f.clk.ms() {
		t.Fatalf("state after restart %+v", st)
	}
}

// TestCosignBody: the body carries exactly the log signature and the
// own cosignature, never other witnesses' lines from the candidate.
func TestCosignBody(t *testing.T) {
	f := newFixture(t)
	f.log.add(t, 2)
	skey, _, err := note.GenerateKey(rand.Reader, "other.witness")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := note.NewSigner(skey)
	cand := f.log.sign(t, f.log.text(t, 2, f.clk.ms()), other)
	// An unknown line with the witness's own name and a bogus signature.
	junk := append(cand[:len(cand):len(cand)], []byte("— witness.test AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")...)
	for _, c := range [][]byte{cand, junk} {
		out, err := f.w.Cosign(c, nil)
		if err != nil {
			t.Fatal(err)
		}
		f.checkBody(out, 2)
		if bytes.Contains(out, []byte("other.witness")) {
			t.Fatal("forwarded another witness's cosignature")
		}
	}
}

// TestSplitView is 10.1 "Server zeigt zwei Clients unterschiedliche
// Logs": a second head of the same size with another hash is refused,
// for good, also after a restart, and nothing is posted for it.
func TestSplitView(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.publish(5)
	if err := f.w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	first := f.srv.lastPost()

	// The server signs another tree of the same size with the same key.
	other := newTestLogKey(t, "b", f.log.priv)
	other.add(t, 5)
	if other.root(t, 5) == f.log.root(t, 5) {
		t.Fatal("test logs do not differ")
	}
	f.clk.add(time.Minute)
	forked := other.head(t, 5, f.clk.ms())
	f.srv.setCandidate(forked)
	if err := f.w.Poll(ctx); !errors.Is(err, ErrFork) {
		t.Fatalf("second head of size 5 accepted: %v", err)
	}
	if f.srv.postCount() != 1 {
		t.Fatal("a cosignature for the second view left the witness")
	}
	if !f.st().Fork {
		t.Fatal("fork not recorded")
	}
	if ev := readFile(t, f.w.path(forkExt)); !bytes.Equal(ev, forked) {
		t.Fatal("fork evidence is not the refused head")
	}
	if !bytes.Equal(readFile(t, f.w.path(headExt)), first) {
		t.Fatal("stored head changed")
	}

	// Permanent: even the original view and its extension are refused.
	f.srv.mu.Lock()
	f.srv.log = f.log
	f.srv.mu.Unlock()
	f.clk.add(time.Minute)
	f.publish(1)
	heads, _ := f.srv.counts()
	if err := f.w.Poll(ctx); !errors.Is(err, ErrFork) {
		t.Fatalf("forked witness polled: %v", err)
	}
	if n, _ := f.srv.counts(); n != heads {
		t.Fatal("forked witness fetched a head")
	}
	if _, err := f.w.Cosign(f.srv.getCandidate(), f.log.proof(t, 5, 6)); !errors.Is(err, ErrFork) {
		t.Fatalf("forked witness cosigned: %v", err)
	}

	// Also after a restart, and Serve stops with ErrFork.
	f.restart()
	if !f.st().Fork {
		t.Fatal("fork forgotten after restart")
	}
	if _, err := f.w.Cosign(f.srv.getCandidate(), f.log.proof(t, 5, 6)); !errors.Is(err, ErrFork) {
		t.Fatalf("cosigned after restart: %v", err)
	}
	f.w.Close()
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := Serve(ctx2, f.config()); !errors.Is(err, ErrFork) {
		t.Fatalf("Serve: %v", err)
	}
	if f.srv.postCount() != 1 {
		t.Fatal("posted after the fork")
	}
}

// TestForkEvidenceNotWritten: Fork holds in memory even when the
// evidence cannot be stored.
func TestForkEvidenceNotWritten(t *testing.T) {
	f := newFixture(t)
	if _, err := f.w.Cosign(f.publish(2), nil); err != nil {
		t.Fatal(err)
	}
	other := newTestLogKey(t, "b", f.log.priv)
	other.add(t, 2)
	f.w.write = func(string, []byte) error { return errors.New("disk full") }
	_, err := f.w.Cosign(other.head(t, 2, f.clk.ms()), nil)
	if !errors.Is(err, ErrFork) || !errors.Is(err, ErrState) {
		t.Fatalf("got %v", err)
	}
	if !f.st().Fork {
		t.Fatal("fork not kept")
	}
}

func TestSignature(t *testing.T) {
	f := newFixture(t)
	text := f.log.text
	f.log.add(t, 3)
	ms := f.clk.ms()

	stranger := newTestLog(t, "a") // another key under the log's name
	stranger.hashes, stranger.size = f.log.hashes, f.log.size
	good := f.log.head(t, 3, ms)
	i := bytes.LastIndex(good, []byte("\n\n"))
	sig := good[i+2:]
	b64 := strings.TrimSuffix(string(sig[len("— "+translog.LogSignerName+" "):]), "\n")
	raw, _ := base64.StdEncoding.DecodeString(b64)
	raw[len(raw)-1] ^= 1
	flipped := append(append([]byte(nil), good[:i+2]...), []byte("— "+translog.LogSignerName+" "+base64.StdEncoding.EncodeToString(raw)+"\n")...)

	// A second configured log key that also signs.
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	second := newTestLogKey(t, "a", priv2)
	cfg := f.config()
	cfg.LogKeys = append(cfg.LogKeys, second.vkey)
	f.w.Close()
	w, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	twice, _ := note.Sign(&note.Note{Text: text(t, 3, ms)}, f.log.signer, second.signer)

	// A non-canonical encoding of a valid signature: an Ed25519 note
	// signature has 68 bytes, so the last base64 character carries two
	// unused bits.
	nc := []byte(b64)
	last := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", nc[len(nc)-2])
	nc[len(nc)-2] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[last|1]
	noncanon := append(append([]byte(nil), good[:i+2]...), []byte("— "+translog.LogSignerName+" "+string(nc)+"\n")...)
	if bytes.Equal(noncanon, good) {
		t.Fatal("test encoding is canonical")
	}

	for name, c := range map[string]struct {
		msg []byte
		err error
	}{
		"other key":      {stranger.head(t, 3, ms), ErrSignature},
		"bad signature":  {flipped, ErrSignature},
		"no signature":   {[]byte(text(t, 3, ms)), ErrProtocol},
		"two log keys":   {twice, ErrProtocol},
		"non-canonical":  {noncanon, ErrProtocol},
		"text not head":  {f.log.sign(t, "hello\n"), ErrProtocol},
		"too long":       {bytes.Repeat([]byte("x"), translog.MaxHeadNote+1), ErrProtocol},
		"other origin":   {otherOrigin(t, f.log, ms), ErrOrigin},
		"control":        {append([]byte("\x01"), good...), ErrProtocol},
		"many sigs":      {manySigs(t, f.log, ms), ErrProtocol},
		"empty":          {nil, ErrProtocol},
		"trailing blank": {append(append([]byte(nil), good...), '\n'), ErrProtocol},
	} {
		if _, err := w.Cosign(c.msg, nil); !errors.Is(err, c.err) {
			t.Errorf("%s: got %v, want %v", name, err, c.err)
		}
	}
	if st, _ := w.State(); st.Head != nil {
		t.Fatal("state after refused heads")
	}
	// The valid head with the same verifier set is cosigned.
	if _, err := w.Cosign(good, nil); err != nil {
		t.Fatal(err)
	}
}

func otherOrigin(t *testing.T, l *testLog, ms int64) []byte {
	h := &translog.Head{Origin: "other.test/log", Size: l.size, Hash: l.root(t, l.size), Time: ms}
	b, _ := h.Text()
	return l.sign(t, string(b))
}

// manySigs returns a head with more than translog.MaxSignatures lines.
func manySigs(t *testing.T, l *testLog, ms int64) []byte {
	var signers []note.Signer
	for i := 0; i < translog.MaxSignatures; i++ {
		skey, _, _ := note.GenerateKey(rand.Reader, "w"+strings.Repeat("x", i))
		s, _ := note.NewSigner(skey)
		signers = append(signers, s)
	}
	return l.sign(t, l.text(t, l.size, ms), signers...)
}

func TestConsistency(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.publish(3)
	if err := f.w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	f.clk.add(time.Minute)
	f.publish(3) // size 6

	// A wrong proof: refused, not permanent.
	bad := f.log.proof(t, 3, 6)
	bad[0][0] ^= 1
	f.srv.with(func(s *testServer) {
		s.proofHook = func(w http.ResponseWriter, from, to int64) bool {
			plain(w, http.StatusOK, string(FormatProof(bad)))
			return true
		}
	})
	if err := f.w.Poll(ctx); !errors.Is(err, ErrConsistency) {
		t.Fatalf("wrong proof: %v", err)
	}
	// A proof of other sizes.
	f.srv.with(func(s *testServer) {
		s.proofHook = func(w http.ResponseWriter, from, to int64) bool {
			plain(w, http.StatusOK, string(FormatProof(f.log.proof(t, 2, 6))))
			return true
		}
	})
	if err := f.w.Poll(ctx); !errors.Is(err, ErrConsistency) {
		t.Fatalf("proof of other sizes: %v", err)
	}
	// A malformed proof body and a missing proof.
	f.srv.with(func(s *testServer) {
		s.proofHook = func(w http.ResponseWriter, from, to int64) bool {
			plain(w, http.StatusOK, "AAAA\n")
			return true
		}
	})
	if err := f.w.Poll(ctx); !errors.Is(err, ErrProtocol) {
		t.Fatalf("malformed proof: %v", err)
	}
	f.srv.with(func(s *testServer) {
		s.proofHook = func(w http.ResponseWriter, from, to int64) bool {
			plain(w, http.StatusNotFound, "no\n")
			return true
		}
	})
	if err := f.w.Poll(ctx); !errors.Is(err, ErrProtocol) {
		t.Fatalf("missing proof: %v", err)
	}
	if f.srv.postCount() != 1 || f.st().Head.Size != 3 || f.st().Fork {
		t.Fatal("state changed by a bad proof")
	}
	// Not permanent: the right proof is accepted.
	f.srv.with(func(s *testServer) { s.proofHook = nil })
	if err := f.w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if f.srv.postCount() != 2 || f.st().Head.Size != 6 {
		t.Fatal("right proof not accepted")
	}

	// Cosign directly: proofs where none is allowed.
	cand := f.srv.getCandidate()
	if _, err := f.w.Cosign(cand, f.log.proof(t, 3, 6)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("proof for the stored size: %v", err)
	}
	g := newFixture(t)
	g.log.add(t, 4)
	if _, err := g.w.Cosign(g.log.head(t, 4, g.clk.ms()), g.log.proof(t, 2, 4)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("proof without state: %v", err)
	}
}

func TestSizeRegression(t *testing.T) {
	f := newFixture(t)
	f.log.add(t, 7)
	if _, err := f.w.Cosign(f.log.head(t, 7, f.clk.ms()), nil); err != nil {
		t.Fatal(err)
	}
	f.clk.add(time.Minute)
	// An old candidate after a server restart: refused, not permanent.
	f.srv.setCandidate(f.log.head(t, 3, f.clk.ms()))
	if err := f.w.Poll(context.Background()); !errors.Is(err, ErrConsistency) {
		t.Fatalf("smaller head: %v", err)
	}
	if f.st().Head.Size != 7 || f.st().Fork || f.srv.postCount() != 0 {
		t.Fatal("state changed")
	}
	f.srv.setCandidate(f.log.head(t, 7, f.clk.ms()))
	if err := f.w.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTime(t *testing.T) {
	f := newFixture(t)
	f.log.add(t, 2)
	skew := translog.MaxClockSkew.Milliseconds()
	now := f.clk.ms()
	// In the future beyond the clock skew.
	if _, err := f.w.Cosign(f.log.head(t, 2, now+skew+1), nil); !errors.Is(err, ErrTime) {
		t.Fatalf("future head: %v", err)
	}
	// At the limit.
	if _, err := f.w.Cosign(f.log.head(t, 2, now+skew), nil); err != nil {
		t.Fatal(err)
	}
	// Older than the stored head: same size and larger size.
	if _, err := f.w.Cosign(f.log.head(t, 2, now+skew-1), nil); !errors.Is(err, ErrTime) {
		t.Fatalf("older head of the same size: %v", err)
	}
	f.log.add(t, 1)
	if _, err := f.w.Cosign(f.log.head(t, 3, now), f.log.proof(t, 2, 3)); !errors.Is(err, ErrTime) {
		t.Fatalf("older larger head: %v", err)
	}
	// Equal time is a harmless repetition.
	if _, err := f.w.Cosign(f.log.head(t, 2, now+skew), nil); err != nil {
		t.Fatal(err)
	}
	// A fork in the future is a time error first, then a fork.
	other := newTestLogKey(t, "b", f.log.priv)
	other.add(t, 2)
	if _, err := f.w.Cosign(other.head(t, 2, now+2*skew), nil); !errors.Is(err, ErrTime) || f.st().Fork {
		t.Fatalf("future fork: %v", err)
	}
	if _, err := f.w.Cosign(other.head(t, 2, now+skew), nil); !errors.Is(err, ErrFork) {
		t.Fatalf("fork: %v", err)
	}
}

// TestCrashBeforeWrite: when the state cannot be written (a crash at
// the injection point), no cosignature leaves the witness.
func TestCrashBeforeWrite(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.publish(2)
	if err := f.w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	f.clk.add(time.Minute)
	f.publish(2)
	crash := errors.New("crash")
	writes := 0
	f.w.write = func(string, []byte) error { writes++; return crash }
	err := f.w.Poll(ctx)
	if !errors.Is(err, ErrState) || !errors.Is(err, crash) || writes != 1 {
		t.Fatalf("got %v after %d writes", err, writes)
	}
	if f.srv.postCount() != 1 {
		t.Fatal("a cosignature left the witness without stored state")
	}
	if f.st().Head.Size != 2 {
		t.Fatal("memory state moved without a write")
	}
	// After the restart the old state holds and the round succeeds.
	f.restart()
	if f.st().Head.Size != 2 {
		t.Fatal("state on disk moved")
	}
	if err := f.w.Poll(ctx); err != nil || f.srv.postCount() != 2 {
		t.Fatalf("after restart: %v", err)
	}

	// A crash after the write and before the post: the next round signs
	// the same head again and posts it.
	f.clk.add(time.Minute)
	f.publish(1)
	if _, err := f.w.Cosign(f.srv.getCandidate(), f.log.proof(t, 4, 5)); err != nil {
		t.Fatal(err)
	}
	f.restart()
	if err := f.w.Poll(ctx); err != nil || f.srv.postCount() != 3 {
		t.Fatalf("after a crash before the post: %v", err)
	}
	f.checkBody(f.srv.lastPost(), 5)
}

// TestCosignResponses: the witness's reaction to the answers of
// POST /gomail/log/cosign in the protocol.
func TestCosignResponses(t *testing.T) {
	ctx := context.Background()

	// 200: stored, the candidate carries the cosignature.
	f := newFixture(t)
	f.publish(1)
	if err := f.w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(f.srv.getCandidate(), []byte("— witness.test ")) {
		t.Fatal("200 without merge")
	}

	// 409: the candidate changed between GET and POST; no error, the
	// next round cosigns the new candidate.
	f.clk.add(time.Minute)
	f.publish(1)
	var once sync.Once
	f.srv.with(func(s *testServer) {
		s.afterHead = func() {
			once.Do(func() {
				f.clk.add(time.Second)
				s.setCandidate(f.log.head(t, 2, f.clk.ms()))
			})
		}
	})
	if err := f.w.Poll(ctx); err != nil {
		t.Fatalf("409: %v", err)
	}
	if f.srv.postCount() != 2 || bytes.Contains(f.srv.getCandidate(), []byte("— witness.test ")) {
		t.Fatal("409 not exercised")
	}
	if err := f.w.Poll(ctx); err != nil || !bytes.Contains(f.srv.getCandidate(), []byte("— witness.test ")) {
		t.Fatalf("after 409: %v", err)
	}

	// 400: the server does not know the witness (nothing to merge).
	g := newFixture(t)
	g.srv.with(func(s *testServer) { s.witnesses = nil })
	g.publish(1)
	if err := g.w.Poll(ctx); !errors.Is(err, ErrProtocol) {
		t.Fatalf("400: %v", err)
	}

	// 403 and other codes: forced.
	for _, code := range []int{http.StatusForbidden, http.StatusBadRequest, http.StatusInternalServerError, http.StatusRequestEntityTooLarge, http.StatusFound} {
		h := newFixture(t)
		h.publish(1)
		h.srv.with(func(s *testServer) { s.cosignCode = code })
		if err := h.w.Poll(ctx); !errors.Is(err, ErrProtocol) {
			t.Fatalf("%d: %v", code, err)
		}
	}
	for _, code := range []int{http.StatusOK, http.StatusConflict} {
		h := newFixture(t)
		h.publish(1)
		h.srv.with(func(s *testServer) { s.cosignCode = code })
		if err := h.w.Poll(ctx); err != nil {
			t.Fatalf("%d: %v", code, err)
		}
	}
}

func TestHTTP(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		hook func(w http.ResponseWriter) bool
		err  error
	}{
		"status 500": {func(w http.ResponseWriter) bool { plain(w, 500, "x\n"); return true }, ErrProtocol},
		"redirect": {func(w http.ResponseWriter) bool {
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(http.StatusFound)
			return true
		}, ErrProtocol},
		"content type": {func(w http.ResponseWriter) bool {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write([]byte("x"))
			return true
		}, ErrProtocol},
		"charset": {func(w http.ResponseWriter) bool {
			w.Header().Set("Content-Type", "text/plain; charset=latin1")
			w.Write([]byte("x"))
			return true
		}, ErrProtocol},
		"too long, length known": {func(w http.ResponseWriter) bool {
			plain(w, 200, strings.Repeat("x", translog.MaxHeadNote+1))
			return true
		}, ErrProtocol},
		"too long, chunked": {func(w http.ResponseWriter) bool {
			w.Header().Set("Content-Type", ContentType)
			w.WriteHeader(200)
			for i := 0; i <= translog.MaxHeadNote/1024; i++ {
				w.Write(bytes.Repeat([]byte("x"), 1024))
				w.(http.Flusher).Flush()
			}
			return true
		}, ErrProtocol},
		"garbage": {func(w http.ResponseWriter) bool { plain(w, 200, "garbage"); return true }, ErrProtocol},
	} {
		f := newFixture(t)
		f.publish(1)
		f.srv.with(func(s *testServer) { s.headHook = c.hook })
		if err := f.w.Poll(ctx); !errors.Is(err, c.err) {
			t.Errorf("%s: got %v", name, err)
		}
		if f.srv.postCount() != 0 {
			t.Errorf("%s: posted", name)
		}
	}

	// A proof body above MaxProofBody.
	f := newFixture(t)
	f.publish(2)
	if err := f.w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	f.clk.add(time.Minute)
	f.publish(2)
	f.srv.with(func(s *testServer) {
		s.proofHook = func(w http.ResponseWriter, from, to int64) bool {
			plain(w, 200, strings.Repeat("A", MaxProofBody+1))
			return true
		}
	})
	if err := f.w.Poll(ctx); !errors.Is(err, ErrProtocol) {
		t.Fatalf("long proof: %v", err)
	}

	// Server down.
	f.srv.Close()
	if err := f.w.Poll(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("server down: %v", err)
	}
	// A cancelled context.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.w.Poll(cctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cancelled: %v", err)
	}
}

// TestPostFailure: a server that drops the connection on the POST.
func TestPostFailure(t *testing.T) {
	f := newFixture(t)
	f.publish(1)
	f.srv.with(func(s *testServer) {
		s.cosignHook = func(w http.ResponseWriter) bool {
			c, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				c.Close()
			}
			return true
		}
	})
	if err := f.w.Poll(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	// The state was written: the cosignature is not forgotten.
	if f.st().Head == nil {
		t.Fatal("state not written before the post")
	}
}

func TestBasePath(t *testing.T) {
	f := newFixture(t)
	mux := http.NewServeMux()
	mux.Handle("/prefix/", http.StripPrefix("/prefix", f.srv.Config.Handler))
	prefixed := httptest.NewServer(mux)
	defer prefixed.Close()
	cfg := f.config()
	cfg.Log = prefixed.URL + "/prefix/"
	f.w.Close()
	w, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	f.publish(1)
	if err := w.Poll(context.Background()); err != nil || f.srv.postCount() != 1 {
		t.Fatalf("base path: %v", err)
	}
}

func TestServe(t *testing.T) {
	f := newFixture(t)
	f.publish(2)
	f.w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, f.config()) }()
	deadline := time.Now().Add(10 * time.Second)
	for f.srv.postCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// Failing rounds do not stop Serve.
	f.srv.with(func(s *testServer) {
		s.headHook = func(w http.ResponseWriter) bool { plain(w, 500, "x\n"); return true }
	})
	heads, _ := f.srv.counts()
	for time.Now().Before(deadline) {
		if n, _ := f.srv.counts(); n > heads+2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if f.srv.postCount() != 1 {
		t.Fatalf("posts %d", f.srv.postCount())
	}
	// A bad configuration fails at once.
	cfg := f.config()
	cfg.Origin = ""
	if err := Serve(context.Background(), cfg); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
}

func TestClosed(t *testing.T) {
	f := newFixture(t)
	if err := f.w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.w.Close(); err != nil {
		t.Fatal("second Close")
	}
	if _, err := f.w.State(); !errors.Is(err, ErrState) {
		t.Fatal("State after Close")
	}
	f.publish(1)
	if _, err := f.w.Cosign(f.srv.getCandidate(), nil); !errors.Is(err, ErrState) {
		t.Fatal("Cosign after Close")
	}
	if err := f.w.Poll(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal("Poll after Close")
	}
	// The lock is released: the state directory opens again.
	f.w = f.open()
}

func TestReason(t *testing.T) {
	for _, e := range sentinels {
		if reason(e) != e.Error() {
			t.Fatal(e)
		}
	}
	if reason(context.Canceled) != "context ended" || reason(errors.New("secret")) == "secret" {
		t.Fatal("reason leaks foreign text")
	}
	if !hasLine([]byte("a\n\n— x y\n"), []byte("— x y\n")) || hasLine([]byte("a\n"), []byte("x\n")) || hasLine([]byte("a\n\n— x y\n"), nil) {
		t.Fatal("hasLine")
	}
	if hashPrefix(tlog.Hash{0xab, 0xcd, 1, 2, 3}) != "abcd0102" {
		t.Fatal("hashPrefix")
	}
	if !textPlain("text/plain; charset=UTF-8") || textPlain("text/plain") || textPlain("text/plain; charset=utf-8; x=y") || textPlain("%%") {
		t.Fatal("textPlain")
	}
}
