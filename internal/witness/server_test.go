package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/translog"
)

// This file holds a minimal log server for the tests: an in-memory tlog
// tree, a log signer and the three handlers of the protocol in the
// package comment. The real server side is task 11.

const testOrigin = "go-mail.test/log"

// testLog is an in-memory tree with a log key.
type testLog struct {
	origin string
	priv   ed25519.PrivateKey
	signer note.Signer
	vkey   string
	hashes []tlog.Hash
	size   int64
	seed   string // makes the leaves of two logs differ
}

func newTestLog(t testing.TB, seed string) *testLog {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newTestLogKey(t, seed, priv)
}

func newTestLogKey(t testing.TB, seed string, priv ed25519.PrivateKey) *testLog {
	t.Helper()
	s, err := translog.NewLogSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	vkey, err := note.NewEd25519VerifierKey(translog.LogSignerName, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return &testLog{origin: testOrigin, priv: priv, signer: s, vkey: vkey, seed: seed}
}

func (l *testLog) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	for i, x := range idx {
		if x < 0 || x >= int64(len(l.hashes)) {
			return nil, errors.New("no such hash")
		}
		out[i] = l.hashes[x]
	}
	return out, nil
}

// add appends n leaves.
func (l *testLog) add(t testing.TB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		hs, err := tlog.StoredHashes(l.size, []byte(fmt.Sprintf("%s leaf %d", l.seed, l.size)), l)
		if err != nil {
			t.Fatal(err)
		}
		l.hashes = append(l.hashes, hs...)
		l.size++
	}
}

// root returns the tree hash of size n.
func (l *testLog) root(t testing.TB, n int64) tlog.Hash {
	t.Helper()
	h, err := tlog.TreeHash(n, l)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// text returns the head text of size n at time ms.
func (l *testLog) text(t testing.TB, n, ms int64) string {
	t.Helper()
	h := &translog.Head{Origin: l.origin, Size: n, Hash: l.root(t, n), Time: ms}
	b, err := h.Text()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sign signs a head text with the log key and the extra signers.
func (l *testLog) sign(t testing.TB, text string, extra ...note.Signer) []byte {
	t.Helper()
	msg, err := note.Sign(&note.Note{Text: text}, append([]note.Signer{l.signer}, extra...)...)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// head returns the signed head of size n at time ms.
func (l *testLog) head(t testing.TB, n, ms int64) []byte { return l.sign(t, l.text(t, n, ms)) }

func (l *testLog) proof(t testing.TB, from, to int64) tlog.TreeProof {
	t.Helper()
	p, err := tlog.ProveTree(to, from, l)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// testServer serves a candidate head over the protocol.
type testServer struct {
	*httptest.Server
	t testing.TB

	mu        sync.Mutex
	log       *testLog // answers /consistency
	candidate []byte   // nil: 404 on /head
	witnesses []note.Verifier
	posts     [][]byte
	heads     int // GET /head requests
	proofs    int // GET /consistency requests

	// Overrides for misbehaving servers.
	headHook   func(w http.ResponseWriter) bool // true: response written
	proofHook  func(w http.ResponseWriter, from, to int64) bool
	cosignCode int // forced status of /cosign when not 0
	cosignHook func(w http.ResponseWriter) bool
	afterHead  func() // runs after a head was served
}

func newTestServer(t testing.TB, l *testLog) *testServer {
	s := &testServer{t: t, log: l}
	mux := http.NewServeMux()
	mux.HandleFunc(PathHead, s.serveHead)
	mux.HandleFunc(PathConsistency, s.serveConsistency)
	mux.HandleFunc(PathCosign, s.serveCosign)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *testServer) setCandidate(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidate = append([]byte(nil), b...)
}

func (s *testServer) getCandidate() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.candidate...)
}

// with changes the server under its lock.
func (s *testServer) with(fn func(s *testServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// counts returns the number of head and proof requests.
func (s *testServer) counts() (heads, proofs int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heads, s.proofs
}

func proofs(s *testServer) int {
	_, p := s.counts()
	return p
}

func (s *testServer) postCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.posts)
}

func (s *testServer) lastPost() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.posts) == 0 {
		return nil
	}
	return s.posts[len(s.posts)-1]
}

func plain(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(code)
	io.WriteString(w, body)
}

func (s *testServer) serveHead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		plain(w, http.StatusMethodNotAllowed, "method\n")
		return
	}
	s.mu.Lock()
	s.heads++
	hook, cand, after := s.headHook, s.candidate, s.afterHead
	s.mu.Unlock()
	if hook != nil && hook(w) {
		return
	}
	if cand == nil {
		plain(w, http.StatusNotFound, "no head\n")
		return
	}
	plain(w, http.StatusOK, string(cand))
	if after != nil {
		after()
	}
}

// decimal parses a size of the protocol: no sign, no leading zeros.
func decimal(s string) (int64, bool) {
	if s == "" || len(s) > 19 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

func (s *testServer) serveConsistency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		plain(w, http.StatusMethodNotAllowed, "method\n")
		return
	}
	q := r.URL.Query()
	from, ok1 := decimal(q.Get("from"))
	to, ok2 := decimal(q.Get("to"))
	if !ok1 || !ok2 || len(q) != 2 || from < 1 || from > to || to > translog.MaxTreeSize {
		plain(w, http.StatusBadRequest, "malformed\n")
		return
	}
	s.mu.Lock()
	s.proofs++
	hook, l, cand := s.proofHook, s.log, s.candidate
	s.mu.Unlock()
	if hook != nil && hook(w, from, to) {
		return
	}
	var size int64
	if cand != nil {
		if h, err := translog.OpenHead(cand, note.VerifierList(mustVerifier(s.t, l.vkey))); err == nil {
			size = h.Size
		}
	}
	if to > size || to > l.size {
		plain(w, http.StatusNotFound, "beyond the candidate\n")
		return
	}
	p, err := tlog.ProveTree(to, from, l)
	if err != nil {
		plain(w, http.StatusInternalServerError, "proof\n")
		return
	}
	plain(w, http.StatusOK, string(FormatProof(p)))
}

// serveCosign follows the protocol: 400 for a malformed head or one
// without a known witness's valid cosignature, 403 for an invalid
// signature by a known key, 409 for another text than the candidate,
// 200 after merging the cosignature into the candidate.
func (s *testServer) serveCosign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		plain(w, http.StatusMethodNotAllowed, "method\n")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, translog.MaxHeadNote+1))
	if err != nil || len(body) > translog.MaxHeadNote {
		plain(w, http.StatusRequestEntityTooLarge, "too large\n")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.posts = append(s.posts, body)
	if s.cosignHook != nil && s.cosignHook(w) {
		return
	}
	if r.Header.Get("Content-Type") != ContentType {
		plain(w, http.StatusBadRequest, "content type\n")
		return
	}
	if s.cosignCode != 0 {
		plain(w, s.cosignCode, "forced\n")
		return
	}
	logV := mustVerifier(s.t, s.log.vkey)
	known := note.VerifierList(append([]note.Verifier{logV}, s.witnesses...)...)
	n, err := note.Open(body, known)
	var invalid *note.InvalidSignatureError
	switch {
	case errors.As(err, &invalid):
		plain(w, http.StatusForbidden, "invalid signature\n")
		return
	case err != nil:
		plain(w, http.StatusBadRequest, "malformed\n")
		return
	}
	if _, err := translog.ParseHeadText([]byte(n.Text)); err != nil {
		plain(w, http.StatusBadRequest, "malformed\n")
		return
	}
	var logSig []note.Signature
	var cos []note.Signature
	for _, sg := range n.Sigs {
		if sg.Name == translog.LogSignerName {
			logSig = append(logSig, sg)
		} else {
			cos = append(cos, sg)
		}
	}
	if len(logSig) != 1 || len(cos) == 0 {
		plain(w, http.StatusBadRequest, "nothing to merge\n")
		return
	}
	cn, err := note.Open(s.candidate, known)
	if err != nil || cn.Text != n.Text {
		plain(w, http.StatusConflict, "not the candidate\n")
		return
	}
	merged := cn.Sigs
	for _, c := range cos {
		dup := false
		for _, m := range merged {
			dup = dup || (m.Name == c.Name && m.Hash == c.Hash)
		}
		if !dup {
			merged = append(merged, c)
		}
	}
	out, err := note.Sign(&note.Note{Text: n.Text, Sigs: merged})
	if err != nil {
		plain(w, http.StatusInternalServerError, "merge\n")
		return
	}
	s.candidate = out
	plain(w, http.StatusOK, "stored\n")
}

func mustVerifier(t testing.TB, vkey string) note.Verifier {
	t.Helper()
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// clock is the injected clock of the tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *clock) ms() int64 { return c.Now().UnixMilli() }

// fixture is a witness against a test server.
type fixture struct {
	t     testing.TB
	log   *testLog
	srv   *testServer
	clk   *clock
	dir   string
	key   string // key file
	vkey  string // the witness's verifier key
	state string // state directory
	w     *Witness
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{t: t, log: newTestLog(t, "a"), clk: &clock{t: time.UnixMilli(1_800_000_000_000)}, dir: t.TempDir()}
	f.srv = newTestServer(t, f.log)
	f.key = filepath.Join(f.dir, "witness.key")
	vkey, err := Keygen("witness.test", f.key, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.vkey = vkey
	f.srv.witnesses = []note.Verifier{mustVerifier(t, vkey)}
	f.state = filepath.Join(f.dir, "state")
	f.w = f.open()
	return f
}

func (f *fixture) config() Config {
	return Config{
		Log:      f.srv.URL,
		LogKeys:  []string{f.log.vkey},
		Origin:   testOrigin,
		KeyFile:  f.key,
		StateDir: f.state,
		Interval: 5 * time.Millisecond,
		Now:      f.clk.Now,
	}
}

func (f *fixture) open() *Witness {
	f.t.Helper()
	w, err := New(f.config())
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { w.Close() })
	return w
}

// restart closes the witness and opens it again on the same state.
func (f *fixture) restart() {
	f.t.Helper()
	if err := f.w.Close(); err != nil {
		f.t.Fatal(err)
	}
	f.w = f.open()
}

// publish adds n leaves to the log and serves the head of the new size
// at the current time.
func (f *fixture) publish(n int) []byte {
	f.t.Helper()
	f.log.add(f.t, n)
	h := f.log.head(f.t, f.log.size, f.clk.ms())
	f.srv.setCandidate(h)
	return h
}

func (f *fixture) st() *State {
	f.t.Helper()
	s, err := f.w.State()
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func readFile(t testing.TB, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
