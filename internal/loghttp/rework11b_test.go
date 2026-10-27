package loghttp

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of task 11b (findings of the verification of task 11).

// witSigner returns the note signer of witness w from its key file.
func witSigner(t testing.TB, w *wit) note.Signer {
	t.Helper()
	data, err := os.ReadFile(w.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signText signs a head text with the given signers.
func signText(t testing.TB, text []byte, ss ...note.Signer) []byte {
	t.Helper()
	b, err := note.Sign(&note.Note{Text: string(text)}, ss...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestKnownPoisonedHead (finding 5, from verifier test 3): with the
// configuration of cmd/gomail-server (Options.Known = the witnesses) a
// published head with an invalid line under the name of a known witness
// is served by GET /head without that line (200), and GET /consistency
// answers (200) while there is no candidate.
func TestKnownPoisonedHead(t *testing.T) {
	e := newEnv(t, 3, 2)
	e.grow(2)
	e.srv.Tick()
	for i := 0; i < 2; i++ {
		if err := e.poll(i); err != nil {
			t.Fatal(err)
		}
	}
	size, _ := e.tree()
	e.start() // a new process: no candidate, Known as main.go sets it
	w2 := e.ws[2].verifier
	poison := append(append([]byte(nil), e.headFile(size)...), poisonLine(w2.Name(), w2.KeyHash())...)
	if err := store.WriteFileAtomic(e.path(translog.HeadPath(size)), poison); err != nil {
		t.Fatal(err)
	}
	if _, err := e.openHead(poison); err == nil {
		t.Fatal("setup: the poisoned head opens")
	}
	r := e.do(http.MethodGet, witness.PathHead, "", nil)
	if r.Code != http.StatusOK || bytes.Contains(r.Body.Bytes(), []byte(w2.Name())) {
		t.Fatalf("GET /head with a poisoned published head: %d %q", r.Code, r.Body.String())
	}
	if h, err := e.openHead(r.Body.Bytes()); err != nil || h.Size != size || len(h.Sigs) != 3 {
		t.Fatalf("served head: %v", err)
	}
	for from := int64(1); from <= size; from++ {
		q := witness.PathConsistency + "?from=" + strconv.FormatInt(from, 10) + "&to=" + strconv.FormatInt(size, 10)
		if r := e.do(http.MethodGet, q, "", nil); r.Code != http.StatusOK {
			t.Fatalf("GET /consistency from %d: %d", from, r.Code)
		}
	}
	// The poisoned witness itself polls: it fetches the clean head,
	// cosigns, and the stored file loses the poisoned line.
	if err := e.poll(2); err != nil {
		t.Fatal(err)
	}
	if h, err := e.openHead(e.headFile(size)); err != nil || len(h.Sigs) != 4 {
		t.Fatalf("not repaired: %v", err)
	}
	e.srv.Tick()
	if r := e.do(http.MethodGet, witness.PathHead, "", nil); r.Code != http.StatusOK {
		t.Fatalf("GET /head after Tick: %d", r.Code)
	}
}

// TestCosignAfterRotation (finding 7): after an ingest rotation the
// server signs with generation 2; a witness body for the newest
// published head, signed by generation 1 that covers its time, is
// merged (200), not refused with 400. A line of generation 2 over that
// head is never stored (it does not cover the head time; the stored log
// line is kept); a generation 1 line over the new candidate is not
// merged.
func TestCosignAfterRotation(t *testing.T) {
	e := newEnv(t, 5, 3)
	e.srv.Tick()
	for i := 0; i < 3; i++ {
		if err := e.poll(i); err != nil {
			t.Fatal(err)
		}
	}
	size, _ := e.tree()
	pub, err := e.openHead(e.headFile(size))
	if err != nil {
		t.Fatal(err)
	}
	ptext, _ := pub.Text()
	gen1 := e.signer
	// Rotation: ingest-2.cert valid from one hour on, logged; the server
	// restarts with the key of generation 2 after the switch.
	ingest2, err := e.plat.IngestKey(2)
	if err != nil {
		t.Fatal(err)
	}
	sw := e.clk.Now().Add(time.Hour).UnixMilli()
	cert, err := keys.NewPlatformCert(e.identity, 1, keys.RoleIngest, 2, ingest2.Public().(ed25519.PublicKey), sw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.WritePlatformFile("ingest-2.cert", data); err != nil {
		t.Fatal(err)
	}
	if _, err := e.op.Append(translog.KindPlatform, data); err != nil {
		t.Fatal(err)
	}
	e.clk.add(2 * time.Hour)
	if e.signer, err = translog.NewLogSigner(ingest2); err != nil {
		t.Fatal(err)
	}
	if e.logKey, err = translog.NewLogVerifier(ingest2.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	e.start()
	post := func(body []byte) int {
		return e.do(http.MethodPost, witness.PathCosign, witness.ContentType, body).Code
	}
	w0, w3, w4 := witSigner(t, e.ws[0]), witSigner(t, e.ws[3]), witSigner(t, e.ws[4])
	v1, _ := translog.NewLogVerifier(e.ingest.Public().(ed25519.PublicKey))
	stored := func(n int) {
		t.Helper()
		b := e.headFile(size)
		h, err := translog.OpenHead(b, note.VerifierList(append([]note.Verifier{v1}, e.verifiers()...)...))
		if err != nil || len(h.Sigs) != n {
			t.Fatalf("stored head: %v", err)
		}
		for _, s := range h.Sigs {
			if s.Name == translog.LogSignerName && s.Hash != gen1.KeyHash() {
				t.Fatal("a log line of generation 2 stored")
			}
		}
	}
	// The witness body as it comes after a GET /head of the published
	// head: generation 1, which covers its time. Merged.
	if code := post(signText(t, ptext, gen1, w3)); code != http.StatusOK {
		t.Fatalf("generation 1 over the published head: %d", code)
	}
	stored(5)
	// A line of generation 2 over that head is dropped; the cosignature
	// is merged beside the stored line of generation 1.
	if code := post(signText(t, ptext, e.signer, w4)); code != http.StatusOK {
		t.Fatalf("generation 2 over the published head: %d", code)
	}
	stored(6)
	// The new candidate of generation 2; a generation 1 line over its
	// text is not merged.
	e.srv.Tick()
	c := e.srv.Candidate()
	if c == nil || c.Sigs[0].Hash != e.signer.KeyHash() {
		t.Fatal("no candidate of generation 2")
	}
	ctext, _ := c.Text()
	if code := post(signText(t, ctext, gen1, w0)); code != http.StatusConflict {
		t.Fatalf("generation 1 over the candidate: %d", code)
	}
	if len(e.srv.Candidate().Sigs) != 1 {
		t.Fatal("merged a body with another generation's line")
	}
	if code := post(signText(t, ctext, e.signer, w0)); code != http.StatusOK || len(e.srv.Candidate().Sigs) != 2 {
		t.Fatalf("generation 2 over the candidate: %d", code)
	}
}

// TestPublishedPathUnverifiedLine (from the attack tests of the
// verification of task 11): through the published-head path an unknown
// foreign line is never stored, and a poisoned line of a known witness
// is refused with 403 without damaging the stored head.
func TestPublishedPathUnverifiedLine(t *testing.T) {
	e := newEnv(t, 3, 2)
	e.srv.Tick()
	c := e.srv.Candidate()
	text, _ := c.Text()
	w0, w1, w2 := witSigner(t, e.ws[0]), witSigner(t, e.ws[1]), witSigner(t, e.ws[2])
	foreign := newWit(t, t.TempDir(), 9)
	fs := witSigner(t, foreign)
	post := func(body []byte) int {
		return e.do(http.MethodPost, witness.PathCosign, witness.ContentType, body).Code
	}
	if post(signText(t, text, e.signer, w0)) != http.StatusOK || post(signText(t, text, e.signer, w1)) != http.StatusOK {
		t.Fatal("cosign")
	}
	if e.headFile(c.Size) == nil {
		t.Fatal("not published")
	}
	e.start()
	if code := post(signText(t, text, e.signer, w2, fs)); code != http.StatusOK {
		t.Fatalf("published-path merge: %d", code)
	}
	stored := e.headFile(c.Size)
	if bytes.Contains(stored, []byte(foreign.name)) {
		t.Fatal("unverified foreign line stored")
	}
	if h, err := e.openHead(stored); err != nil || len(h.Sigs) != 4 {
		t.Fatalf("stored head: %v", err)
	}
	e.start()
	w2v := e.ws[2].verifier
	bad := append(signText(t, text, e.signer, w0), poisonLine(w2v.Name(), w2v.KeyHash())...)
	if code := post(bad); code != http.StatusForbidden {
		t.Fatalf("poisoned line: %d", code)
	}
	if !bytes.Equal(e.headFile(c.Size), stored) {
		t.Fatal("stored head changed after 403")
	}
}

// TestDuplicateWitnessNoQuorum (from the attack tests): one witness
// posting the same cosignature repeatedly counts once.
func TestDuplicateWitnessNoQuorum(t *testing.T) {
	e := newEnv(t, 3, 2)
	e.srv.Tick()
	c := e.srv.Candidate()
	text, _ := c.Text()
	w0 := witSigner(t, e.ws[0])
	for n := 0; n < 5; n++ {
		if code := e.do(http.MethodPost, witness.PathCosign, witness.ContentType, signText(t, text, e.signer, w0)).Code; code != http.StatusOK {
			t.Fatalf("cosign: %d", code)
		}
	}
	if got := len(e.srv.Candidate().Sigs); got != 2 {
		t.Fatalf("duplicate witness counted: %d lines", got)
	}
	if e.headFile(c.Size) != nil {
		t.Fatal("published below the quorum")
	}
}

// TestConsistencyQueries (from the attack tests): malformed and extreme
// queries of GET /consistency get only the statuses of the protocol,
// always as text/plain.
func TestConsistencyQueries(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.grow(3)
	e.srv.Tick()
	size := strconv.FormatInt(e.srv.Candidate().Size, 10)
	next := strconv.FormatInt(e.srv.Candidate().Size+1, 10)
	for _, tc := range []struct {
		q    string
		want int
	}{
		{"from=1&to=" + size, http.StatusOK},
		{"from=1&to=" + next, http.StatusNotFound},
		{"from=2&to=1", http.StatusBadRequest},
		{"from=0&to=1", http.StatusBadRequest},
		{"from=01&to=2", http.StatusBadRequest},
		{"from=1", http.StatusBadRequest},
		{"from=1&to=2&x=3", http.StatusBadRequest},
		{"from=1&from=1&to=2", http.StatusBadRequest},
		{"from=-1&to=2", http.StatusBadRequest},
		{"from=1&to=99999999999999999999999", http.StatusBadRequest},
		{"from=1&to=1099511627777", http.StatusBadRequest},
		{"from=1&to=0x10", http.StatusBadRequest},
		{"from=%2B1&to=2", http.StatusBadRequest},
	} {
		r := e.do(http.MethodGet, witness.PathConsistency+"?"+tc.q, "", nil)
		if r.Code != tc.want || r.Header().Get("Content-Type") != witness.ContentType {
			t.Fatalf("%q: %d %q", tc.q, r.Code, r.Header().Get("Content-Type"))
		}
	}
}
