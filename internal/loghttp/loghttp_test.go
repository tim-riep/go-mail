package loghttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// TestEndToEnd: the server signs, the witness cosigns over HTTP,
// heads/<n>.sig appears only with the quorum, and a client accepts it;
// growth and re-signing follow the cadence.
func TestEndToEnd(t *testing.T) {
	e := newEnv(t, 1, 1)
	if r := e.do(http.MethodGet, witness.PathHead, "", nil); r.Code != http.StatusNotFound {
		t.Fatalf("head before signing: %d", r.Code)
	}
	e.srv.Tick()
	size, _ := e.tree()
	c := e.srv.Candidate()
	if c == nil || c.Size != size {
		t.Fatal("no candidate")
	}
	if e.headFile(size) != nil {
		t.Fatal("published before any cosignature")
	}
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	pub := e.headFile(size)
	h, err := e.openHead(pub)
	if err != nil || len(h.Sigs) != 2 || h.Time != e.clk.Now().UnixMilli() {
		t.Fatalf("published head: %v", err)
	}
	// A client of the pin accepts the published head.
	cl, err := translog.Open(translog.Options{Store: e.st, Verifier: e.verifier(), IndexFile: filepath.Join(t.TempDir(), "index.json")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Refresh(e.clk.Now()); err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := cl.CheckFresh(e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	// A second round posts nothing new.
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	// Growth: within MinGap nothing is signed; after it a new candidate,
	// published only after the witness cosigned it.
	e.grow(2)
	e.clk.add(30 * time.Second)
	e.srv.Tick()
	if e.srv.Candidate().Size != size {
		t.Fatal("signed again within a minute")
	}
	e.clk.add(30 * time.Second)
	e.srv.Tick()
	if e.srv.Candidate().Size != size+2 || e.headFile(size+2) != nil {
		t.Fatal("growth")
	}
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	if e.headFile(size+2) == nil {
		t.Fatal("grown head not published")
	}
	if _, err := cl.Refresh(e.clk.Now()); err != nil {
		t.Fatalf("client after growth: %v", err)
	}
	// Without growth: no new candidate before HeadInterval, a
	// re-signature of the same size with a new time after it.
	signed := e.srv.Candidate().Time
	e.clk.add(30 * time.Minute)
	e.srv.Tick()
	if e.srv.Candidate().Time != signed {
		t.Fatal("re-signed before HeadInterval")
	}
	e.clk.add(30 * time.Minute)
	e.srv.Tick()
	c = e.srv.Candidate()
	if c.Size != size+2 || c.Time != e.clk.Now().UnixMilli() {
		t.Fatal("not re-signed after HeadInterval")
	}
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	if h, err := e.openHead(e.headFile(size + 2)); err != nil || h.Time != c.Time {
		t.Fatalf("re-signature not published: %v", err)
	}
	if _, err := cl.Refresh(e.clk.Now()); err != nil {
		t.Fatalf("client after the re-signature: %v", err)
	}
	if !strings.Contains(e.logs.String(), "head published") {
		t.Fatal("log")
	}
}

// TestQuorumTwoOfTwo: with two witnesses and quorum 2 the head is
// published only after the second cosignature.
func TestQuorumTwoOfTwo(t *testing.T) {
	e := newEnv(t, 2, 2)
	e.srv.Tick()
	size, _ := e.tree()
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	if e.headFile(size) != nil {
		t.Fatal("published with one of two")
	}
	if c := e.srv.Candidate(); len(c.Sigs) != 2 {
		t.Fatalf("candidate carries %d lines", len(c.Sigs))
	}
	// GET /head serves the candidate with the first cosignature; the
	// second witness cosigns it and posts only its own line.
	if err := e.poll(1); err != nil {
		t.Fatal(err)
	}
	h, err := e.openHead(e.headFile(size))
	if err != nil || len(h.Sigs) != 3 {
		t.Fatalf("published: %v", err)
	}
	cl, err := translog.Open(translog.Options{Store: e.st, Verifier: e.verifier(), IndexFile: filepath.Join(t.TempDir(), "i.json")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Refresh(e.clk.Now()); err != nil {
		t.Fatalf("client with quorum 2 of 2: %v", err)
	}
}

// TestForkedWitness: a witness that cosigned another tree of the same
// size refuses for good, and nothing is published.
func TestForkedWitness(t *testing.T) {
	seed, err := keys.NewSeed(nil)
	if err != nil {
		t.Fatal(err)
	}
	a := newEnvSeed(t, seed, 1, 1, nil)
	b := newEnvSeed(t, seed, 1, 1, a.ws)
	a.grow(1)
	b.vf = 7 // another assignment: another tree of the same size
	b.grow(1)
	sa, ha := a.tree()
	sb, hb := b.tree()
	if sa != sb || ha == hb {
		t.Fatal("setup")
	}
	b.srv.Tick()
	if err := b.poll(0); err != nil {
		t.Fatal(err)
	}
	if b.headFile(sb) == nil {
		t.Fatal("b not published")
	}
	a.srv.Tick()
	// The witness's state directory is shared through a.ws.
	if err := a.poll(0); !errors.Is(err, witness.ErrFork) {
		t.Fatalf("fork: %v", err)
	}
	if a.headFile(sa) != nil {
		t.Fatal("published without the witness")
	}
	a.grow(1)
	a.clk.add(time.Minute)
	a.srv.Tick()
	if err := a.poll(0); !errors.Is(err, witness.ErrFork) {
		t.Fatalf("forked witness cosigned later: %v", err)
	}
}

// TestRolledBackTree: the server with a rolled back tree.rec signs
// nothing and serves the published head; RepairTree restores tree.rec.
func TestRolledBackTree(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.grow(3)
	e.srv.Tick()
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	size, full := e.tree()
	e.writeTree(size-1, e.root(size-1))
	e.clk.add(2 * time.Hour)
	e.srv.Tick()
	if e.srv.Candidate() != nil {
		t.Fatal("candidate over a rolled back tree")
	}
	if !strings.Contains(e.logs.String(), "signing refused") {
		t.Fatal("not logged")
	}
	r := e.do(http.MethodGet, witness.PathHead, "", nil)
	if h, err := e.openHead(r.Body.Bytes()); r.Code != http.StatusOK || err != nil || h.Size != size {
		t.Fatalf("published head not served: %d", r.Code)
	}
	if err := translog.RepairTree(e.options()); err != nil {
		t.Fatal(err)
	}
	if s, h := e.tree(); s != size || h != full {
		t.Fatal("not repaired")
	}
	e.clk.add(time.Minute)
	e.srv.Tick()
	if c := e.srv.Candidate(); c == nil || c.Size != size {
		t.Fatal("no candidate after the repair")
	}
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
}

// TestInvalidEntry: an entry written past Append is covered, reported
// and skipped; the head is still published.
func TestInvalidEntry(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.srv.Tick()
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(e.path(translog.EntryPath(0)))
	if err != nil {
		t.Fatal(err)
	}
	e.appendRaw(first) // a copy of entry 0: a duplicate
	e.grow(1)
	e.start() // a new process opens the log with the invalid entry
	e.clk.add(time.Minute)
	e.srv.Tick()
	size, _ := e.tree()
	if c := e.srv.Candidate(); c == nil || c.Size != size {
		t.Fatal("no head over the invalid entry")
	}
	if !strings.Contains(e.logs.String(), "invalid entries") || !strings.Contains(e.logs.String(), "2:duplicate") {
		t.Fatalf("not reported: %s", e.logs.String())
	}
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	if e.headFile(size) == nil {
		t.Fatal("not published")
	}
	cl, err := translog.Open(translog.Options{Store: e.st, Verifier: e.verifier(), IndexFile: filepath.Join(t.TempDir(), "i.json")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Refresh(e.clk.Now()); err != nil {
		t.Fatal(err)
	}
}

// TestCrashBetweenSignAndPublish: the witness cosigned a candidate, the
// server lost it before PublishHead. The restarted server signs the same
// size with a later time (the witness accepts: same hash) or a larger
// tree (consistency proof), and publishes.
func TestCrashBetweenSignAndPublish(t *testing.T) {
	for _, grow := range []bool{false, true} {
		e := newEnv(t, 1, 1)
		e.srv.Tick()
		// The witness cosigns and stores the candidate, but the server
		// never gets the cosignature (crash before PublishHead).
		w := e.witness(0)
		c := e.srv.Candidate()
		if _, err := w.Cosign(c.Note, nil); err != nil {
			t.Fatal(err)
		}
		w.Close()
		size, _ := e.tree()
		if e.headFile(size) != nil {
			t.Fatal("published")
		}
		e.start()
		if grow {
			e.grow(2)
		}
		e.clk.add(time.Second)
		e.srv.Tick()
		if err := e.poll(0); err != nil {
			t.Fatalf("grow %v: %v", grow, err)
		}
		size, _ = e.tree()
		h, err := e.openHead(e.headFile(size))
		if err != nil || h.Time != e.clk.Now().UnixMilli() {
			t.Fatalf("grow %v: not published: %v", grow, err)
		}
	}
}

// TestCosignBodies: POST /gomail/log/cosign with foreign, invalid and
// malformed lines.
func TestCosignBodies(t *testing.T) {
	e := newEnv(t, 3, 2)
	e.srv.Tick()
	c := e.srv.Candidate()
	text, _ := c.Text()
	sig := func(signers ...note.Signer) []byte {
		b, err := note.Sign(&note.Note{Text: string(text)}, signers...)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	wsign := func(i int) note.Signer {
		data, err := os.ReadFile(e.ws[i].keyFile)
		if err != nil {
			t.Fatal(err)
		}
		s, err := note.NewSigner(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	foreign := newWit(t, t.TempDir(), 9)
	fs := func() note.Signer {
		data, _ := os.ReadFile(foreign.keyFile)
		s, err := note.NewSigner(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}()
	post := func(body []byte) int {
		return e.do(http.MethodPost, witness.PathCosign, witness.ContentType, body).Code
	}
	// Only a foreign cosignature: nothing to merge.
	if code := post(sig(e.signer, fs)); code != http.StatusBadRequest {
		t.Fatalf("foreign only: %d", code)
	}
	// Without a log signature.
	if code := post(sig(wsign(0))); code != http.StatusBadRequest {
		t.Fatalf("no log signature: %d", code)
	}
	// A known witness line with a wrong signature: 403, nothing merged.
	other := *c
	other.Time++
	otext, _ := other.Text()
	wrong, _ := note.Sign(&note.Note{Text: string(otext)}, wsign(1))
	bad := append(sig(e.signer, wsign(0)), lastLine(wrong)...)
	if code := post(bad); code != http.StatusForbidden {
		t.Fatalf("invalid line: %d", code)
	}
	if len(e.srv.Candidate().Sigs) != 1 {
		t.Fatal("merged after 403")
	}
	// A valid cosignature with a foreign line: merged without it.
	if code := post(sig(e.signer, wsign(0), fs)); code != http.StatusOK {
		t.Fatalf("with a foreign line: %d", code)
	}
	cand := e.srv.Candidate()
	if len(cand.Sigs) != 2 || bytes.Contains(cand.Note, []byte(foreign.name)) {
		t.Fatal("foreign line kept")
	}
	// The same line again: still one per key; nothing published yet.
	if code := post(sig(e.signer, wsign(0))); code != http.StatusOK || len(e.srv.Candidate().Sigs) != 2 {
		t.Fatal("repeated line")
	}
	if e.headFile(c.Size) != nil {
		t.Fatal("published below the quorum")
	}
	// Another text: 409.
	if code := post(func() []byte { b, _ := note.Sign(&note.Note{Text: string(otext)}, e.signer, wsign(1)); return b }()); code != http.StatusConflict {
		t.Fatalf("other text: %d", code)
	}
	// The second witness: published; the stored note holds only
	// verified lines.
	if code := post(sig(e.signer, wsign(1), fs)); code != http.StatusOK {
		t.Fatalf("second witness: %d", code)
	}
	stored := e.headFile(c.Size)
	if h, err := e.openHead(stored); err != nil || len(h.Sigs) != 3 || bytes.Contains(stored, []byte(foreign.name)) {
		t.Fatalf("stored: %v", err)
	}
	// A restarted server without candidate merges into the published
	// head of that text.
	e.start()
	if code := post(sig(e.signer, wsign(2))); code != http.StatusOK {
		t.Fatalf("published head: %d", code)
	}
	if h, err := e.openHead(e.headFile(c.Size)); err != nil || len(h.Sigs) != 4 {
		t.Fatalf("merged into the published head: %v", err)
	}
	// Malformed bodies.
	for name, body := range map[string][]byte{
		"empty":      nil,
		"garbage":    []byte("garbage"),
		"no head":    func() []byte { b, _ := note.Sign(&note.Note{Text: "x\n"}, e.signer, wsign(0)); return b }(),
		"two lines?": append(sig(e.signer, wsign(0)), "— x\n"...),
	} {
		if code := post(body); code != http.StatusBadRequest {
			t.Fatalf("%s: %d", name, code)
		}
	}
	if r := e.do(http.MethodPost, witness.PathCosign, "text/html", sig(e.signer, wsign(0))); r.Code != http.StatusBadRequest {
		t.Fatalf("content type: %d", r.Code)
	}
	if r := e.do(http.MethodPost, witness.PathCosign, witness.ContentType, bytes.Repeat([]byte("x"), translog.MaxHeadNote+1)); r.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too large: %d", r.Code)
	}
	// Too large without a length: read up to the limit only.
	req, _ := http.NewRequest(http.MethodPost, e.http.URL+witness.PathCosign, &endless{})
	req.Header.Set("Content-Type", witness.ContentType)
	req.ContentLength = -1
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked too large: %d", resp.StatusCode)
	}
}

// endless is a body that never ends.
type endless struct{}

func (*endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// lastLine returns the last line of a note, with newline.
func lastLine(msg []byte) []byte {
	t := bytes.TrimSuffix(msg, []byte("\n"))
	return msg[bytes.LastIndexByte(t, '\n')+1:]
}

func TestRoutes(t *testing.T) {
	e := newEnv(t, 1, 1)
	for _, tc := range []struct {
		method, target string
		code           int
	}{
		{http.MethodPost, witness.PathHead, http.StatusMethodNotAllowed},
		{http.MethodHead, witness.PathHead, http.StatusMethodNotAllowed},
		{http.MethodPost, witness.PathConsistency + "?from=1&to=2", http.StatusMethodNotAllowed},
		{http.MethodGet, witness.PathCosign, http.StatusMethodNotAllowed},
		{http.MethodGet, "/", http.StatusNotFound},
		{http.MethodGet, "/gomail/log/heads", http.StatusNotFound},
		{http.MethodGet, witness.PathConsistency + "?from=1&to=1", http.StatusNotFound},
	} {
		r := e.do(tc.method, tc.target, "", nil)
		if r.Code != tc.code || r.Header().Get("Content-Type") != witness.ContentType {
			t.Fatalf("%s %s: %d", tc.method, tc.target, r.Code)
		}
		if tc.code == http.StatusMethodNotAllowed && r.Header().Get("Allow") == "" {
			t.Fatal("Allow")
		}
	}
}

func TestConsistency(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.grow(5)
	e.srv.Tick()
	size, root := e.tree()
	for _, q := range []string{"", "from=1", "from=1&to=2&x=1", "from=1&from=1&to=2", "from=01&to=2", "from=0&to=2",
		"from=3&to=2", "from=-1&to=2", "from=1&to=1099511627777", "from=a&to=2", "from=1&to=99999999999999999999"} {
		if r := e.do(http.MethodGet, witness.PathConsistency+"?"+q, "", nil); r.Code != http.StatusBadRequest {
			t.Fatalf("%q: %d", q, r.Code)
		}
	}
	if r := e.do(http.MethodGet, witness.PathConsistency+"?from=1&to=8", "", nil); r.Code != http.StatusNotFound {
		t.Fatalf("beyond: %d", r.Code)
	}
	for from := int64(1); from <= size; from++ {
		r := e.do(http.MethodGet, witness.PathConsistency+"?from="+itoa(from)+"&to="+itoa(size), "", nil)
		if r.Code != http.StatusOK {
			t.Fatalf("from %d: %d", from, r.Code)
		}
		p, err := witness.ParseProof(r.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if err := tlog.CheckTree(p, size, root, from, e.root(from)); err != nil {
			t.Fatalf("from %d: %v", from, err)
		}
	}
	// A proof the log cannot give (tiles gone) is 500, without detail.
	if err := os.RemoveAll(e.path(translog.TilesDir)); err != nil {
		t.Fatal(err)
	}
	if r := e.do(http.MethodGet, witness.PathConsistency+"?from=1&to="+itoa(size), "", nil); r.Code != http.StatusInternalServerError || r.Body.String() != "internal error\n" {
		t.Fatalf("broken tiles: %d", r.Code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// poisonLine is a signature line with the name and key hash of a known
// key and a signature that does not verify.
func poisonLine(name string, hash uint32) string {
	b := make([]byte, 4+64)
	binary.BigEndian.PutUint32(b, hash)
	return "— " + name + " " + base64.StdEncoding.EncodeToString(b) + "\n"
}

func TestHeadUnreadable(t *testing.T) {
	e := newEnv(t, 3, 2)
	e.srv.Tick()
	for i := 0; i < 2; i++ {
		if err := e.poll(i); err != nil {
			t.Fatal(err)
		}
	}
	size, _ := e.tree()
	e.start()
	// A poisoned published head (a writer of log/ added an invalid line
	// under the name of witness 2): clients cannot open it. The server
	// opens it line by line and serves it without the poisoned line
	// (task 11b finding 5), witness 2 cosigns it, and the merge in
	// PublishHead drops the poisoned line from the file.
	w2 := e.ws[2].verifier
	poison := append(append([]byte(nil), e.headFile(size)...), poisonLine(w2.Name(), w2.KeyHash())...)
	if err := store.WriteFileAtomic(e.path(translog.HeadPath(size)), poison); err != nil {
		t.Fatal(err)
	}
	if _, err := e.openHead(poison); err == nil {
		t.Fatal("setup: poisoned head opens")
	}
	r := e.do(http.MethodGet, witness.PathHead, "", nil)
	if h, err := e.openHead(r.Body.Bytes()); r.Code != http.StatusOK || err != nil || len(h.Sigs) != 3 || h.Size != size {
		t.Fatalf("poisoned head: %d %v", r.Code, err)
	}
	if err := e.poll(2); err != nil {
		t.Fatal(err)
	}
	if h, err := e.openHead(e.headFile(size)); err != nil || len(h.Sigs) != 4 {
		t.Fatalf("not repaired: %v", err)
	}
	// A published head that does not open at all: GET /head and
	// /consistency answer 500 without detail.
	if err := store.WriteFileAtomic(e.path(translog.HeadPath(size+5)), []byte("garbage")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{witness.PathHead, witness.PathConsistency + "?from=1&to=1"} {
		if r := e.do(http.MethodGet, target, "", nil); r.Code != http.StatusInternalServerError || r.Body.String() != "internal error\n" {
			t.Fatalf("%s: %d", target, r.Code)
		}
	}
}

func TestNewConfig(t *testing.T) {
	e := newEnv(t, 1, 1)
	good := e.config()
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	other, _ := translog.NewLogVerifier(e.identity.Public().(ed25519.PublicKey))
	for name, mod := range map[string]func(c *Config){
		"no log":        func(c *Config) { c.Log = nil },
		"no signer":     func(c *Config) { c.Signer = nil },
		"other key":     func(c *Config) { c.LogKey = other },
		"no witnesses":  func(c *Config) { c.Witnesses = nil },
		"nil witness":   func(c *Config) { c.Witnesses = []note.Verifier{nil} },
		"log as wit":    func(c *Config) { c.Witnesses = []note.Verifier{e.logKey} },
		"long interval": func(c *Config) { c.HeadInterval = 2 * time.Hour },
		"gap > interv":  func(c *Config) { c.HeadInterval = time.Minute; c.MinGap = 2 * time.Minute },
		"negative":      func(c *Config) { c.MinGap = -1 },
	} {
		c := good
		mod(&c)
		if _, err := New(c); !errors.Is(err, ErrConfig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	c := good
	c.Now, c.Logger = nil, nil
	if _, err := New(c); err != nil {
		t.Fatal(err)
	}
}

// TestRun: Run signs at once and stops with the context; the HTTP server
// has the timeouts of the package.
func TestRun(t *testing.T) {
	e := newEnv(t, 1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.srv.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for e.srv.Candidate() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if e.srv.Candidate() == nil {
		t.Fatal("Run did not sign")
	}
	hs := NewHTTPServer(e.srv)
	if hs.ReadHeaderTimeout == 0 || hs.ReadTimeout == 0 || hs.WriteTimeout == 0 || hs.IdleTimeout == 0 || hs.MaxHeaderBytes == 0 || hs.ErrorLog == nil {
		t.Fatal("timeouts")
	}
}

// TestSignerNotCovering: a signer of an unlogged generation signs
// nothing; the candidate is dropped and the published head served.
func TestSignerNotCovering(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.srv.Tick()
	if err := e.poll(0); err != nil {
		t.Fatal(err)
	}
	seed, _ := keys.NewSeed(nil)
	k, _ := keys.DerivePlatform(seed).IngestKey(1)
	s, _ := translog.NewLogSigner(k)
	v, _ := translog.NewLogVerifier(k.Public().(ed25519.PublicKey))
	c := e.config()
	c.Signer, c.LogKey = s, v
	srv, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	srv.Tick()
	if srv.Candidate() != nil {
		t.Fatal("candidate of a foreign key")
	}
	if !strings.Contains(e.logs.String(), translog.ErrHead.Error()) {
		t.Fatal("reason not logged")
	}
	if reason(errors.New("x")) != "unexpected error" {
		t.Fatal("reason of a foreign error")
	}
}
