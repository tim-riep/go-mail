package loghttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
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

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

const (
	origin = "gomail-test-log"
	t0     = int64(1_800_000_000_000)
)

// clock is the injected clock shared by server and witnesses.
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

// logBuf collects the server's log lines.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// wit is a witness of the tests: its key file and verifier.
type wit struct {
	name     string
	keyFile  string
	verifier note.Verifier
	pub      ed25519.PublicKey
	state    string
}

// env is a data directory with a platform, the operator log of the
// server, the log side of the server over HTTP and witnesses.
type env struct {
	t        testing.TB
	dir      string
	st       *store.Store
	plat     *keys.PlatformRoot
	identity ed25519.PrivateKey
	ingest   ed25519.PrivateKey
	admin    ed25519.PrivateKey
	signer   note.Signer
	logKey   note.Verifier
	logVKey  string
	ws       []*wit
	min      int
	clk      *clock
	op       translog.Operator
	srv      *Server
	http     *httptest.Server
	logs     *logBuf
	vf       int64
	mbx      store.ID
}

func newEnv(t testing.TB, n, min int) *env {
	t.Helper()
	seed, err := keys.NewSeed(nil)
	if err != nil {
		t.Fatal(err)
	}
	return newEnvSeed(t, seed, n, min, nil)
}

// newEnvSeed builds an environment from a platform seed and, when ws is
// given, the same witnesses.
func newEnvSeed(t testing.TB, seed *keys.Seed, n, min int, ws []*wit) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Init(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	p := keys.DerivePlatform(seed)
	e := &env{t: t, dir: dir, st: st, plat: p, min: min, clk: &clock{t: time.UnixMilli(t0)}, logs: &logBuf{}}
	if e.identity, err = p.IdentityKey(1); err != nil {
		t.Fatal(err)
	}
	if e.ingest, err = p.IngestKey(1); err != nil {
		t.Fatal(err)
	}
	if e.admin, err = p.AdminKey(1); err != nil {
		t.Fatal(err)
	}
	if e.signer, err = translog.NewLogSigner(e.ingest); err != nil {
		t.Fatal(err)
	}
	ipub := e.ingest.Public().(ed25519.PublicKey)
	if e.logKey, err = translog.NewLogVerifier(ipub); err != nil {
		t.Fatal(err)
	}
	if e.logVKey, err = note.NewEd25519VerifierKey(translog.LogSignerName, ipub); err != nil {
		t.Fatal(err)
	}
	e.ws = ws
	for i := len(ws); i < n; i++ {
		e.ws = append(e.ws, newWit(t, dir, i))
	}
	for _, w := range e.ws {
		w.state = filepath.Join(dir, "state-"+w.name)
	}
	list := witness.Witnesses{Min: min}
	for _, w := range e.ws {
		list.List = append(list.List, witness.Key{Name: w.name, Pub: w.pub})
	}
	wr, err := list.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WritePlatformFile("witnesses.rec", wr); err != nil {
		t.Fatal(err)
	}
	e.op = e.openOp()
	for _, c := range []struct {
		name string
		role keys.Role
		key  ed25519.PrivateKey
	}{{"admin-1.cert", keys.RoleAdmin, e.admin}, {"ingest-1.cert", keys.RoleIngest, e.ingest}} {
		cert, err := keys.NewPlatformCert(e.identity, 1, c.role, 1, c.key.Public().(ed25519.PublicKey), t0-24*3600*1000)
		if err != nil {
			t.Fatal(err)
		}
		data, err := cert.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := st.WritePlatformFile(c.name, data); err != nil {
			t.Fatal(err)
		}
		if _, err := e.op.Append(translog.KindPlatform, data); err != nil {
			t.Fatal(err)
		}
	}
	if e.mbx, err = store.NewID(nil); err != nil {
		t.Fatal(err)
	}
	e.start()
	return e
}

func newWit(t testing.TB, dir string, i int) *wit {
	t.Helper()
	name := "witness-" + string(rune('a'+i))
	kf := filepath.Join(dir, name+".key")
	vkey, err := witness.Keygen(name, kf, nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(vkey, "+", 3)
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 33 {
		t.Fatal("verifier key")
	}
	pub := ed25519.PublicKey(raw[1:])
	v, err := translog.NewWitnessVerifier(name, pub)
	if err != nil {
		t.Fatal(err)
	}
	return &wit{name: name, keyFile: kf, verifier: v, pub: pub}
}

func (e *env) verifiers() []note.Verifier {
	var out []note.Verifier
	for _, w := range e.ws {
		out = append(out, w.verifier)
	}
	return out
}

func (e *env) ids() []translog.Identity {
	return []translog.Identity{{Gen: 1, Pub: e.identity.Public().(ed25519.PublicKey)}}
}

// options are the options of the operator log as cmd/gomail-server
// opens it: Known holds the witnesses of witnesses.rec (task 11b
// finding 5).
func (e *env) options() translog.Options {
	return translog.Options{Store: e.st, Identities: e.ids(), Origin: origin, Known: note.VerifierList(e.verifiers()...),
		Witnesses: e.verifiers(), MinWitnesses: e.min}
}

func (e *env) openOp() translog.Operator {
	e.t.Helper()
	l, err := translog.Open(e.options())
	if err != nil {
		e.t.Fatal(err)
	}
	return l.(translog.Operator)
}

func (e *env) config() Config {
	return Config{Log: e.op, Signer: e.signer, LogKey: e.logKey, Witnesses: e.verifiers(), Now: e.clk.Now,
		Logger: slog.New(slog.NewTextHandler(e.logs, nil))}
}

// start runs a new server process: a new operator log and a new log side
// without candidate behind a new HTTP server.
func (e *env) start() {
	e.t.Helper()
	if e.http != nil {
		e.http.Close()
	}
	e.op = e.openOp()
	srv, err := New(e.config())
	if err != nil {
		e.t.Fatal(err)
	}
	e.srv = srv
	e.http = httptest.NewServer(srv)
	e.t.Cleanup(e.http.Close)
}

// witness opens witness i against the current server.
func (e *env) witness(i int) *witness.Witness {
	e.t.Helper()
	w, err := witness.New(witness.Config{Log: e.http.URL, LogKeys: []string{e.logVKey}, Origin: origin,
		KeyFile: e.ws[i].keyFile, StateDir: e.ws[i].state, Now: e.clk.Now})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { w.Close() })
	return w
}

// poll runs one round of witness i and closes it again.
func (e *env) poll(i int) error {
	e.t.Helper()
	w := e.witness(i)
	defer w.Close()
	return w.Poll(context.Background())
}

// grow appends n address assignments.
func (e *env) grow(n int) {
	e.t.Helper()
	for i := 0; i < n; i++ {
		e.vf++
		a := &store.AddressAssignment{Address: "info@example.org", MailboxID: e.mbx, ValidFrom: t0 + e.vf, AdminGen: 1}
		if err := a.Sign(e.admin); err != nil {
			e.t.Fatal(err)
		}
		data, err := a.Encode()
		if err != nil {
			e.t.Fatal(err)
		}
		if _, err := e.op.Append(translog.KindAddress, data); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) path(rel string) string { return filepath.Join(e.st.Root, filepath.FromSlash(rel)) }

// headFile returns heads/<size>.sig or nil.
func (e *env) headFile(size int64) []byte {
	b, err := os.ReadFile(e.path(translog.HeadPath(size)))
	if err != nil {
		return nil
	}
	return b
}

// tree returns the committed size and root of tree.rec.
func (e *env) tree() (int64, tlog.Hash) {
	e.t.Helper()
	data, err := os.ReadFile(e.path(translog.TreeFile))
	if err != nil {
		e.t.Fatal(err)
	}
	r, err := rec.Decode(translog.TreeSchema, data)
	if err != nil {
		e.t.Fatal(err)
	}
	var h tlog.Hash
	copy(h[:], r.Bytes(2))
	return r.I64(1), h
}

// writeTree writes tree.rec.
func (e *env) writeTree(size int64, h tlog.Hash) {
	e.t.Helper()
	b, err := rec.New(translog.TreeSchema).SetI64(1, size).SetBytes(2, h[:]).Encode()
	if err != nil {
		e.t.Fatal(err)
	}
	if err := store.WriteFileAtomic(e.path(translog.TreeFile), b); err != nil {
		e.t.Fatal(err)
	}
}

// tiles reads the tiles under log/tree/.
type tiles struct{ e *env }

func (t tiles) Height() int { return translog.TileHeight }

func (t tiles) ReadTiles(ts []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(ts))
	for i, x := range ts {
		b, err := os.ReadFile(t.e.path(translog.TilePath(x)))
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

func (t tiles) SaveTiles([]tlog.Tile, [][]byte) {}

func (e *env) reader(size int64, h tlog.Hash) tlog.HashReader {
	return tlog.TileHashReader(tlog.Tree{N: size, Hash: h}, tiles{e})
}

// root returns the root hash of size n of the committed tree.
func (e *env) root(n int64) tlog.Hash {
	e.t.Helper()
	size, h := e.tree()
	r, err := tlog.TreeHash(n, e.reader(size, h))
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// appendRaw writes data as the next entry past Append (no validity
// rules): entry, tiles and tree.rec, as a writer of log/ could.
func (e *env) appendRaw(data []byte) {
	e.t.Helper()
	n, h := e.tree()
	if err := store.CreateFileAtomic(e.path(translog.EntryPath(n)), data); err != nil {
		e.t.Fatal(err)
	}
	old := e.reader(n, h)
	hashes, err := tlog.StoredHashes(n, data, old)
	if err != nil {
		e.t.Fatal(err)
	}
	base := tlog.StoredHashCount(n)
	comb := tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(idx))
		for i, x := range idx {
			if x >= base {
				out[i] = hashes[x-base]
				continue
			}
			hs, err := old.ReadHashes([]int64{x})
			if err != nil {
				return nil, err
			}
			out[i] = hs[0]
		}
		return out, nil
	})
	for _, t := range tlog.NewTiles(translog.TileHeight, n, n+1) {
		b, err := tlog.ReadTileData(t, comb)
		if err != nil {
			e.t.Fatal(err)
		}
		p := e.path(translog.TilePath(t))
		if err := store.MkdirAll(filepath.Dir(p)); err != nil {
			e.t.Fatal(err)
		}
		if err := store.WriteFileAtomic(p, b); err != nil {
			e.t.Fatal(err)
		}
	}
	root, err := tlog.TreeHash(n+1, comb)
	if err != nil {
		e.t.Fatal(err)
	}
	e.writeTree(n+1, root)
}

// openHead opens a signed head with the log key and every witness.
func (e *env) openHead(msg []byte) (*translog.Head, error) {
	return translog.OpenHead(msg, note.VerifierList(append([]note.Verifier{e.logKey}, e.verifiers()...)...))
}

// do sends a request to the handler directly.
func (e *env) do(method, target, ctype string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	return w
}

// client returns a client Verifier of the pin of this platform.
func (e *env) verifier() *translog.Verifier {
	ids := e.ids()
	return &translog.Verifier{Origin: origin, Witnesses: e.verifiers(), MinWitnesses: e.min, Identity: ids[0], Identities: ids,
		Now: e.clk.Now}
}

var _ http.Handler = (*Server)(nil)

func newRequest(method, target, ctype string, body []byte) *http.Request {
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	return r
}

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }
