package translog

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// t0 is the start of the test clock (ms since 1970).
const t0 int64 = 1_800_000_000_000

const testOrigin = "gomail-test"

// twit is a test witness.
type twit struct {
	name     string
	signer   note.Signer
	verifier note.Verifier
	pub      ed25519.PublicKey
}

func newWitnesses(t testing.TB, n int) []twit {
	t.Helper()
	out := make([]twit, n)
	for i := range out {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("witness-%d", i)
		v, err := NewWitnessVerifier(name, pub)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = twit{name: name, signer: &edSigner{name: name, hash: v.KeyHash(), priv: priv}, verifier: v, pub: pub}
	}
	return out
}

// edSigner is a note signer of an Ed25519 key (note has no constructor
// from a raw key).
type edSigner struct {
	name string
	hash uint32
	priv ed25519.PrivateKey
}

func (s *edSigner) Name() string                    { return s.name }
func (s *edSigner) KeyHash() uint32                 { return s.hash }
func (s *edSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }

// tplat is a test platform: the derivation root of its keys.
type tplat struct {
	root *keys.PlatformRoot
}

func newPlat(t testing.TB) *tplat {
	t.Helper()
	seed, err := keys.NewSeed(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &tplat{root: keys.DerivePlatform(seed)}
}

func (p *tplat) identity(t testing.TB, g uint32) ed25519.PrivateKey {
	t.Helper()
	k, err := p.root.IdentityKey(g)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (p *tplat) ingest(t testing.TB, g uint32) ed25519.PrivateKey {
	t.Helper()
	k, err := p.root.IngestKey(g)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (p *tplat) admin(t testing.TB, g uint32) ed25519.PrivateKey {
	t.Helper()
	k, err := p.root.AdminKey(g)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ids returns the identity list of generations 1 to n.
func (p *tplat) ids(t testing.TB, n uint32) []Identity {
	t.Helper()
	var out []Identity
	for g := uint32(1); g <= n; g++ {
		out = append(out, Identity{Gen: g, Pub: p.identity(t, g).Public().(ed25519.PublicKey)})
	}
	return out
}

// cert returns a certificate of role and gen, signed by identity
// generation idGen.
func (p *tplat) cert(t testing.TB, role keys.Role, gen, idGen uint32, validFrom int64) []byte {
	t.Helper()
	var priv ed25519.PrivateKey
	if role == keys.RoleIngest {
		priv = p.ingest(t, gen)
	} else {
		priv = p.admin(t, gen)
	}
	c, err := keys.NewPlatformCert(p.identity(t, idGen), idGen, role, gen, priv.Public().(ed25519.PublicKey), validFrom)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// succ returns identity-<gen>.succ signed by generation gen-1.
func (p *tplat) succ(t testing.TB, gen uint32, validFrom int64) []byte {
	t.Helper()
	s, err := keys.NewPlatformSuccession(p.identity(t, gen-1), gen, p.identity(t, gen).Public().(ed25519.PublicKey), validFrom)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tuser is a test user.
type tuser struct {
	root  *keys.UserRoot
	id    store.ID
	certs []*keys.GenerationCert
}

func newUser(t testing.TB) *tuser {
	t.Helper()
	seed, err := keys.NewSeed(nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.NewID(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &tuser{root: keys.DeriveUser(seed), id: id}
}

func (u *tuser) identity(t testing.TB, g uint32) ed25519.PrivateKey {
	t.Helper()
	k, err := u.root.IdentityKey(g)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// rec returns the signed user.rec with generations 1 to gens.
func (u *tuser) rec(t testing.TB, gens uint32) []byte {
	t.Helper()
	root, err := u.root.RootKey()
	if err != nil {
		t.Fatal(err)
	}
	for g := uint32(len(u.certs)) + 1; g <= gens; g++ {
		uw, err := u.root.UnwrapKey(g)
		if err != nil {
			t.Fatal(err)
		}
		c, err := keys.NewGenerationCert(root, g, u.identity(t, g).Public().(ed25519.PublicKey), uw.PublicKey(), t0)
		if err != nil {
			t.Fatal(err)
		}
		u.certs = append(u.certs, c)
	}
	su := &store.User{ID: u.id, RootPub: root.Public().(ed25519.PublicKey), Generations: u.certs[:gens]}
	if err := su.Sign(root); err != nil {
		t.Fatal(err)
	}
	b, err := su.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func member(u *tuser, gen uint32) store.Member {
	return store.Member{Kind: store.MemberUser, ID: u.id, Gen: gen}
}

// mkEpoch returns epoch n of mbx after prev (nil for n = 1), signed by
// signer with generation gen.
func mkEpoch(t testing.TB, mbx store.ID, n uint32, prev []byte, signer *tuser, gen uint32, members []store.Member, begin int64) []byte {
	t.Helper()
	content, _ := ecdh.X25519().GenerateKey(rand.Reader)
	meta, _ := ecdh.X25519().GenerateKey(rand.Reader)
	e := &store.Epoch{MailboxID: mbx, Number: n, Begin: begin, Reason: store.ReasonRegular, Suite: envelope.Suite1,
		ContentPub: content.PublicKey(), MetaPub: meta.PublicKey(), Members: members, SignerID: signer.id, SignerGen: gen}
	if n > 1 {
		e.PrevHash = store.EpochHash(prev)
	}
	if err := e.Sign(signer.identity(t, gen)); err != nil {
		t.Fatal(err)
	}
	b, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tenv is a data directory with a platform, an operator log and a
// simulated server that signs heads.
type tenv struct {
	t      testing.TB
	st     *store.Store
	p      *tplat
	idGen  uint32 // identity generations of the pin
	ws     []twit
	min    int
	op     Operator
	now    time.Time
	signer note.Signer // log signer (current ingest generation)
}

// newEnv creates a platform with n witnesses (quorum min), certificates
// admin-1 and ingest-1 (valid from t0 - 1 day) in platform/ and in the
// log, and an operator log.
func newEnv(t testing.TB, n, min int) *tenv {
	t.Helper()
	return newEnvWith(t, newPlat(t), newWitnesses(t, n), min)
}

func newEnvWith(t testing.TB, p *tplat, ws []twit, min int) *tenv {
	t.Helper()
	st, err := store.Init(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	e := &tenv{t: t, st: st, p: p, idGen: 1, ws: ws, min: min, now: time.UnixMilli(t0)}
	e.op = e.openOp()
	for _, c := range []struct {
		name string
		role keys.Role
	}{{"admin-1.cert", keys.RoleAdmin}, {"ingest-1.cert", keys.RoleIngest}} {
		data := p.cert(t, c.role, 1, 1, t0-day)
		if err := st.WritePlatformFile(c.name, data); err != nil {
			t.Fatal(err)
		}
		e.mustAppend(KindPlatform, data)
	}
	e.signer = e.logSigner(1)
	return e
}

const day = int64(24 * time.Hour / time.Millisecond)
const hour = int64(time.Hour / time.Millisecond)

func (e *tenv) openOp() Operator {
	e.t.Helper()
	l, err := Open(Options{Store: e.st, Identities: e.p.ids(e.t, e.idGen), Known: e.known()})
	if err != nil {
		e.t.Fatal(err)
	}
	return l.(Operator)
}

func (e *tenv) known() note.Verifiers {
	var vs []note.Verifier
	for g := uint32(1); g <= 3; g++ {
		v, err := NewLogVerifier(e.p.ingest(e.t, g).Public().(ed25519.PublicKey))
		if err != nil {
			e.t.Fatal(err)
		}
		vs = append(vs, v)
	}
	for _, w := range e.ws {
		vs = append(vs, w.verifier)
	}
	return note.VerifierList(vs...)
}

func (e *tenv) logSigner(g uint32) note.Signer {
	e.t.Helper()
	s, err := NewLogSigner(e.p.ingest(e.t, g))
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *tenv) mustAppend(kind Kind, content []byte) int64 {
	e.t.Helper()
	i, err := e.op.Append(kind, content)
	if err != nil {
		e.t.Fatalf("append %v: %v", kind, err)
	}
	return i
}

func (e *tenv) tree() treeState {
	e.t.Helper()
	tr, err := (&files{root: e.st.Root}).readTree()
	if err != nil {
		e.t.Fatal(err)
	}
	return tr
}

// headText returns the head of the committed tree at time ms.
func (e *tenv) headOf(ms int64) *Head {
	tr := e.tree()
	return &Head{Origin: testOrigin, Size: tr.Size, Hash: tr.Hash, Time: ms}
}

// sign signs h with the given signers and returns the note.
func sign(t testing.TB, h *Head, signers ...note.Signer) []byte {
	t.Helper()
	text, err := h.Text()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := note.Sign(&note.Note{Text: string(text)}, signers...)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// publish writes heads/<size>.sig for h signed by the given signers.
func (e *tenv) publish(h *Head, signers ...note.Signer) {
	e.t.Helper()
	if err := store.WriteFileAtomic(filepath.Join(e.st.Root, filepath.FromSlash(HeadPath(h.Size))), sign(e.t, h, signers...)); err != nil {
		e.t.Fatal(err)
	}
}

// all returns the log signer and every witness.
func (e *tenv) all() []note.Signer {
	out := []note.Signer{e.signer}
	for _, w := range e.ws {
		out = append(out, w.signer)
	}
	return out
}

// head publishes a head of the committed tree at the current clock,
// signed by the log and every witness.
func (e *tenv) head() *Head {
	e.t.Helper()
	h := e.headOf(e.now.UnixMilli())
	e.publish(h, e.all()...)
	return h
}

func (e *tenv) verifier() *Verifier {
	var wv []note.Verifier
	for _, w := range e.ws {
		wv = append(wv, w.verifier)
	}
	ids := e.p.ids(e.t, e.idGen)
	return &Verifier{Origin: testOrigin, Witnesses: wv, MinWitnesses: e.min, Identity: ids[len(ids)-1], Identities: ids,
		Now: func() time.Time { return e.now }}
}

// client opens a client log with a fresh Verifier and audit index.
func (e *tenv) client() (*fileLog, *Verifier) {
	e.t.Helper()
	v := e.verifier()
	l, err := Open(Options{Store: e.st, Verifier: v, IndexFile: filepath.Join(e.t.TempDir(), "index.json")})
	if err != nil {
		e.t.Fatal(err)
	}
	return l.(*fileLog), v
}

func (e *tenv) path(rel string) string { return filepath.Join(e.st.Root, filepath.FromSlash(rel)) }

// addr returns a signed address assignment.
func (e *tenv) addr(t testing.TB, a string, mbx store.ID, validFrom int64, adminGen uint32) []byte {
	t.Helper()
	as := &store.AddressAssignment{Address: a, MailboxID: mbx, ValidFrom: validFrom, AdminGen: adminGen}
	if err := as.Sign(e.p.admin(t, adminGen)); err != nil {
		t.Fatal(err)
	}
	b, err := as.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newMbx(t testing.TB) store.ID {
	t.Helper()
	id, err := store.NewID(nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// proofTree returns the operator's tree for proofs.
func (e *tenv) hashReader() tlog.HashReader {
	return (&files{root: e.st.Root}).reader(e.tree())
}

type (
	ed25519PublicKey = ed25519.PublicKey
	noteSigner       = note.Signer
)
