// Package testenv builds a complete development platform for tests: a
// data directory from the development ceremony, users with key stores,
// mailboxes and address assignments, and a controllable clock. It is used
// only by tests.
package testenv

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/translog/translogtest"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Clock is a settable clock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// Now returns the current time of the clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Set sets the clock.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Env is a development platform.
type Env struct {
	T         testing.TB
	Base      string
	Store     *store.Store
	Log       translog.Log
	Pin       *store.PlatformPin
	IngestKey ed25519.PrivateKey
	AdminKey  ed25519.PrivateKey
	KeyDir    string
	Clock     *Clock
	Warnings  *Warnings
	// Witness is the pinned witness (quorum 1 of 1) and WitnessSigner
	// its note signer, for tests that cosign heads; WitnessKeyFile holds
	// its note signer key (0600, outside the data directory) for
	// witness.Config.KeyFile.
	Witness        witness.Key
	WitnessSigner  note.Signer
	WitnessKeyFile string
	// Operator is the operator log of the data directory in an
	// environment from NewLogged (Log is the same log), nil in one from
	// New.
	Operator translog.Operator
	// AutoHeads lets the server of the platform sign a head of the
	// committed tree, cosigned by the witness, and publish it before
	// every Refresh of a client (Config.BeforeRefresh), as gomail-server
	// and the witness do on their cadence. On by default; tests of the
	// freshness rules (2.3) and of withheld entries switch it off and
	// publish heads themselves (PublishHead).
	AutoHeads bool

	// logOp is the operator log of the data directory in every
	// environment: the clients append to and check against this log
	// (their own client logs, task 14), the platform signs its heads.
	logOp   translog.Operator
	headsMu sync.Mutex
}

// Warnings collects client warnings.
type Warnings struct {
	mu   sync.Mutex
	list []string
}

// Add records a warning.
func (w *Warnings) Add(s string) {
	w.mu.Lock()
	w.list = append(w.list, s)
	w.mu.Unlock()
}

// Take returns and clears the warnings.
func (w *Warnings) Take() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	l := w.list
	w.list = nil
	return l
}

// Start is the default clock start: 2026-10-26 10:00 UTC.
var Start = time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)

// New runs the development ceremony in a temporary directory; it exists
// only in a build with the tag gomail_dev (ceremony.InitDev), and
// without the tag New and NewLogged skip the test (task 15b point 4: the
// tests on a test platform run with "go test -tags
// gomail_dev,gomail_test"). The server of the environment (Log, for
// ingest) uses the accepting placeholder translogtest.Unverified; the
// clients always work with their client log on the transparency log of
// the data directory (task 14), into which InitDev wrote the certificates
// and the environment writes every address assignment, forged epoch and
// rotation.
func New(t testing.TB) *Env {
	t.Helper()
	return newEnv(t, false)
}

// NewLogged is New with the transparency log on the server side too: Log
// and Operator are the operator log of the data directory, opened
// against the identity list, origin and witnesses of the pin as
// gomail-server opens it, so that ingest checks every user, epoch,
// address and certificate against it.
func NewLogged(t testing.TB) *Env {
	t.Helper()
	return newEnv(t, true)
}

// RequireDev skips the test in a build without the tag gomail_dev, which
// has no development ceremony (ceremony.DevBuild, task 15b point 4):
// every test on a test platform needs it, also one that builds its
// platform in a child process.
func RequireDev(tb testing.TB) {
	tb.Helper()
	if !ceremony.DevBuild {
		tb.Skip("needs the development ceremony (ceremony.InitDev): go test -tags gomail_dev,gomail_test")
	}
}

func newEnv(t testing.TB, logged bool) *Env {
	t.Helper()
	RequireDev(t)
	base := t.TempDir()
	unv, err := translogtest.NewUnverified(true)
	if err != nil {
		t.Fatal(err)
	}
	var log translog.Log = unv
	// One witness, quorum 1 of 1 (2.7: the PoC runs one witness).
	// witness.Keygen is built by task 08; the key comes from note.
	skey, vkey, err := note.GenerateKey(rand.Reader, WitnessName)
	if err != nil {
		t.Fatal(err)
	}
	wsigner, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(vkeyData(vkey))
	if err != nil || len(raw) != 1+ed25519.PublicKeySize {
		t.Fatal("witness key", err)
	}
	wkey := witness.Key{Name: WitnessName, Pub: ed25519.PublicKey(raw[1:])}
	wkeyFile := filepath.Join(base, "witness.key")
	if err := store.CreatePrivateFileAtomic(wkeyFile, []byte(skey+"\n")); err != nil {
		t.Fatal(err)
	}
	clock := &Clock{t: Start}
	res, err := ceremony.InitDev(filepath.Join(base, "data"), filepath.Join(base, "keys"), clock.Now().Add(-time.Hour), []witness.Key{wkey}, 1)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(base, "data"))
	if err != nil {
		t.Fatal(err)
	}
	logOp := openOperator(t, st, res.Pin)
	var op translog.Operator
	if logged {
		op = logOp
		log = op
	}
	ingest, _, err := ceremony.ReadKey(filepath.Join(res.KeyDir, ceremony.IngestKeyFile), store.KeyRoleIngest)
	if err != nil {
		t.Fatal(err)
	}
	admin, _, err := ceremony.ReadKey(filepath.Join(res.KeyDir, ceremony.AdminKeyFile), store.KeyRoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return &Env{T: t, Base: base, Store: st, Log: log, Pin: res.Pin, IngestKey: ingest, AdminKey: admin, KeyDir: res.KeyDir,
		Clock: clock, Warnings: &Warnings{}, Witness: wkey, WitnessSigner: wsigner, WitnessKeyFile: wkeyFile, Operator: op,
		AutoHeads: true, logOp: logOp}
}

// recordLog is the log into which ForgeEpoch and Rotate append: Log in
// an environment from NewLogged (a test may put a placeholder there to
// leave a record unlogged), the operator log of the data directory in
// one from New, whose Log is the server's placeholder.
func (e *Env) recordLog() translog.Log {
	if e.Operator != nil {
		return e.Log
	}
	return e.logOp
}

// LogOperator returns the operator log of the data directory into which
// the clients of the environment append (in an environment from
// NewLogged the same as Operator).
func (e *Env) LogOperator() translog.Operator { return e.logOp }

// PublishHead lets the server sign a head of the committed tree at the
// time of the clock (Operator.SignHead with the ingest key, Q4), the
// witness cosign it and the server publish it (PublishHead), as the log
// side of gomail-server and gomail-witness do. It returns the head.
func (e *Env) PublishHead() (*translog.Head, error) {
	e.headsMu.Lock()
	defer e.headsMu.Unlock()
	signer, err := translog.NewLogSigner(e.IngestKey)
	if err != nil {
		return nil, err
	}
	h, err := e.logOp.SignHead(signer, e.Clock.Now())
	if err != nil {
		return nil, err
	}
	text, err := h.Text()
	if err != nil {
		return nil, err
	}
	msg, err := note.Sign(&note.Note{Text: string(text)}, signer, e.WitnessSigner)
	if err != nil {
		return nil, err
	}
	c := *h
	c.Note = msg
	if err := e.logOp.PublishHead(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// MustPublishHead is PublishHead that fails the test on an error.
func (e *Env) MustPublishHead() *translog.Head {
	e.T.Helper()
	h, err := e.PublishHead()
	if err != nil {
		e.T.Fatal(err)
	}
	return h
}

// beforeRefresh publishes a head before a client refreshes, while
// AutoHeads is on. A head that cannot be signed (the clock of a test was
// set back) is skipped: the client then judges the heads there are.
func (e *Env) beforeRefresh() {
	if !e.AutoHeads {
		return
	}
	e.PublishHead()
}

// openOperator opens the operator log of st as gomail-server does: the
// identity list and origin of the pin, the witnesses and quorum of
// platform/witnesses.rec.
func openOperator(t testing.TB, st *store.Store, pin *store.PlatformPin) translog.Operator {
	t.Helper()
	ids := make([]translog.Identity, 0, len(pin.Identities))
	for _, id := range pin.Identities {
		ids = append(ids, translog.Identity{Gen: id.Gen, Pub: id.Pub})
	}
	wr, err := st.ReadPlatformFile("witnesses.rec")
	if err != nil {
		t.Fatal(err)
	}
	ws, err := witness.DecodeWitnesses(wr)
	if err != nil {
		t.Fatal(err)
	}
	wvs, err := ws.Verifiers()
	if err != nil {
		t.Fatal(err)
	}
	l, err := translog.Open(translog.Options{Store: st, Identities: ids, Origin: pin.Origin, Known: note.VerifierList(wvs...),
		Witnesses: wvs, MinWitnesses: ws.Min})
	if err != nil {
		t.Fatal(err)
	}
	return l.(translog.Operator)
}

// OpenOperator opens another operator log on the data directory, as a
// restarted server or a second process would.
func (e *Env) OpenOperator() translog.Operator {
	e.T.Helper()
	return openOperator(e.T, e.Store, e.Pin)
}

// WitnessName is the name of the witness of a test platform.
const WitnessName = "testenv-witness"

// ClientConfig returns the configuration of a client in dir: the pin of
// the development ceremony (accepted with AllowDevIdentity, which only
// tests set) and the head publication of the platform before every
// Refresh (AutoHeads).
func (e *Env) ClientConfig(dir string) client.Config {
	return client.Config{Store: e.Store, Dir: dir, Pin: e.Pin, AllowDevIdentity: true, BeforeRefresh: e.beforeRefresh,
		Now: e.Clock.Now, Warn: e.Warnings.Add}
}

// AssignAddress logs the assignment of addr to mailbox mbx, signed with
// the admin key and valid from now (2.3), as "gomail-server address add"
// does, in every environment: the clients check every recipient against
// the log. The caller changes addresses.json.
func (e *Env) AssignAddress(addr string, mbx store.ID) {
	e.T.Helper()
	a, err := store.NormalizeAddress(addr)
	if err != nil {
		e.T.Fatal(err)
	}
	as := &store.AddressAssignment{Address: a, MailboxID: mbx, ValidFrom: e.Clock.Now().UnixMilli(), AdminGen: 1}
	if err := as.Sign(e.AdminKey); err != nil {
		e.T.Fatal(err)
	}
	enc, err := as.Encode()
	if err != nil {
		e.T.Fatal(err)
	}
	if _, err := e.logOp.Append(translog.KindAddress, enc); err != nil {
		e.T.Fatal(err)
	}
}

// Echo answers the seed confirmation correctly.
type Echo struct {
	words  []string
	shares [][]string
}

// ShowWords remembers the words.
func (p *Echo) ShowWords(w []string) error { p.words = append([]string(nil), w...); return nil }

// AskWord returns the word at pos.
func (p *Echo) AskWord(pos int) (string, error) { return p.words[pos-1], nil }

// Words returns the words shown last (for a recovery seed in tests).
func (p *Echo) Words() []string { return append([]string(nil), p.words...) }

// ShowShares remembers the shares (client.SharePrompter).
func (p *Echo) ShowShares(s [][]string) error {
	p.shares = nil
	for _, w := range s {
		p.shares = append(p.shares, append([]string(nil), w...))
	}
	return nil
}

// Shares returns the shares shown last.
func (p *Echo) Shares() [][]string {
	var out [][]string
	for _, w := range p.shares {
		out = append(out, append([]string(nil), w...))
	}
	return out
}

// Passphrase of test users.
var Passphrase = []byte("correct horse battery staple")

// User is a registered user with an open client.
type User struct {
	Dir    string
	ID     store.ID
	Client *client.Client
	// Words are the seed words shown at Keygen, kept only by tests so
	// that Rotate can derive a later generation.
	Words []string
}

// NewUser creates, registers and opens a user.
func (e *Env) NewUser(name string) *User {
	e.T.Helper()
	dir := filepath.Join(e.Base, "clients", name)
	cfg := e.ClientConfig(dir)
	echo := &Echo{}
	if _, err := client.Keygen(cfg, Passphrase, echo); err != nil {
		e.T.Fatal(err)
	}
	code, err := e.Store.CreateInvite(e.Clock.Now().UnixMilli())
	if err != nil {
		e.T.Fatal(err)
	}
	id, err := client.Register(cfg, code)
	if err != nil {
		e.T.Fatal(err)
	}
	c, err := client.Open(cfg, Passphrase)
	if err != nil {
		e.T.Fatal(err)
	}
	e.T.Cleanup(c.Close)
	return &User{Dir: dir, ID: id, Client: c, Words: echo.Words()}
}

// DeviceLost runs client.DeviceLost for u with its seed words (the client
// of u is closed first, as gomailctl device lost runs as its own process)
// and opens the client again. It returns the new generation; an error of
// DeviceLost fails the test.
func (e *Env) DeviceLost(u *User) uint32 {
	e.T.Helper()
	u.Client.Close()
	gen, err := client.DeviceLost(e.ClientConfig(u.Dir), Passphrase, u.Words)
	if err != nil {
		e.T.Fatal(err)
	}
	e.Reopen(u)
	return gen
}

// Rotate moves u to its next generation like a lost device, but without
// anything client.DeviceLost does in the mailboxes (no wraps, epoch or
// files issued again): from u's seed it derives identity and unwrap key
// of generation current+1, appends their certificate (which revokes the
// current generation) to user.rec signed by the root, writes user.rec to
// the data directory and the client directory, the key store with the
// new generation, appends user.rec to the operator log of the data
// directory and opens the client again.
// It returns the new generation.
func (e *Env) Rotate(u *User) uint32 {
	e.T.Helper()
	fail := func(err error) {
		e.T.Helper()
		if err != nil {
			e.T.Fatal(err)
		}
	}
	seed, err := keys.SeedFromWords(u.Words)
	fail(err)
	defer seed.Zero()
	d := keys.DeriveUser(seed)
	defer d.Zero()
	root, err := d.RootKey()
	fail(err)
	defer keys.Wipe(root)
	user, _, err := e.Store.ReadUser(u.ID)
	fail(err)
	gen := user.Current().Gen + 1
	identity, err := d.IdentityKey(gen)
	fail(err)
	unwrap, err := d.UnwrapKey(gen)
	fail(err)
	ks := &keys.Keystore{Generation: gen, Identity: identity, Unwrap: unwrap}
	defer ks.Zero()
	cert, err := keys.NewGenerationCert(root, gen, identity.Public().(ed25519.PublicKey), unwrap.PublicKey(), e.Clock.Now().UnixMilli())
	fail(err)
	user.Generations = append(user.Generations, cert)
	fail(user.Sign(root))
	data, err := user.Encode()
	fail(err)
	fail(store.WriteFileAtomic(e.Store.UserFile(u.ID), data))
	fail(store.WritePrivateFileAtomic(filepath.Join(u.Dir, "user.rec"), data))
	ksData, err := ks.Seal(Passphrase, nil)
	fail(err)
	fail(keys.WriteKeystoreFile(filepath.Join(u.Dir, "keystore"), ksData))
	_, err = e.recordLog().Append(translog.KindUser, data)
	fail(err)
	e.Reopen(u)
	return gen
}

// Reopen opens the user's client again (a new process).
func (e *Env) Reopen(u *User) *client.Client {
	e.T.Helper()
	u.Client.Close()
	c, err := client.Open(e.ClientConfig(u.Dir), Passphrase)
	if err != nil {
		e.T.Fatal(err)
	}
	e.T.Cleanup(c.Close)
	u.Client = c
	return c
}

// Mailbox creates a mailbox of u and assigns the addresses to it (in a
// logged environment logged first, AssignAddress).
func (e *Env) Mailbox(u *User, name string, addrs ...string) store.ID {
	e.T.Helper()
	id, err := u.Client.CreateMailbox(name)
	if err != nil {
		e.T.Fatal(err)
	}
	for _, a := range addrs {
		e.AssignAddress(a, id)
		if _, err := e.Store.AddAddress(a, id); err != nil {
			e.T.Fatal(err)
		}
	}
	return id
}

// ImmediateEpoch appends an epoch with immediate effect (2.4) to mailbox
// mbx, created and signed by its member u like a client would do it:
// fresh random keys, the wrap for u, folders.gml with name and the inbox
// of mailbox.rec as the only folder, discards naming every epoch of the
// chain up to the head of mailbox.rec that is not discarded and begins
// after begin (2.4 rule 1), epoch.rec in the log and mailbox.rec pointing
// to the new epoch. It holds the mailbox lock while it writes.
//
// It serves every reason with immediate effect alike (member-added,
// member-removed, delegation-ended, recovery-changed, generation-revoked):
// reason is written into epoch.rec as given and changes nothing else, so
// the member list is always u alone, whatever the reason says about the
// members. The reason regular is planned and discards nothing (2.4 rule
// 2): if discards would not be empty, the epoch record is refused and the
// test fails; otherwise the result is a planned epoch beginning at begin.
// Clients do not create epochs with immediate effect yet;
// tests use it to check how client and server treat them.
func (e *Env) ImmediateEpoch(u *User, mbx store.ID, begin time.Time, reason store.Reason, name string) *store.Epoch {
	e.T.Helper()
	return e.ForgeEpoch(u, mbx, begin, reason, []store.Member{{Kind: store.MemberUser, ID: u.ID, Gen: 1}}, name)
}

// Keystore opens the key store of u (the test passphrase). The caller
// zeroes it.
func (e *Env) Keystore(u *User) *keys.Keystore {
	e.T.Helper()
	ksData, err := keys.ReadKeystoreFile(filepath.Join(u.Dir, "keystore"))
	if err != nil {
		e.T.Fatal(err)
	}
	ks, err := keys.OpenKeystore(ksData, Passphrase)
	keys.Wipe(ksData)
	if err != nil {
		e.T.Fatal(err)
	}
	return ks
}

// ForgeEpoch appends epoch head+1 to mailbox mbx as signer would create
// it, whether or not the chain rules allow it: begin, reason and the
// given members (the entry of signer gets its current generation; it is
// added as a user member if missing, because an epoch.rec names its
// signer), discards as for ImmediateEpoch when the reason is immediate,
// fresh keys with a wrap for signer only, folders.gml with name and the
// inbox, epoch.rec in the log and mailbox.rec pointing to it. It is the
// tool for forged epochs: an epoch signed by a removed member, a delegate
// or a recovery recipient listed as a user. The epoch is appended to the
// operator log of the data directory if the log accepts it; a forged
// epoch that the validity rules refuse (ErrOrder, ErrPrerequisite) or
// whose number the log holds already (ErrDuplicate) stays
// a file in the data directory without a log entry, as an attacker with
// write access to it would leave it.
func (e *Env) ForgeEpoch(signer *User, mbx store.ID, begin time.Time, reason store.Reason, members []store.Member, name string) *store.Epoch {
	e.T.Helper()
	fail := func(err error) {
		e.T.Helper()
		if err != nil {
			e.T.Fatal(err)
		}
	}
	unlock, err := e.Store.LockMailbox(mbx)
	fail(err)
	defer unlock()
	m, err := e.Store.ReadMailbox(mbx)
	fail(err)
	links := store.NewChain()
	var headData []byte
	for n := uint32(1); n <= m.Epoch; n++ {
		ep, data, err := e.Store.ReadEpoch(mbx, n)
		fail(err)
		fail(links.Add(ep, data))
		headData = data
	}
	var discards []uint32
	if reason.Immediate() {
		for n := uint32(1); n <= m.Epoch; n++ {
			if !links.Discarded(n) && links.Epoch(n).Begin > begin.UnixMilli() {
				discards = append(discards, n)
			}
		}
	}
	ks := e.Keystore(signer)
	defer ks.Zero()
	list := append([]store.Member(nil), members...)
	found := false
	for i := range list {
		if list[i].ID == signer.ID {
			list[i].Gen, found = ks.Generation, true
		}
	}
	if !found {
		list = append(list, store.Member{Kind: store.MemberUser, ID: signer.ID, Gen: ks.Generation})
	}
	content, err := ecdh.X25519().GenerateKey(rand.Reader)
	fail(err)
	meta, err := ecdh.X25519().GenerateKey(rand.Reader)
	fail(err)
	n := m.Epoch + 1
	ek := &store.EpochKeys{MailboxID: mbx, Epoch: n, Content: content, Meta: meta}
	_, err = io.ReadFull(rand.Reader, ek.Index[:])
	fail(err)
	defer ek.Zero()
	ep := &store.Epoch{
		MailboxID: mbx, Number: n, Begin: begin.UnixMilli(), Reason: reason, Suite: envelope.Suite1,
		ContentPub: content.PublicKey(), MetaPub: meta.PublicKey(),
		Members:  list,
		Discards: discards, PrevHash: store.EpochHash(headData),
		SignerID: signer.ID, SignerGen: ks.Generation,
	}
	fail(ep.Sign(ks.Identity))
	sig := &envelope.Signer{Type: envelope.SignerUser, ID: signer.ID, Gen: ks.Generation, Key: ks.Identity}
	now := e.Clock.Now().UnixMilli()
	plain, err := ek.Encode()
	fail(err)
	wrap, err := envelope.Seal(
		envelope.Header{Kind: envelope.KindWrap, MailboxID: mbx, Epoch: n, FileID: signer.ID, Created: now},
		[]envelope.Recipient{{Type: envelope.RecipientUserUnwrap, ID: signer.ID, Gen: ks.Generation, PublicKey: ks.Unwrap.PublicKey()}},
		plain, &envelope.SealOptions{Signer: sig})
	keys.Wipe(plain)
	fail(err)
	fail(e.Store.WriteWrap(mbx, n, signer.ID, wrap))
	fl, err := (&store.FolderList{MailboxID: mbx, Epoch: n, Name: name, Folders: []store.Folder{{ID: m.Inbox, Name: client.InboxName}}}).Encode()
	fail(err)
	folders, err := envelope.Seal(
		envelope.Header{Kind: envelope.KindMeta, MailboxID: mbx, Epoch: n, FileID: m.Inbox, Created: now, Version: 1},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: mbx, Gen: n, PublicKey: ep.MetaPub}},
		fl, &envelope.SealOptions{Signer: sig})
	fail(err)
	fail(e.Store.WriteFolders(mbx, n, folders))
	data, err := e.Store.WriteEpoch(ep)
	fail(err)
	if _, err := e.recordLog().Append(translog.KindEpoch, data); err != nil && !errors.Is(err, translog.ErrOrder) && !errors.Is(err, translog.ErrPrerequisite) && !errors.Is(err, translog.ErrDuplicate) {
		e.T.Fatal(err)
	}
	next := *m
	next.Epoch = n
	fail(e.Store.WriteMailbox(&next))
	return ep
}

// vkeyData returns the key part of a note verifier key
// <name>+<hash>+<base64>.
func vkeyData(vkey string) string {
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return ""
	}
	return parts[2]
}

// Share shares mailbox mbx of member u with other (2.5), fails the test
// on an error (also client.ErrPartial) and returns the existing epochs
// that were wrapped for other.
func (e *Env) Share(u *User, mbx store.ID, other *User, opts client.ShareOptions) []uint32 {
	e.T.Helper()
	wrapped, err := u.Client.Share(mbx, other.ID, opts)
	if err != nil {
		e.T.Fatal(err)
	}
	return wrapped
}
