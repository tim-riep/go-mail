//go:build gomail_dev

package testenv

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/translog/translogtest"
	"github.com/tim-riep/go-mail/internal/witness"
)

// fatalOn runs fn with e.T replaced by a fatalTB and fails t unless fn
// fails that test; e.T is restored afterwards.
func fatalOn(t *testing.T, e *Env, fn func()) string {
	t.Helper()
	old := e.T
	defer func() { e.T = old }()
	return expectFatal(t, func(tb testing.TB) {
		e.T = tb
		fn()
	})
}

// TestRequireDev: a build with the tag gomail_dev has the development
// ceremony, and RequireDev lets the test run.
func TestRequireDev(t *testing.T) {
	if !ceremony.DevBuild {
		t.Fatal("DevBuild false with the tag gomail_dev")
	}
	RequireDev(t)
	if t.Skipped() {
		t.Fatal("skipped")
	}
}

// TestNew: the environment of New is a complete platform. The server's
// Log is the accepting placeholder, Operator is nil, the clients' log
// is the operator log of the data directory; the ingest and admin keys
// are those of the pin's certificates; the witness key file is private,
// outside the data directory and holds the key of Witness; the clock
// stands at Start; AutoHeads is on.
func TestNew(t *testing.T) {
	e := New(t)
	if e.T != t || e.Store == nil || e.Pin == nil || e.Clock == nil || e.Warnings == nil {
		t.Fatalf("incomplete env %+v", e)
	}
	if _, ok := e.Log.(*translogtest.Unverified); !ok || e.Log.Verified() {
		t.Fatalf("Log %T", e.Log)
	}
	if e.Operator != nil {
		t.Fatal("Operator in env from New")
	}
	if e.LogOperator() == nil || !e.LogOperator().Verified() {
		t.Fatal("LogOperator")
	}
	if e.recordLog() != e.LogOperator() {
		t.Fatal("recordLog of New is not the operator log")
	}
	if !e.Clock.Now().Equal(Start) || !e.AutoHeads {
		t.Fatal("clock or AutoHeads")
	}
	if e.Store.Path() != filepath.Join(e.Base, "data") || e.KeyDir == "" {
		t.Fatalf("paths %s %s", e.Store.Path(), e.KeyDir)
	}
	ingest, err := e.Store.ReadPlatformCert(keys.RoleIngest, 1)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := e.Store.ReadPlatformCert(keys.RoleAdmin, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ingest.Pub, e.IngestKey.Public().(ed25519.PublicKey)) || !bytes.Equal(admin.Pub, e.AdminKey.Public().(ed25519.PublicKey)) {
		t.Fatal("ingest or admin key does not match its certificate")
	}
	if e.Witness.Name != WitnessName || e.WitnessSigner.Name() != WitnessName {
		t.Fatal("witness name")
	}
	ws, err := e.Store.ReadPlatformFile("witnesses.rec")
	if err != nil {
		t.Fatal(err)
	}
	wl, err := witness.DecodeWitnesses(ws)
	if err != nil {
		t.Fatal(err)
	}
	if wl.Min != 1 || len(wl.List) != 1 || !bytes.Equal(wl.List[0].Pub, e.Witness.Pub) {
		t.Fatalf("witnesses.rec %+v", wl)
	}
	fi, err := os.Stat(e.WitnessKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("witness key mode %v", fi.Mode())
	}
	if rel, err := filepath.Rel(e.Store.Path(), e.WitnessKeyFile); err != nil || !strings.HasPrefix(rel, "..") {
		t.Fatalf("witness key inside the data directory: %s", rel)
	}
	skey, err := os.ReadFile(e.WitnessKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(strings.TrimSpace(string(skey)))
	if err != nil {
		t.Fatal(err)
	}
	if s.KeyHash() != e.WitnessSigner.KeyHash() {
		t.Fatal("witness key file holds another key")
	}
	msg, err := s.Sign([]byte("x"))
	if err != nil || !ed25519.Verify(e.Witness.Pub, []byte("x"), msg) {
		t.Fatal("Witness.Pub does not verify the signer of the key file")
	}
	cfg := e.ClientConfig("dir")
	if cfg.Store != e.Store || cfg.Dir != "dir" || cfg.Pin != e.Pin || !cfg.AllowDevIdentity || cfg.BeforeRefresh == nil ||
		cfg.Now == nil || !cfg.Now().Equal(Start) || cfg.Warn == nil {
		t.Fatalf("ClientConfig %+v", cfg)
	}
	cfg.Warn("w")
	if l := e.Warnings.Take(); len(l) != 1 || l[0] != "w" {
		t.Fatalf("Warn %v", l)
	}
}

// TestNewLogged: Log, Operator and LogOperator are one operator log, and
// the records of the environment go into it.
func TestNewLogged(t *testing.T) {
	e := NewLogged(t)
	if e.Operator == nil || e.Log != translog.Log(e.Operator) || e.LogOperator() != e.Operator || e.recordLog() != e.Log {
		t.Fatal("logged env")
	}
	// A test may put a placeholder into Log to leave a record unlogged.
	unv, _ := translogtest.NewUnverified(true)
	e.Log = unv
	if e.recordLog() != translog.Log(unv) {
		t.Fatal("recordLog ignores Log")
	}
}

// TestPublishHead: the head is signed by the ingest key and cosigned by
// the witness, published in the data directory, and opens with both
// verifiers; MustPublishHead does the same. Without new entries the
// next head has the same size and a later time. With the clock set back
// PublishHead fails (SignHead, ErrHead) and MustPublishHead fails the
// test; beforeRefresh skips that head silently.
func TestPublishHead(t *testing.T) {
	e := New(t)
	h, err := e.PublishHead()
	if err != nil {
		t.Fatal(err)
	}
	if h.Origin != e.Pin.Origin || h.Time != Start.UnixMilli() || h.Size < 1 {
		t.Fatalf("head %+v", h)
	}
	lv, err := translog.NewLogVerifier(e.IngestKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	wv, err := e.Witness.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []note.Verifier{lv, wv} {
		if _, err := note.Open(h.Note, note.VerifierList(v)); err != nil {
			t.Fatalf("%s: %v", v.Name(), err)
		}
	}
	stored, err := os.ReadFile(e.Store.Path(translog.HeadPath(h.Size)))
	if err != nil {
		t.Fatal(err)
	}
	if hs, err := translog.OpenHead(stored, note.VerifierList(lv, wv)); err != nil || hs.Size != h.Size || hs.Hash != h.Hash || len(hs.Sigs) != 2 {
		t.Fatalf("stored head %v %v", hs, err)
	}
	e.Clock.Advance(time.Minute)
	h2 := e.MustPublishHead()
	if h2.Size != h.Size || h2.Hash != h.Hash || h2.Time != h.Time+time.Minute.Milliseconds() {
		t.Fatalf("second head %+v", h2)
	}

	e.Clock.Set(Start)
	if _, err := e.PublishHead(); !errors.Is(err, translog.ErrHead) {
		t.Fatalf("clock back: %v", err)
	}
	if msg := fatalOn(t, e, func() { e.MustPublishHead() }); !strings.Contains(msg, "the clock lies before the newest head") {
		t.Fatalf("clock back: %q", msg)
	}
	e.beforeRefresh()
	e.Clock.Advance(2 * time.Minute)
	e.beforeRefresh()
	if h3, err := e.LogOperator().Head(); err != nil || h3.Time != Start.Add(2*time.Minute).UnixMilli() {
		t.Fatalf("beforeRefresh did not publish: %v %v", h3, err)
	}
	e.AutoHeads = false
	e.Clock.Advance(time.Minute)
	e.ClientConfig("x").BeforeRefresh()
	if h4, err := e.LogOperator().Head(); err != nil || h4.Time != Start.Add(2*time.Minute).UnixMilli() {
		t.Fatalf("published without AutoHeads: %v %v", h4, err)
	}
}

// badNameSigner is a note signer with an invalid name, which note.Sign
// refuses.
type badNameSigner struct{ note.Signer }

func (badNameSigner) Name() string { return "bad+name" }

// TestPublishHeadErrors: the error paths of PublishHead reachable
// through the fields of Env: an ingest key of wrong length (no log
// signer), a witness signer that note.Sign refuses, and a cosignature by
// a witness the data directory does not list (PublishHead, ErrWitness).
func TestPublishHeadErrors(t *testing.T) {
	e := New(t)
	ingest := e.IngestKey
	e.IngestKey = ingest[:10]
	if _, err := e.PublishHead(); !errors.Is(err, translog.ErrHead) {
		t.Fatalf("short ingest key: %v", err)
	}
	e.IngestKey = ingest
	ws := e.WitnessSigner
	e.WitnessSigner = badNameSigner{ws}
	if _, err := e.PublishHead(); err == nil {
		t.Fatal("bad witness signer name accepted")
	}
	skey, _, err := note.GenerateKey(rand.Reader, "other-witness")
	if err != nil {
		t.Fatal(err)
	}
	other, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	e.WitnessSigner = other
	if _, err := e.PublishHead(); !errors.Is(err, translog.ErrWitness) {
		t.Fatalf("unknown witness: %v", err)
	}
	if _, err := e.LogOperator().Head(); err == nil {
		t.Fatal("a head was published")
	}
	e.WitnessSigner = ws
	e.MustPublishHead()
}

// TestOpenOperator: a second operator log on the data directory sees the
// entries of the first; openOperator fails the test when the witness
// list of the data directory is missing or broken, or the pin has an
// invalid origin or no identity list.
func TestOpenOperator(t *testing.T) {
	e := New(t)
	u := e.NewUser("alice")
	_, data, err := e.Store.ReadUser(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	op := e.OpenOperator()
	if op == e.LogOperator() {
		t.Fatal("same instance")
	}
	if err := op.CheckUser(u.ID, data); err != nil {
		t.Fatal(err)
	}

	pin := *e.Pin
	pin.Origin = "bad+origin"
	if msg := expectFatal(t, func(tb testing.TB) { openOperator(tb, e.Store, &pin) }); !strings.Contains(msg, "origin must be printable ASCII") {
		t.Fatalf("invalid origin: %q", msg)
	}
	pin = *e.Pin
	pin.Identities = nil
	if msg := expectFatal(t, func(tb testing.TB) { openOperator(tb, e.Store, &pin) }); !strings.Contains(msg, "an operator log needs the identity list of a pin") {
		t.Fatalf("pin without identities: %q", msg)
	}
	wfile := e.Store.Path("platform", "witnesses.rec")
	ws, err := os.ReadFile(wfile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wfile, ws[:len(ws)-1], 0o644); err != nil {
		t.Fatal(err)
	}
	if msg := fatalOn(t, e, func() { e.OpenOperator() }); !strings.Contains(msg, "invalid witness list") {
		t.Fatalf("broken witnesses.rec: %q", msg)
	}
	if err := os.Remove(wfile); err != nil {
		t.Fatal(err)
	}
	if msg := fatalOn(t, e, func() { e.OpenOperator() }); !strings.Contains(msg, "not found: witnesses.rec") {
		t.Fatalf("missing witnesses.rec: %q", msg)
	}
}

// TestAssignAddress: the signed assignment is in the operator log of the
// data directory from now on, also in an environment from New; an
// invalid address, an admin key that cannot sign and an assignment the
// log refuses fail the test.
func TestAssignAddress(t *testing.T) {
	e := New(t)
	u := e.NewUser("alice")
	mbx := e.Mailbox(u, "A")
	e.AssignAddress("Info@Example.org", mbx)
	now := e.Clock.Now().UnixMilli()
	if err := e.LogOperator().CheckAddress("info@example.org", mbx, now); err != nil {
		t.Fatal(err)
	}
	if err := e.LogOperator().CheckAddress("info@example.org", mbx, now-1); err == nil {
		t.Fatal("assignment valid before now")
	}
	if err := e.LogOperator().CheckAddress("other@example.org", mbx, now); err == nil {
		t.Fatal("unassigned address")
	}
	if msg := fatalOn(t, e, func() { e.AssignAddress("no address", mbx) }); !strings.Contains(msg, "malformed address") {
		t.Fatalf("invalid address: %q", msg)
	}
	admin := e.AdminKey
	e.AdminKey = admin[:10]
	if msg := fatalOn(t, e, func() { e.AssignAddress("x@example.org", mbx) }); !strings.Contains(msg, "private key has wrong length") {
		t.Fatalf("short admin key: %q", msg)
	}
	// Signed by the ingest key: well formed, but no admin certificate
	// verifies it, so the log refuses the entry.
	e.AdminKey = e.IngestKey
	if msg := fatalOn(t, e, func() { e.AssignAddress("y@example.org", mbx) }); !strings.Contains(msg, "validity rule: admin signature") {
		t.Fatalf("assignment by a wrong key: %q", msg)
	}
	e.AdminKey = admin
}

// TestUsers: NewUser registers a user with a key store of generation 1
// and an open client, and keeps the seed words; Reopen gives a new
// client; Keystore opens the key store. A second user of the same name,
// a missing key store and a client that cannot open fail the test.
func TestUsers(t *testing.T) {
	e := New(t)
	u := e.NewUser("alice")
	if u.Dir != filepath.Join(e.Base, "clients", "alice") || u.ID.IsZero() || u.Client.UserID() != u.ID || len(u.Words) == 0 {
		t.Fatalf("user %+v", u)
	}
	user, data, err := e.Store.ReadUser(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if user.Current().Gen != 1 {
		t.Fatalf("generation %d", user.Current().Gen)
	}
	if err := e.LogOperator().CheckUser(u.ID, data); err != nil {
		t.Fatal(err)
	}
	seed, err := keys.SeedFromWords(u.Words)
	if err != nil {
		t.Fatal(err)
	}
	d := keys.DeriveUser(seed)
	seed.Zero()
	idk, err := d.IdentityKey(1)
	d.Zero()
	if err != nil {
		t.Fatal(err)
	}
	ks := e.Keystore(u)
	if ks.Generation != 1 || !bytes.Equal(ks.Identity.Public().(ed25519.PublicKey), idk.Public().(ed25519.PublicKey)) {
		t.Fatal("key store does not hold the identity of the seed")
	}
	ks.Zero()
	old := u.Client
	c := e.Reopen(u)
	if c == old || u.Client != c || c.UserID() != u.ID {
		t.Fatal("Reopen")
	}

	if msg := fatalOn(t, e, func() { e.NewUser("alice") }); !strings.Contains(msg, client.ErrRegistered.Error()) {
		t.Fatalf("second alice: %q", msg)
	}
	ksFile := filepath.Join(u.Dir, "keystore")
	ksData, err := os.ReadFile(ksFile)
	if err != nil {
		t.Fatal(err)
	}
	bad := slices.Clone(ksData)
	bad[len(bad)-1] ^= 1
	if err := os.WriteFile(ksFile, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if msg := fatalOn(t, e, func() { e.Keystore(u) }); !strings.Contains(msg, "key store authentication failed") {
		t.Fatalf("broken key store: %q", msg)
	}
	if msg := fatalOn(t, e, func() { e.Reopen(u) }); !strings.Contains(msg, "key store authentication failed") {
		t.Fatalf("Reopen with a broken key store: %q", msg)
	}
	if err := os.Remove(ksFile); err != nil {
		t.Fatal(err)
	}
	if msg := fatalOn(t, e, func() { e.Keystore(u) }); !strings.Contains(msg, "keystore: no such file or directory") {
		t.Fatalf("missing key store: %q", msg)
	}
	if err := os.WriteFile(ksFile, ksData, 0o600); err != nil {
		t.Fatal(err)
	}
	e.Reopen(u)
}

// TestNewEnvFails: New fails the test when its temporary directory
// already holds a witness key file or a data directory that the
// ceremony refuses.
func TestNewEnvFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "witness.key"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if msg := expectFatalIn(t, dir, func(tb testing.TB) { New(tb) }); !strings.Contains(msg, "file exists: witness.key") {
		t.Fatalf("witness key file exists: %q", msg)
	}
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if msg := expectFatalIn(t, dir, func(tb testing.TB) { NewLogged(tb) }); !strings.Contains(msg, "data is not a directory") {
		t.Fatalf("data is a file: %q", msg)
	}
}

// TestNewUserFails: a user for whom no invite can be created fails the
// test.
func TestNewUserFails(t *testing.T) {
	e := New(t)
	// No invite can be created when invites/ is a file.
	inv := e.Store.Path("invites")
	if err := os.RemoveAll(inv); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if msg := fatalOn(t, e, func() { e.NewUser("bob") }); !strings.Contains(msg, "invites/.tmp-") || !strings.Contains(msg, "not a directory") {
		t.Fatalf("invite: %q", msg)
	}
}

// TestNewUserRegisterOpenFails: NewUser fails the test when the data
// directory refuses the registration (users/ is not a directory) and
// when the new client cannot open (no fresh head: AutoHeads off and the
// clock three days on).
func TestNewUserRegisterOpenFails(t *testing.T) {
	e := New(t)
	e.NewUser("alice")
	users := e.Store.Path("users")
	saved := users + ".saved"
	if err := os.Rename(users, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(users, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if msg := fatalOn(t, e, func() { e.NewUser("bob") }); !strings.Contains(msg, "users is not a directory") {
		t.Fatalf("register: %q", msg)
	}
	if err := os.Remove(users); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, users); err != nil {
		t.Fatal(err)
	}
	e.AutoHeads = false
	e.Clock.Advance(72 * time.Hour)
	if msg := fatalOn(t, e, func() { e.NewUser("carol") }); !strings.Contains(msg, "no fresh verified tree head") {
		t.Fatalf("open: %q", msg)
	}
}

// TestMailbox: Mailbox creates a mailbox (the client writes epoch 1 and
// the planned epochs up to the supply, 2.4) and assigns every
// address in addresses.json and in the log; an address assigned to
// another mailbox and a name the client refuses fail the test.
func TestMailbox(t *testing.T) {
	e := New(t)
	u := e.NewUser("alice")
	mbx := e.Mailbox(u, "A", "a@example.org", "b@example.org")
	if name, err := u.Client.MailboxName(mbx); err != nil || name != "A" {
		t.Fatalf("name %q %v", name, err)
	}
	as, err := e.Store.LoadAddresses()
	if err != nil {
		t.Fatal(err)
	}
	now := e.Clock.Now().UnixMilli()
	for _, a := range []string{"a@example.org", "b@example.org"} {
		if as[a] != mbx {
			t.Fatalf("addresses.json: %s -> %v", a, as[a])
		}
		if err := e.LogOperator().CheckAddress(a, mbx, now); err != nil {
			t.Fatal(err)
		}
	}
	if msg := fatalOn(t, e, func() { e.Mailbox(u, "B", "a@example.org") }); !strings.Contains(msg, "duplicate log entry") {
		t.Fatalf("address of another mailbox: %q", msg)
	}
	if msg := fatalOn(t, e, func() { e.Mailbox(u, " ") }); !strings.Contains(msg, "empty mailbox name") {
		t.Fatalf("empty name: %q", msg)
	}
	// Logged, but addresses.json cannot be read.
	if err := os.WriteFile(e.Store.AddressesFile(), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if msg := fatalOn(t, e, func() { e.Mailbox(u, "D", "d@example.org") }); !strings.Contains(msg, "invalid record: addresses.json") {
		t.Fatalf("broken addresses.json: %q", msg)
	}
}

// TestImmediateEpoch: the epoch is appended after the head, signed by u,
// with u as the only member, discards every epoch that begins after
// begin, is logged and mailbox.rec points to it; the wrap for u and
// folders.gml exist, and the client reads the mailbox with the new
// name. A regular epoch discards nothing.
func TestImmediateEpoch(t *testing.T) {
	e := NewLogged(t)
	u := e.NewUser("alice")
	mbx := e.Mailbox(u, "A")
	m, err := e.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	head := m.Epoch // 1 and the planned epochs, which begin after today
	var planned []uint32
	for n := uint32(2); n <= head; n++ {
		planned = append(planned, n)
	}
	e5 := e.ImmediateEpoch(u, mbx, e.Clock.Now().Add(time.Hour), store.ReasonMemberAdded, "B")
	if e5.Number != head+1 || !slices.Equal(e5.Discards, planned) || e5.SignerID != u.ID || e5.SignerGen != 1 ||
		e5.Reason != store.ReasonMemberAdded {
		t.Fatalf("epoch %d %+v", head+1, e5)
	}
	// Begins before e5: discards e5, not again the planned epochs.
	e6 := e.ImmediateEpoch(u, mbx, e.Clock.Now().Add(30*time.Minute), store.ReasonMemberRemoved, "C")
	if e6.Number != head+2 || !slices.Equal(e6.Discards, []uint32{head + 1}) || e6.Reason != store.ReasonMemberRemoved {
		t.Fatalf("epoch %d %+v", head+2, e6)
	}
	if len(e6.Members) != 1 || e6.Members[0] != (store.Member{Kind: store.MemberUser, ID: u.ID, Gen: 1}) {
		t.Fatalf("members %+v", e6.Members)
	}
	if m, err := e.Store.ReadMailbox(mbx); err != nil || m.Epoch != head+2 {
		t.Fatalf("mailbox %+v %v", m, err)
	}
	for n := head + 1; n <= head+2; n++ {
		_, data, err := e.Store.ReadEpoch(mbx, n)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Log.CheckEpoch(mbx, n, data); err != nil {
			t.Fatalf("epoch %d not logged: %v", n, err)
		}
		for _, f := range []string{e.Store.WrapFile(mbx, n, u.ID), filepath.Join(e.Store.EpochDir(mbx, n), "folders.gml")} {
			if _, err := os.Stat(f); err != nil {
				t.Fatal(err)
			}
		}
	}
	e.Clock.Advance(time.Hour)
	e.Reopen(u)
	if err := u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	if name, err := u.Client.MailboxName(mbx); err != nil || name != "C" {
		t.Fatalf("name %q %v", name, err)
	}
	if fs, err := u.Client.Folders(mbx); err != nil || len(fs) != 1 || fs[0].ID != m.Inbox || fs[0].Name != client.InboxName {
		t.Fatalf("folders %+v %v", fs, err)
	}
	// A regular epoch discards nothing, whatever begins after it (Sync
	// has added planned epochs to the supply again).
	m, err = e.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	e7 := e.ImmediateEpoch(u, mbx, e.Clock.Now().Add(-3*time.Hour), store.ReasonRegular, "D")
	if e7.Number != m.Epoch+1 || len(e7.Discards) != 0 || e7.Reason != store.ReasonRegular {
		t.Fatalf("regular epoch %+v", e7)
	}
}

// failLog refuses every append with errFail.
type failLog struct{ translog.Log }

var errFail = errors.New("append refused")

func (failLog) Append(translog.Kind, []byte) (int64, error) { return 0, errFail }

// TestForgeEpoch: ForgeEpoch adds the signer as a member when missing
// and sets its generation; an epoch the log refuses with ErrOrder,
// ErrPrerequisite or ErrDuplicate stays in the data directory without a
// log entry; any other error of the log, and a mailbox that does not
// exist, fail the test.
func TestForgeEpoch(t *testing.T) {
	e := NewLogged(t)
	alice := e.NewUser("alice")
	mallory := e.NewUser("mallory")
	mbx := e.Mailbox(alice, "A")
	m, err := e.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	n := m.Epoch + 1
	// Signed by a user who is no member: the log refuses it, the file
	// stays.
	ep := e.ForgeEpoch(mallory, mbx, e.Clock.Now(), store.ReasonMemberAdded, []store.Member{{Kind: store.MemberUser, ID: alice.ID, Gen: 7}}, "M")
	if ep.Number != n || ep.SignerID != mallory.ID || len(ep.Members) != 2 || ep.Members[1] != (store.Member{Kind: store.MemberUser, ID: mallory.ID, Gen: 1}) ||
		ep.Members[0].Gen != 7 {
		t.Fatalf("forged epoch %+v", ep)
	}
	_, data, err := e.Store.ReadEpoch(mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.LogOperator().CheckEpoch(mbx, n, data); err == nil {
		t.Fatal("forged epoch logged")
	}
	if m, err := e.Store.ReadMailbox(mbx); err != nil || m.Epoch != n {
		t.Fatalf("mailbox %+v %v", m, err)
	}
	// The signer's own entry gets its current generation.
	e.Rotate(alice)
	mbx2 := e.Mailbox(alice, "B")
	ep = e.ForgeEpoch(alice, mbx2, e.Clock.Now(), store.ReasonMemberAdded, []store.Member{{Kind: store.MemberUser, ID: alice.ID, Gen: 1}}, "B")
	if len(ep.Members) != 1 || ep.Members[0].Gen != 2 || ep.SignerGen != 2 {
		t.Fatalf("signer entry %+v", ep.Members)
	}

	e.Log = failLog{e.Log}
	if msg := fatalOn(t, e, func() {
		e.ForgeEpoch(alice, mbx2, e.Clock.Now(), store.ReasonMemberAdded, nil, "C")
	}); !strings.Contains(msg, errFail.Error()) {
		t.Fatalf("message %q", msg)
	}
	// The mailbox lock was released on the way out.
	unlock, err := e.Store.LockMailbox(mbx2)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	e.Log = e.Operator
	var none store.ID
	none[0] = 1
	if msg := fatalOn(t, e, func() { e.ForgeEpoch(alice, none, e.Clock.Now(), store.ReasonMemberAdded, nil, "D") }); !strings.Contains(msg, "not found: mailbox.rec") {
		t.Fatalf("missing mailbox: %q", msg)
	}
}

// TestRotate: Rotate moves u to generation 2 in user.rec of the data
// directory and of the client directory, in the key store and in the
// log, without touching the mailboxes; broken seed words fail the test.
func TestRotate(t *testing.T) {
	e := New(t)
	u := e.NewUser("alice")
	mbx := e.Mailbox(u, "A")
	before, err := e.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := os.ReadFile(e.Store.WrapFile(mbx, 1, u.ID))
	if err != nil {
		t.Fatal(err)
	}
	if gen := e.Rotate(u); gen != 2 {
		t.Fatalf("generation %d", gen)
	}
	user, data, err := e.Store.ReadUser(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(user.Generations) != 2 || user.Current().Gen != 2 {
		t.Fatalf("user.rec %+v", user.Generations)
	}
	local, err := os.ReadFile(filepath.Join(u.Dir, "user.rec"))
	if err != nil || !bytes.Equal(local, data) {
		t.Fatalf("client user.rec %v", err)
	}
	if err := e.LogOperator().CheckUser(u.ID, data); err != nil {
		t.Fatal(err)
	}
	if err := e.LogOperator().CheckGeneration(u.ID, 2); err != nil {
		t.Fatal(err)
	}
	ks := e.Keystore(u)
	if ks.Generation != 2 {
		t.Fatalf("key store generation %d", ks.Generation)
	}
	ks.Zero()
	if m, err := e.Store.ReadMailbox(mbx); err != nil || *m != *before {
		t.Fatalf("mailbox touched: %+v %v", m, err)
	}
	if w, err := os.ReadFile(e.Store.WrapFile(mbx, 1, u.ID)); err != nil || !bytes.Equal(w, wrap) {
		t.Fatalf("wrap issued again: %v", err)
	}
	bad := &User{Dir: u.Dir, ID: u.ID, Client: u.Client, Words: []string{"no", "seed"}}
	if msg := fatalOn(t, e, func() { e.Rotate(bad) }); !strings.Contains(msg, "a seed has exactly 24 words") {
		t.Fatalf("bad seed: %q", msg)
	}
}

// TestDeviceLost: DeviceLost gives generation 2, a key store of that
// generation and an open client; wrong seed words fail the test.
func TestDeviceLost(t *testing.T) {
	e := New(t)
	u := e.NewUser("alice")
	e.Mailbox(u, "A")
	old := u.Client
	if gen := e.DeviceLost(u); gen != 2 {
		t.Fatalf("generation %d", gen)
	}
	if u.Client == old {
		t.Fatal("client not reopened")
	}
	ks := e.Keystore(u)
	if ks.Generation != 2 {
		t.Fatalf("key store generation %d", ks.Generation)
	}
	ks.Zero()
	other := e.NewUser("bob")
	wrong := &User{Dir: u.Dir, ID: u.ID, Client: u.Client, Words: other.Words}
	if msg := fatalOn(t, e, func() { e.DeviceLost(wrong) }); !strings.Contains(msg, client.ErrSeed.Error()) {
		t.Fatalf("wrong seed: %q", msg)
	}
}

// TestShare: Share makes other a member of the next epoch and returns
// the existing epochs wrapped for it; a share the client refuses fails
// the test.
func TestShare(t *testing.T) {
	e := New(t)
	alice := e.NewUser("alice")
	bob := e.NewUser("bob")
	mbx := e.Mailbox(alice, "A")
	if w := e.Share(alice, mbx, bob, client.ShareOptions{From: 1}); !slices.Equal(w, []uint32{1}) {
		t.Fatalf("wrapped %v", w)
	}
	m, err := e.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	ep, _, err := e.Store.ReadEpoch(mbx, m.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(ep.Members, func(mm store.Member) bool { return mm.ID == bob.ID }) {
		t.Fatalf("bob not a member: %+v", ep.Members)
	}
	if _, err := os.Stat(e.Store.WrapFile(mbx, 1, bob.ID)); err != nil {
		t.Fatal(err)
	}
	other := e.Mailbox(alice, "B")
	if msg := fatalOn(t, e, func() { e.Share(bob, other, alice, client.ShareOptions{}) }); !strings.Contains(msg, client.ErrNotMember.Error()) {
		t.Fatalf("share by a user who is no member: %q", msg)
	}
}
