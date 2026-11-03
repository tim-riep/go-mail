package client_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 21b: the client takes pin field 7 (D93) into its
// Verifier; metadata and term lists of a revoked ingest generation
// received from revoked_at_time on are rejected with the fixed cause
// "Generation widerrufen", and an address assignment of a revoked or
// superseded admin generation assigns nothing (F-2 of
// docs/tasks/20-mandatory-tests.md).

// revokedPin returns a copy of the pin of env with field 7 set to rev,
// encoded and decoded again (the rules of store.CheckPinRevoked), as a
// client receives it.
func revokedPin(t *testing.T, env *testenv.Env, rev ...store.PlatformRevoked) *store.PlatformPin {
	t.Helper()
	p := *env.Pin
	p.Revoked = rev
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := store.DecodePlatformPin(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// platformCert logs a certificate of role and gen with key pub and
// valid_from, signed by identity generation 1, and writes it and the key
// into platform/.
func platformCert(t *testing.T, env *testenv.Env, identity ed25519.PrivateKey, role keys.Role, gen uint32, pub ed25519.PublicKey, validFrom time.Time) {
	t.Helper()
	cert, err := keys.NewPlatformCert(identity, 1, role, gen, pub, validFrom.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	data, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	name := "ingest"
	if role == keys.RoleAdmin {
		name = "admin"
	}
	if err := store.WriteFileAtomic(env.Store.Path("platform", store.PlatformFileName(name, gen, "cert")), data); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(env.Store.Path("platform", store.PlatformFileName(name, gen, "pub")), pub); err != nil {
		t.Fatal(err)
	}
	if _, err := env.LogOperator().Append(translog.KindPlatform, data); err != nil {
		t.Fatal(err)
	}
}

// platformAdminKey derives admin generation gen from the root of the
// development ceremony of env.
func platformAdminKey(t *testing.T, env *testenv.Env, gen uint32) ed25519.PrivateKey {
	t.Helper()
	seed := rootSeed(t, env)
	p := keys.DerivePlatform(&seed)
	defer p.Zero()
	k, err := p.AdminKey(gen)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// assign logs an assignment of addr to mbx valid from validFrom, signed
// by admin generation gen with key, and adds it to addresses.json.
func assign(t *testing.T, env *testenv.Env, addr string, mbx store.ID, validFrom time.Time, key ed25519.PrivateKey, gen uint32) {
	t.Helper()
	as := &store.AddressAssignment{Address: addr, MailboxID: mbx, ValidFrom: validFrom.UnixMilli(), AdminGen: gen}
	if err := as.Sign(key); err != nil {
		t.Fatal(err)
	}
	enc, err := as.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.LogOperator().Append(translog.KindAddress, enc); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Store.AddAddress(addr, mbx); err != nil {
		t.Fatal(err)
	}
}

// inboxIDs returns the mail files of the inbox of f.
func inboxIDs(t *testing.T, f *fixture) map[store.ID]bool {
	t.Helper()
	ids, err := f.env.Store.ListMails(f.mbx, f.inbox(t))
	if err != nil {
		t.Fatal(err)
	}
	out := map[store.ID]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// newMail delivers a mail to addr and returns its ID.
func newMail(t *testing.T, f *fixture, addr, subject string) store.ID {
	t.Helper()
	before := inboxIDs(t, f)
	deliverTo(t, f, addr, subject)
	for id := range inboxIDs(t, f) {
		if !before[id] {
			return id
		}
	}
	t.Fatalf("mail %q not delivered", subject)
	return store.ID{}
}

// countWarnings counts the warnings that contain part.
func countWarnings(warnings []string, part string) int {
	n := 0
	for _, w := range warnings {
		if strings.Contains(w, part) {
			n++
		}
	}
	return n
}

// TestLogIngestRevoked (F-2, beside TestLogIngestSuperseded): the pin
// revokes ingest generation 1 at a witness-confirmed head (size and
// time). Generation 2 is certified with a valid_from an hour later. A
// mail signed with the key of generation 1 and backdated to a time
// before that valid_from, but after revoked_at_time, is shown by a
// client without field 7 (the supersession rule alone lets it pass) and
// no longer listed by a client with it; Read fails with the fixed cause
// (ErrPlatformRevoked, warning "Generation widerrufen"). A mail received
// before revoked_at_time stays readable (one millisecond before it as
// well, one at it does not); a term list created from revoked_at_time on
// is refused the same way, mails of generation 2 are shown, and ingest
// does not start with generation 1 once its pin revokes it.
func TestLogIngestRevoked(t *testing.T) {
	f := newFixture(t)
	early := f.deliver(t, "early", "before the revocation")
	f.env.Clock.Advance(time.Minute)
	h := f.env.MustPublishHead()
	// The ceremony sets revoked_at_time to the time of the confirmed head
	// plus 1 ms (D93 addendum): the head itself stays valid.
	at := time.UnixMilli(h.Time + 1)
	identity, ingest2 := platformKeys(t, f.env, 2)
	defer keys.Wipe(identity)
	defer keys.Wipe(ingest2)
	validFrom := at.Add(time.Hour)
	platformCert(t, f.env, identity, keys.RoleIngest, 2, ingest2.Public().(ed25519.PublicKey), validFrom)
	e, _, err := f.env.Store.ReadEpoch(f.mbx, early.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	// The key of generation 1, in the hands of an attacker: receipt
	// times before valid_from of generation 2.
	backdated := f.forge(t, e, at.Add(30*time.Minute), "backdated", 1, f.env.IngestKey, 1)
	edgeBefore := f.forge(t, e, at.Add(-time.Millisecond), "edge before", 1, f.env.IngestKey, 1)
	edgeAt := f.forge(t, e, at, "edge at", 1, f.env.IngestKey, 1)
	pendingAt := f.forgePending(t, e, at)
	pendingBefore := f.forgePending(t, e, at.Add(-time.Millisecond))

	// From valid_from on the platform signs its heads with generation 2.
	f.env.Clock.Advance(validFrom.Sub(f.env.Clock.Now()) + time.Minute)
	f.env.IngestKey = ingest2
	f.env.Warnings.Take()
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err != nil || len(list) != 4 {
		t.Fatalf("without field 7: %v %d %v", err, len(list), f.env.Warnings.Take())
	}

	rev := []store.PlatformRevoked{{Role: store.KeyRoleIngest, Gen: 1, AtSize: h.Size, AtTime: h.Time + 1}}
	f.env.Pin = revokedPin(t, f.env, rev...)
	c := f.env.Reopen(f.u)

	// ingest does not start with the revoked generation, but with 2.
	f.in.Close()
	_, revoked := translog.AnchorFromPin(f.env.Pin)
	cfg := ingest.Config{Store: f.env.Store, Log: f.env.Log, IngestKey: f.env.IngestKey, IngestGen: 2, Now: f.env.Clock.Now, Revoked: revoked,
		DiskSpace: func(string) (uint64, uint64, error) { return 1, 2, nil }}
	_, old := platformKeys(t, f.env, 1)
	defer keys.Wipe(old)
	stale := cfg
	stale.IngestKey, stale.IngestGen = old, 1
	if _, err := ingest.New(stale); !errors.Is(err, ingest.ErrRevoked) || !errors.Is(err, ingest.ErrConfig) {
		t.Fatalf("ingest with the revoked generation: %v", err)
	}
	if f.in, err = ingest.New(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.in.Close() })
	deliverTo(t, f, "a@example.org", "generation 2")

	f.env.Warnings.Take()
	list, err = c.List(f.mbx, store.ID{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[store.ID]bool{}
	for _, m := range list {
		got[m.ID] = true
	}
	if len(list) != 3 || !got[early.ID] || !got[edgeBefore] || !strings.Contains(subjects(list), "generation 2") {
		t.Fatalf("with field 7: %s", subjects(list))
	}
	if w := f.env.Warnings.Take(); countWarnings(w, "wird nicht verarbeitet: Generation widerrufen") != 2 {
		t.Fatalf("warnings: %q", w)
	}
	for _, id := range []store.ID{backdated, edgeAt} {
		_, _, err := c.Read(f.mbx, id)
		if !errors.Is(err, client.ErrPlatformRevoked) || !errors.Is(err, client.ErrPlatform) || !errors.Is(err, translog.ErrRevoked) {
			t.Fatalf("read of a mail received after revoked_at_time: %v", err)
		}
		w := f.env.Warnings.Take()
		warningWith(t, w, id.String(), "wird nicht geöffnet: Generation widerrufen")
	}
	readBody(t, f.env, c, f.mbx, early.ID, "before the revocation")
	readBody(t, f.env, c, f.mbx, edgeBefore, "edge before")

	if _, err := c.OpenPending(f.mbx, e.Number, pendingAt); !errors.Is(err, client.ErrPlatformRevoked) {
		t.Fatalf("term list created at revoked_at_time: %v", err)
	}
	warningWith(t, f.env.Warnings.Take(), pendingAt.String(), "Generation widerrufen")
	if _, err := c.OpenPending(f.mbx, e.Number, pendingBefore); err != nil {
		t.Fatalf("term list created before revoked_at_time: %v", err)
	}
}

// TestLogAdminRevoked (F-2, D93 (2)): the pin revokes admin generation 1
// at a witness-confirmed head. An assignment it signs that is logged from
// revoked_at_size on assigns nothing for a client with field 7 (the mail
// is not listed: "Adresse nicht zugeordnet", Read fails with ErrAddress),
// while a client without field 7 shows the mail; assignments logged
// before stay in force.
func TestLogAdminRevoked(t *testing.T) {
	f := newFixture(t)
	assign(t, f.env, "frueh@example.org", f.mbx, f.env.Clock.Now(), f.env.AdminKey, 1)
	f.env.Clock.Advance(time.Minute)
	h := f.env.MustPublishHead()
	f.env.Clock.Advance(time.Minute)
	assign(t, f.env, "spaet@example.org", f.mbx, f.env.Clock.Now(), f.env.AdminKey, 1)
	early := newMail(t, f, "frueh@example.org", "early assignment")
	late := newMail(t, f, "spaet@example.org", "late assignment")
	inbox := newMail(t, f, "a@example.org", "first assignment")
	f.env.Warnings.Take()
	if list, err := f.u.Client.List(f.mbx, store.ID{}); err != nil || len(list) != 3 {
		t.Fatalf("without field 7: %v %s %q", err, subjects(list), f.env.Warnings.Take())
	}

	f.env.Pin = revokedPin(t, f.env, store.PlatformRevoked{Role: store.KeyRoleAdmin, Gen: 1, AtSize: h.Size, AtTime: h.Time + 1})
	c := f.env.Reopen(f.u)
	f.env.Warnings.Take()
	list, err := c.List(f.mbx, store.ID{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[store.ID]bool{}
	for _, m := range list {
		got[m.ID] = true
	}
	if len(list) != 2 || !got[early] || !got[inbox] {
		t.Fatalf("with field 7: %s", subjects(list))
	}
	if w := f.env.Warnings.Take(); countWarnings(w, late.String()+" wird nicht verarbeitet: Adresse nicht zugeordnet") != 1 {
		t.Fatalf("warnings: %q", w)
	}
	if _, _, err := c.Read(f.mbx, late); !errors.Is(err, client.ErrAddress) || !errors.Is(err, translog.ErrNotInLog) {
		t.Fatalf("read: %v", err)
	}
}

// TestLogAdminSuperseded (F-2, D93 (3)): admin generation 1 is valid
// only until valid_from of admin-2.cert. An assignment of generation 1
// logged before that certificate but dated after its valid_from is not
// in force (Read: ErrAddressSuperseded, ErrAddress and translog.ErrOrder,
// warning "Zuordnung einer abgelösten Admin-Generation"); one of generation 1 dated before stays in force
// after the switch, and one of generation 2 assigns.
func TestLogAdminSuperseded(t *testing.T) {
	f := newFixture(t)
	validFrom := f.env.Clock.Now().Add(time.Hour)
	assign(t, f.env, "vorab@example.org", f.mbx, validFrom.Add(time.Minute), f.env.AdminKey, 1)
	identity, _ := platformKeys(t, f.env, 1)
	defer keys.Wipe(identity)
	admin2 := platformAdminKey(t, f.env, 2)
	defer keys.Wipe(admin2)
	platformCert(t, f.env, identity, keys.RoleAdmin, 2, admin2.Public().(ed25519.PublicKey), validFrom)
	f.env.Clock.Advance(time.Hour + 2*time.Minute)
	ahead := newMail(t, f, "vorab@example.org", "dated after the switch")
	inbox := newMail(t, f, "a@example.org", "first assignment")
	assign(t, f.env, "neu@example.org", f.mbx, f.env.Clock.Now(), admin2, 2)
	f.env.Clock.Advance(time.Second)
	fresh := newMail(t, f, "neu@example.org", "generation 2")
	// Admin generation 1 assigns nothing from valid_from of admin-2.cert
	// on: the log refuses a new assignment of it.
	as := &store.AddressAssignment{Address: "nach@example.org", MailboxID: f.mbx, ValidFrom: f.env.Clock.Now().UnixMilli(), AdminGen: 1}
	if err := as.Sign(f.env.AdminKey); err != nil {
		t.Fatal(err)
	}
	enc, err := as.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.LogOperator().Append(translog.KindAddress, enc); !errors.Is(err, translog.ErrOrder) {
		t.Fatalf("assignment of the superseded admin generation: %v", err)
	}

	f.env.Warnings.Take()
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[store.ID]bool{}
	for _, m := range list {
		got[m.ID] = true
	}
	if len(list) != 2 || !got[inbox] || !got[fresh] {
		t.Fatalf("list: %s", subjects(list))
	}
	if w := f.env.Warnings.Take(); countWarnings(w, ahead.String()+" wird nicht verarbeitet: Zuordnung einer abgelösten Admin-Generation") != 1 {
		t.Fatalf("warnings: %q", w)
	}
	if _, _, err := f.u.Client.Read(f.mbx, ahead); !errors.Is(err, client.ErrAddressSuperseded) || !errors.Is(err, client.ErrAddress) || !errors.Is(err, translog.ErrOrder) {
		t.Fatalf("read: %v", err)
	}
}

// cascadePin returns a pin of identity generation 2 (list 1 and 2, a
// fresh key for 2) that revokes identity generation 1 at (size, at), the
// issuer of ingest-1.cert: the pin after "succeed --compromised" of
// identity 1 (D93 (4)) before ingest is reissued under identity 2.
func cascadePin(t *testing.T, env *testenv.Env, size, at int64) *store.PlatformPin {
	t.Helper()
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := *env.Pin
	p.Gen, p.Pub = 2, pub2
	p.Identities = append(append([]store.PlatformIdentity(nil), env.Pin.Identities...), store.PlatformIdentity{Gen: 2, Pub: pub2})
	p.Revoked = []store.PlatformRevoked{{Role: store.KeyRoleIdentity, Gen: 1, AtSize: size, AtTime: at}}
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := store.DecodePlatformPin(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestLogIngestCascadeRefused (task 21b, rework after review, finding
// F1): the pin revokes identity generation 1, which certified ingest
// generation 1 (the cascade of D93, addendum on task 21a). A client with
// that pin rejects what generation 1 signs from revoked_at_time on, so
// ingest.New with the same revocation list refuses generation 1
// (ErrRevoked with ErrConfig) before it takes the server lock, as for a
// revocation of the generation itself; the mail received before
// revoked_at_time stays listed.
func TestLogIngestCascadeRefused(t *testing.T) {
	f := newFixture(t)
	early := f.deliver(t, "early", "before the revocation")
	f.env.Clock.Advance(time.Minute)
	h := f.env.MustPublishHead()
	at := h.Time + 1
	e, _, err := f.env.Store.ReadEpoch(f.mbx, early.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	late := f.forge(t, e, time.UnixMilli(at), "after the cascade", 1, f.env.IngestKey, 1)
	f.env.Pin = cascadePin(t, f.env, h.Size, at)
	f.env.Clock.Advance(time.Minute)
	c := f.env.Reopen(f.u)

	// The operator after succeed --compromised, before the reissue,
	// starts the server with the old ingest key.
	f.in.Close()
	_, rev := translog.AnchorFromPin(f.env.Pin)
	cfg := ingest.Config{Store: f.env.Store, Log: f.env.Log, IngestKey: f.env.IngestKey, IngestGen: 1, Now: f.env.Clock.Now, Revoked: rev,
		DiskSpace: func(string) (uint64, uint64, error) { return 1, 2, nil }}
	if in, err := ingest.New(cfg); !errors.Is(err, ingest.ErrRevoked) || !errors.Is(err, ingest.ErrConfig) {
		if in != nil {
			in.Close()
		}
		t.Fatalf("ingest.New with the cascade-revoked generation 1: %v", err)
	}
	release, err := f.env.Store.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatalf("server lock left behind: %v", err)
	}
	release()

	f.env.Warnings.Take()
	list, err := c.List(f.mbx, store.ID{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != early.ID {
		t.Fatalf("list: %s", subjects(list))
	}
	f.env.Warnings.Take()
	if _, _, err := c.Read(f.mbx, late); !errors.Is(err, client.ErrPlatformRevoked) || !errors.Is(err, translog.ErrRevoked) {
		t.Fatalf("read of a mail generation 1 signed at revoked_at_time: %v", err)
	}
	warningWith(t, f.env.Warnings.Take(), late.String(), "Generation widerrufen")
}

// TestLogFlagLaundering (task 21b, rework after review, finding F2): a
// thief with the key of ingest generation 1 plants a mail backdated to
// after revoked_at_time (before valid_from of generation 2). A device
// with the old pin (no field 7) accepts it and sets a flag, which
// rewrites the metadata as version 2 signed by the user. A device with
// the new pin does not list it either: the receipt time of user-signed
// metadata must lie in the interval of an ingest generation the pin does
// not revoke at it (checkReceivedCovered), here generation 1 from its
// revoked_at_time on (ErrPlatformRevoked, "Generation widerrufen"). The
// mail flagged before the revocation stays listed with its flags.
func TestLogFlagLaundering(t *testing.T) {
	f := newFixture(t)
	early := f.deliver(t, "early", "before the revocation")
	if _, err := f.u.Client.SetFlags(f.mbx, early.ID, []string{"flagged"}, nil); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	h := f.env.MustPublishHead()
	at := time.UnixMilli(h.Time + 1)
	identity, ingest2 := platformKeys(t, f.env, 2)
	defer keys.Wipe(identity)
	defer keys.Wipe(ingest2)
	validFrom := at.Add(time.Hour)
	platformCert(t, f.env, identity, keys.RoleIngest, 2, ingest2.Public().(ed25519.PublicKey), validFrom)
	e, _, err := f.env.Store.ReadEpoch(f.mbx, early.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	backdated := f.forge(t, e, at.Add(30*time.Minute), "backdated", 1, f.env.IngestKey, 1)
	f.env.Clock.Advance(validFrom.Sub(f.env.Clock.Now()) + time.Minute)
	f.env.IngestKey = ingest2

	// The device with the old pin accepts the forged mail and marks it
	// seen: version 2, signed by the user.
	if m, err := f.u.Client.SetFlags(f.mbx, backdated, []string{"seen"}, nil); err != nil || m.Meta.Version != 2 {
		t.Fatalf("old pin SetFlags: %v", err)
	}

	f.env.Pin = revokedPin(t, f.env, store.PlatformRevoked{Role: store.KeyRoleIngest, Gen: 1, AtSize: h.Size, AtTime: h.Time + 1})
	c := f.env.Reopen(f.u)
	f.env.Warnings.Take()
	list, err := c.List(f.mbx, store.ID{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != early.ID || list[0].Meta.Version != 2 {
		t.Fatalf("list: %s", subjects(list))
	}
	warningWith(t, f.env.Warnings.Take(), backdated.String(), "wird nicht verarbeitet: Generation widerrufen")
	if _, _, err := c.Read(f.mbx, backdated); !errors.Is(err, client.ErrPlatformRevoked) || !errors.Is(err, translog.ErrRevoked) {
		t.Fatalf("read of the laundered mail: %v", err)
	}
	warningWith(t, f.env.Warnings.Take(), backdated.String(), "wird nicht geöffnet: Generation widerrufen")
	// The device with the new pin does not launder it either.
	if _, err := c.SetFlags(f.mbx, backdated, nil, []string{"seen"}); !errors.Is(err, client.ErrPlatformRevoked) {
		t.Fatalf("SetFlags with field 7: %v", err)
	}
}

// TestLogFlagsAcrossGenerations (task 21b, rework after review, finding
// F2): the check of the receipt time of user-signed metadata leaves the
// honest flows alone. Flags set on mails received under ingest
// generation 1 (before revoked_at_time) and under generation 2 (after
// the supersession, valid_from of ingest-2.cert) stay listed and can be
// changed again, without field 7 and after the pin revokes generation 1
// (the reissue); a user-signed version with a receipt time no logged
// generation covers (before valid_from of generation 1) is ErrPlatform,
// not ErrPlatformRevoked.
func TestLogFlagsAcrossGenerations(t *testing.T) {
	f := newFixture(t)
	early := f.deliver(t, "early", "gen 1")
	if _, err := f.u.Client.SetFlags(f.mbx, early.ID, []string{"seen"}, nil); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	h := f.env.MustPublishHead()
	identity, ingest2 := platformKeys(t, f.env, 2)
	defer keys.Wipe(identity)
	defer keys.Wipe(ingest2)
	validFrom := time.UnixMilli(h.Time + 1).Add(time.Hour)
	platformCert(t, f.env, identity, keys.RoleIngest, 2, ingest2.Public().(ed25519.PublicKey), validFrom)
	f.env.Clock.Advance(validFrom.Sub(f.env.Clock.Now()) + time.Minute)
	f.env.IngestKey = ingest2
	f.in.Close()
	in, err := ingest.New(ingest.Config{Store: f.env.Store, Log: f.env.Log, IngestKey: ingest2, IngestGen: 2, Now: f.env.Clock.Now,
		DiskSpace: func(string) (uint64, uint64, error) { return 1, 2, nil }})
	if err != nil {
		t.Fatal(err)
	}
	f.in = in
	t.Cleanup(func() { in.Close() })
	late := f.deliver(t, "late", "gen 2")
	if _, err := f.u.Client.SetFlags(f.mbx, late.ID, []string{"flagged"}, nil); err != nil {
		t.Fatal(err)
	}
	check := func(c *client.Client, what string) {
		t.Helper()
		f.env.Warnings.Take()
		list, err := c.List(f.mbx, store.ID{})
		if err != nil || len(list) != 2 {
			t.Fatalf("%s: %v %s %q", what, err, subjects(list), f.env.Warnings.Take())
		}
		for _, m := range list {
			if m.Meta.Version < 2 {
				t.Fatalf("%s: %s version %d", what, m.Meta.Subject, m.Meta.Version)
			}
		}
	}
	check(f.u.Client, "superseded, without field 7")

	f.env.Pin = revokedPin(t, f.env, store.PlatformRevoked{Role: store.KeyRoleIngest, Gen: 1, AtSize: h.Size, AtTime: h.Time + 1})
	c := f.env.Reopen(f.u)
	check(c, "generation 1 revoked")
	for _, id := range []store.ID{early.ID, late.ID} {
		if _, err := c.SetFlags(f.mbx, id, []string{"answered"}, nil); err != nil {
			t.Fatalf("SetFlags after the revocation: %v", err)
		}
	}
	check(c, "flags changed after the revocation")
	readBody(t, f.env, c, f.mbx, early.ID, "gen 1")
	readBody(t, f.env, c, f.mbx, late.ID, "gen 2")

	// A user-signed version received before any generation was valid.
	cert, err := f.env.Store.ReadPlatformCert(keys.RoleIngest, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.forgeVersion(t, f.u, early.Meta, early.Epoch, 9, func(m *store.MailMeta) { m.Received = cert.ValidFrom - 1 })
	f.env.Warnings.Take()
	if _, _, err := c.Read(f.mbx, early.ID); !errors.Is(err, client.ErrPlatform) || errors.Is(err, client.ErrPlatformRevoked) {
		t.Fatalf("user-signed version before valid_from of generation 1: %v", err)
	}
}

// TestLogAddressRefreshAfterOrder (task 21b, D93 (3)): an assignment in
// force at the reference head that the log refuses (translog.ErrOrder:
// admin generation 1 superseded at its valid_from) gets the one refresh
// per operation as well; a newer assignment of admin generation 2,
// logged after the reference head, then assigns the address and the
// mail is listed.
func TestLogAddressRefreshAfterOrder(t *testing.T) {
	f := newFixture(t)
	validFrom := f.env.Clock.Now().Add(time.Hour)
	assign(t, f.env, "vorab@example.org", f.mbx, validFrom.Add(time.Minute), f.env.AdminKey, 1)
	identity, _ := platformKeys(t, f.env, 1)
	defer keys.Wipe(identity)
	admin2 := platformAdminKey(t, f.env, 2)
	defer keys.Wipe(admin2)
	platformCert(t, f.env, identity, keys.RoleAdmin, 2, admin2.Public().(ed25519.PublicKey), validFrom)
	f.env.Clock.Advance(time.Hour + 2*time.Minute)
	f.env.MustPublishHead()
	c := f.env.Reopen(f.u)
	// Logged after the reference head of c, valid before the receipt.
	assign(t, f.env, "vorab@example.org", f.mbx, f.env.Clock.Now(), admin2, 2)
	f.env.Clock.Advance(time.Second)
	id := newMail(t, f, "vorab@example.org", "reassigned by generation 2")
	f.env.Warnings.Take()
	list, err := c.List(f.mbx, store.ID{})
	if err != nil || len(list) != 1 || list[0].ID != id {
		t.Fatalf("list: %v %s %q", err, subjects(list), f.env.Warnings.Take())
	}
}
