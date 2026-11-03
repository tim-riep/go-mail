package e2e

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// devPlatformRoot derives the platform keys from the root seed of the
// development ceremony of env (its key directory).
func devPlatformRoot(t *testing.T, env *testenv.Env) *keys.PlatformRoot {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(env.KeyDir, ceremony.RootFile))
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(text), "seed: ")
	if i < 0 {
		t.Fatal("no seed in the root file")
	}
	b, err := hex.DecodeString(strings.Fields(string(text[i+len("seed: "):]))[0])
	if err != nil || len(b) != len(keys.Seed{}) {
		t.Fatal("seed", err)
	}
	var seed keys.Seed
	copy(seed[:], b)
	return keys.DerivePlatform(&seed)
}

// TestRevokedIngestEndToEnd (task 21b, F-2 of 20-mandatory-tests.md,
// D93): SMTP server, ingest and client on the transparency log of the
// data directory, with a pin built by hand until the ceremony writes
// field 7 (task 21c). Ingest generation 1 is compromised: the operator
// reads a witness-confirmed head, ingest-2.cert is logged with a
// valid_from an hour later, and a server that kept key 1 delivers a mail
// whose receipt time lies between the head and that valid_from. The
// server with the pin revoking generation 1 does not start with key 1,
// but with key 2. A client without field 7 shows the backdated mail; with
// the new pin it does not list it, Read fails with
// client.ErrPlatformRevoked and the warning "Generation widerrufen", and
// the mails before the head and of generation 2 stay readable.
func TestRevokedIngestEndToEnd(t *testing.T) {
	env := testenv.NewLogged(t)
	alice := env.NewUser("alice")
	mbx := env.Mailbox(alice, "Büro", "info@brownbear.example")
	s := startServer(t, env)
	to := []string{"info@brownbear.example"}
	if err := send(s, "s@x.example", to, "Subject: vor dem Widerruf\r\n\r\nalt\r\n"); err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(time.Minute)
	h := env.MustPublishHead()
	// The ceremony sets revoked_at_time to the time of the confirmed head
	// plus 1 ms (D93 addendum): the head itself stays valid.
	at := time.UnixMilli(h.Time + 1)

	// The ceremony part (21c) by hand: ingest-2.cert from identity 1.
	root := devPlatformRoot(t, env)
	identity, err := root.IdentityKey(1)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe(identity)
	ingest2, err := root.IngestKey(2)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe(ingest2)
	root.Zero()
	validFrom := at.Add(time.Hour)
	pub2 := ingest2.Public().(ed25519.PublicKey)
	cert, err := keys.NewPlatformCert(identity, 1, keys.RoleIngest, 2, pub2, validFrom.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	data, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(env.Store.Path("platform", "ingest-2.cert"), data); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(env.Store.Path("platform", "ingest-2.pub"), pub2); err != nil {
		t.Fatal(err)
	}
	if _, err := env.LogOperator().Append(translog.KindPlatform, data); err != nil {
		t.Fatal(err)
	}
	p := *env.Pin
	p.Revoked = []store.PlatformRevoked{{Role: store.KeyRoleIngest, Gen: 1, AtSize: h.Size, AtTime: h.Time + 1}}
	enc, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pin, err := store.DecodePlatformPin(enc)
	if err != nil {
		t.Fatal(err)
	}
	_, revoked := translog.AnchorFromPin(pin)

	// A server that kept ingest key 1 (no field 7) delivers a mail
	// backdated to before valid_from of generation 2.
	s.srv.Close()
	s.in.Close()
	backdated := at.Add(30 * time.Minute)
	stale := startServer(t, env, func(c *ingest.Config) { c.Now = func() time.Time { return backdated } })
	if err := send(stale, "s@x.example", to, "Subject: zurueckdatiert\r\n\r\nfalsch\r\n"); err != nil {
		t.Fatal(err)
	}
	stale.srv.Close()
	stale.in.Close()

	// From valid_from on: the server with the new pin refuses key 1 and
	// starts with key 2, which also signs the heads.
	env.Clock.Advance(validFrom.Sub(env.Clock.Now()) + time.Minute)
	key1 := env.IngestKey
	env.IngestKey = ingest2
	if _, err := ingest.New(ingest.Config{Store: env.Store, Log: env.Log, IngestKey: key1, IngestGen: 1, Now: env.Clock.Now,
		Revoked: revoked}); !errors.Is(err, ingest.ErrRevoked) {
		t.Fatalf("server with key 1 and the new pin: %v", err)
	}
	s2 := startServer(t, env, func(c *ingest.Config) { c.IngestKey, c.IngestGen, c.Revoked = ingest2, 2, revoked })
	if err := send(s2, "s@x.example", to, "Subject: nach dem Widerruf\r\n\r\nneu\r\n"); err != nil {
		t.Fatal(err)
	}

	list, err := alice.Client.List(mbx, store.ID{})
	if err != nil || len(list) != 3 {
		t.Fatalf("client without field 7: %v %d %q", err, len(list), env.Warnings.Take())
	}
	var forged store.ID
	for _, m := range list {
		if m.Meta.Subject == "zurueckdatiert" {
			forged = m.ID
		}
	}
	if forged.IsZero() {
		t.Fatal("backdated mail not delivered")
	}

	env.Pin = pin
	c := env.Reopen(alice)
	env.Warnings.Take()
	list, err = c.List(mbx, store.ID{})
	if err != nil || len(list) != 2 {
		t.Fatalf("client with field 7: %v %d", err, len(list))
	}
	for _, m := range list {
		if m.ID == forged {
			t.Fatal("backdated mail listed")
		}
		if _, _, err := c.Read(mbx, m.ID); err != nil {
			t.Fatalf("read %q: %v", m.Meta.Subject, err)
		}
	}
	w := strings.Join(env.Warnings.Take(), "\n")
	if !strings.Contains(w, forged.String()+" wird nicht verarbeitet: Generation widerrufen") || strings.Contains(w, "zurueckdatiert") {
		t.Fatalf("warnings: %s", w)
	}
	if _, _, err := c.Read(mbx, forged); !errors.Is(err, client.ErrPlatformRevoked) {
		t.Fatalf("read of the backdated mail: %v", err)
	}
	if w := env.Warnings.Take(); len(w) != 1 || !strings.Contains(w[0], "wird nicht geöffnet: Generation widerrufen") {
		t.Fatalf("warnings of read: %q", w)
	}
}
