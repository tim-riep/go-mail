package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Test of task 26, package 26D, point 1 (backlog item 66): the branch
// sc.Verify of identityKey.

// succLookupLog is a translog.Log whose Lookup returns, for the platform
// subjects in content, the logged entry with that content in place of
// its own; every subject in content must be logged. The operator log never returns such an entry: Lookup returns only
// valid entries, and a succession is valid only with the signature of
// the identity generation before it (translog admitSucc), which is the
// key identityKey derives from the same pin. identityKey checks the
// signature itself all the same, as client/read.go does; only a log
// that breaks that contract tells the two apart.
type succLookupLog struct {
	translog.Log
	content map[string][]byte
}

func (l succLookupLog) Lookup(kind translog.Kind, subject []byte) ([]translog.Entry, error) {
	es, err := l.Log.Lookup(kind, subject)
	if err != nil || kind != translog.KindPlatform {
		return es, err
	}
	c, ok := l.content[string(subject)]
	if !ok {
		return es, nil
	}
	out := append([]translog.Entry(nil), es...)
	out[0].Content = c
	return out, nil
}

// TestAddressAddIdentitySuccessionChain: under a pin with identities 1
// and 2, identity-3.succ (signed by identity 2), identity-4.succ (signed
// by identity 3) and admin-2.cert signed by identity 4 are logged.
// "address add" with the admin key of generation 2 takes the key of
// identity 4 through both logged successions and assigns, and identityKey
// gives the key of every generation of the chain. A succession that its
// predecessor did not sign, or that names another generation, ends the
// chain with an error, whatever generation it stands at: identityKey
// verifies every succession with the key of generation g-1, which it took
// from the pin or from the succession before. Counter-proof: without
// sc.Verify the forged successions give a key. sc.Gen != g and
// sc.Verify(key, g-1) cover the same condition, since Verify refuses a
// generation other than g; the case "identity 3 holds identity 4" does
// not tell them apart, and a version without sc.Gen != g passes it.
func TestAddressAddIdentitySuccessionChain(t *testing.T) {
	s := newLogSetup(t)
	now := time.Now().UnixMilli()
	newKey := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub, priv
	}
	pub2, priv2 := newKey()
	pub3, priv3 := newKey()
	pub4, priv4 := newKey()
	_, privX := newKey()
	adminPub, adminPriv := newKey()
	encSucc := func(prev ed25519.PrivateKey, gen uint32, pub ed25519.PublicKey) []byte {
		t.Helper()
		sc, err := keys.NewPlatformSuccession(prev, gen, pub, now-60_000)
		if err != nil {
			t.Fatal(err)
		}
		data, err := sc.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	p := *s.p
	p.Gen, p.Pub = 2, pub2
	p.Identities = append(append([]store.PlatformIdentity(nil), s.p.Identities...), store.PlatformIdentity{Gen: 2, Pub: pub2})
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join(s.dir, "identity-2.pin")
	if err := store.WriteFileAtomic(pin, data); err != nil {
		t.Fatal(err)
	}
	ids := []translog.Identity{{Gen: 1, Pub: s.p.Pub}, {Gen: 2, Pub: pub2}}
	l, err := translog.Open(translog.Options{Store: s.st, Origin: p.Origin, Identities: ids})
	if err != nil {
		t.Fatal(err)
	}
	op := l.(translog.Operator)
	cert, err := keys.NewPlatformCert(priv4, 4, keys.RoleAdmin, 2, adminPub, now-60_000)
	if err != nil {
		t.Fatal(err)
	}
	certEnc, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	succ3, succ4 := encSucc(priv2, 3, pub3), encSucc(priv3, 4, pub4)
	for _, f := range []struct {
		name   string
		data   []byte
		logged bool // a .pub is not logged
	}{
		{store.PlatformFileName("identity", 3, "succ"), succ3, true},
		{store.PlatformFileName("identity", 4, "succ"), succ4, true},
		{store.PlatformFileName("admin", 2, "cert"), certEnc, true},
		{store.PlatformFileName("admin", 2, "pub"), adminPub, false},
	} {
		if f.logged {
			if err := op.AppendPlatform(f.name, f.data); err != nil {
				t.Fatalf("%s: %v", f.name, err)
			}
		}
		if err := store.WriteFileAtomic(s.st.Path("platform", f.name), f.data); err != nil {
			t.Fatal(err)
		}
	}

	// "address add" under identity 4, two logged successions above the
	// pin.
	setAddressClock(t, now)
	args := []string{"address", "add", "chain@example.org", "--mailbox", s.mbx.String(), "--data", s.data,
		"--admin-key", writeAdminKey(t, s, 2, adminPriv), "--pin", pin}
	var out, errb bytes.Buffer
	if code := run(context.Background(), args, &out, &errb, nil); code != 0 {
		t.Fatalf("exit status %d: %q", code, errb.String())
	}
	es, err := op.Lookup(translog.KindAddress, []byte("chain@example.org"))
	if err != nil || len(es) != 1 {
		t.Fatalf("logged: %d %v", len(es), err)
	}
	if a, err := store.DecodeAddressAssignment(es[0].Content); err != nil || a.AdminGen != 2 || a.MailboxID != s.mbx {
		t.Fatalf("assignment %+v %v", a, err)
	}

	// identityKey on the log as it is: the pin, then each succession.
	for gen, want := range map[uint32]ed25519.PublicKey{1: s.p.Pub, 2: pub2, 3: pub3, 4: pub4} {
		if k, err := identityKey(op, ids, gen); err != nil || !k.Equal(want) {
			t.Fatalf("identity %d: %v", gen, err)
		}
	}
	if _, err := identityKey(op, ids, 5); err == nil || !strings.Contains(err.Error(), "succession to identity generation 5 not in the log") {
		t.Fatalf("identity 5: %v", err)
	}

	// Lookup returns successions the log would not hold.
	name3 := store.PlatformFileName("identity", 3, "succ")
	name4 := store.PlatformFileName("identity", 4, "succ")
	for _, tc := range []struct {
		name    string
		content map[string][]byte
		gen     uint32 // the generation asked for
		bad     uint32 // the generation whose succession is refused
	}{
		// identity-3.succ naming identity 3, signed by identity 1, not
		// by identity 2 from the pin.
		{"identity 3 signed by identity 1", map[string][]byte{name3: encSucc(s.identityPriv(t), 3, pub3)}, 3, 3},
		{"identity 3 signed by another key", map[string][]byte{name3: encSucc(privX, 3, pub3)}, 3, 3},
		// The forged succession below the generation asked for ends the
		// chain there.
		{"identity 3 signed by another key, asked for 4", map[string][]byte{name3: encSucc(privX, 3, pub3)}, 4, 3},
		// identity-4.succ signed by identity 2, from the pin, not by
		// identity 3 from identity-3.succ.
		{"identity 4 signed by identity 2", map[string][]byte{name4: encSucc(priv2, 4, pub4)}, 4, 4},
		{"identity 4 signed by another key", map[string][]byte{name4: encSucc(privX, 4, pub4)}, 4, 4},
		// identity-3.succ names another key, signed by identity 2:
		// valid, but identity-4.succ is not signed by that key.
		{"identity 3 names another key", map[string][]byte{name3: encSucc(priv2, 3, privX.Public().(ed25519.PublicKey))}, 4, 4},
		// Under identity-3.succ the succession to identity 4, signed by
		// identity 3 (sc.Gen != g, which Verify refuses as well).
		{"identity 3 holds identity 4", map[string][]byte{name3: succ4}, 3, 3},
	} {
		k, err := identityKey(succLookupLog{op, tc.content}, ids, tc.gen)
		want := fmt.Sprintf("succession to identity generation %d", tc.bad)
		if err == nil || k != nil || err.Error() != want {
			t.Fatalf("%s: key %x, %v; want %q", tc.name, []byte(k), err, want)
		}
	}
}
