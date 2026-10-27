package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/rec"
)

func pinKey(b byte) ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)).Public().(ed25519.PublicKey)
}

// testPin returns a valid development pin of generation 1 with key pub.
func testPin(pub ed25519.PublicKey) *PlatformPin {
	return &PlatformPin{Gen: 1, Pub: pub, Dev: true, Origin: "gomail.example/log",
		Witnesses: []Witness{{Name: "w1", Pub: pinKey(201)}}, MinWitnesses: 1,
		Identities: []PlatformIdentity{{Gen: 1, Pub: pub}}}
}

func TestPinFields(t *testing.T) {
	p := testPin(pinKey(1))
	p.Gen, p.Pub = 2, pinKey(2)
	p.Identities = []PlatformIdentity{{Gen: 1, Pub: pinKey(1)}, {Gen: 2, Pub: pinKey(2)}}
	p.Witnesses = []Witness{{Name: "w1", Pub: pinKey(201)}, {Name: "w2", Pub: pinKey(202)}, {Name: "w3", Pub: pinKey(203)}}
	p.MinWitnesses = 2
	b := mustEncode(t, p)
	d, err := DecodePlatformPin(b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Origin != p.Origin || d.MinWitnesses != 2 || len(d.Witnesses) != 3 || d.Witnesses[2].Name != "w3" ||
		len(d.Identities) != 2 || !d.Identities[0].Pub.Equal(pinKey(1)) || !bytes.Equal(mustEncode(t, d), b) {
		t.Fatal("round trip")
	}
	// Every rule, on Encode and on Decode.
	for name, f := range map[string]func(x *PlatformPin){
		"gen 0":            func(x *PlatformPin) { x.Gen = 0 },
		"short key":        func(x *PlatformPin) { x.Pub = x.Pub[:5] },
		"empty origin":     func(x *PlatformPin) { x.Origin = "" },
		"long origin":      func(x *PlatformPin) { x.Origin = strings.Repeat("o", MaxOrigin+1) },
		"space in origin":  func(x *PlatformPin) { x.Origin = "a b" },
		"plus in origin":   func(x *PlatformPin) { x.Origin = "a+b" },
		"no witnesses":     func(x *PlatformPin) { x.Witnesses = nil; x.MinWitnesses = 0 },
		"min 0":            func(x *PlatformPin) { x.MinWitnesses = 0 },
		"min above n":      func(x *PlatformPin) { x.MinWitnesses = 4 },
		"split view":       func(x *PlatformPin) { x.Witnesses = x.Witnesses[:2]; x.MinWitnesses = 1 },
		"1 of 3":           func(x *PlatformPin) { x.MinWitnesses = 1 },
		"duplicate name":   func(x *PlatformPin) { x.Witnesses[1].Name = "w1" },
		"duplicate key":    func(x *PlatformPin) { x.Witnesses[1].Pub = x.Witnesses[0].Pub },
		"log name":         func(x *PlatformPin) { x.Witnesses[0].Name = "gomail-log" },
		"long name":        func(x *PlatformPin) { x.Witnesses[0].Name = strings.Repeat("n", MaxWitnessName+1) },
		"empty name":       func(x *PlatformPin) { x.Witnesses[0].Name = "" },
		"plus in name":     func(x *PlatformPin) { x.Witnesses[0].Name = "w+1" },
		"short wkey":       func(x *PlatformPin) { x.Witnesses[0].Pub = x.Witnesses[0].Pub[:3] },
		"no identities":    func(x *PlatformPin) { x.Identities = nil },
		"gap":              func(x *PlatformPin) { x.Identities[0].Gen = 0 },
		"repeated":         func(x *PlatformPin) { x.Identities[0].Pub = pinKey(2) },
		"not current":      func(x *PlatformPin) { x.Identities = x.Identities[:1] },
		"short identity":   func(x *PlatformPin) { x.Identities[0].Pub = pinKey(1)[:4] },
		"too many witness": func(x *PlatformPin) { x.Witnesses = make([]Witness, MaxPinWitnesses+1) },
	} {
		x := *p
		x.Witnesses = append([]Witness(nil), p.Witnesses...)
		x.Identities = append([]PlatformIdentity(nil), p.Identities...)
		f(&x)
		if _, err := x.Encode(); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s: encoded (%v)", name, err)
		}
	}
	// Decode applies the same rules to bytes nobody checked.
	ws := []*rec.Record{rec.New(WitnessSchema).SetString(1, "w1").SetBytes(2, pinKey(201)),
		rec.New(WitnessSchema).SetString(1, "w2").SetBytes(2, pinKey(202))}
	ids := []*rec.Record{rec.New(PlatformIdentitySchema).SetU32(1, 1).SetBytes(2, pinKey(1))}
	raw := func(dev uint8, min uint32, ws []*rec.Record) []byte {
		b, err := rec.New(PlatformPinSchema).SetU32(1, 1).SetBytes(2, pinKey(1)).SetU8(3, dev).SetString(4, "o").
			SetList(5, ws).SetU32(6, min).SetList(8, ids).Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := DecodePlatformPin(raw(0, 2, ws)); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"split view": raw(0, 1, ws), "dev 2": raw(2, 2, ws), "min huge": raw(0, 1<<31, ws), "no witnesses": raw(0, 0, nil),
	} {
		if _, err := DecodePlatformPin(b); err == nil {
			t.Fatalf("%s decoded", name)
		}
	}
	// Field 7 is not part of the schema until Q8 is decided.
	withSeven := append(raw(0, 2, ws)[:0:0], raw(0, 2, ws)...)
	if _, err := DecodePlatformPin(append(withSeven, 7, 0, 0, 0, 0)); err == nil {
		t.Fatal("field 7 accepted")
	}
	if CheckWitnessQuorum(2, 3) != nil || CheckWitnessQuorum(1, 2) == nil || CheckWitnessQuorum(0, 0) == nil {
		t.Fatal("quorum")
	}
}

func TestReadPlatformPin(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "identity-1.pin")
	if err := WritePrivateFileAtomic(p, mustEncode(t, testPin(pinKey(1)))); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadPlatformPin(p); err != nil || got.Gen != 1 {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.pin")
	os.WriteFile(big, make([]byte, MaxPinFile+1), 0o600)
	if _, err := ReadPlatformPin(big); !errors.Is(err, ErrTooLarge) {
		t.Fatal("oversized pin read")
	}
	if _, err := ReadPlatformPin(filepath.Join(dir, "none")); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing pin")
	}
}

func TestEnsureUserAndEpoch(t *testing.T) {
	s, _ := Init(t.TempDir())
	tu := newTestUser(t, 3, 1)
	if err := s.EnsureUser(tu.user); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureUser(tu.user); err != nil {
		t.Fatal("same user.rec again", err)
	}
	if err := s.CreateUser(tu.user); !errors.Is(err, ErrExists) {
		t.Fatal("CreateUser stays exclusive")
	}
	two := newTestUser(t, 3, 2)
	if err := s.EnsureUser(two.user); !errors.Is(err, ErrExists) {
		t.Fatal("other content accepted")
	}
	if err := s.EnsureUser(&User{}); err == nil {
		t.Fatal("invalid user")
	}
	mbx := ID{7}
	e1, d1 := newTestEpoch(t, tu, mbx, 1, 1000, nil)
	if got, err := s.EnsureEpoch(e1); err != nil || !bytes.Equal(got, d1) {
		t.Fatal(err)
	}
	// After a crash between epoch.rec and the rest: done, the key copies
	// are written again.
	os.Remove(filepath.Join(s.EpochDir(mbx, 1), "meta.pub"))
	if got, err := s.EnsureEpoch(e1); err != nil || !bytes.Equal(got, d1) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.EpochDir(mbx, 1), "meta.pub")); err != nil {
		t.Fatal("meta.pub")
	}
	if _, err := s.WriteEpoch(e1); !errors.Is(err, ErrExists) {
		t.Fatal("WriteEpoch stays exclusive")
	}
	other, _ := newTestEpoch(t, tu, mbx, 1, 2000, nil)
	if _, err := s.EnsureEpoch(other); !errors.Is(err, ErrExists) {
		t.Fatal("other epoch accepted")
	}
	if _, err := s.EnsureEpoch(&Epoch{}); err == nil {
		t.Fatal("invalid epoch")
	}
}

func TestReplaceEpoch(t *testing.T) {
	s, _ := Init(t.TempDir())
	tu := newTestUser(t, 4, 1)
	mbx := ID{8}
	e1, d1 := newTestEpoch(t, tu, mbx, 1, 1000, nil)
	if _, err := s.WriteEpoch(e1); err != nil {
		t.Fatal(err)
	}
	_, d2 := newTestEpoch(t, tu, mbx, 1, 5000, nil)
	_, other := newTestEpoch(t, tu, ID{9}, 1, 5000, nil)
	never := func([]byte) bool { return false }
	called := 0
	yes := func(old []byte) bool {
		called++
		// The mailbox lock is held while the log is asked.
		if _, err := s.tryLockMailbox(mbx); !errors.Is(err, ErrLocked) {
			t.Error("unloggable runs without the mailbox lock")
		}
		return bytes.Equal(old, d1)
	}
	for name, err := range map[string]error{
		"loggable":       s.ReplaceEpoch(mbx, 1, d1, d2, never),
		"nil function":   s.ReplaceEpoch(mbx, 1, d1, d2, nil),
		"wrong old":      s.ReplaceEpoch(mbx, 1, d2, d2, yes),
		"other mailbox":  s.ReplaceEpoch(mbx, 1, d1, other, yes),
		"other number":   s.ReplaceEpoch(mbx, 2, d1, d2, yes),
		"garbage":        s.ReplaceEpoch(mbx, 1, d1, []byte("x"), yes),
		"missing epoch":  s.ReplaceEpoch(mbx, 3, d1, d2, yes),
		"same as stored": s.ReplaceEpoch(mbx, 1, d1, d1, yes),
	} {
		if err == nil {
			t.Fatalf("%s: replaced", name)
		}
	}
	if _, got, _ := s.ReadEpoch(mbx, 1); !bytes.Equal(got, d1) {
		t.Fatal("refused replacement changed the file")
	}
	called = 0
	if err := s.ReplaceEpoch(mbx, 1, d1, d2, yes); err != nil || called != 1 {
		t.Fatal(err)
	}
	if _, got, _ := s.ReadEpoch(mbx, 1); !bytes.Equal(got, d2) {
		t.Fatal("not replaced")
	}
}

// tryLockMailbox probes the mailbox lock without waiting.
func (s *Store) tryLockMailbox(id ID) (func(), error) {
	return tryLockFile(filepath.Join(s.MailboxDir(id), "lock"))
}

func TestLockPath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock")
	unlock, err := LockPath(p)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		u, err := LockPath(p)
		if err == nil {
			u()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("second holder did not wait")
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("lock not released")
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != FilePerm {
		t.Fatal("lock file mode")
	}
}
