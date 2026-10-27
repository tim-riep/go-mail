package translog

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
)

// records holds one loggable record of every kind.
type records struct {
	user, user2, epoch, address, cert, succ []byte
	userID, mbx                             store.ID
}

func newID(t testing.TB) store.ID {
	t.Helper()
	id, err := store.NewID(nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func makeRecords(t testing.TB) *records {
	t.Helper()
	seed, err := keys.NewSeed(nil)
	if err != nil {
		t.Fatal(err)
	}
	ur := keys.DeriveUser(seed)
	root, _ := ur.RootKey()
	r := &records{userID: newID(t), mbx: newID(t)}
	var certs []*keys.GenerationCert
	encodeUser := func(gens uint32) []byte {
		for g := uint32(len(certs)) + 1; g <= gens; g++ {
			id, _ := ur.IdentityKey(g)
			uw, _ := ur.UnwrapKey(g)
			c, err := keys.NewGenerationCert(root, g, id.Public().(ed25519.PublicKey), uw.PublicKey(), 1_800_000_000_000)
			if err != nil {
				t.Fatal(err)
			}
			certs = append(certs, c)
		}
		u := &store.User{ID: r.userID, RootPub: root.Public().(ed25519.PublicKey), Generations: certs}
		// user.rec is signed by the root from task 02 on; sign when the
		// method exists so that this test compiles before and after.
		if s, ok := any(u).(interface {
			Sign(ed25519.PrivateKey) error
		}); ok {
			if err := s.Sign(root); err != nil {
				t.Fatal(err)
			}
		}
		b, err := u.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	r.user = encodeUser(1)
	r.user2 = encodeUser(2)

	identity, _ := ur.IdentityKey(1)
	content, _ := ecdh.X25519().GenerateKey(rand.Reader)
	meta, _ := ecdh.X25519().GenerateKey(rand.Reader)
	e := &store.Epoch{
		MailboxID: r.mbx, Number: 1, Begin: 1_800_000_000_000, Reason: store.Reason(1), Suite: envelope.Suite1,
		ContentPub: content.PublicKey(), MetaPub: meta.PublicKey(),
		Members:  []store.Member{{Kind: store.MemberUser, ID: r.userID, Gen: 1}},
		SignerID: r.userID, SignerGen: 1,
	}
	if err := e.Sign(identity); err != nil {
		t.Fatal(err)
	}
	if r.epoch, err = e.Encode(); err != nil {
		t.Fatal(err)
	}

	pseed, _ := keys.NewSeed(nil)
	p := keys.DerivePlatform(pseed)
	id1, _ := p.IdentityKey(1)
	id2, _ := p.IdentityKey(2)
	admin, _ := p.AdminKey(1)
	a := &store.AddressAssignment{Address: "info@example.org", MailboxID: r.mbx, ValidFrom: 1_800_000_000_000, AdminGen: 1}
	if err := a.Sign(admin); err != nil {
		t.Fatal(err)
	}
	if r.address, err = a.Encode(); err != nil {
		t.Fatal(err)
	}
	ingest, _ := p.IngestKey(2)
	c, err := keys.NewPlatformCert(id1, 1, keys.RoleIngest, 2, ingest.Public().(ed25519.PublicKey), 1)
	if err != nil {
		t.Fatal(err)
	}
	if r.cert, err = c.Encode(); err != nil {
		t.Fatal(err)
	}
	s, err := keys.NewPlatformSuccession(id1, 2, id2.Public().(ed25519.PublicKey), 1)
	if err != nil {
		t.Fatal(err)
	}
	if r.succ, err = s.Encode(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestEntryKeysAndRoundTrip(t *testing.T) {
	r := makeRecords(t)
	for _, c := range []struct {
		kind    Kind
		content []byte
		subject []byte
		seq     int64
	}{
		{KindUser, r.user, r.userID[:], 1},
		{KindUser, r.user2, r.userID[:], 2},
		{KindEpoch, r.epoch, r.mbx[:], 1},
		{KindAddress, r.address, []byte("info@example.org"), 1_800_000_000_000},
		{KindPlatform, r.cert, []byte("ingest-2.cert"), 0},
		{KindPlatform, r.succ, []byte("identity-2.succ"), 0},
	} {
		k, err := KindOf(c.content)
		if err != nil || k != c.kind {
			t.Fatalf("KindOf %v: %v %v", c.kind, k, err)
		}
		e, err := NewEntry(c.kind, c.content)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(e.Subject, c.subject) || e.Seq != c.seq || e.Index != -1 {
			t.Fatalf("%v: key %x/%d", c.kind, e.Subject, e.Seq)
		}
		enc, err := e.Encode()
		if err != nil {
			t.Fatal(err)
		}
		d, err := DecodeEntry(enc, 7)
		if err != nil {
			t.Fatal(err)
		}
		if d.Index != 7 || !d.Key.Equal(e.Key) || !bytes.Equal(d.Content, c.content) {
			t.Fatalf("%v: round trip", c.kind)
		}
		again, _ := d.Encode()
		if !bytes.Equal(again, enc) {
			t.Fatalf("%v: encoding not canonical", c.kind)
		}
		if LeafHash(enc) != tlog.RecordHash(enc) {
			t.Fatal("leaf hash")
		}
		// The key must be the one derived from the content.
		for _, bad := range []Key{
			{Kind: e.Kind, Subject: append(clone(e.Subject), 'x'), Seq: e.Seq},
			{Kind: e.Kind, Subject: e.Subject, Seq: e.Seq + 1},
		} {
			b := rec.New(EntrySchema).SetU8(1, uint8(bad.Kind)).SetBytes(2, bad.Subject).SetI64(3, bad.Seq).SetBytes(4, c.content)
			raw, err := b.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeEntry(raw, 0); !errors.Is(err, ErrEntry) {
				t.Fatalf("%v: wrong key accepted: %v", c.kind, err)
			}
			if _, err := (&Entry{Key: bad, Content: c.content}).Encode(); !errors.Is(err, ErrEntry) {
				t.Fatalf("%v: wrong key encoded", c.kind)
			}
		}
	}
	// Content of another kind than claimed.
	for _, c := range []struct {
		kind    Kind
		content []byte
	}{{KindUser, r.epoch}, {KindEpoch, r.address}, {KindAddress, r.cert}, {KindPlatform, r.user}, {Kind(9), r.user}, {Kind(0), r.user}} {
		if _, err := NewEntry(c.kind, c.content); !errors.Is(err, ErrEntry) {
			t.Fatalf("kind %v accepted foreign content", c.kind)
		}
	}
	if _, err := KindOf([]byte("gomail/v1/rec/mailbox\x00")); !errors.Is(err, ErrEntry) {
		t.Fatal("unloggable record")
	}
	if _, err := KeyOf(KindUser, make([]byte, MaxContent+1)); !errors.Is(err, ErrEntry) {
		t.Fatal("oversized content")
	}
	// A well-formed entry around content that is not a valid record.
	for _, c := range []struct {
		kind    Kind
		content []byte
	}{
		{KindPlatform, append(keys.PlatformCertSchema.Prefix(), 1)},
		{KindPlatform, append(keys.PlatformSuccessionSchema.Prefix(), 1)},
		{KindEpoch, r.epoch[:len(r.epoch)-1]},
	} {
		raw, err := rec.New(EntrySchema).SetU8(1, uint8(c.kind)).SetBytes(2, []byte("x")).SetI64(3, 0).SetBytes(4, c.content).Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeEntry(raw, 0); !errors.Is(err, ErrEntry) {
			t.Fatalf("%v: invalid content accepted", c.kind)
		}
	}
	// valid_from must not be negative (it is a duplicate key).
	a, _ := store.DecodeAddressAssignment(r.address)
	a.ValidFrom = -1
	a.Signature = make([]byte, ed25519.SignatureSize)
	neg, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := KeyOf(KindAddress, neg); !errors.Is(err, ErrEntry) {
		t.Fatal("negative valid_from")
	}
	if _, err := DecodeEntry([]byte("garbage"), 0); !errors.Is(err, ErrEntry) {
		t.Fatal("garbage entry")
	}
	if _, err := (*Entry)(nil).Encode(); !errors.Is(err, ErrEntry) {
		t.Fatal("nil entry")
	}
	if KindUser.String() != "user" || KindEpoch.String() != "epoch" || KindAddress.String() != "address" ||
		KindPlatform.String() != "platform" || Kind(9).String() != "kind(9)" {
		t.Fatal("kind names")
	}
}

func TestDuplicateKeys(t *testing.T) {
	r := makeRecords(t)
	k1, _ := KeyOf(KindUser, r.user)
	k2, _ := KeyOf(KindUser, r.user2)
	if k1.Equal(k2) {
		t.Fatal("two generations of one user must have different keys")
	}
	again, _ := KeyOf(KindUser, r.user)
	if !again.Equal(k1) || KeyPath(again) != KeyPath(k1) {
		t.Fatal("the same user.rec must give the same key")
	}
	if KeyPath(k1) == KeyPath(k2) {
		t.Fatal("key paths must differ per generation")
	}
	ke, _ := KeyOf(KindEpoch, r.epoch)
	if strings.Contains(KeyPath(ke), r.mbx.String()) {
		t.Fatal("subjects are hashed in key paths")
	}
	ka, _ := KeyOf(KindAddress, r.address)
	if p := KeyPath(ka); strings.Contains(p, "example") || !strings.HasPrefix(p, "log/keys/address/") || !strings.HasSuffix(p, "/1800000000000") {
		t.Fatalf("address key path %s", p)
	}
	// Same subject and seq, other kind: different keys.
	if (Key{Kind: KindUser, Subject: ke.Subject, Seq: 1}).Equal(ke) {
		t.Fatal("kind is part of the key")
	}
	if EntryPath(12) != "log/entries/12.rec" || HeadPath(3) != "log/heads/3.sig" {
		t.Fatal("paths")
	}
	if p := TilePath(tlog.Tile{H: 8, L: 0, N: 1, W: 5}); p != "log/tree/tile/8/0/001.p/5" {
		t.Fatalf("tile path %s", p)
	}
}

func testHead() *Head {
	h := &Head{Origin: "gomail.example/log", Size: 42, Time: 1_800_000_000_123}
	for i := range h.Hash {
		h.Hash[i] = byte(i)
	}
	return h
}

func TestHeadText(t *testing.T) {
	h := testHead()
	text, err := h.Text()
	if err != nil {
		t.Fatal(err)
	}
	want := "gomail.example/log\n42\nAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\ntime 1800000000123\n"
	if string(text) != want {
		t.Fatalf("text %q", text)
	}
	p, err := ParseHeadText(text)
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != h.Origin || p.Size != h.Size || p.Hash != h.Hash || p.Time != h.Time {
		t.Fatal("round trip")
	}
	hash := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	for _, bad := range []string{
		"",
		"o\n1\n" + hash + "\n",                                  // three lines
		"o\n1\n" + hash + "\ntime 1\nx\n",                       // five lines
		"o\n1\n" + hash + "\ntime 1",                            // no final newline
		"o\n0\n" + hash + "\ntime 1\n",                          // empty log
		"o\n01\n" + hash + "\ntime 1\n",                         // leading zero
		"o\n+1\n" + hash + "\ntime 1\n",                         // sign
		"o\n-1\n" + hash + "\ntime 1\n",                         // negative
		"o\n99999999999999999999\n" + hash + "\ntime 1\n",       // overflow
		"o\n1\n" + strings.TrimSuffix(hash, "=") + "\ntime 1\n", // no padding
		"o\n1\nAAAA\ntime 1\n",                                  // short hash
		"o\n1\n" + hash + "\ntime 01\n",                         // leading zero
		"o\n1\n" + hash + "\ntime -1\n",
		"o\n1\n" + hash + "\nTime 1\n",
		"o\n1\n" + hash + "\ntime  1\n",
		"o p\n1\n" + hash + "\ntime 1\n", // space in origin
		"o+p\n1\n" + hash + "\ntime 1\n", // plus in origin
		"ö\n1\n" + hash + "\ntime 1\n",   // non-ASCII
		"\n1\n" + hash + "\ntime 1\n",    // empty origin
		strings.Repeat("o", MaxOrigin+1) + "\n1\n" + hash + "\ntime 1\n",
		"o\r\n1\n" + hash + "\ntime 1\n",
	} {
		if _, err := ParseHeadText([]byte(bad)); !errors.Is(err, ErrHead) {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := ParseHeadText([]byte(strings.Repeat("x", MaxHeadText+1))); !errors.Is(err, ErrHead) {
		t.Fatal("too long")
	}
	for _, bad := range []*Head{{Origin: "", Size: 1}, {Origin: "o", Size: 0}, {Origin: "o", Size: 1, Time: -1}} {
		if _, err := bad.Text(); !errors.Is(err, ErrHead) {
			t.Fatal("invalid head formatted")
		}
	}
	if CheckOrigin("gomail.example/log") != nil || CheckOrigin("a b") == nil {
		t.Fatal("CheckOrigin")
	}
}

func TestOpenHead(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := NewLogSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	logV, err := NewLogVerifier(priv.Public().(ed25519.PublicKey))
	if err != nil || logV.Name() != LogSignerName || logV.KeyHash() != signer.KeyHash() || signer.Name() != LogSignerName {
		t.Fatal("log verifier", err)
	}
	wPub, _, _ := ed25519.GenerateKey(rand.Reader)
	wV, err := NewWitnessVerifier("witness.example", wPub)
	if err != nil {
		t.Fatal(err)
	}
	skey, _, _ := note.GenerateKey(rand.Reader, "witness.example")
	wSigner, _ := note.NewSigner(skey)

	h := testHead()
	text, _ := h.Text()
	msg, err := note.Sign(&note.Note{Text: string(text)}, signer)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenHead(msg, note.VerifierList(logV, wV))
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != 42 || len(got.Sigs) != 1 || got.Sigs[0].Name != LogSignerName || !bytes.Equal(got.Note, msg) {
		t.Fatal("open head")
	}
	// A cosignature by a witness the verifier does not know never counts.
	co, err := note.Sign(&note.Note{Text: string(text), Sigs: []note.Signature{got.Sigs[0]}}, wSigner)
	if err != nil {
		t.Fatal(err)
	}
	got, err = OpenHead(co, note.VerifierList(logV, wV))
	if err != nil || len(got.Sigs) != 1 {
		t.Fatalf("unknown witness counted: %v %d", err, len(got.Sigs))
	}
	// Without any known key the head is rejected.
	if _, err := OpenHead(msg, note.VerifierList(wV)); !errors.Is(err, ErrHead) {
		t.Fatal("unsigned head accepted")
	}
	// A changed text breaks the signature.
	bad := bytes.Replace(msg, []byte("\n42\n"), []byte("\n43\n"), 1)
	if _, err := OpenHead(bad, note.VerifierList(logV)); !errors.Is(err, ErrHead) {
		t.Fatal("tampered head accepted")
	}
	// A validly signed note that is not a head.
	other, _ := note.Sign(&note.Note{Text: "hello\n"}, signer)
	if _, err := OpenHead(other, note.VerifierList(logV)); !errors.Is(err, ErrHead) {
		t.Fatal("non-head note accepted")
	}
	if _, err := OpenHead(make([]byte, MaxHeadNote+1), note.VerifierList(logV)); !errors.Is(err, ErrHead) {
		t.Fatal("oversized note")
	}
	// Too many signature lines.
	many := &note.Note{Text: string(text)}
	var signers []note.Signer
	for i := 0; i < MaxSignatures; i++ {
		sk, _, _ := note.GenerateKey(rand.Reader, "w"+strings.Repeat("x", i))
		s, _ := note.NewSigner(sk)
		signers = append(signers, s)
	}
	signers = append(signers, signer)
	mm, err := note.Sign(many, signers...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHead(mm, note.VerifierList(logV)); !errors.Is(err, ErrHead) {
		t.Fatal("too many signatures")
	}
	// The log signer never signs a text with NUL (a 3.7 message).
	if _, err := signer.Sign([]byte("gomail/v1/sig/epoch\x00x")); !errors.Is(err, ErrHead) {
		t.Fatal("signed a NUL text")
	}
	if _, err := NewLogSigner(priv[:10]); !errors.Is(err, ErrHead) {
		t.Fatal("short key")
	}
	if _, err := NewLogVerifier(ed25519.PublicKey(priv[:10])); !errors.Is(err, ErrHead) {
		t.Fatal("short public key")
	}
	if _, err := NewWitnessVerifier(LogSignerName, wPub); !errors.Is(err, ErrWitness) {
		t.Fatal("witness with the log's name")
	}
	if _, err := NewWitnessVerifier("a b", wPub); !errors.Is(err, ErrWitness) {
		t.Fatal("invalid witness name")
	}
	if _, err := NewWitnessVerifier("w", wPub[:3]); !errors.Is(err, ErrWitness) {
		t.Fatal("short witness key")
	}
}

func TestInterfaceStubs(t *testing.T) {
	if !errors.Is(ErrPending, ErrNotInLog) {
		t.Fatal("ErrPending must be an ErrNotInLog")
	}
	v := &Verifier{Revoked: []Revoked{{Role: store.KeyRoleIngest, Gen: 2}}}
	if !v.IsRevoked(store.KeyRoleIngest, 2) || v.IsRevoked(store.KeyRoleIngest, 1) || v.IsRevoked(store.KeyRoleAdmin, 2) {
		t.Fatal("IsRevoked")
	}
	// A Verifier without pinned anchors accepts nothing.
	for _, err := range []error{
		v.CheckHead(testHead(), nil), v.Fresh(time.Now()), v.CheckInclusion(0, nil, nil),
		v.CheckCheckpoint("o", 1, tlog.Hash{}, 0, nil),
	} {
		if err == nil {
			t.Fatal("empty verifier accepted")
		}
	}
	if l, err := Open(Options{}); l != nil || !errors.Is(err, ErrConsistency) {
		t.Fatal("Open without a data directory")
	}
	var _ Operator = (*operatorLog)(nil)
}
