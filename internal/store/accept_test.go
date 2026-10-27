package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
)

func testAccept(t testing.TB, tu *testUser) *WrapAccept {
	t.Helper()
	a := &WrapAccept{MailboxID: ID{9}, Epoch: 3, UserID: tu.user.ID, WrapHash: sha256.Sum256([]byte("wrap")), UserGen: tu.user.Current().Gen}
	if err := a.Sign(tu.identity); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestWrapAccept(t *testing.T) {
	tu := newTestUser(t, 1, 2)
	other := newTestUser(t, 2, 1)
	pub := tu.identity.Public().(ed25519.PublicKey)
	a := testAccept(t, tu)
	data := mustEncode(t, a)
	if !bytes.HasPrefix(data, []byte("gomail/v1/rec/wrap-accept\x00")) {
		t.Fatal("record type")
	}
	d, err := DecodeWrapAccept(data)
	if err != nil {
		t.Fatal(err)
	}
	if again := mustEncode(t, d); !bytes.Equal(again, data) {
		t.Fatal("wrap acceptance not byte-identical")
	}
	if err := d.Verify(pub); err != nil {
		t.Fatal(err)
	}
	tbs, _ := a.record(false).Encode()
	if !ed25519.Verify(pub, append([]byte("gomail/v1/sig/wrap-accept\x00"), tbs...), a.Signature) {
		t.Fatal("signature not under wrap-accept over the record without sig")
	}
	// Wrong signatures: another member, another domain, a changed field.
	if err := d.Verify(other.identity.Public().(ed25519.PublicKey)); !errors.Is(err, keys.ErrSignature) {
		t.Fatal("foreign key verified")
	}
	wrong := *d
	wrong.Signature, _ = keys.Sign(tu.identity, keys.DomainWrap, tbs)
	if err := wrong.Verify(pub); !errors.Is(err, keys.ErrSignature) {
		t.Fatal("signature of another domain verified")
	}
	for name, f := range map[string]func(x *WrapAccept){
		"mailbox": func(x *WrapAccept) { x.MailboxID = ID{8} },
		"epoch":   func(x *WrapAccept) { x.Epoch = 4 },
		"user":    func(x *WrapAccept) { x.UserID = other.user.ID },
		"hash":    func(x *WrapAccept) { x.WrapHash[0] ^= 1 },
		"gen":     func(x *WrapAccept) { x.UserGen = 1 },
	} {
		c := *d
		f(&c)
		if err := c.Verify(pub); !errors.Is(err, keys.ErrSignature) {
			t.Fatalf("changed %s verified: %v", name, err)
		}
	}
	// Missing signature.
	unsigned := *a
	unsigned.Signature = nil
	if _, err := unsigned.Encode(); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned acceptance encoded")
	}
	if _, err := DecodeWrapAccept(tbs); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned acceptance decoded")
	}
	if err := unsigned.Verify(pub); !errors.Is(err, keys.ErrSignature) {
		t.Fatal("unsigned acceptance verified")
	}
	if err := (&WrapAccept{MailboxID: ID{9}, Epoch: 1, UserID: ID{1}, WrapHash: [32]byte{1}, UserGen: 1}).Sign(tu.identity[:5]); err == nil {
		t.Fatal("short key signed")
	}
	// Incomplete records.
	for name, f := range map[string]func(x *WrapAccept){
		"zero mailbox": func(x *WrapAccept) { x.MailboxID = ID{} },
		"epoch 0":      func(x *WrapAccept) { x.Epoch = 0 },
		"zero user":    func(x *WrapAccept) { x.UserID = ID{} },
		"zero hash":    func(x *WrapAccept) { x.WrapHash = [32]byte{} },
		"gen 0":        func(x *WrapAccept) { x.UserGen = 0 },
	} {
		c := *a
		f(&c)
		if err := c.Sign(tu.identity); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s signed", name)
		}
		if _, err := c.Encode(); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s encoded", name)
		}
		if err := c.Verify(pub); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s verified", name)
		}
		if _, err := DecodeWrapAccept(mustEncode(t, c.record(true))); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s decoded", name)
		}
	}
	// Lengths: the hash has 32 bytes, the signature 64.
	short, _ := rec.New(WrapAcceptSchema).SetBytes(1, a.MailboxID[:]).SetU32(2, 1).SetBytes(3, a.UserID[:]).SetBytes(4, make([]byte, 31)).Encode()
	if short != nil {
		t.Fatal("short hash encoded")
	}
	if _, err := DecodeWrapAccept(append(data, 0)); err == nil {
		t.Fatal("trailing byte")
	}
	if _, err := DecodeWrapAccept(data[:len(data)-1]); err == nil {
		t.Fatal("truncated signature")
	}

	// The file members/<user-id>.accept of the epoch.
	s, _ := Init(t.TempDir())
	if err := s.WriteAccept(a); err != nil {
		t.Fatal(err)
	}
	if s.AcceptFile(ID{9}, 3, tu.user.ID) != filepath.Join(s.EpochDir(ID{9}, 3), "members", tu.user.ID.String()+".accept") {
		t.Fatal("path of the acceptance")
	}
	got, err := s.ReadAccept(ID{9}, 3, tu.user.ID)
	if err != nil || got.Verify(pub) != nil {
		t.Fatal(err)
	}
	// Replaced by a newer acceptance.
	b := *a
	b.WrapHash = sha256.Sum256([]byte("new wrap"))
	b.Sign(tu.identity)
	if err := s.WriteAccept(&b); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ReadAccept(ID{9}, 3, tu.user.ID); got.WrapHash != b.WrapHash {
		t.Fatal("acceptance not replaced")
	}
	if err := s.WriteAccept(&unsigned); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned acceptance written")
	}
	// An acceptance in the place of another member, epoch or mailbox.
	for _, p := range []string{s.AcceptFile(ID{9}, 3, other.user.ID), s.AcceptFile(ID{9}, 4, tu.user.ID), s.AcceptFile(ID{8}, 3, tu.user.ID)} {
		MkdirAll(filepath.Dir(p))
		WriteFileAtomic(p, data)
	}
	if _, err := s.ReadAccept(ID{9}, 3, other.user.ID); !errors.Is(err, ErrRecord) {
		t.Fatal("acceptance of another member")
	}
	if _, err := s.ReadAccept(ID{9}, 4, tu.user.ID); !errors.Is(err, ErrRecord) {
		t.Fatal("acceptance of another epoch")
	}
	if _, err := s.ReadAccept(ID{8}, 3, tu.user.ID); !errors.Is(err, ErrRecord) {
		t.Fatal("acceptance of another mailbox")
	}
	if _, err := s.ReadAccept(ID{9}, 5, tu.user.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing acceptance")
	}
	WriteFileAtomic(s.AcceptFile(ID{9}, 4, tu.user.ID), []byte("junk"))
	if _, err := s.ReadAccept(ID{9}, 4, tu.user.ID); err == nil {
		t.Fatal("junk acceptance")
	}
}
