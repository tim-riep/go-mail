package store

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"testing"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
)

type testUser struct {
	user     *User
	identity ed25519.PrivateKey
	unwrap   *ecdh.PrivateKey
	root     ed25519.PrivateKey
}

func newTestUser(t testing.TB, b byte, gens int) *testUser {
	t.Helper()
	seed := keys.Seed{b}
	d := keys.DeriveUser(&seed)
	root, err := d.RootKey()
	if err != nil {
		t.Fatal(err)
	}
	tu := &testUser{root: root, user: &User{RootPub: root.Public().(ed25519.PublicKey)}}
	tu.user.ID = ID{b, 1}
	for g := uint32(1); g <= uint32(gens); g++ {
		id, _ := d.IdentityKey(g)
		uw, _ := d.UnwrapKey(g)
		c, err := keys.NewGenerationCert(root, g, id.Public().(ed25519.PublicKey), uw.PublicKey(), int64(g))
		if err != nil {
			t.Fatal(err)
		}
		tu.user.Generations = append(tu.user.Generations, c)
		tu.identity, tu.unwrap = id, uw
	}
	if err := tu.user.Sign(root); err != nil {
		t.Fatal(err)
	}
	return tu
}

func x25519(t testing.TB, b byte) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newTestEpoch returns signed epoch n of mailbox mbx; prev is the encoded
// predecessor (nil for epoch 1).
func newTestEpoch(t testing.TB, tu *testUser, mbx ID, n uint32, begin int64, prev []byte) (*Epoch, []byte) {
	t.Helper()
	e := unsignedEpoch(t, tu, mbx, n, begin, ReasonRegular, prev)
	return signEpoch(t, tu, e)
}

// unsignedEpoch returns epoch n with tu as its only member and signer.
func unsignedEpoch(t testing.TB, tu *testUser, mbx ID, n uint32, begin int64, reason Reason, prev []byte) *Epoch {
	t.Helper()
	e := &Epoch{
		MailboxID: mbx, Number: n, Begin: begin, Reason: reason, Suite: envelope.Suite1,
		ContentPub: x25519(t, byte(n)).PublicKey(), MetaPub: x25519(t, byte(n)+100).PublicKey(),
		Members:  []Member{{Kind: MemberUser, ID: tu.user.ID, Gen: tu.user.Current().Gen}},
		SignerID: tu.user.ID, SignerGen: tu.user.Current().Gen,
	}
	if prev != nil {
		e.PrevHash = EpochHash(prev)
	}
	return e
}

// signEpoch signs e with the identity of tu and encodes it.
func signEpoch(t testing.TB, tu *testUser, e *Epoch) (*Epoch, []byte) {
	t.Helper()
	if err := e.Sign(tu.identity); err != nil {
		t.Fatal(err)
	}
	data, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return e, data
}

// ed25519Sign signs tbs as an epoch with the identity of tu, without any
// structural check.
func ed25519Sign(tu *testUser, tbs []byte) []byte {
	sig, err := keys.Sign(tu.identity, keys.DomainEpoch, tbs)
	if err != nil {
		panic(err)
	}
	return sig
}

func mustEncode(t testing.TB, r interface{ Encode() ([]byte, error) }) []byte {
	t.Helper()
	b, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
