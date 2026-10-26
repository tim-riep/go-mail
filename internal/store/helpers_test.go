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
	reason := ReasonMonthly
	if n == 1 {
		reason = ReasonInitial
	}
	e := &Epoch{
		MailboxID: mbx, Number: n, Begin: begin, Reason: reason, Suite: envelope.Suite1,
		ContentPub: x25519(t, byte(n)).PublicKey(), MetaPub: x25519(t, byte(n)+100).PublicKey(),
		Members:  []Member{{Kind: MemberUser, ID: tu.user.ID, Gen: tu.user.Current().Gen}},
		SignerID: tu.user.ID, SignerGen: tu.user.Current().Gen,
	}
	if prev != nil {
		e.PrevHash = EpochHash(prev)
	}
	if err := e.Sign(tu.identity); err != nil {
		t.Fatal(err)
	}
	data, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return e, data
}
