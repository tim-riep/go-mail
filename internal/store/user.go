package store

import (
	"crypto/ed25519"
	"fmt"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
)

// UserSchema is users/<user-id>/user.rec (2.2): the user ID, the public
// root key, the generation certificates 1..n (each signed by the root)
// and the signature of the root under the short name "user" (3.7, S16)
// over the record without field 4. The signature binds the user ID to the
// root key and to the list of generations.
var UserSchema = rec.MustSchema("gomail/v1/rec/user",
	id16(1, "user_id", true),
	rec.Field{Num: 2, Name: "root_pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
	rec.Field{Num: 3, Name: "generations", Kind: rec.List, Elem: keys.GenerationCertSchema, MaxCount: MaxGenerations, Required: true},
	rec.Field{Num: 4, Name: "sig", Kind: rec.Bytes, Size: ed25519.SignatureSize},
)

// User is a decoded and verified user.rec.
type User struct {
	ID          ID
	RootPub     ed25519.PublicKey
	Generations []*keys.GenerationCert // generations 1..n in order
	Signature   []byte                 // by the root under "user"
}

func (u *User) check() error {
	if u.ID.IsZero() {
		return fmt.Errorf("%w: zero user id", ErrRecord)
	}
	if len(u.RootPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: root key length", ErrRecord)
	}
	if err := keys.VerifyGenerationChain(u.RootPub, u.Generations); err != nil {
		return fmt.Errorf("%w: %v", ErrRecord, err)
	}
	return nil
}

func (u *User) record(withSig bool) (*rec.Record, error) {
	list := make([]*rec.Record, 0, len(u.Generations))
	for _, g := range u.Generations {
		b, err := g.Encode()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRecord, err)
		}
		r, err := rec.Decode(keys.GenerationCertSchema, b)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRecord, err)
		}
		list = append(list, r)
	}
	r := rec.New(UserSchema).SetBytes(1, u.ID[:]).SetBytes(2, u.RootPub).SetList(3, list)
	if withSig {
		r.SetBytes(4, u.Signature)
	}
	return r, nil
}

func (u *User) tbs() ([]byte, error) {
	r, err := u.record(false)
	if err != nil {
		return nil, err
	}
	return r.Encode()
}

// Sign signs the record with the root key; root must belong to RootPub.
func (u *User) Sign(root ed25519.PrivateKey) error {
	if err := u.check(); err != nil {
		return err
	}
	if len(root) != ed25519.PrivateKeySize || !u.RootPub.Equal(root.Public()) {
		return fmt.Errorf("%w: not the root key of the user", ErrRecord)
	}
	tbs, err := u.tbs()
	if err != nil {
		return err
	}
	sig, err := keys.Sign(root, keys.DomainUser, tbs)
	if err != nil {
		return err
	}
	u.Signature = sig
	return nil
}

// Verify checks the generation chain and the signature against the root
// key in the record.
func (u *User) Verify() error {
	if err := u.check(); err != nil {
		return err
	}
	tbs, err := u.tbs()
	if err != nil {
		return err
	}
	if !keys.Verify(u.RootPub, keys.DomainUser, tbs, u.Signature) {
		return fmt.Errorf("%w: user.rec of %s", keys.ErrSignature, u.ID)
	}
	return nil
}

// Encode returns the canonical encoding of a signed user record after
// checking the chain and the signature.
func (u *User) Encode() ([]byte, error) {
	if len(u.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: user.rec is not signed", ErrRecord)
	}
	if err := u.Verify(); err != nil {
		return nil, err
	}
	r, err := u.record(true)
	if err != nil {
		return nil, err
	}
	return r.Encode()
}

// DecodeUser decodes user.rec and verifies the generation chain and the
// signature against the root key in it (fail closed: an unsigned record
// is rejected).
func DecodeUser(data []byte) (*User, error) {
	r, err := rec.Decode(UserSchema, data)
	if err != nil {
		return nil, err
	}
	if !r.Has(4) {
		return nil, fmt.Errorf("%w: user.rec is not signed", ErrRecord)
	}
	u := &User{ID: idFromBytes(r.Bytes(1)), RootPub: ed25519.PublicKey(r.Bytes(2)), Signature: r.Bytes(4)}
	for _, e := range r.List(3) {
		b, err := e.Encode()
		if err != nil {
			return nil, err
		}
		c, err := keys.DecodeGenerationCert(b)
		if err != nil {
			return nil, err
		}
		u.Generations = append(u.Generations, c)
	}
	if err := u.Verify(); err != nil {
		return nil, err
	}
	return u, nil
}

// Current returns the newest generation; all older ones are revoked by
// their successors (2.2).
func (u *User) Current() *keys.GenerationCert { return u.Generations[len(u.Generations)-1] }

// Generation returns generation gen or nil.
func (u *User) Generation(gen uint32) *keys.GenerationCert {
	if gen == 0 || uint64(gen) > uint64(len(u.Generations)) {
		return nil
	}
	return u.Generations[gen-1]
}
