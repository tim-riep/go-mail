package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// pinData is a pin of the real ceremony as translog doc.go "Pin"
// describes it: the identity list (field 8, whose last element is fields
// 1 and 2), the log origin (field 4) and the witnesses with their quorum
// (fields 5 and 6). Field 3 (dev) is 0; field 7 exists only if Q8 is
// decided as proposed.
type pinData struct {
	Identities   []translog.Identity
	Origin       string
	Witnesses    []witness.Key
	MinWitnesses int
}

// checkTrust checks origin, witnesses and quorum as the pin requires
// them (translog.CheckQuorum first, translog.CheckOrigin, the witness
// list rules of witness.Witnesses) and returns the encoding of
// platform/witnesses.rec.
func checkTrust(origin string, ws []witness.Key, min int) ([]byte, error) {
	if err := translog.CheckQuorum(min, len(ws)); err != nil {
		return nil, err
	}
	if err := translog.CheckOrigin(origin); err != nil {
		return nil, err
	}
	return (&witness.Witnesses{List: ws, Min: min}).Encode()
}

// newPin checks d and returns the pin and its encoding, fields 1 to 6
// and 8 (store.PlatformPin.Encode); it is the only place of this package
// that makes a pin.
func newPin(d *pinData) (*store.PlatformPin, []byte, error) {
	if len(d.Identities) == 0 {
		return nil, nil, fmt.Errorf("%w: empty identity list", translog.ErrPin)
	}
	cur := d.Identities[len(d.Identities)-1]
	if err := translog.CheckIdentities(d.Identities, cur); err != nil {
		return nil, nil, err
	}
	if _, err := checkTrust(d.Origin, d.Witnesses, d.MinWitnesses); err != nil {
		return nil, nil, err
	}
	p := &store.PlatformPin{Gen: cur.Gen, Pub: bytes.Clone(cur.Pub), Origin: d.Origin, MinWitnesses: d.MinWitnesses}
	for _, w := range d.Witnesses {
		p.Witnesses = append(p.Witnesses, store.Witness{Name: w.Name, Pub: bytes.Clone(w.Pub)})
	}
	for _, id := range d.Identities {
		p.Identities = append(p.Identities, store.PlatformIdentity{Gen: id.Gen, Pub: bytes.Clone(id.Pub)})
	}
	b, err := p.Encode()
	if err != nil {
		return nil, nil, err
	}
	return p, b, nil
}

// PinIdentities returns a copy of the identity list (field 8) of a pin
// of the real ceremony, checked against fields 1 and 2
// (translog.CheckIdentities). A development pin (dev = 1, InitDev) is
// never an anchor of the real ceremony (ErrIdentity).
func PinIdentities(p *store.PlatformPin) ([]translog.Identity, error) {
	if p == nil || len(p.Pub) != ed25519.PublicKeySize || p.Gen == 0 {
		return nil, fmt.Errorf("%w: invalid pin", ErrIdentity)
	}
	if p.Dev {
		return nil, fmt.Errorf("%w: development pin", ErrIdentity)
	}
	ids := make([]translog.Identity, 0, len(p.Identities))
	for _, id := range p.Identities {
		ids = append(ids, translog.Identity{Gen: id.Gen, Pub: bytes.Clone(id.Pub)})
	}
	if err := translog.CheckIdentities(ids, translog.Identity{Gen: p.Gen, Pub: p.Pub}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIdentity, err)
	}
	return ids, nil
}

// pinWitnesses returns the witnesses of a pin (field 5).
func pinWitnesses(p *store.PlatformPin) []witness.Key {
	ws := make([]witness.Key, 0, len(p.Witnesses))
	for _, w := range p.Witnesses {
		ws = append(ws, witness.Key{Name: w.Name, Pub: bytes.Clone(w.Pub)})
	}
	return ws
}

// sameWitnesses reports whether a and b are the same witnesses with the
// same quorum, in any order.
func sameWitnesses(a []witness.Key, minA int, b []witness.Key, minB int) bool {
	if minA != minB || len(a) != len(b) {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			found = found || (x.Name == y.Name && x.Pub.Equal(y.Pub))
		}
		if !found {
			return false
		}
	}
	return true
}
