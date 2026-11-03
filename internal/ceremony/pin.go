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
// 1 and 2), the log origin (field 4), the witnesses with their quorum
// (fields 5 and 6) and the revoked platform generations (field 7, D93;
// empty: no field 7). Field 3 (dev) is 0.
type pinData struct {
	Identities   []translog.Identity
	Origin       string
	Witnesses    []witness.Key
	MinWitnesses int
	// Revoked is field 7 in the canonical order (addRevoked); every pin
	// after the first carries over the list of its predecessor (D93 (4)).
	Revoked []store.PlatformRevoked
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
// and 8, and 7 when d.Revoked is not empty (store.PlatformPin.Encode);
// it is the only place of this package that makes a pin.
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
	if len(d.Revoked) > 0 {
		p.Revoked = append([]store.PlatformRevoked(nil), d.Revoked...)
	}
	if err := translog.CheckRevoked(revokedOf(p.Revoked), cur.Gen); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrRevocation, err)
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

// revokedOf returns field 7 of a pin in the form of translog.
func revokedOf(list []store.PlatformRevoked) []translog.Revoked {
	var out []translog.Revoked
	for _, r := range list {
		out = append(out, translog.Revoked{Role: r.Role, Gen: r.Gen, AtSize: r.AtSize, AtTime: r.AtTime})
	}
	return out
}

// addRevoked returns a copy of list (field 7 of the current pin) with r
// added, in the canonical order of store.CheckPinRevoked (ascending by
// role, then generation). A generation that list already revokes is
// ErrRevocation: its boundary is never moved, neither later (that would
// make valid again what the old pin refuses) nor earlier (a new
// revocation of the same generation is not a correction of the old one
// the clients could tell apart); and so is a list that would exceed
// store.MaxPinRevoked.
func addRevoked(list []store.PlatformRevoked, r store.PlatformRevoked) ([]store.PlatformRevoked, error) {
	out := make([]store.PlatformRevoked, 0, len(list)+1)
	added := false
	for _, x := range list {
		if x.Role == r.Role && x.Gen == r.Gen {
			return nil, fmt.Errorf("%w: the pin already revokes %s generation %d (from log index %d, time %d)",
				ErrRevocation, RoleName(r.Role), r.Gen, x.AtSize, x.AtTime)
		}
		if !added && (r.Role < x.Role || r.Role == x.Role && r.Gen < x.Gen) {
			out = append(out, r)
			added = true
		}
		out = append(out, x)
	}
	if !added {
		out = append(out, r)
	}
	if len(out) > store.MaxPinRevoked {
		return nil, fmt.Errorf("%w: a pin revokes at most %d generations", ErrRevocation, store.MaxPinRevoked)
	}
	return out, nil
}

// RoleName returns the name of a platform role in file names and
// messages: identity, admin or ingest.
func RoleName(role uint8) string {
	switch role {
	case store.KeyRoleIdentity:
		return "identity"
	case store.KeyRoleAdmin:
		return "admin"
	case store.KeyRoleIngest:
		return "ingest"
	}
	return fmt.Sprintf("role-%d", role)
}
