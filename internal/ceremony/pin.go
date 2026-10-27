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

// newPin checks d and returns the pin and its encoding.
//
// Since the merge of task 07 (task 10f) store.PlatformPin carries
// origin, witnesses, min_witnesses and identities (fields 4 to 6 and 8),
// and they are set from d here; nothing else in this package writes a
// pin. TODO(task-15b): the other TODO(task-07) places of this package
// and of gomail-ceremony still use Result.Identities and the flags
// instead of the pin's fields.
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

// PinIdentities returns the identity list (field 8) of a pin of the real
// ceremony.
//
// TODO(task-07): return a copy of the pin's field 8 once
// store.PlatformPin has it. Today's pin carries only its current
// generation, so the list is known only for generation 1, where it is
// that one element; for a later generation PinIdentities reports
// ErrIdentity and the caller has to pass the list itself
// (PublishOptions.Identities, Result.Identities). A development pin (dev
// = 1, InitDev) is never an anchor of the real ceremony (ErrIdentity).
func PinIdentities(p *store.PlatformPin) ([]translog.Identity, error) {
	if p == nil || len(p.Pub) != ed25519.PublicKeySize || p.Gen == 0 {
		return nil, fmt.Errorf("%w: invalid pin", ErrIdentity)
	}
	if p.Dev {
		return nil, fmt.Errorf("%w: development pin", ErrIdentity)
	}
	if p.Gen != 1 {
		return nil, fmt.Errorf("%w: the pin of generation %d carries no identity list yet", ErrIdentity, p.Gen)
	}
	return []translog.Identity{{Gen: 1, Pub: bytes.Clone(p.Pub)}}, nil
}
