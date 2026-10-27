package witness

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// ErrWitnesses reports an invalid witness list.
var ErrWitnesses = errors.New("witness: invalid witness list")

// WitnessSchema is one witness: its note name and Ed25519 public key.
// The verifier key line is derived (note.NewEd25519VerifierKey), so the
// key hash is never stored and cannot disagree with the key. The element
// is shared with the client pin (field 5, translog doc.go "Pin") and is
// defined in store (store.WitnessSchema, task 07); MaxName equals
// store.MaxWitnessName.
var WitnessSchema = store.WitnessSchema

// WitnessesSchema is platform/witnesses.rec (section 4): the witnesses
// the server accepts cosignatures from and the number of cosignatures a
// head needs before the server publishes it in heads/. It is NOT signed
// and binds nobody but the server: it is the server's working copy
// (like addresses.json). The list a client trusts is the one in its pin
// (Q4); a server that edits witnesses.rec can only make its own heads
// unacceptable to clients. The minimum must be a quorum that excludes a
// split view among honest witnesses: 2*min > number of witnesses
// (translog.CheckQuorum, task 03b finding S1); the same rule holds for
// the pin.
var WitnessesSchema = rec.MustSchema("gomail/v1/rec/witnesses",
	rec.Field{Num: 1, Name: "witnesses", Kind: rec.List, Elem: WitnessSchema, MaxCount: MaxWitnesses, Required: true},
	rec.Field{Num: 2, Name: "min", Kind: rec.U32, Required: true},
)

// Key is a witness public key.
type Key struct {
	Name string
	Pub  ed25519.PublicKey
}

// Verifier returns the note verifier of the key.
func (k Key) Verifier() (note.Verifier, error) {
	if err := CheckName(k.Name); err != nil {
		return nil, err
	}
	return translog.NewWitnessVerifier(k.Name, k.Pub)
}

// Witnesses is a decoded witnesses.rec.
type Witnesses struct {
	List []Key
	Min  int
}

// CheckName reports whether name is a valid witness name: 1 to MaxName
// bytes of printable ASCII (0x21 to 0x7e) without "+" (note forbids "+"
// and spaces in names), and not translog.LogSignerName.
func CheckName(name string) error {
	if name == "" || len(name) > MaxName {
		return fmt.Errorf("%w: name length", ErrWitnesses)
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x21 || c > 0x7e || c == '+' {
			return fmt.Errorf("%w: name must be printable ASCII without spaces and '+'", ErrWitnesses)
		}
	}
	if name == translog.LogSignerName {
		return fmt.Errorf("%w: name of the log signer", ErrWitnesses)
	}
	return nil
}

func (w *Witnesses) check() error {
	if len(w.List) == 0 || len(w.List) > MaxWitnesses {
		return fmt.Errorf("%w: %d witnesses", ErrWitnesses, len(w.List))
	}
	if translog.CheckQuorum(w.Min, len(w.List)) != nil {
		return fmt.Errorf("%w: minimum %d of %d admits a split view (2*min must exceed the number of witnesses)", ErrWitnesses, w.Min, len(w.List))
	}
	for i, k := range w.List {
		if err := CheckName(k.Name); err != nil {
			return err
		}
		if len(k.Pub) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: key length", ErrWitnesses)
		}
		for _, o := range w.List[:i] {
			if o.Name == k.Name || bytes.Equal(o.Pub, k.Pub) {
				return fmt.Errorf("%w: duplicate witness", ErrWitnesses)
			}
		}
	}
	return nil
}

// Encode returns the canonical encoding.
func (w *Witnesses) Encode() ([]byte, error) {
	if err := w.check(); err != nil {
		return nil, err
	}
	list := make([]*rec.Record, 0, len(w.List))
	for _, k := range w.List {
		list = append(list, rec.New(WitnessSchema).SetString(1, k.Name).SetBytes(2, k.Pub))
	}
	b, err := rec.New(WitnessesSchema).SetList(1, list).SetU32(2, uint32(w.Min)).Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWitnesses, err)
	}
	return b, nil
}

// DecodeWitnesses decodes witnesses.rec strictly: names valid and
// unique, keys unique, 1 <= min <= number of witnesses and 2*min >
// number of witnesses (translog.CheckQuorum).
func DecodeWitnesses(data []byte) (*Witnesses, error) {
	r, err := rec.Decode(WitnessesSchema, data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWitnesses, err)
	}
	m := r.U32(2)
	if m > MaxWitnesses {
		return nil, fmt.Errorf("%w: minimum %d", ErrWitnesses, m)
	}
	w := &Witnesses{Min: int(m)}
	for _, e := range r.List(1) {
		w.List = append(w.List, Key{Name: e.String(1), Pub: ed25519.PublicKey(e.Bytes(2))})
	}
	if err := w.check(); err != nil {
		return nil, err
	}
	return w, nil
}

// Verifiers returns the note verifiers of all witnesses.
func (w *Witnesses) Verifiers() ([]note.Verifier, error) {
	vs := make([]note.Verifier, 0, len(w.List))
	for _, k := range w.List {
		v, err := k.Verifier()
		if err != nil {
			return nil, err
		}
		vs = append(vs, v)
	}
	return vs, nil
}
