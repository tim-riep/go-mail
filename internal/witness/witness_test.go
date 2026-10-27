package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/translog"
)

func key(t *testing.T, name string) Key {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Key{Name: name, Pub: pub}
}

func TestWitnessesRecord(t *testing.T) {
	w := &Witnesses{List: []Key{key(t, "witness.example/a"), key(t, "b")}, Min: 2}
	enc, err := w.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeWitnesses(enc)
	if err != nil {
		t.Fatal(err)
	}
	if d.Min != 2 || len(d.List) != 2 || d.List[0].Name != "witness.example/a" || !d.List[1].Pub.Equal(w.List[1].Pub) {
		t.Fatal("round trip")
	}
	again, _ := d.Encode()
	if !bytes.Equal(again, enc) {
		t.Fatal("not canonical")
	}
	vs, err := d.Verifiers()
	if err != nil || len(vs) != 2 || vs[0].Name() != "witness.example/a" {
		t.Fatal("verifiers", err)
	}
	// The derived verifier key is the one note computes for the key.
	vkey, _ := note.NewEd25519VerifierKey("b", w.List[1].Pub)
	nv, _ := note.NewVerifier(vkey)
	if nv.KeyHash() != vs[1].KeyHash() {
		t.Fatal("key hash")
	}

	a := key(t, "a")
	for _, bad := range []*Witnesses{
		{List: nil, Min: 1},
		{List: []Key{a}, Min: 0},
		{List: []Key{a}, Min: 2},
		{List: []Key{a, {Name: "a", Pub: key(t, "x").Pub}}, Min: 1},       // duplicate name
		{List: []Key{a, {Name: "c", Pub: a.Pub}}, Min: 1},                 // duplicate key
		{List: []Key{{Name: "a b", Pub: a.Pub}}, Min: 1},                  // space
		{List: []Key{{Name: "a+b", Pub: a.Pub}}, Min: 1},                  // plus
		{List: []Key{{Name: translog.LogSignerName, Pub: a.Pub}}, Min: 1}, // log's name
		{List: []Key{{Name: "", Pub: a.Pub}}, Min: 1},
		{List: []Key{{Name: strings.Repeat("n", MaxName+1), Pub: a.Pub}}, Min: 1},
		{List: []Key{{Name: "ä", Pub: a.Pub}}, Min: 1},
		{List: []Key{{Name: "a", Pub: a.Pub[:5]}}, Min: 1},
	} {
		if _, err := bad.Encode(); !errors.Is(err, ErrWitnesses) {
			t.Fatalf("accepted %+v", bad)
		}
	}
	var many []Key
	for i := 0; i <= MaxWitnesses; i++ {
		many = append(many, key(t, "w"+strings.Repeat("x", i)))
	}
	if _, err := (&Witnesses{List: many, Min: 1}).Encode(); !errors.Is(err, ErrWitnesses) {
		t.Fatal("too many witnesses")
	}
	// Decoding applies the same rules.
	el := func(name string, pub []byte) *rec.Record {
		return rec.New(WitnessSchema).SetString(1, name).SetBytes(2, pub)
	}
	for _, raw := range []*rec.Record{
		rec.New(WitnessesSchema).SetList(1, []*rec.Record{el("a", a.Pub)}).SetU32(2, 0),
		rec.New(WitnessesSchema).SetList(1, []*rec.Record{el("a", a.Pub)}).SetU32(2, 1000),
		rec.New(WitnessesSchema).SetList(1, []*rec.Record{el("a", a.Pub), el("a", key(t, "y").Pub)}).SetU32(2, 1),
		rec.New(WitnessesSchema).SetList(1, []*rec.Record{el("a b", a.Pub)}).SetU32(2, 1),
	} {
		b, err := raw.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeWitnesses(b); !errors.Is(err, ErrWitnesses) {
			t.Fatal("decoded an invalid list")
		}
	}
	if _, err := DecodeWitnesses([]byte("x")); !errors.Is(err, ErrWitnesses) {
		t.Fatal("garbage")
	}
	if _, err := (&Witnesses{List: []Key{{Name: "a b", Pub: a.Pub}}, Min: 1}).Verifiers(); !errors.Is(err, ErrWitnesses) {
		t.Fatal("verifier for an invalid name")
	}
}

func TestProofFormat(t *testing.T) {
	var p tlog.TreeProof
	for i := 0; i < 3; i++ {
		var h tlog.Hash
		h[0] = byte(i)
		h[31] = 0xff
		p = append(p, h)
	}
	body := FormatProof(p)
	if strings.Count(string(body), "\n") != 3 {
		t.Fatalf("%q", body)
	}
	q, err := ParseProof(body)
	if err != nil || len(q) != 3 || q[2] != p[2] {
		t.Fatal("round trip", err)
	}
	if e, err := ParseProof(nil); err != nil || len(e) != 0 || len(FormatProof(nil)) != 0 {
		t.Fatal("empty proof")
	}
	line := strings.Split(string(body), "\n")[0]
	for _, bad := range []string{
		line,                                 // no final newline
		line + "\n\n",                        // blank line
		strings.TrimSuffix(line, "=") + "\n", // no padding
		"AAAA\n",                             // short
		line + "\r\n",
		strings.Repeat(line+"\n", MaxProofHashes+1),
	} {
		if _, err := ParseProof([]byte(bad)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// TestWitnessQuorum: a quorum with 2*min <= n admits a split view among
// honest witnesses and is refused (task 03b, finding S1).
func TestWitnessQuorum(t *testing.T) {
	a, b, c, d := key(t, "a"), key(t, "b"), key(t, "c"), key(t, "d")
	for _, ok := range []*Witnesses{
		{List: []Key{a}, Min: 1},
		{List: []Key{a, b, c}, Min: 2},
		{List: []Key{a, b, c}, Min: 3},
		{List: []Key{a, b, c, d}, Min: 3},
	} {
		enc, err := ok.Encode()
		if err != nil {
			t.Fatalf("%d of %d refused: %v", ok.Min, len(ok.List), err)
		}
		if _, err := DecodeWitnesses(enc); err != nil {
			t.Fatal(err)
		}
	}
	el := func(k Key) *rec.Record { return rec.New(WitnessSchema).SetString(1, k.Name).SetBytes(2, k.Pub) }
	for _, bad := range []*Witnesses{
		{List: []Key{a, b}, Min: 1},
		{List: []Key{a, b, c}, Min: 1},
		{List: []Key{a, b, c, d}, Min: 2},
	} {
		if _, err := bad.Encode(); !errors.Is(err, ErrWitnesses) {
			t.Fatalf("%d of %d accepted: %v", bad.Min, len(bad.List), err)
		}
		var list []*rec.Record
		for _, k := range bad.List {
			list = append(list, el(k))
		}
		raw, err := rec.New(WitnessesSchema).SetList(1, list).SetU32(2, uint32(bad.Min)).Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeWitnesses(raw); !errors.Is(err, ErrWitnesses) {
			t.Fatalf("decoded %d of %d", bad.Min, len(bad.List))
		}
	}
}
