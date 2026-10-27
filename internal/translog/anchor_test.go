package translog

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/rec"
)

func testIdentities(t *testing.T, n int) []Identity {
	t.Helper()
	list := make([]Identity, n)
	for i := range list {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i + 1)
		list[i] = Identity{Gen: uint32(i + 1), Pub: ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)}
	}
	return list
}

func TestCheckIdentities(t *testing.T) {
	list := testIdentities(t, 3)
	if err := CheckIdentities(list, list[2]); err != nil {
		t.Fatal(err)
	}
	if err := CheckIdentities(list[:1], list[0]); err != nil {
		t.Fatal(err)
	}
	gap := []Identity{list[0], list[2]}
	repeated := []Identity{list[0], {Gen: 2, Pub: list[0].Pub}}
	short := []Identity{{Gen: 1, Pub: list[0].Pub[:5]}}
	zero := []Identity{{Gen: 0, Pub: list[0].Pub}}
	long := make([]Identity, MaxIdentities+1)
	for _, c := range []struct {
		name    string
		list    []Identity
		current Identity
	}{
		{"empty", nil, list[0]},
		{"too long", long, list[0]},
		{"gap", gap, list[2]},
		{"starts at 0", zero, zero[0]},
		{"repeated key", repeated, repeated[1]},
		{"short key", short, short[0]},
		{"current not last", list, list[1]},
		{"current other key", list[:2], Identity{Gen: 2, Pub: list[2].Pub}},
	} {
		if err := CheckIdentities(c.list, c.current); !errors.Is(err, ErrPin) {
			t.Fatalf("%s: got %v", c.name, err)
		}
	}
}

func TestIdentityKey(t *testing.T) {
	list := testIdentities(t, 2)
	for gen := uint32(1); gen <= 2; gen++ {
		k, ok := IdentityKey(list, gen)
		if !ok || !k.Equal(list[gen-1].Pub) {
			t.Fatalf("generation %d", gen)
		}
	}
	for _, gen := range []uint32{0, 3, 1 << 31} {
		if _, ok := IdentityKey(list, gen); ok {
			t.Fatalf("generation %d outside the list", gen)
		}
	}
	// A list that was not checked never yields a key of another generation.
	if _, ok := IdentityKey([]Identity{{Gen: 2, Pub: list[1].Pub}}, 1); ok {
		t.Fatal("unchecked list")
	}
}

func TestLogKeyCovers(t *testing.T) {
	open := LogKey{Gen: 1, ValidFrom: 1000, Logged: true}
	closed := LogKey{Gen: 1, ValidFrom: 1000, Until: 5000, Logged: true}
	// A certificate from platform/ that is not logged in the tree of the
	// head opens heads but signs none validly (task 03d finding 1).
	unlogged := LogKey{Gen: 2, ValidFrom: 1000}
	for _, c := range []struct {
		k    LogKey
		t    int64
		want bool
	}{
		{open, 999, false}, {open, 1000, true}, {open, 1 << 60, true},
		{closed, 999, false}, {closed, 1000, true}, {closed, 4999, true}, {closed, 5000, false}, {closed, 6000, false},
		{unlogged, 999, false}, {unlogged, 1000, false}, {unlogged, 1 << 60, false},
	} {
		if got := c.k.Covers(c.t); got != c.want {
			t.Fatalf("%+v at %d: got %v", c.k, c.t, got)
		}
	}
}

// TestLogKeysDisjoint checks the claim behind MaxSignatures: for one
// tree, consecutive generations cover disjoint time spans, so exactly
// one generation covers any time from the first valid_from on.
func TestLogKeysDisjoint(t *testing.T) {
	keys := []LogKey{
		{Gen: 1, ValidFrom: 1000, Until: 5000, Logged: true},
		{Gen: 2, ValidFrom: 5000, Until: 9000, Logged: true},
		{Gen: 3, ValidFrom: 9000, Logged: true},
	}
	for _, tm := range []int64{1000, 4999, 5000, 8999, 9000, 1 << 50} {
		n := 0
		for _, k := range keys {
			if k.Covers(tm) {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("time %d covered by %d generations", tm, n)
		}
	}
	if MaxSignatures != 1+MaxWitnesses {
		t.Fatal("a head carries one log signature and one per witness")
	}
}

// TestPendingHeadAge checks the bound of task 03d finding 7: a head
// time frozen at the append time + HeadInterval reaches the shorter
// limit exactly 24 hours after the append.
func TestPendingHeadAge(t *testing.T) {
	if MaxPendingHeadAge != 23*time.Hour || HeadInterval+MaxPendingHeadAge != MaxHeadAge {
		t.Fatalf("MaxPendingHeadAge %v", MaxPendingHeadAge)
	}
}

func TestAnchorErrors(t *testing.T) {
	if !errors.Is(ErrUnloggedSigner, ErrPrerequisite) {
		t.Fatal("ErrUnloggedSigner must be an ErrPrerequisite")
	}
	if errors.Is(ErrUnloggedSigner, ErrOrder) || errors.Is(ErrPin, ErrMismatch) {
		t.Fatal("error classes must stay apart")
	}
	// Until Q8 the pin has no field 7: an empty Revoked list revokes nothing.
	if (&Verifier{}).IsRevoked(1, 1) {
		t.Fatal("IsRevoked without field 7")
	}
}

// TestPinSize measures the largest pin of the proposal in doc.go "Pin"
// (task 03d finding 9): fields 1 to 6 and 8 at their limits, with
// MaxIdentities identity generations, MaxWitnesses witnesses with names
// of 64 bytes and an origin of MaxOrigin bytes. Field 7 exists only if
// Q8 is decided; it is measured with MaxIdentities elements to show the
// margin. The schemas mirror the
// proposal; task 07 moves them to store.
func TestPinSize(t *testing.T) {
	identity := rec.MustSchema("gomail/v1/rec/platform-identity",
		rec.Field{Num: 1, Name: "gen", Kind: rec.U32, Required: true},
		rec.Field{Num: 2, Name: "pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
	)
	witness := rec.MustSchema("gomail/v1/rec/witness",
		rec.Field{Num: 1, Name: "name", Kind: rec.String, MaxLen: 64, Required: true},
		rec.Field{Num: 2, Name: "pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
	)
	revoked := rec.MustSchema("gomail/v1/rec/platform-revoked",
		rec.Field{Num: 1, Name: "role", Kind: rec.U8, Required: true},
		rec.Field{Num: 2, Name: "gen", Kind: rec.U32, Required: true},
		rec.Field{Num: 3, Name: "revoked_at_size", Kind: rec.I64, Required: true},
	)
	pin := rec.MustSchema("gomail/v1/rec/platform-pin",
		rec.Field{Num: 1, Name: "gen", Kind: rec.U32, Required: true},
		rec.Field{Num: 2, Name: "pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
		rec.Field{Num: 3, Name: "dev", Kind: rec.U8, Required: true},
		rec.Field{Num: 4, Name: "origin", Kind: rec.String, MaxLen: MaxOrigin, Required: true},
		rec.Field{Num: 5, Name: "witnesses", Kind: rec.List, Elem: witness, MaxCount: MaxWitnesses, Required: true},
		rec.Field{Num: 6, Name: "min_witnesses", Kind: rec.U32, Required: true},
		rec.Field{Num: 7, Name: "revoked", Kind: rec.List, Elem: revoked, MaxCount: 3 * MaxIdentities},
		rec.Field{Num: 8, Name: "identities", Kind: rec.List, Elem: identity, MaxCount: MaxIdentities, Required: true},
	)
	list := testIdentities(t, MaxIdentities)
	ids := make([]*rec.Record, 0, len(list))
	for _, id := range list {
		ids = append(ids, rec.New(identity).SetU32(1, id.Gen).SetBytes(2, id.Pub))
	}
	ws := make([]*rec.Record, 0, MaxWitnesses)
	for i := 0; i < MaxWitnesses; i++ {
		ws = append(ws, rec.New(witness).SetString(1, strings.Repeat(string(rune('a'+i)), 64)).SetBytes(2, list[i].Pub))
	}
	last := list[len(list)-1]
	base := func() *rec.Record {
		return rec.New(pin).SetU32(1, last.Gen).SetBytes(2, last.Pub).SetU8(3, 0).
			SetString(4, strings.Repeat("o", MaxOrigin)).SetList(5, ws).SetU32(6, MaxWitnesses).SetList(8, ids)
	}
	without, err := base().Encode()
	if err != nil {
		t.Fatal(err)
	}
	rv := make([]*rec.Record, 0, MaxIdentities)
	for i := 0; i < MaxIdentities; i++ {
		rv = append(rv, rec.New(revoked).SetU8(1, uint8(i%3+1)).SetU32(2, uint32(i+1)).SetI64(3, MaxTreeSize))
	}
	with, err := base().SetList(7, rv).Encode()
	if err != nil {
		t.Fatal(err)
	}
	one, err := rec.New(pin).SetU32(1, 1).SetBytes(2, list[0].Pub).SetU8(3, 0).
		SetString(4, strings.Repeat("o", MaxOrigin)).SetList(5, ws).SetU32(6, MaxWitnesses).SetList(8, ids[:1]).Encode()
	if err != nil {
		t.Fatal(err)
	}
	per := (len(without) - len(one)) / (MaxIdentities - 1)
	t.Logf("largest pin: %d bytes without field 7 (%d bytes per identity generation), %d bytes with %d revoked generations; read limit %d",
		len(without), per, len(with), len(rv), MaxPinFile)
	if len(without) <= 20<<10 || len(without) > 24<<10 {
		t.Fatalf("doc.go states about 23 KiB, got %d bytes", len(without))
	}
	if len(with) > MaxPinFile {
		t.Fatalf("pin of %d bytes exceeds MaxPinFile", len(with))
	}
}
