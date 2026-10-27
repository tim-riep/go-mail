package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
)

func testCheckpoint(t testing.TB, tu *testUser, device ID) *Checkpoint {
	t.Helper()
	c := &Checkpoint{UserID: tu.user.ID, DeviceID: device, Origin: "gomail.example/log", Size: 42,
		RootHash: [32]byte{1, 2, 3}, HeadTime: 1_800_000_000_000, UserGen: tu.user.Current().Gen}
	if err := c.Sign(tu.identity); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCheckpoint(t *testing.T) {
	tu := newTestUser(t, 1, 2)
	other := newTestUser(t, 2, 1)
	pub := tu.identity.Public().(ed25519.PublicKey)
	c := testCheckpoint(t, tu, ID{5})
	data := mustEncode(t, c)
	d, err := DecodeCheckpoint(data)
	if err != nil {
		t.Fatal(err)
	}
	if again := mustEncode(t, d); !bytes.Equal(again, data) {
		t.Fatal("checkpoint not byte-identical")
	}
	if err := d.Verify(pub); err != nil {
		t.Fatal(err)
	}
	tbs, _ := c.record(false).Encode()
	if !ed25519.Verify(pub, append([]byte("gomail/v1/sig/checkpoint\x00"), tbs...), c.Signature) {
		t.Fatal("signature not under checkpoint over the record without sig")
	}
	// Bounds: size 1, time 0 and the longest origin are valid.
	edge := &Checkpoint{UserID: ID{1}, DeviceID: ID{2}, Origin: strings.Repeat("o", MaxOrigin), Size: 1, UserGen: 1}
	if err := edge.Sign(tu.identity); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCheckpoint(mustEncode(t, edge)); err != nil {
		t.Fatal(err)
	}
	// Wrong signatures.
	if err := d.Verify(other.identity.Public().(ed25519.PublicKey)); !errors.Is(err, keys.ErrSignature) {
		t.Fatal("foreign key verified")
	}
	wrong := *d
	wrong.Signature, _ = keys.Sign(tu.identity, keys.DomainEpoch, tbs)
	if err := wrong.Verify(pub); !errors.Is(err, keys.ErrSignature) {
		t.Fatal("signature of another domain verified")
	}
	for name, f := range map[string]func(x *Checkpoint){
		"user": func(x *Checkpoint) { x.UserID = ID{7} }, "device": func(x *Checkpoint) { x.DeviceID = ID{7} },
		"origin": func(x *Checkpoint) { x.Origin = "other" }, "size": func(x *Checkpoint) { x.Size++ },
		"root": func(x *Checkpoint) { x.RootHash[0] ^= 1 }, "time": func(x *Checkpoint) { x.HeadTime++ },
		"gen": func(x *Checkpoint) { x.UserGen = 1 },
	} {
		x := *d
		f(&x)
		if err := x.Verify(pub); !errors.Is(err, keys.ErrSignature) {
			t.Fatalf("changed %s verified", name)
		}
	}
	// Missing signature.
	unsigned := *c
	unsigned.Signature = nil
	if _, err := unsigned.Encode(); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned checkpoint encoded")
	}
	if _, err := DecodeCheckpoint(tbs); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned checkpoint decoded")
	}
	if err := unsigned.Verify(pub); !errors.Is(err, keys.ErrSignature) {
		t.Fatal("unsigned checkpoint verified")
	}
	// Invalid values.
	for name, f := range map[string]func(x *Checkpoint){
		"zero user":      func(x *Checkpoint) { x.UserID = ID{} },
		"zero device":    func(x *Checkpoint) { x.DeviceID = ID{} },
		"empty origin":   func(x *Checkpoint) { x.Origin = "" },
		"negative size":  func(x *Checkpoint) { x.Size = -1 },
		"size 0":         func(x *Checkpoint) { x.Size = 0 },
		"size too large": func(x *Checkpoint) { x.Size = MaxCheckpointSize + 1 },
		"negative time":  func(x *Checkpoint) { x.HeadTime = -1 },
		"gen 0":          func(x *Checkpoint) { x.UserGen = 0 },
	} {
		x := *c
		f(&x)
		if err := x.Sign(tu.identity); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s signed", name)
		}
		if _, err := x.Encode(); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s encoded", name)
		}
		if err := x.Verify(pub); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s verified", name)
		}
		if _, err := DecodeCheckpoint(mustEncode(t, x.record(true))); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s decoded", name)
		}
	}
	for name, origin := range map[string]string{"too long": strings.Repeat("o", MaxOrigin+1), "not NFC": "é", "NUL": "a\x00b", "not UTF-8": "\xff"} {
		x := *c
		x.Origin = origin
		if err := x.Sign(tu.identity); err == nil {
			t.Fatalf("origin %s signed", name)
		}
	}
	if _, err := rec.New(CheckpointSchema).SetBytes(1, c.UserID[:]).SetBytes(2, c.DeviceID[:]).SetString(3, "o").SetI64(4, 1).SetBytes(5, make([]byte, 31)).Encode(); err == nil {
		t.Fatal("short root hash encoded")
	}
	if _, err := DecodeCheckpoint(append(data, 1)); err == nil {
		t.Fatal("trailing byte")
	}

	// Files checkpoints/<user-id>-<device-id>.rec.
	s, _ := Init(t.TempDir())
	mbx := ID{9}
	if refs, err := s.ListCheckpoints(mbx); err != nil || refs != nil {
		t.Fatal("checkpoints of a new mailbox")
	}
	c2 := testCheckpoint(t, tu, ID{3})
	c3 := testCheckpoint(t, other, ID{4})
	for _, x := range []*Checkpoint{c, c2, c3} {
		if err := s.WriteCheckpoint(mbx, x); err != nil {
			t.Fatal(err)
		}
	}
	if s.CheckpointFile(mbx, tu.user.ID, ID{5}) != filepath.Join(s.MailboxDir(mbx), "checkpoints", tu.user.ID.String()+"-"+(ID{5}).String()+".rec") {
		t.Fatal("path of a checkpoint")
	}
	// The newest checkpoint of a device replaces the older one.
	c.Size = 43
	c.Sign(tu.identity)
	if err := s.WriteCheckpoint(mbx, c); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ReadCheckpoint(mbx, tu.user.ID, ID{5}); err != nil || got.Size != 43 || got.Verify(pub) != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	if err := s.WriteCheckpoint(mbx, &unsigned); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned checkpoint written")
	}
	// Names that are no checkpoints are ignored.
	dir := s.CheckpointDir(mbx)
	for _, n := range []string{"x.rec", tu.user.ID.String() + ".rec", tu.user.ID.String() + "_" + (ID{5}).String() + ".rec",
		strings.ToUpper(tu.user.ID.String()) + "-" + (ID{5}).String() + ".rec", tu.user.ID.String() + "-" + (ID{6}).String() + ".tmp", tmpPrefix + "1"} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	MkdirAll(filepath.Join(dir, other.user.ID.String()+"-"+(ID{6}).String()+".rec"))
	refs, err := s.ListCheckpoints(mbx)
	if err != nil || len(refs) != 3 {
		t.Fatalf("checkpoints %v %v", refs, err)
	}
	want := []CheckpointRef{{tu.user.ID, ID{3}}, {tu.user.ID, ID{5}}, {other.user.ID, ID{4}}}
	if bytes.Compare(tu.user.ID[:], other.user.ID[:]) > 0 {
		want = []CheckpointRef{{other.user.ID, ID{4}}, {tu.user.ID, ID{3}}, {tu.user.ID, ID{5}}}
	}
	for i := range want {
		if refs[i] != want[i] {
			t.Fatalf("order of checkpoints: %v", refs)
		}
	}
	// A checkpoint in the place of another device.
	WriteFileAtomic(s.CheckpointFile(mbx, tu.user.ID, ID{6}), data)
	if _, err := s.ReadCheckpoint(mbx, tu.user.ID, ID{6}); !errors.Is(err, ErrRecord) {
		t.Fatal("checkpoint of another device")
	}
	WriteFileAtomic(s.CheckpointFile(mbx, other.user.ID, ID{5}), data)
	if _, err := s.ReadCheckpoint(mbx, other.user.ID, ID{5}); !errors.Is(err, ErrRecord) {
		t.Fatal("checkpoint of another user")
	}
	if _, err := s.ReadCheckpoint(mbx, other.user.ID, ID{9}); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing checkpoint")
	}
	WriteFileAtomic(s.CheckpointFile(mbx, other.user.ID, ID{5}), []byte("junk"))
	if _, err := s.ReadCheckpoint(mbx, other.user.ID, ID{5}); err == nil {
		t.Fatal("junk checkpoint")
	}
	// An unreadable directory is an error, not an empty list.
	os.RemoveAll(dir)
	os.WriteFile(dir, nil, 0o600)
	if _, err := s.ListCheckpoints(mbx); err == nil {
		t.Fatal("checkpoints directory is a file")
	}
}
