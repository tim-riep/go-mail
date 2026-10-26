package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
)

func TestID(t *testing.T) {
	id, err := NewID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := id.String()
	if len(s) != IDLen || strings.ToLower(s) != s {
		t.Fatalf("text form %q", s)
	}
	back, err := ParseID(s)
	if err != nil || back != id {
		t.Fatal("round trip")
	}
	if (ID{}).IsZero() != true || id.IsZero() {
		t.Fatal("IsZero")
	}
	bad := []string{"", s[:25], s + "a", strings.ToUpper(s), "../" + s[3:], "aaaaaaaaaaaaaaaaaaaaaaaaa1", "aaaaaaaaaaaaaaaaaaaaaaaaab"}
	for _, b := range bad {
		if _, err := ParseID(b); !errors.Is(err, ErrID) {
			t.Fatalf("%q accepted", b)
		}
	}
	if _, err := NewID(bytes.NewReader([]byte{1, 2})); err == nil {
		t.Fatal("short random accepted")
	}
}

func TestAtomicFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a", "b", "f")
	if err := MkdirAll(filepath.Dir(p)); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(filepath.Dir(p)); err != nil {
		t.Fatal("MkdirAll must be idempotent")
	}
	if err := WriteFileAtomic(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Fatal("replace")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if err := CreateFileAtomic(p, []byte("three")); !errors.Is(err, ErrExists) {
		t.Fatal("exclusive create over an existing file")
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Fatal("exclusive create changed the file")
	}
	q := filepath.Join(dir, "a", "q")
	if err := CreateFileAtomic(q, []byte("q")); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(p); err == nil {
		t.Fatal("MkdirAll over a file")
	}
	// No temporary files remain.
	entries, _ := os.ReadDir(filepath.Join(dir, "a", "b"))
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
	// Size limits and missing files.
	if _, err := ReadFileLimited(p, 2); !errors.Is(err, ErrTooLarge) {
		t.Fatal("size limit")
	}
	if _, err := ReadFileLimited(filepath.Join(dir, "missing"), 2); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing file")
	}
	if _, err := ReadFileLimited(dir, 10); err == nil {
		t.Fatal("directory read as file")
	}
	// RemoveTemp deletes only temporary files.
	os.WriteFile(filepath.Join(dir, "a", tmpPrefix+"x"), []byte("t"), 0o600)
	if err := RemoveTemp(filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a", tmpPrefix+"x")); !os.IsNotExist(err) {
		t.Fatal("temp file kept")
	}
	if _, err := os.Stat(q); err != nil {
		t.Fatal("RemoveTemp removed a data file")
	}
	if err := RemoveTemp(filepath.Join(dir, "nope")); err != nil {
		t.Fatal(err)
	}
	// Rename and remove.
	r := filepath.Join(dir, "a", "b", "moved")
	if err := RenameDurable(q, r); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDurable(r); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDurable(r); err != nil {
		t.Fatal("removing a missing file is not an error")
	}
	if err := WriteFileAtomic(filepath.Join(dir, "nodir", "x"), nil); err == nil {
		t.Fatal("write into missing directory")
	}
	if err := CreateFileAtomic(filepath.Join(dir, "nodir", "x"), nil); err == nil {
		t.Fatal("create in missing directory")
	}
	if err := SyncDir(filepath.Join(dir, "nodir")); err == nil {
		t.Fatal("sync of missing dir")
	}
}

func TestUserRecord(t *testing.T) {
	tu := newTestUser(t, 1, 3)
	data, err := tu.user.Encode()
	if err != nil {
		t.Fatal(err)
	}
	u, err := DecodeUser(data)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != tu.user.ID || u.Current().Gen != 3 || u.Generation(2).Gen != 2 || u.Generation(0) != nil || u.Generation(4) != nil {
		t.Fatal("decoded user")
	}
	again, _ := u.Encode()
	if !bytes.Equal(again, data) {
		t.Fatal("not byte-identical")
	}
	// A gap in the chain, a foreign root and a zero ID are rejected.
	gap := *tu.user
	gap.Generations = []*keys.GenerationCert{tu.user.Generations[0], tu.user.Generations[2]}
	if _, err := gap.Encode(); !errors.Is(err, ErrRecord) {
		t.Fatal("gap accepted")
	}
	other := newTestUser(t, 2, 1)
	mixed := *tu.user
	mixed.RootPub = other.user.RootPub
	if _, err := mixed.Encode(); !errors.Is(err, ErrRecord) {
		t.Fatal("foreign root accepted")
	}
	zero := *tu.user
	zero.ID = ID{}
	if _, err := zero.Encode(); !errors.Is(err, ErrRecord) {
		t.Fatal("zero id accepted")
	}
	short := *tu.user
	short.RootPub = short.RootPub[:5]
	if _, err := short.Encode(); !errors.Is(err, ErrRecord) {
		t.Fatal("short root accepted")
	}
	// A decoded record with a swapped root fails the chain.
	bad := bytes.Replace(data, tu.user.RootPub, other.user.RootPub, 1)
	if _, err := DecodeUser(bad); !errors.Is(err, ErrRecord) {
		t.Fatal("decoded user with foreign root")
	}
	if _, err := DecodeUser(data[:len(data)-1]); err == nil {
		t.Fatal("truncated user")
	}
	// An element that is a valid record but not a valid certificate.
	g := rec.New(keys.GenerationCertSchema).SetU32(1, 0).SetBytes(2, make([]byte, 32)).SetBytes(3, make([]byte, 32)).SetI64(4, 0).SetBytes(6, make([]byte, 64))
	enc, _ := rec.New(UserSchema).SetBytes(1, tu.user.ID[:]).SetBytes(2, tu.user.RootPub).SetList(3, []*rec.Record{g}).Encode()
	if _, err := DecodeUser(enc); err == nil {
		t.Fatal("generation 0 accepted")
	}
}

func TestMailboxRecord(t *testing.T) {
	m := &Mailbox{ID: ID{1}, Epoch: 3, Inbox: ID{2}, Name: []byte("sealed")}
	data, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeMailbox(data)
	if err != nil || d.Epoch != 3 || d.Inbox != m.Inbox || string(d.Name) != "sealed" {
		t.Fatal("mailbox round trip")
	}
	for _, bad := range []*Mailbox{{Epoch: 1, Inbox: ID{2}, Name: []byte("x")}, {ID: ID{1}, Inbox: ID{2}, Name: []byte("x")}, {ID: ID{1}, Epoch: 1, Name: []byte("x")}, {ID: ID{1}, Epoch: 1, Inbox: ID{2}}} {
		if _, err := bad.Encode(); !errors.Is(err, ErrRecord) {
			t.Fatalf("incomplete mailbox accepted: %+v", bad)
		}
	}
	zero, _ := rec.New(MailboxSchema).SetBytes(1, make([]byte, 16)).SetU32(2, 1).SetBytes(3, make([]byte, 16)).SetBytes(4, []byte("x")).Encode()
	if _, err := DecodeMailbox(zero); !errors.Is(err, ErrRecord) {
		t.Fatal("zero ids accepted")
	}
	if _, err := DecodeMailbox([]byte("junk")); err == nil {
		t.Fatal("junk")
	}
}

func TestEpochRecord(t *testing.T) {
	tu := newTestUser(t, 1, 1)
	mbx := ID{9}
	e1, d1 := newTestEpoch(t, tu, mbx, 1, 1000, nil)
	if err := e1.VerifySignature(tu.identity.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	other := newTestUser(t, 2, 1)
	if err := e1.VerifySignature(other.identity.Public().(ed25519.PublicKey)); !errors.Is(err, keys.ErrSignature) {
		t.Fatal("foreign key verified")
	}
	got, err := DecodeEpoch(d1)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := got.Encode(); !bytes.Equal(again, d1) {
		t.Fatal("epoch not byte-identical")
	}
	if err := got.VerifySignature(tu.identity.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if m, ok := got.Member(tu.user.ID); !ok || m.Gen != 1 {
		t.Fatal("member")
	}
	if _, ok := got.Member(other.user.ID); ok {
		t.Fatal("non-member")
	}
	e2, d2 := newTestEpoch(t, tu, mbx, 2, 2000, d1)
	if err := CheckLink(e1, d1, e2); err != nil {
		t.Fatal(err)
	}
	// Chain violations.
	mut := func(f func(e *Epoch)) *Epoch {
		c := *e2
		f(&c)
		return &c
	}
	cases := map[string]*Epoch{
		"other mailbox":  mut(func(e *Epoch) { e.MailboxID = ID{8} }),
		"skipped number": mut(func(e *Epoch) { e.Number = 3 }),
		"wrong prev":     mut(func(e *Epoch) { e.PrevHash[0] ^= 1 }),
		"earlier begin":  mut(func(e *Epoch) { e.Begin = 999 }),
		"older suite":    mut(func(e *Epoch) { e.Suite = 0 }),
		"non-member":     mut(func(e *Epoch) { e.SignerID = other.user.ID }),
	}
	for name, e := range cases {
		if err := CheckLink(e1, d1, e); !errors.Is(err, ErrChain) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	_ = d2
	// Structural rules.
	bad := map[string]func(e *Epoch){
		"zero mailbox":      func(e *Epoch) { e.MailboxID = ID{} },
		"epoch 0":           func(e *Epoch) { e.Number = 0 },
		"reason 0":          func(e *Epoch) { e.Reason = 0 },
		"reason 7":          func(e *Epoch) { e.Reason = 7 },
		"suite 2":           func(e *Epoch) { e.Suite = 2 },
		"no content key":    func(e *Epoch) { e.ContentPub = nil },
		"no members":        func(e *Epoch) { e.Members = nil },
		"no signer":         func(e *Epoch) { e.SignerGen = 0 },
		"epoch 1 with prev": func(e *Epoch) { e.PrevHash = [32]byte{1} },
		"epoch 2 initial":   func(e *Epoch) { e.Number = 2; e.PrevHash = [32]byte{1} },
		"member gen 0":      func(e *Epoch) { e.Members = []Member{{Kind: MemberUser, ID: ID{1}}} },
		"member kind 3":     func(e *Epoch) { e.Members = []Member{{Kind: 3, ID: ID{1}, Gen: 1}} },
		"duplicate member":  func(e *Epoch) { e.Members = []Member{{MemberUser, ID{1}, 1}, {MemberUser, ID{1}, 2}} },
		"two recovery":      func(e *Epoch) { e.Members = []Member{{MemberRecovery, ID{1}, 1}, {MemberRecovery, ID{2}, 1}} },
		"too many members": func(e *Epoch) {
			e.Members = nil
			for i := 0; i <= MaxMembers; i++ {
				e.Members = append(e.Members, Member{MemberUser, ID{byte(i), 1}, 1})
			}
		},
	}
	for name, f := range bad {
		c := *e1
		f(&c)
		if err := c.Sign(tu.identity); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s accepted by Sign: %v", name, err)
		}
		if _, err := c.Encode(); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s accepted by Encode", name)
		}
	}
	unsigned := *e1
	unsigned.Signature = nil
	if _, err := unsigned.Encode(); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned epoch encoded")
	}
	tbs, _ := unsigned.record(false).Encode()
	if _, err := DecodeEpoch(tbs); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned epoch decoded")
	}
	// Decoder-only rules: zero previous hash, invalid keys.
	r := e1.record(true).SetBytes(9, make([]byte, 32))
	enc, _ := r.Encode()
	if _, err := DecodeEpoch(enc); !errors.Is(err, ErrRecord) {
		t.Fatal("zero previous hash")
	}
	if _, err := DecodeEpoch(append(d1, 0)); err == nil {
		t.Fatal("trailing byte")
	}
	if !ReasonImmediate.valid() || Reason(0).valid() {
		t.Fatal("reason range")
	}
}

func TestEpochKeys(t *testing.T) {
	tu := newTestUser(t, 1, 1)
	e, _ := newTestEpoch(t, tu, ID{9}, 1, 1, nil)
	k := &EpochKeys{MailboxID: ID{9}, Epoch: 1, Content: x25519(t, 1), Meta: x25519(t, 101), Index: [32]byte{7}}
	data, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeEpochKeys(data)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Matches(e) || d.Index != k.Index {
		t.Fatal("keys do not match their epoch")
	}
	d2 := *d
	d2.Epoch = 2
	if d2.Matches(e) {
		t.Fatal("other epoch matched")
	}
	d3 := *d
	d3.Meta = x25519(t, 5)
	if d3.Matches(e) {
		t.Fatal("other key matched")
	}
	d.Zero()
	if d.Index != [32]byte{} || d.Content != nil {
		t.Fatal("Zero")
	}
	if _, err := (&EpochKeys{}).Encode(); !errors.Is(err, ErrRecord) {
		t.Fatal("empty keys encoded")
	}
	zero, _ := rec.New(EpochKeysSchema).SetBytes(1, make([]byte, 16)).SetU32(2, 1).SetBytes(3, bytes.Repeat([]byte{1}, 32)).SetBytes(4, bytes.Repeat([]byte{1}, 32)).SetBytes(5, make([]byte, 32)).Encode()
	if _, err := DecodeEpochKeys(zero); !errors.Is(err, ErrRecord) {
		t.Fatal("zero mailbox")
	}
	if _, err := DecodeEpochKeys(data[:10]); err == nil {
		t.Fatal("truncated")
	}
}

func testMeta() *MailMeta {
	return &MailMeta{Version: 1, MailID: ID{3}, Received: 1234, MailHash: [32]byte{4}, Size: 99, Folder: ID{5},
		EnvelopeFrom: "a@b.example", Recipients: []string{"x@y.example", "z@y.example"}, From: "A <a@b.example>",
		To: "x@y.example", Subject: "Grüße", Date: "Mon, 26 Oct 2026 10:00:00 +0100", MessageID: "<1@b>", Attachment: true, HeadersParsed: true}
}

func TestMailMeta(t *testing.T) {
	m := testMeta()
	data, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeMailMeta(data)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := d.Encode(); !bytes.Equal(again, data) {
		t.Fatal("meta not byte-identical")
	}
	if d.Subject != m.Subject || !d.Attachment || !d.HeadersParsed || len(d.Recipients) != 2 {
		t.Fatal("meta fields")
	}
	minimal := &MailMeta{Version: 1, MailID: ID{3}, Folder: ID{5}, Recipients: []string{"x@y"}}
	md, _ := minimal.Encode()
	if d, err := DecodeMailMeta(md); err != nil || d.Attachment || d.HeadersParsed {
		t.Fatal("minimal meta")
	}
	if _, err := (&MailMeta{Version: 1, MailID: ID{3}, Folder: ID{5}}).Encode(); !errors.Is(err, ErrRecord) {
		t.Fatal("meta without recipients")
	}
	// Non-canonical encodings: empty optional string, flag values.
	base := func(v ...uint32) *rec.Record {
		ver := uint32(1)
		if len(v) > 0 {
			ver = v[0]
		}
		return rec.New(MailMetaSchema).SetU32(1, ver).SetBytes(2, (&ID{3})[:]).SetI64(3, 1).SetBytes(4, make([]byte, 32)).
			SetU32(5, 1).SetBytes(6, (&ID{5})[:]).SetU32(7, 0)
	}
	rcpt := []*rec.Record{rec.New(RcptSchema).SetString(1, "x@y")}
	for name, r := range map[string]*rec.Record{
		"empty subject": base().SetList(9, rcpt).SetString(13, "").SetU8(17, 0),
		"attachment 0":  base().SetList(9, rcpt).SetU8(16, 0).SetU8(17, 0),
		"parsed 2":      base().SetList(9, rcpt).SetU8(17, 2),
		"version 0":     base(0).SetList(9, rcpt).SetU8(17, 0),
		"no recipients": base().SetList(9, nil).SetU8(17, 0),
	} {
		enc, err := r.Encode()
		if err != nil {
			t.Fatal(name, err)
		}
		if _, err := DecodeMailMeta(enc); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := DecodeMailMeta([]byte{1}); err == nil {
		t.Fatal("junk")
	}
	ex1, _ := m.SignedExtra(ID{1}, 2)
	m2 := *m
	m2.Version = 2
	ex2, _ := m2.SignedExtra(ID{1}, 2)
	ex3, _ := m.SignedExtra(ID{1}, 3)
	if bytes.Equal(ex1, ex2) || bytes.Equal(ex1, ex3) || !bytes.HasPrefix(ex1, []byte("gomail/v1/rec/meta-signed\x00")) {
		t.Fatal("signed extra must bind version and epoch")
	}
}

func TestPending(t *testing.T) {
	p := &Pending{MailboxID: ID{1}, Epoch: 2, Entries: []PendingEntry{{MailID: ID{3}, Unprocessed: true}, {MailID: ID{4}, Terms: []string{"from:a@b", "day:2026-10-26"}}, {MailID: ID{5}}}}
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodePending(data)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := d.Encode(); !bytes.Equal(again, data) {
		t.Fatal("pending not byte-identical")
	}
	if !d.Entries[0].Unprocessed || len(d.Entries[1].Terms) != 2 || d.Entries[2].Unprocessed {
		t.Fatal("pending entries")
	}
	for name, bad := range map[string]*Pending{
		"empty":      {MailboxID: ID{1}, Epoch: 1},
		"no mailbox": {Epoch: 1, Entries: []PendingEntry{{MailID: ID{3}, Unprocessed: true}}},
		"zero mail":  {MailboxID: ID{1}, Epoch: 1, Entries: []PendingEntry{{Unprocessed: true}}},
		"both":       {MailboxID: ID{1}, Epoch: 1, Entries: []PendingEntry{{MailID: ID{3}, Unprocessed: true, Terms: []string{"x"}}}},
	} {
		if _, err := bad.Encode(); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s encoded", name)
		}
	}
	entry := func(f func(r *rec.Record)) []byte {
		r := rec.New(PendingEntrySchema).SetBytes(1, (&ID{3})[:])
		f(r)
		enc, _ := rec.New(PendingSchema).SetBytes(1, (&ID{1})[:]).SetU32(2, 1).SetList(3, []*rec.Record{r}).Encode()
		return enc
	}
	for name, enc := range map[string][]byte{
		"neither":       entry(func(r *rec.Record) {}),
		"unprocessed 2": entry(func(r *rec.Record) { r.SetU8(2, 2) }),
		"both":          entry(func(r *rec.Record) { r.SetU8(2, 1).SetList(3, nil) }),
		"zero mail": func() []byte {
			e := rec.New(PendingEntrySchema).SetBytes(1, make([]byte, 16)).SetU8(2, 1)
			b, _ := rec.New(PendingSchema).SetBytes(1, (&ID{1})[:]).SetU32(2, 1).SetList(3, []*rec.Record{e}).Encode()
			return b
		}(),
		"no entries": func() []byte {
			b, _ := rec.New(PendingSchema).SetBytes(1, (&ID{1})[:]).SetU32(2, 1).SetList(3, nil).Encode()
			return b
		}(),
		"epoch 0": func() []byte {
			b, _ := rec.New(PendingSchema).SetBytes(1, (&ID{1})[:]).SetU32(2, 0).SetList(3, nil).Encode()
			return b
		}(),
	} {
		if _, err := DecodePending(enc); err == nil {
			t.Fatalf("%s decoded", name)
		}
	}
	if _, err := DecodePending(nil); err == nil {
		t.Fatal("nil")
	}
}

func TestSmallRecords(t *testing.T) {
	n := &EpochNote{MailboxID: ID{1}, Epoch: 2, First: 3, Last: 4, Count: 5}
	data, _ := n.Encode()
	if d, err := DecodeEpochNote(data); err != nil || *d != *n {
		t.Fatal("note")
	}
	if _, err := DecodeEpochNote(data[1:]); err == nil {
		t.Fatal("note junk")
	}
	moves := []Move{{"spool/a/b.gml", "mailboxes/x/mail/y/b.gml"}}
	j, err := EncodeJournal(moves)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := DecodeJournal(j); err != nil || d[0] != moves[0] {
		t.Fatal("journal")
	}
	for _, p := range []string{"/abs", "../up", "a//b", "a/./b", "A/b", "a/b c", ""} {
		bad, _ := EncodeJournal([]Move{{"spool/x", p}})
		if bad == nil {
			continue
		}
		if _, err := DecodeJournal(bad); err == nil {
			t.Fatalf("unsafe path %q accepted", p)
		}
	}
	if _, err := DecodeJournal([]byte("x")); err == nil {
		t.Fatal("journal junk")
	}
	_, _, priv, _ := DecodePlatformKey(nil)
	if priv != nil {
		t.Fatal("nil key")
	}
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	kd, err := EncodePlatformKey(KeyRoleIngest, 4, k)
	if err != nil {
		t.Fatal(err)
	}
	role, gen, back, err := DecodePlatformKey(kd)
	if err != nil || role != KeyRoleIngest || gen != 4 || !back.Equal(k) {
		t.Fatal("platform key")
	}
	if _, err := EncodePlatformKey(1, 0, k); err == nil {
		t.Fatal("gen 0")
	}
	bad, _ := rec.New(PlatformKeySchema).SetU8(1, 9).SetU32(2, 1).SetBytes(3, make([]byte, 32)).Encode()
	if _, _, _, err := DecodePlatformKey(bad); err == nil {
		t.Fatal("role 9")
	}
	pin := &PlatformPin{Gen: 1, Pub: k.Public().(ed25519.PublicKey), Dev: true}
	pd, _ := pin.Encode()
	if d, err := DecodePlatformPin(pd); err != nil || !d.Dev || d.Gen != 1 || !d.Pub.Equal(pin.Pub) {
		t.Fatal("pin")
	}
	pin.Dev = false
	pd, _ = pin.Encode()
	if d, _ := DecodePlatformPin(pd); d.Dev {
		t.Fatal("pin dev flag")
	}
	badPin, _ := rec.New(PlatformPinSchema).SetU32(1, 1).SetBytes(2, make([]byte, 32)).SetU8(3, 2).Encode()
	if _, err := DecodePlatformPin(badPin); err == nil {
		t.Fatal("pin dev 2")
	}
	if _, err := DecodePlatformPin(nil); err == nil {
		t.Fatal("pin nil")
	}
}

func TestAddressAssignment(t *testing.T) {
	admin := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	a := &AddressAssignment{Address: "info@example.org", MailboxID: ID{1}, ValidFrom: 10, AdminGen: 1}
	if _, err := a.Encode(); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned encoded")
	}
	if err := a.Sign(admin); err != nil {
		t.Fatal(err)
	}
	data, _ := a.Encode()
	d, err := DecodeAddressAssignment(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Verify(admin.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	d.MailboxID = ID{2}
	if err := d.Verify(admin.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("changed mailbox verified")
	}
	if err := (&AddressAssignment{Address: "Info@example.org", MailboxID: ID{1}, AdminGen: 1}).Sign(admin); !errors.Is(err, ErrRecord) {
		t.Fatal("not normalized")
	}
	if err := (&AddressAssignment{Address: "info@example.org", AdminGen: 1}).Sign(admin); !errors.Is(err, ErrRecord) {
		t.Fatal("no mailbox")
	}
	tbs, _ := a.record(false).Encode()
	if _, err := DecodeAddressAssignment(tbs); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned decoded")
	}
	if _, err := DecodeAddressAssignment(nil); err == nil {
		t.Fatal("nil")
	}
}

func TestCleanText(t *testing.T) {
	cases := map[string]string{
		"plain":          "plain",
		"a\x00b\r\nc\td": "a b  c\td",
		"bad \xff utf8":  "bad � utf8",
		"é":             "é",
		"\x7f":           " ",
	}
	for in, want := range cases {
		if got := CleanText(in, 100); got != want {
			t.Fatalf("CleanText(%q) = %q, want %q", in, got, want)
		}
	}
	if CleanText("abc", 0) != "" {
		t.Fatal("max 0")
	}
	long := strings.Repeat("ä", 1000)
	got := CleanText(long, 101)
	if len(got) > 101 || !strings.HasPrefix(long, got) || len(got) != 100 {
		t.Fatalf("cut: %d bytes", len(got))
	}
	// A string whose NFC is longer than its input (U+0958 decomposes).
	exp := strings.Repeat("क़", 50)
	if got := CleanText(exp, 20); len(got) > 20 {
		t.Fatal("expanding text exceeds the limit")
	}
	// The result is always storable.
	for _, s := range []string{long, exp, "a\xffb\x00", strings.Repeat("́", 100)} {
		v := CleanText(s, 33)
		if _, err := rec.New(TermSchema).SetString(1, v+"x").Encode(); err != nil {
			t.Fatalf("CleanText result %q not storable: %v", v, err)
		}
	}
}

func TestNormalizeAddress(t *testing.T) {
	good := map[string]string{"Info@Example.ORG": "info@example.org", "a.b+c@x.y": "a.b+c@x.y"}
	for in, want := range good {
		if got, err := NormalizeAddress(in); err != nil || got != want {
			t.Fatalf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "a", "@b", "a@", "a@@b", "a@b@c", "a b@c", "ä@b", "<a@b>", "a@.b", "a@b.", "a@b..c", strings.Repeat("a", 250) + "@b.cd"} {
		if _, err := NormalizeAddress(bad); !errors.Is(err, ErrAddress) {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestStoreOperations(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(s.Root); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.TempDir()); !errors.Is(err, ErrNotFound) {
		t.Fatal("open of an empty dir")
	}
	// Users.
	tu := newTestUser(t, 1, 1)
	if err := s.CreateUser(tu.user); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(tu.user); !errors.Is(err, ErrExists) {
		t.Fatal("user created twice")
	}
	u, raw, err := s.ReadUser(tu.user.ID)
	if err != nil || u.ID != tu.user.ID || len(raw) == 0 {
		t.Fatal(err)
	}
	// user.rec of another user under this ID.
	other := newTestUser(t, 2, 1)
	od, _ := other.user.Encode()
	os.WriteFile(s.UserFile(tu.user.ID), od, 0o600)
	if _, _, err := s.ReadUser(tu.user.ID); !errors.Is(err, ErrRecord) {
		t.Fatal("foreign user.rec accepted")
	}
	os.WriteFile(s.UserFile(tu.user.ID), []byte("junk"), 0o600)
	if _, _, err := s.ReadUser(tu.user.ID); err == nil {
		t.Fatal("junk user.rec")
	}
	if _, _, err := s.ReadUser(ID{77}); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing user")
	}
	// Invites.
	code, err := s.CreateInvite(5)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeInvite(code); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeInvite(code); !errors.Is(err, ErrInvite) {
		t.Fatal("invite used twice")
	}
	if err := s.ConsumeInvite(ID{1}); !errors.Is(err, ErrInvite) {
		t.Fatal("unknown invite")
	}
	// Concurrent use of one invite: exactly one succeeds.
	code2, _ := s.CreateInvite(5)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.ConsumeInvite(code2) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d successful uses of one invite", ok)
	}
	// Addresses.
	if a, _ := s.LoadAddresses(); len(a) != 0 {
		t.Fatal("empty table")
	}
	if n, err := s.AddAddress("Info@Example.org", ID{4}); err != nil || n != "info@example.org" {
		t.Fatal(err)
	}
	if _, err := s.AddAddress("info@example.org", ID{4}); err != nil {
		t.Fatal("idempotent add")
	}
	if _, err := s.AddAddress("info@example.org", ID{5}); !errors.Is(err, ErrExists) {
		t.Fatal("reassignment")
	}
	if _, err := s.AddAddress("bad", ID{5}); !errors.Is(err, ErrAddress) {
		t.Fatal("bad address")
	}
	a, err := s.LoadAddresses()
	if err != nil || a["info@example.org"] != (ID{4}) {
		t.Fatal("load")
	}
	for _, bad := range []string{`{`, `{"addresses":{"Info@x.y":"` + (ID{4}).String() + `"}}`, `{"addresses":{"i@x.y":"zz"}}`} {
		os.WriteFile(s.AddressesFile(), []byte(bad), 0o600)
		if _, err := s.LoadAddresses(); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s accepted", bad)
		}
	}
	// Mailboxes and epochs.
	mbx := ID{9}
	if _, err := s.ReadMailbox(mbx); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing mailbox")
	}
	e1, d1 := newTestEpoch(t, tu, mbx, 1, 1, nil)
	if _, err := s.WriteEpoch(e1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteEpoch(e1); !errors.Is(err, ErrExists) {
		t.Fatal("epoch replaced")
	}
	ge, gd, err := s.ReadEpoch(mbx, 1)
	if err != nil || !bytes.Equal(gd, d1) || ge.Number != 1 {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(filepath.Join(s.EpochDir(mbx, 1), "content.pub"))
	if !bytes.Equal(pub, e1.ContentPub.Bytes()) {
		t.Fatal("content.pub")
	}
	// An epoch file in the wrong place.
	MkdirAll(s.EpochDir(mbx, 2))
	os.WriteFile(s.EpochFile(mbx, 2), d1, 0o600)
	if _, _, err := s.ReadEpoch(mbx, 2); !errors.Is(err, ErrChain) {
		t.Fatal("misplaced epoch")
	}
	MkdirAll(filepath.Join(s.MailboxDir(mbx), "epochs", "007"))
	MkdirAll(filepath.Join(s.MailboxDir(mbx), "epochs", "x"))
	if ns, _ := s.ListEpochs(mbx); len(ns) != 2 || ns[0] != 1 || ns[1] != 2 {
		t.Fatalf("epochs %v", ns)
	}
	if ns, _ := s.ListEpochs(ID{55}); ns != nil {
		t.Fatal("epochs of missing mailbox")
	}
	if err := s.WriteWrap(mbx, 1, tu.user.ID, []byte("wrap")); err != nil {
		t.Fatal(err)
	}
	if w, err := s.ReadWrap(mbx, 1, tu.user.ID); err != nil || string(w) != "wrap" {
		t.Fatal("wrap")
	}
	m := &Mailbox{ID: mbx, Epoch: 1, Inbox: ID{6}, Name: []byte("n")}
	if err := s.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	if gm, err := s.ReadMailbox(mbx); err != nil || gm.Inbox != m.Inbox {
		t.Fatal(err)
	}
	m2 := *m
	m2.ID = ID{10}
	d2, _ := m2.Encode()
	os.WriteFile(s.MailboxFile(mbx), d2, 0o600)
	if _, err := s.ReadMailbox(mbx); !errors.Is(err, ErrRecord) {
		t.Fatal("foreign mailbox.rec")
	}
	if err := s.WriteMailbox(&Mailbox{}); err == nil {
		t.Fatal("empty mailbox written")
	}
	// Mail listing ignores foreign names and metadata files.
	MkdirAll(s.MailDir(mbx, m.Inbox))
	mail := ID{11}
	os.WriteFile(s.MailFile(mbx, m.Inbox, mail), []byte("m"), 0o600)
	os.WriteFile(s.MetaFile(mbx, m.Inbox, mail), []byte("meta"), 0o600)
	os.WriteFile(filepath.Join(s.MailDir(mbx, m.Inbox), "README.gml"), nil, 0o600)
	os.WriteFile(filepath.Join(s.MailDir(mbx, m.Inbox), tmpPrefix+"x"), nil, 0o600)
	ids, err := s.ListMails(mbx, m.Inbox)
	if err != nil || len(ids) != 1 || ids[0] != mail {
		t.Fatalf("mails %v %v", ids, err)
	}
	if b, err := s.ReadMail(mbx, m.Inbox, mail); err != nil || string(b) != "m" {
		t.Fatal("read mail")
	}
	if b, err := s.ReadMeta(mbx, m.Inbox, mail); err != nil || string(b) != "meta" {
		t.Fatal("read meta")
	}
	if ids, _ := s.ListMails(mbx, ID{99}); ids != nil {
		t.Fatal("missing folder")
	}
	MkdirAll(s.PendingDir(mbx, 1))
	os.WriteFile(s.PendingFile(mbx, 1, mail), []byte("p"), 0o600)
	if ps, _ := s.ListPending(mbx, 1); len(ps) != 1 {
		t.Fatal("pending")
	}
	if b, _ := s.ReadPending(mbx, 1, mail); string(b) != "p" {
		t.Fatal("read pending")
	}
	if es, _ := s.ListPendingEpochs(mbx); len(es) != 1 || es[0] != 1 {
		t.Fatal("pending epochs")
	}
	// Notes.
	if n, err := s.ReadNote(mbx); n != nil || err != nil {
		t.Fatal("no note")
	}
	note := &EpochNote{MailboxID: mbx, Epoch: 1, First: 1, Last: 2, Count: 3}
	if err := s.WriteNote(note); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ReadNote(mbx); err != nil || n.Count != 3 {
		t.Fatal("note")
	}
	note.MailboxID = ID{1}
	nd, _ := note.Encode()
	os.WriteFile(s.NoteFile(mbx), nd, 0o600)
	if _, err := s.ReadNote(mbx); !errors.Is(err, ErrRecord) {
		t.Fatal("foreign note")
	}
	os.WriteFile(s.NoteFile(mbx), []byte("x"), 0o600)
	if _, err := s.ReadNote(mbx); err == nil {
		t.Fatal("junk note")
	}
	if err := s.RemoveNote(mbx); err != nil {
		t.Fatal(err)
	}
	// Paths.
	rel, err := s.Rel(s.MailFile(mbx, m.Inbox, mail))
	if err != nil {
		t.Fatal(err)
	}
	if abs, err := s.Abs(rel); err != nil || abs != s.MailFile(mbx, m.Inbox, mail) {
		t.Fatal("Abs")
	}
	if _, err := s.Rel("/etc/passwd"); err == nil {
		t.Fatal("path outside")
	}
	if _, err := s.Abs("../x"); err == nil {
		t.Fatal("unsafe Abs")
	}
}

func TestPlatformFiles(t *testing.T) {
	s, _ := Init(t.TempDir())
	var seed keys.Seed
	seed[0] = 4
	p := keys.DerivePlatform(&seed)
	id, _ := p.IdentityKey(1)
	ingest, _ := p.IngestKey(1)
	admin, _ := p.AdminKey(1)
	c, _ := keys.NewPlatformCert(id, 1, keys.RoleIngest, 1, ingest.Public().(ed25519.PublicKey), 0)
	cd, _ := c.Encode()
	if err := s.WritePlatformFile(PlatformFileName("ingest", 1, "cert"), cd); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadPlatformCert(keys.RoleIngest, 1); !errors.Is(err, ErrNotFound) {
		t.Fatal("cert without pub")
	}
	s.WritePlatformFile(PlatformFileName("ingest", 1, "pub"), admin.Public().(ed25519.PublicKey))
	if _, err := s.ReadPlatformCert(keys.RoleIngest, 1); !errors.Is(err, ErrRecord) {
		t.Fatal("pub differs from cert")
	}
	os.Remove(s.platformFile("ingest-1.pub"))
	s.WritePlatformFile(PlatformFileName("ingest", 1, "pub"), ingest.Public().(ed25519.PublicKey))
	got, err := s.ReadPlatformCert(keys.RoleIngest, 1)
	if err != nil || got.Verify(id.Public().(ed25519.PublicKey)) != nil {
		t.Fatal(err)
	}
	// A certificate of another role or generation under this name.
	s.WritePlatformFile(PlatformFileName("admin", 1, "cert"), cd)
	if _, err := s.ReadPlatformCert(keys.RoleAdmin, 1); !errors.Is(err, ErrRecord) {
		t.Fatal("ingest cert accepted as admin cert")
	}
	if err := s.WritePlatformFile(PlatformFileName("ingest", 1, "cert"), cd); !errors.Is(err, ErrExists) {
		t.Fatal("platform file replaced")
	}
	os.WriteFile(s.platformFile("ingest-2.cert"), []byte("x"), 0o600)
	if _, err := s.ReadPlatformCert(keys.RoleIngest, 2); err == nil {
		t.Fatal("junk cert")
	}
}

func TestLocks(t *testing.T) {
	s, _ := Init(t.TempDir())
	a, b := ID{1}, ID{2}
	var mu sync.Mutex
	inside := 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids := []ID{a, b, a}
			if i%2 == 1 {
				ids = []ID{b, a}
			}
			unlock, err := s.LockMailboxes(ids)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			inside++
			if inside != 1 {
				t.Error("two holders of one lock")
			}
			mu.Unlock()
			mu.Lock()
			inside--
			mu.Unlock()
			unlock()
		}(i)
	}
	wg.Wait()
}

var _ = envelope.Suite1

func TestNameAndFolders(t *testing.T) {
	d, err := EncodeMailboxName(ID{1}, "Büro")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := DecodeMailboxName(ID{1}, d); err != nil || n != "Büro" {
		t.Fatal("name")
	}
	if _, err := DecodeMailboxName(ID{2}, d); !errors.Is(err, ErrRecord) {
		t.Fatal("name of another mailbox")
	}
	if _, err := EncodeMailboxName(ID{1}, ""); !errors.Is(err, ErrRecord) {
		t.Fatal("empty name")
	}
	empty, _ := rec.New(MailboxNameSchema).SetBytes(1, (&ID{1})[:]).SetString(2, "").Encode()
	if _, err := DecodeMailboxName(ID{1}, empty); !errors.Is(err, ErrRecord) {
		t.Fatal("empty decoded name")
	}
	if _, err := DecodeMailboxName(ID{1}, nil); err == nil {
		t.Fatal("nil")
	}
	fs := []Folder{{ID{2}, "INBOX"}, {ID{3}, "Archiv"}}
	fd, err := EncodeFolders(ID{1}, fs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFolders(ID{1}, fd)
	if err != nil || len(got) != 2 || got[1] != fs[1] {
		t.Fatal("folders")
	}
	if _, err := DecodeFolders(ID{9}, fd); !errors.Is(err, ErrRecord) {
		t.Fatal("folders of another mailbox")
	}
	if _, err := EncodeFolders(ID{1}, []Folder{{ID{2}, "a"}, {ID{2}, "b"}}); !errors.Is(err, ErrRecord) {
		t.Fatal("duplicate folder")
	}
	dup, _ := rec.New(FoldersSchema).SetBytes(1, (&ID{1})[:]).SetList(2, []*rec.Record{
		rec.New(FolderSchema).SetBytes(1, (&ID{2})[:]).SetString(2, "a"),
		rec.New(FolderSchema).SetBytes(1, (&ID{2})[:]).SetString(2, "b")}).Encode()
	if _, err := DecodeFolders(ID{1}, dup); !errors.Is(err, ErrRecord) {
		t.Fatal("duplicate decoded folder")
	}
	if _, err := DecodeFolders(ID{1}, nil); err == nil {
		t.Fatal("nil")
	}
	s, _ := Init(t.TempDir())
	if err := s.WriteFolders(ID{1}, fd); err != nil {
		t.Fatal(err)
	}
	if b, err := s.ReadFolders(ID{1}); err != nil || !bytes.Equal(b, fd) {
		t.Fatal("folders file")
	}
	MkdirAll(s.MailDir(ID{1}, ID{2}))
	MkdirAll(filepath.Join(s.MailboxDir(ID{1}), "mail", "junk"))
	if f, _ := s.ListFolders(ID{1}); len(f) != 1 || f[0] != (ID{2}) {
		t.Fatal("list folders")
	}
	if f, _ := s.ListFolders(ID{5}); f != nil {
		t.Fatal("folders of missing mailbox")
	}
}

func TestTempFilesLocksAndIncompleteEpochs(t *testing.T) {
	s, _ := Init(t.TempDir())
	p := s.Path("mailboxes", "x", tmpPrefix+"1")
	MkdirAll(filepath.Dir(p))
	os.WriteFile(p, nil, 0o600)
	os.WriteFile(s.Path("mailboxes", "x", "keep"), nil, 0o600)
	if err := s.RemoveTempFiles(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("temporary file kept")
	}
	if _, err := os.Stat(s.Path("mailboxes", "x", "keep")); err != nil {
		t.Fatal("data file removed")
	}
	unlock, err := LockFile(s.Path("l"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockFile(s.Path("l")); !errors.Is(err, ErrLocked) {
		t.Fatal("second lock")
	}
	unlock()
	u2, err := LockFile(s.Path("l"))
	if err != nil {
		t.Fatal(err)
	}
	u2()
	tu := newTestUser(t, 1, 1)
	mbx := ID{3}
	if err := s.RemoveIncompleteEpoch(mbx, 1); err != nil {
		t.Fatal("missing epoch dir")
	}
	MkdirAll(filepath.Join(s.EpochDir(mbx, 1), "members"))
	os.WriteFile(s.WrapFile(mbx, 1, tu.user.ID), []byte("w"), 0o600)
	if err := s.RemoveIncompleteEpoch(mbx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.EpochDir(mbx, 1)); !os.IsNotExist(err) {
		t.Fatal("incomplete epoch kept")
	}
	e, _ := newTestEpoch(t, tu, mbx, 1, 1, nil)
	s.WriteEpoch(e)
	if err := s.RemoveIncompleteEpoch(mbx, 1); !errors.Is(err, ErrExists) {
		t.Fatal("complete epoch removed")
	}
}
