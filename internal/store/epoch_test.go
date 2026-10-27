package store

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/rec"
)

func TestReasons(t *testing.T) {
	want := map[Reason]bool{ReasonRegular: false, ReasonMemberAdded: true, ReasonMemberRemoved: true,
		ReasonDelegationEnded: true, ReasonRecoveryChanged: true, ReasonGenerationRevoked: true}
	for r, imm := range want {
		if !r.valid() || r.Immediate() != imm {
			t.Fatalf("reason %d: valid %v immediate %v", r, r.valid(), r.Immediate())
		}
	}
	if ReasonRegular != 1 || ReasonGenerationRevoked != 6 {
		t.Fatal("reason values are fixed by 2.4")
	}
	for _, r := range []Reason{0, 7, 255} {
		if r.valid() || r.Immediate() {
			t.Fatalf("reason %d accepted", r)
		}
	}
}

func TestEpochStructure(t *testing.T) {
	tu := newTestUser(t, 1, 2)
	mbx := ID{9}
	e1, d1 := newTestEpoch(t, tu, mbx, 1, 100, nil)
	e2 := unsignedEpoch(t, tu, mbx, 2, 200, ReasonMemberRemoved, d1)
	e2.Members = append(e2.Members, Member{MemberRecovery, ID{7}, 1}, Member{MemberDelegate, ID{8}, 3})
	_, d2 := signEpoch(t, tu, e2)
	e3 := unsignedEpoch(t, tu, mbx, 3, 300, ReasonGenerationRevoked, d2)
	e3.Discards = []uint32{1, 2}
	e3, d3 := signEpoch(t, tu, e3)
	for _, d := range [][]byte{d1, d2, d3} {
		got, err := DecodeEpoch(d)
		if err != nil {
			t.Fatal(err)
		}
		again, err := got.Encode()
		if err != nil || !bytes.Equal(again, d) {
			t.Fatal("epoch not byte-identical")
		}
	}
	if got, _ := DecodeEpoch(d3); len(got.Discards) != 2 || got.Discards[1] != 2 {
		t.Fatal("discards not decoded")
	}
	if got, _ := DecodeEpoch(d1); got.Discards != nil {
		t.Fatal("absent discards decoded as a list")
	}
	// A delegate and the recovery recipient are no user members.
	if _, ok := e3.Member(ID{8}); ok {
		t.Fatal("delegate returned as user member")
	}
	if _, ok := e3.Member(ID{7}); ok {
		t.Fatal("recovery returned as user member")
	}
	many := make([]uint32, MaxDiscards+1)
	for i := range many {
		many[i] = uint32(i + 1)
	}
	bad := map[string]func(e *Epoch){
		"zero mailbox":      func(e *Epoch) { e.MailboxID = ID{} },
		"epoch 0":           func(e *Epoch) { e.Number = 0 },
		"reason 0":          func(e *Epoch) { e.Reason = 0 },
		"reason 7":          func(e *Epoch) { e.Reason = 7 },
		"suite 2":           func(e *Epoch) { e.Suite = 2 },
		"no content key":    func(e *Epoch) { e.ContentPub = nil },
		"no members":        func(e *Epoch) { e.Members = nil },
		"no signer":         func(e *Epoch) { e.SignerGen = 0 },
		"epoch 3 no prev":   func(e *Epoch) { e.PrevHash = [32]byte{} },
		"epoch 1 with prev": func(e *Epoch) { e.Number = 1; e.Discards = nil },
		"member gen 0":      func(e *Epoch) { e.Members = append(e.Members, Member{Kind: MemberUser, ID: ID{1}}) },
		"member kind 0":     func(e *Epoch) { e.Members = append(e.Members, Member{Kind: 0, ID: ID{1}, Gen: 1}) },
		"member kind 4":     func(e *Epoch) { e.Members = append(e.Members, Member{Kind: 4, ID: ID{1}, Gen: 1}) },
		"zero member id":    func(e *Epoch) { e.Members = append(e.Members, Member{Kind: MemberUser, Gen: 1}) },
		"duplicate member":  func(e *Epoch) { e.Members = append(e.Members, e.Members[0]) },
		"id in two kinds":   func(e *Epoch) { e.Members = append(e.Members, Member{MemberDelegate, tu.user.ID, 2}) },
		"two recovery": func(e *Epoch) {
			e.Members = append(e.Members, Member{MemberRecovery, ID{1}, 1}, Member{MemberRecovery, ID{2}, 1})
		},
		"signer not member":  func(e *Epoch) { e.SignerID = ID{5} },
		"signer delegate":    func(e *Epoch) { e.Members = []Member{{MemberDelegate, tu.user.ID, 2}} },
		"signer recovery":    func(e *Epoch) { e.Members = []Member{{MemberRecovery, tu.user.ID, 2}} },
		"signer other gen":   func(e *Epoch) { e.SignerGen = 1 },
		"member other gen":   func(e *Epoch) { e.Members[0].Gen = 1 },
		"discards regular":   func(e *Epoch) { e.Reason = ReasonRegular },
		"discards unordered": func(e *Epoch) { e.Discards = []uint32{2, 1} },
		"discards duplicate": func(e *Epoch) { e.Discards = []uint32{1, 1} },
		"discards zero":      func(e *Epoch) { e.Discards = []uint32{0, 1} },
		"discards self":      func(e *Epoch) { e.Discards = []uint32{1, 3} },
		"discards later":     func(e *Epoch) { e.Discards = []uint32{4} },
		"discards too many":  func(e *Epoch) { e.Number = MaxDiscards + 2; e.Discards = many },
		"too many members": func(e *Epoch) {
			for i := 0; len(e.Members) <= MaxMembers; i++ {
				e.Members = append(e.Members, Member{MemberUser, ID{byte(i), 2}, 1})
			}
		},
	}
	for name, f := range bad {
		c := *e3
		c.Members = append([]Member(nil), e3.Members...)
		f(&c)
		if err := c.Sign(tu.identity); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s accepted by Sign: %v", name, err)
		}
		if _, err := c.Encode(); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s accepted by Encode", name)
		}
		// The decoder applies the same rules. record() cannot encode a
		// missing key and omits prev_hash of epoch 1 (tested below).
		if name == "no content key" || name == "epoch 1 with prev" {
			continue
		}
		if enc, err := c.record(true).Encode(); err == nil {
			if _, err := DecodeEpoch(enc); err == nil {
				t.Fatalf("%s accepted by DecodeEpoch", name)
			}
		}
	}
	// An immediate epoch may discard nothing.
	e4 := unsignedEpoch(t, tu, mbx, 4, 400, ReasonMemberAdded, d3)
	if _, err := e4.Encode(); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned epoch encoded")
	}
	signEpoch(t, tu, e4)
	tbs, _ := e3.record(false).Encode()
	if _, err := DecodeEpoch(tbs); !errors.Is(err, ErrRecord) {
		t.Fatal("unsigned epoch decoded")
	}
	// Decoder-only rules: zero previous hash, prev_hash in epoch 1, empty
	// discards.
	raw := func(e *Epoch, discards []*rec.Record, prev []byte, content []byte) *rec.Record {
		members := []*rec.Record{rec.New(MemberSchema).SetU8(1, 1).SetBytes(2, e.SignerID[:]).SetU32(3, e.SignerGen)}
		r := rec.New(EpochSchema).SetBytes(1, e.MailboxID[:]).SetU32(2, e.Number).SetI64(3, e.Begin).
			SetU8(4, uint8(e.Reason)).SetU8(5, 1).SetBytes(6, content).SetBytes(7, e.MetaPub.Bytes()).SetList(8, members)
		if discards != nil {
			r.SetList(9, discards)
		}
		if prev != nil {
			r.SetBytes(10, prev)
		}
		return r.SetBytes(11, e.SignerID[:]).SetU32(12, e.SignerGen).SetBytes(13, e.Signature)
	}
	one := []*rec.Record{rec.New(DiscardSchema).SetU32(1, 1)}
	if _, err := DecodeEpoch(mustEncode(t, raw(e3, one, e3.PrevHash[:], e3.ContentPub.Bytes()))); err != nil {
		t.Fatalf("raw encoding of a valid epoch: %v", err)
	}
	for name, r := range map[string]*rec.Record{
		"zero previous hash": raw(e3, one, make([]byte, 32), e3.ContentPub.Bytes()),
		"epoch 1 with prev":  raw(e1, nil, bytes.Repeat([]byte{1}, 32), e1.ContentPub.Bytes()),
		"empty discards":     raw(e3, []*rec.Record{}, e3.PrevHash[:], e3.ContentPub.Bytes()),
	} {
		enc, err := r.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeEpoch(enc); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := DecodeEpoch(append(d3, 0)); err == nil {
		t.Fatal("trailing byte")
	}
	if _, err := DecodeEpoch(nil); err == nil {
		t.Fatal("nil")
	}
}

// chainCase builds epochs in order; each step is signed by its signer
// and linked to the encoding of the step before (unless prev is set).
type chainStep struct {
	n        uint32
	begin    int64
	reason   Reason
	discards []uint32
	members  []*testUser // nil: the members of the case
	signer   *testUser   // nil: the first member
	mutate   func(e *Epoch)
	raw      func(e *Epoch, data []byte) (*Epoch, []byte) // replaces the encoding
}

func TestChain(t *testing.T) {
	a, b, c := newTestUser(t, 1, 1), newTestUser(t, 2, 2), newTestUser(t, 3, 1)
	mbx := ID{9}
	build := func(t *testing.T, steps []chainStep) ([]*Epoch, [][]byte) {
		var es []*Epoch
		var ds [][]byte
		var prev []byte
		for _, s := range steps {
			members := s.members
			if members == nil {
				members = []*testUser{a, b}
			}
			signer := s.signer
			if signer == nil {
				signer = members[0]
			}
			reason := s.reason
			if reason == 0 {
				reason = ReasonRegular
			}
			e := unsignedEpoch(t, signer, mbx, s.n, s.begin, reason, prev)
			e.Members = nil
			for _, m := range members {
				e.Members = append(e.Members, Member{MemberUser, m.user.ID, m.user.Current().Gen})
			}
			e.Discards = s.discards
			if s.mutate != nil {
				s.mutate(e)
			}
			var d []byte
			if s.raw != nil {
				e, d = s.raw(e, nil)
			} else {
				e, d = signEpoch(t, signer, e)
			}
			es, ds = append(es, e), append(ds, d)
			prev = d
		}
		return es, ds
	}
	// forge signs with the identity of signer whatever the record says
	// and encodes without the structural checks of Encode.
	forge := func(signer *testUser) func(e *Epoch, _ []byte) (*Epoch, []byte) {
		return func(e *Epoch, _ []byte) (*Epoch, []byte) {
			tbs, _ := e.record(false).Encode()
			e.Signature = ed25519Sign(signer, tbs)
			d, err := e.record(true).Encode()
			if err != nil {
				t.Fatal(err)
			}
			return e, d
		}
	}
	removeB := []*testUser{a}
	cases := []struct {
		name  string
		steps []chainStep
		fail  int // index of the step Add rejects; -1 accepts all
	}{
		{"valid chain with discards", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 200}, {n: 3, begin: 300},
			{n: 4, begin: 150, reason: ReasonMemberRemoved, discards: []uint32{2, 3}, members: removeB},
			{n: 5, begin: 400, members: removeB},
		}, -1},
		{"immediate epoch without later ones", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 150, reason: ReasonGenerationRevoked, signer: b},
		}, -1},
		{"equal begin is not later", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 100}, {n: 3, begin: 100, reason: ReasonMemberAdded},
		}, -1},
		{"first epoch not 1", []chainStep{{n: 2, begin: 100, mutate: func(e *Epoch) { e.PrevHash = [32]byte{1} }}}, 0},
		{"epoch 1 with prev_hash", []chainStep{{n: 1, begin: 100, mutate: func(e *Epoch) { e.PrevHash = [32]byte{1} }, raw: forge(a)}}, 0},
		{"wrong prev_hash", []chainStep{{n: 1, begin: 100}, {n: 2, begin: 200, mutate: func(e *Epoch) { e.PrevHash[0] ^= 1 }}}, 1},
		{"number jump", []chainStep{{n: 1, begin: 100}, {n: 3, begin: 200}}, 1},
		{"number repeated", []chainStep{{n: 1, begin: 100}, {n: 1, begin: 200, mutate: func(e *Epoch) { e.PrevHash = [32]byte{} }}}, 1},
		{"other mailbox", []chainStep{{n: 1, begin: 100}, {n: 2, begin: 200, mutate: func(e *Epoch) { e.MailboxID = ID{8} }}}, 1},
		{"signer not member of predecessor", []chainStep{
			{n: 1, begin: 100, members: []*testUser{a}},
			{n: 2, begin: 200, members: []*testUser{c, a}},
		}, 1},
		{"signer not member of new epoch", []chainStep{
			{n: 1, begin: 100},
			{n: 2, begin: 200, reason: ReasonMemberRemoved, members: removeB, signer: b,
				mutate: func(e *Epoch) { e.SignerID, e.SignerGen = b.user.ID, 2 }, raw: forge(b)},
		}, 1},
		{"member entry of other generation", []chainStep{
			{n: 1, begin: 100},
			{n: 2, begin: 200, signer: b, mutate: func(e *Epoch) { e.SignerID, e.SignerGen = b.user.ID, 1 }, raw: forge(b)},
		}, 1},
		{"discards incomplete", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 200}, {n: 3, begin: 300},
			{n: 4, begin: 150, reason: ReasonMemberRemoved, discards: []uint32{2}, members: removeB},
		}, 3},
		{"discards too many", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 200}, {n: 3, begin: 300},
			{n: 4, begin: 150, reason: ReasonMemberRemoved, discards: []uint32{1, 2, 3}, members: removeB},
		}, 3},
		{"discards in regular epoch", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 200},
			{n: 3, begin: 150, discards: []uint32{2}, raw: forge(a)},
		}, 2},
		{"later begin missing from regular epoch", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 200}, {n: 3, begin: 150},
		}, 2},
		{"later begin missing from immediate epoch", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 200}, {n: 3, begin: 150, reason: ReasonDelegationEnded},
		}, 2},
		{"begin before last valid predecessor", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 50},
		}, 1},
		{"begin before a discarded predecessor", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 300},
			{n: 3, begin: 150, reason: ReasonRecoveryChanged, discards: []uint32{2}},
			{n: 4, begin: 200},
		}, -1},
		{"discarded number again", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 300},
			{n: 3, begin: 150, reason: ReasonMemberRemoved, discards: []uint32{2}},
			{n: 4, begin: 140, reason: ReasonMemberRemoved, discards: []uint32{2, 3}},
		}, 3},
		{"discards the predecessor that begins earlier", []chainStep{
			{n: 1, begin: 100}, {n: 2, begin: 200, reason: ReasonMemberAdded, discards: []uint32{1}},
		}, 1},
	}
	// The texts of the rules that cover each other (see Chain.Add) are
	// pinned, so that removing one of them is noticed.
	texts := map[string]string{
		"discarded number again":                       "epoch 4 discards epoch 2 again",
		"discards too many":                            "discards epoch 1, which does not begin later",
		"discards the predecessor that begins earlier": "discards epoch 1, which does not begin later",
		"later begin missing from regular epoch":       "regular epoch 3 begins before epoch 2",
		"later begin missing from immediate epoch":     "epoch 3 does not discard epoch 2, which begins later",
		"discards incomplete":                          "epoch 4 does not discard epoch 3, which begins later",
		"begin before last valid predecessor":          "regular epoch 2 begins before epoch 1",
	}
	for name := range texts {
		found := false
		for _, tc := range cases {
			found = found || tc.name == name
		}
		if !found {
			t.Fatalf("no case %q", name)
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			es, ds := build(t, tc.steps)
			ch := NewChain()
			for i := range es {
				head := ch.Head()
				err := ch.Add(es[i], ds[i])
				if i == tc.fail {
					if !errors.Is(err, ErrChain) {
						t.Fatalf("step %d accepted: %v", i, err)
					}
					if ch.Head() != head {
						t.Fatal("a rejected epoch changed the chain")
					}
					if want, ok := texts[tc.name]; ok && !strings.Contains(err.Error(), want) {
						t.Fatalf("rejected by another rule: %v, want %q", err, want)
					}
					t.Logf("rejected: %v", err)
					return
				}
				if err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
			}
			if tc.fail >= 0 {
				t.Fatal("no step rejected")
			}
		})
	}

	// The state of the valid chain.
	es, ds := build(t, cases[0].steps)
	ch := NewChain()
	if ch.Head() != nil || ch.Epoch(1) != nil {
		t.Fatal("empty chain")
	}
	for i := range es {
		if err := ch.Add(es[i], ds[i]); err != nil {
			t.Fatal(err)
		}
	}
	if ch.Head() != es[4] || ch.Epoch(2) != es[1] || ch.Epoch(0) != nil || ch.Epoch(6) != nil {
		t.Fatal("Head or Epoch")
	}
	for n, want := range map[uint32]bool{1: false, 2: true, 3: true, 4: false, 5: false, 6: false} {
		if ch.Discarded(n) != want {
			t.Fatalf("Discarded(%d)", n)
		}
	}
	if b, ok := ch.Begin(4); !ok || b != 150 {
		t.Fatal("Begin(4)")
	}
	if _, ok := ch.Begin(2); ok {
		t.Fatal("a discarded epoch has a begin")
	}
	if _, ok := ch.Begin(9); ok {
		t.Fatal("begin of a missing epoch")
	}

	// Add checks the encoding against the epoch and the epoch itself.
	es, ds = build(t, cases[0].steps[:2])
	ch = NewChain()
	if err := ch.Add(nil, nil); !errors.Is(err, ErrChain) {
		t.Fatal("nil epoch")
	}
	if err := ch.Add(es[0], ds[1]); !errors.Is(err, ErrChain) {
		t.Fatal("foreign encoding accepted")
	}
	if err := ch.Add(es[0], ds[0]); err != nil {
		t.Fatal(err)
	}
	// Suite backwards: the PoC knows only suite 1, so the predecessor
	// is given a newer suite after it was added.
	ch.epochs[0].Suite = 2
	if err := ch.Add(es[1], ds[1]); !errors.Is(err, ErrChain) {
		t.Fatal("older suite accepted")
	}
	ch.epochs[0].Suite = 1
	if err := ch.Add(es[1], ds[1]); err != nil {
		t.Fatal(err)
	}
}
