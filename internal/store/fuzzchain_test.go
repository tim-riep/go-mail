package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"testing"

	"github.com/tim-riep/go-mail/internal/envelope"
)

// heapAllocated returns the bytes the heap allocated while f ran
// (runtime.MemStats.TotalAlloc, whatever was freed again).
func heapAllocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// chainPiece is one step of FuzzChain: the epoch to add and the bytes
// passed as its encoding.
type chainPiece struct {
	data []byte
	// other passes the bytes of the piece before instead of data as the
	// encoding of the epoch decoded from data.
	other bool
	// patch makes the epoch from data with patchedEpoch.
	patch bool
}

// splitChain cuts the input of FuzzChain into pieces: each is a 2-byte
// big-endian header, whose top bit is chainPiece.other, the next
// chainPiece.patch and whose low 14 bits are the length, followed by
// that many bytes. A short last piece takes what is left.
func splitChain(in []byte) []chainPiece {
	var out []chainPiece
	for len(in) >= 2 {
		h := binary.BigEndian.Uint16(in)
		in = in[2:]
		n := min(int(h&0x3fff), len(in))
		out = append(out, chainPiece{data: in[:n], other: h&0x8000 != 0, patch: h&0x4000 != 0})
		in = in[n:]
	}
	return out
}

// joinChain is the inverse of splitChain, for seeds: plain pieces, and
// patch pieces when a piece is marked by patchPiece.
func joinChain(pieces ...[]byte) []byte {
	var out []byte
	for _, p := range pieces {
		h := uint16(len(p))
		if q, ok := bytes.CutPrefix(p, patchMark); ok {
			p, h = q, uint16(len(q))|0x4000
		}
		out = binary.BigEndian.AppendUint16(out, h)
		out = append(out, p...)
	}
	return out
}

// patchMark marks a piece of joinChain as a patch piece.
var patchMark = []byte("\xffpatch:")

// patchPiece returns a patch piece for joinChain: base epoch i of
// chainBases, then the patches (operation, value).
func patchPiece(i byte, patches ...byte) []byte {
	return append(append(bytes.Clone(patchMark), i), patches...)
}

// patchedEpoch returns the encoding of the epoch made from a patch piece:
// data[0] picks a base epoch, every further pair of bytes changes one
// field (operation, value), so that the fuzzer reaches the rules of the
// chain with well-formed epochs; nil if the result does not encode. The
// signature is not changed: Chain does not check it. prev is the
// encoding of the piece before (nil for the first): operation 12 makes
// the epoch name it as its predecessor, so that one operation passes
// rule 3 for any base, also one that repeats or skips a number (review
// of task 26E, B2).
func patchedEpoch(bases [][]byte, prev, data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	e, err := DecodeEpoch(bytes.Clone(bases[int(data[0])%len(bases)]))
	if err != nil {
		return nil
	}
	for data = data[1:]; len(data) >= 2; data = data[2:] {
		op, v := data[0], data[1]
		i := int(v) % len(e.Members)
		switch op % 13 {
		case 0:
			e.Begin += int64(int8(v)) * 100
		case 1:
			e.Reason = Reason(v % 8)
		case 2:
			e.Number = uint32(int64(e.Number) + int64(int8(v)))
		case 3:
			e.PrevHash = EpochHash(bases[int(v)%len(bases)])
		case 4:
			e.Members[i].Gen = uint32(v >> 4)
		case 5:
			e.Members[i].Kind = MemberKind(v >> 6)
		case 6:
			if len(e.Members) > 1 {
				e.Members = append(e.Members[:i:i], e.Members[i+1:]...)
			}
		case 7:
			e.SignerID, e.SignerGen = e.Members[i].ID, e.Members[i].Gen
		case 8:
			e.SignerGen = uint32(v % 4)
		case 9:
			d := uint32(uint64(v) % (uint64(e.Number) + 1))
			if j, ok := slices.BinarySearch(e.Discards, d); ok {
				e.Discards = slices.Delete(e.Discards, j, j+1)
			} else {
				e.Discards = slices.Insert(e.Discards, j, d)
			}
		case 10:
			o, err := DecodeEpoch(bases[int(v)%len(bases)])
			if err == nil {
				e.Members = append(e.Members, o.Members[int(v>>4)%len(o.Members)])
			}
		case 11:
			e.MailboxID[v%16] ^= 1
		case 12:
			e.PrevHash = EpochHash(prev)
		}
	}
	b, _ := e.Encode()
	return b
}

// chainBases returns every distinct epoch of the seed chains, the bases
// of patch pieces.
func chainBases(seeds [][][]byte) [][]byte {
	var out [][]byte
	for _, s := range seeds {
		for _, e := range s {
			if !slices.ContainsFunc(out, func(b []byte) bool { return bytes.Equal(b, e) }) {
				out = append(out, e)
			}
		}
	}
	return out
}

// chainState is what a failed Chain.Add must leave unchanged.
type chainState struct {
	n         int
	head      *Epoch
	discarded string
}

func stateOf(c *Chain) chainState {
	ds := make([]uint32, 0, len(c.discarded))
	for n, ok := range c.discarded {
		if ok {
			ds = append(ds, n)
		}
	}
	slices.Sort(ds)
	return chainState{n: len(c.epochs), head: c.Head(), discarded: fmt.Sprint(ds)}
}

// checkChain reports the first rule of 2.4 that the whole chain c breaks
// (Chain.Add rules 1 to 7, stated for the chain instead of for one step),
// "" if none; data[i] is the encoding of epoch i+1.
func checkChain(c *Chain, data [][]byte) string {
	if len(c.epochs) != len(data) {
		return fmt.Sprintf("chain holds %d epochs, %d were added", len(c.epochs), len(data))
	}
	discarded := map[uint32]bool{}
	for i := range data {
		n := uint32(i + 1)
		e := c.Epoch(n)
		if e == nil || e.Number != n {
			return fmt.Sprintf("epoch %d missing or misnumbered", n)
		}
		if enc, err := e.Encode(); err != nil || !bytes.Equal(enc, data[i]) {
			return fmt.Sprintf("epoch %d is not its encoding (%v)", n, err)
		}
		if e.MailboxID != c.Epoch(1).MailboxID {
			return fmt.Sprintf("epoch %d of another mailbox", n)
		}
		if m, ok := e.Member(e.SignerID); !ok || m.Gen != e.SignerGen {
			return fmt.Sprintf("epoch %d signed by a non-member of itself", n)
		}
		if n == 1 {
			if e.PrevHash != [32]byte{} || len(e.Discards) != 0 {
				return "epoch 1 names a predecessor or discards"
			}
		} else {
			prev := c.Epoch(n - 1)
			if e.PrevHash != EpochHash(data[i-1]) {
				return fmt.Sprintf("epoch %d does not name its predecessor", n)
			}
			if envelope.CheckSuiteTransition(prev.Suite, e.Suite) != nil {
				return fmt.Sprintf("epoch %d lowers the suite", n)
			}
			if _, ok := prev.Member(e.SignerID); !ok {
				return fmt.Sprintf("epoch %d signed by a non-member of epoch %d", n, n-1)
			}
		}
		if len(e.Discards) > 0 && !e.Reason.Immediate() {
			return fmt.Sprintf("regular epoch %d discards", n)
		}
		for _, d := range e.Discards {
			p := c.Epoch(d)
			if d >= n || p == nil || discarded[d] || p.Begin <= e.Begin {
				return fmt.Sprintf("epoch %d discards epoch %d, which is not a later-beginning epoch still in use", n, d)
			}
			discarded[d] = true
		}
	}
	// The epochs that are not discarded never begin before one of them
	// earlier in the chain (rules 2, 4 and 6 together), and the head is
	// never discarded.
	var last int64
	have := false
	for i := range data {
		n := uint32(i + 1)
		if c.Discarded(n) != discarded[n] {
			return fmt.Sprintf("Discarded(%d) = %v, the discards of the chain say %v", n, c.Discarded(n), discarded[n])
		}
		b, ok := c.Begin(n)
		if ok == discarded[n] {
			return fmt.Sprintf("Begin(%d) reports %v, discarded %v", n, ok, discarded[n])
		}
		if !ok {
			continue
		}
		if have && b < last {
			return fmt.Sprintf("epoch %d begins before an earlier epoch that is not discarded", n)
		}
		last, have = b, true
	}
	if len(data) > 0 && c.Discarded(uint32(len(data))) {
		return "the head is discarded"
	}
	return ""
}

// chainSeeds returns chains of valid epochs: a supply of regular epochs,
// an immediate epoch that discards two planned ones and adds a member,
// that member signing the next epochs (one immediate, one regular with a
// recovery recipient), and gaps.
func chainSeeds(f testing.TB) [][][]byte {
	// c has the generation of a: one byte of signer_id makes c the
	// signer of an epoch of a that adds c.
	a, b, c := newTestUser(f, 1, 1), newTestUser(f, 2, 2), newTestUser(f, 3, 1)
	mbx := ID{9}
	_, e1 := newTestEpoch(f, a, mbx, 1, 1000, nil)
	_, e2 := newTestEpoch(f, a, mbx, 2, 2000, e1)
	_, e3 := newTestEpoch(f, a, mbx, 3, 3000, e2)
	x := unsignedEpoch(f, a, mbx, 4, 1500, ReasonMemberAdded, e3)
	x.Discards = []uint32{2, 3}
	x.Members = append(x.Members, Member{MemberUser, b.user.ID, b.user.Current().Gen}, Member{MemberUser, c.user.ID, 1})
	_, e4 := signEpoch(f, a, x)
	y := unsignedEpoch(f, b, mbx, 5, 1600, ReasonMemberRemoved, e4)
	_, e5 := signEpoch(f, b, y)
	z := unsignedEpoch(f, b, mbx, 6, 2600, ReasonRegular, e5)
	z.Members = append(z.Members, Member{MemberRecovery, ID{7}, 1})
	_, e6 := signEpoch(f, b, z)
	// The boundary of rule 6: an immediate epoch with the begin of its
	// predecessor keeps it, and must not discard it.
	q := unsignedEpoch(f, a, mbx, 3, 2000, ReasonRecoveryChanged, e2)
	_, keeps := signEpoch(f, a, q)
	q.Discards = []uint32{2}
	_, drops := signEpoch(f, a, q)
	return [][][]byte{{e1}, {e1, e2, e3}, {e1, e2, e3, e4, e5, e6}, {e1, e3}, {e2}, {e1, e2, e4}, {e1, e2, e2},
		{e1, e2, keeps}, {e1, e2, drops}}
}

// TestChainSeeds: the seed chains of FuzzChain are accepted whole, up to
// the gaps, so that the fuzzer starts from valid chains.
func TestChainSeeds(t *testing.T) {
	for i, s := range chainSeeds(t) {
		c := NewChain()
		n := 0
		for _, data := range s {
			e, err := DecodeEpoch(data)
			if err != nil {
				t.Fatal(err)
			}
			if c.Add(e, data) == nil {
				n++
			}
		}
		if want := []int{1, 3, 6, 1, 0, 2, 2, 3, 2}[i]; n != want {
			t.Errorf("seed %d: %d epochs added, want %d", i, n, want)
		}
	}
}

// FuzzChain adds the epochs of the input to one Chain (store.Chain, the
// structural check of an epoch chain that client and server share; the
// input is cut by splitChain, a piece is an encoded epoch or a base epoch
// with field patches, patchedEpoch). Nothing may panic; a failed Add
// returns ErrChain and leaves the chain unchanged; after every successful
// Add the epoch is the head and the whole chain obeys the rules of 2.4
// (checkChain); and the heap that DecodeEpoch and Add allocate stays
// within a bound linear in the input and the patched epochs.
func FuzzChain(f *testing.F) {
	seeds := chainSeeds(f)
	bases := chainBases(seeds)
	for _, s := range seeds {
		f.Add(joinChain(s...))
	}
	e1, e2, e3 := seeds[1][0], seeds[1][1], seeds[1][2]
	f.Add(joinChain(e1, patchPiece(1), patchPiece(2, 0, 0xf6)))
	f.Add(joinChain(e1, e2, e3, patchPiece(3, 7, 1)))
	f.Add(joinChain(e1, e2, e3, patchPiece(3, 9, 1), patchPiece(4, 10, 0x21)))
	f.Add(joinChain(e1, e2, patchPiece(6, 9, 2, 0, 1)))
	// Every operation once on epoch 4, with a value that changes little.
	for op := byte(0); op < 13; op++ {
		f.Add(joinChain(e1, e2, e3, patchPiece(3, op, 0)))
	}
	// A repeated number (rule 2): epoch 3 once more after epoch 3, naming
	// it as its predecessor (operation 12), so that only the number is
	// wrong; and epoch 3 once more after epoch 2 renumbered to 2.
	f.Add(joinChain(e1, e2, e3, patchPiece(2, 12, 0)))
	f.Add(joinChain(e1, e2, patchPiece(2, 2, 0xff, 12, 0)))
	f.Add([]byte{})
	f.Add([]byte{0x80, 0x00})
	f.Fuzz(func(t *testing.T, in []byte) {
		c := NewChain()
		var added [][]byte
		var prev []byte
		// used counts the heap of DecodeEpoch and Add only, not that of
		// the checks of this target.
		var used uint64
		size := len(in)
		for _, p := range splitChain(in) {
			raw := p.data
			if p.patch {
				raw = patchedEpoch(bases, prev, p.data)
				size += len(raw)
			}
			var e *Epoch
			var err error
			used += heapAllocated(func() { e, err = DecodeEpoch(raw) })
			data := raw
			if p.other {
				data = prev
			}
			prev = raw
			if err != nil {
				continue
			}
			before := stateOf(c)
			used += heapAllocated(func() { err = c.Add(e, data) })
			if err != nil {
				if !errors.Is(err, ErrChain) {
					t.Fatalf("Add failed without ErrChain: %v", err)
				}
				if stateOf(c) != before {
					t.Fatalf("a failed Add changed the chain: %v", err)
				}
				continue
			}
			if c.Head() != e {
				t.Fatal("a successful Add did not make the epoch the head")
			}
			added = append(added, bytes.Clone(data))
			if bad := checkChain(c, added); bad != "" {
				t.Fatal(bad)
			}
		}
		if limit := uint64(1<<20 + 64*size); used > limit {
			t.Fatalf("allocated %d bytes for %d bytes of input and patched epochs (bound %d)", used, size, limit)
		}
	})
}
