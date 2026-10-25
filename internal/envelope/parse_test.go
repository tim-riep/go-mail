package envelope

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/tim-riep/go-mail/internal/rec"
)

// parts splits a valid file into its pieces so tests can rebuild
// variations of it.
type parts struct {
	preamble   []byte
	header     []byte
	recipients []byte
	blocks     [][]byte
	trailer    []byte // nil for unsigned
}

func split(t testing.TB, data []byte) parts {
	t.Helper()
	f, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	p := parts{preamble: append([]byte(nil), data[:6]...), header: f.headerBytes, recipients: f.recipientBytes, trailer: f.trailerBytes}
	for _, b := range f.blocks {
		p.blocks = append(p.blocks, append([]byte(nil), b...))
	}
	return p
}

func u32(n int) []byte { return binary.BigEndian.AppendUint32(nil, uint32(n)) }

func (p parts) build() []byte {
	var out []byte
	out = append(out, p.preamble...)
	out = append(out, u32(len(p.header))...)
	out = append(out, p.header...)
	out = append(out, u32(len(p.recipients))...)
	out = append(out, p.recipients...)
	for _, b := range p.blocks {
		out = append(out, u32(len(b))...)
		out = append(out, b...)
	}
	out = append(out, u32(len(p.trailer))...)
	return append(out, p.trailer...)
}

func (p parts) with(f func(p *parts)) parts {
	q := p
	q.blocks = append([][]byte(nil), p.blocks...)
	f(&q)
	return q
}

func reencodeHeader(t testing.TB, h Header) []byte {
	t.Helper()
	b, err := h.encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseRejectsStructure(t *testing.T) {
	small := seal(t, testHeader(KindMail), []byte("x"), false)
	signed := seal(t, testHeader(KindMeta), []byte("x"), true)
	p := split(t, small)
	ps := split(t, signed)
	f, _ := Parse(small)
	hdr := f.Header

	// Recipient sections with structural problems.
	entry := f.Recipients[0]
	recs := func(entries ...RecipientEntry) []byte {
		b, err := encodeRecipients(entries)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	emptyList, _ := rec.New(RecipientsSchema).SetList(1, nil).Encode()
	var many []RecipientEntry
	for i := 0; i <= MaxRecipients; i++ {
		e := entry
		e.Gen = uint32(i + 1)
		many = append(many, e)
	}
	manyRecs, _ := rec.New(RecipientsSchema).SetList(1, func() []*rec.Record {
		var l []*rec.Record
		for _, e := range many {
			l = append(l, rec.New(RecipientSchema).SetU8(1, uint8(e.Type)).SetBytes(2, e.ID[:]).SetU32(3, e.Gen).SetBytes(4, e.Enc).SetBytes(5, e.WrappedKey))
		}
		return l
	}()).Encode()
	typeFour := entry
	typeFour.Type = 4
	genZero := entry
	genZero.Gen = 0

	cases := []struct {
		name string
		data []byte
		err  error
	}{
		{"empty", nil, ErrTruncated},
		{"preamble only", small[:6], ErrTruncated},
		{"bad magic", append([]byte("GOMX"), small[4:]...), ErrMagic},
		{"version 2", append([]byte("GOML\x02"), small[5:]...), ErrVersion},
		{"version 0", append([]byte("GOML\x00"), small[5:]...), ErrVersion},
		{"suite 2", append([]byte("GOML\x01\x02"), small[6:]...), ErrSuite},
		{"suite 0", append([]byte("GOML\x01\x00"), small[6:]...), ErrSuite},
		{"header length beyond limit", p.with(func(p *parts) { p.header = make([]byte, MaxHeaderSize+1) }).build(), ErrHeaderSize},
		{"header length beyond data", append(append([]byte(nil), small[:6]...), 0, 0, 1, 0), ErrTruncated},
		{"header length huge", append(append([]byte(nil), small[:6]...), 0xff, 0xff, 0xff, 0xff), ErrHeaderSize},
		{"header empty", p.with(func(p *parts) { p.header = nil }).build(), ErrHeader},
		{"header kind 6", p.with(func(p *parts) { h := hdr; h.Kind = 6; p.header = reencodeHeader(t, h) }).build(), ErrHeader},
		{"header kind 0", p.with(func(p *parts) { h := hdr; h.Kind = 0; p.header = reencodeHeader(t, h) }).build(), ErrHeader},
		{"header chunk size 1024", p.with(func(p *parts) { h := hdr; h.ChunkSize = 1024; p.header = reencodeHeader(t, h) }).build(), ErrHeader},
		{"header chunk size 0", p.with(func(p *parts) { h := hdr; h.ChunkSize = 0; p.header = reencodeHeader(t, h) }).build(), ErrHeader},
		{"header trailing byte", p.with(func(p *parts) { p.header = append(append([]byte(nil), p.header...), 0) }).build(), ErrHeader},
		{"header is a trailer record", p.with(func(p *parts) { p.header = ps.trailer }).build(), ErrHeader},
		{"recipients length beyond limit", p.with(func(p *parts) { p.recipients = make([]byte, MaxRecipientsSize+1) }).build(), ErrRecipientsSize},
		{"recipients truncated", small[:6+4+len(p.header)+4+3], ErrTruncated},
		{"recipients empty", p.with(func(p *parts) { p.recipients = nil }).build(), ErrRecipients},
		{"recipients empty list", p.with(func(p *parts) { p.recipients = emptyList }).build(), ErrRecipients},
		{"recipients 33 entries", p.with(func(p *parts) { p.recipients = manyRecs }).build(), ErrRecipients},
		{"recipients duplicate", p.with(func(p *parts) { p.recipients = recs(entry, entry) }).build(), ErrRecipients},
		{"recipients type 4", p.with(func(p *parts) { p.recipients = recs(typeFour) }).build(), ErrRecipients},
		{"recipients gen 0", p.with(func(p *parts) { p.recipients = recs(genZero) }).build(), ErrRecipients},
		{"recipients is header record", p.with(func(p *parts) { p.recipients = p.header }).build(), ErrRecipients},
		{"no blocks", p.with(func(p *parts) { p.blocks = nil }).build(), ErrNoBlocks},
		{"no blocks signed", ps.with(func(p *parts) { p.blocks = nil }).build(), ErrNoBlocks},
		{"block shorter than tag", p.with(func(p *parts) { p.blocks = [][]byte{make([]byte, 15)} }).build(), ErrBlockSize},
		{"block longer than chunk", p.with(func(p *parts) { p.blocks = [][]byte{make([]byte, MaxBlockSize+1)} }).build(), ErrBlockSize},
		{"short block followed by block", p.with(func(p *parts) { p.blocks = [][]byte{p.blocks[0], p.blocks[0]} }).build(), ErrBlockSize},
		{"empty block after full block", p.with(func(p *parts) { p.blocks = [][]byte{make([]byte, MaxBlockSize), make([]byte, TagSize)} }).build(), ErrEmptyBlock},
		{"block truncated", small[:len(small)-4-1-10], ErrTruncated},
		{"missing trailer length", small[:len(small)-4], nil}, // the last block is taken for a trailer, leaving no blocks
		{"trailer length beyond limit", p.with(func(p *parts) { p.trailer = make([]byte, MaxTrailerSize+1) }).build(), ErrTrailerSize},
		{"trailer garbage", p.with(func(p *parts) { p.trailer = []byte("garbage trailer") }).build(), ErrTrailer},
		{"trailer is header record", p.with(func(p *parts) { p.trailer = p.header }).build(), ErrTrailer},
		{"trailer signer type 3", ps.with(func(p *parts) {
			tr, _ := decodeTrailer(p.trailer)
			tr.Signer.Type = 3
			p.trailer, _ = tr.encode()
		}).build(), ErrTrailer},
		{"trailer signer gen 0", ps.with(func(p *parts) {
			tr, _ := decodeTrailer(p.trailer)
			tr.Signer.Gen = 0
			p.trailer, _ = tr.encode()
		}).build(), ErrTrailer},
		{"data after trailer", append(append([]byte(nil), signed...), 0), nil},
		{"data after unsigned file", append(append([]byte(nil), small...), 1, 2, 3, 4), nil},
		{"trailer length claims less than rest", func() []byte {
			d := append([]byte(nil), signed...)
			binary.BigEndian.PutUint32(d[ps.trailerPos(signed):], uint32(len(ps.trailer)-1))
			return d
		}(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Parse(tc.data)
			if err == nil {
				t.Fatalf("expected %v, got file %+v", tc.err, f.Header)
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if f != nil {
				t.Fatal("no file on error")
			}
		})
	}
}

func (p parts) trailerPos(data []byte) int {
	return len(data) - 4 - len(p.trailer)
}

func TestParseTooManyBlocksAndTooLarge(t *testing.T) {
	p := split(t, seal(t, testHeader(KindMail), []byte("x"), false))
	full := make([]byte, MaxBlockSize)
	q := p.with(func(p *parts) {
		p.blocks = nil
		for i := 0; i <= MaxBlocks; i++ {
			p.blocks = append(p.blocks, full)
		}
	})
	if _, err := Parse(q.build()); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("801 blocks: %v", err)
	}
	big := make([]byte, MaxFileSize+1)
	copy(big, "GOML\x01\x01")
	if _, err := Parse(big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized file: %v", err)
	}
}

func TestEveryTruncationFails(t *testing.T) {
	for _, signed := range []bool{false, true} {
		// Every prefix of a small file, and a sample of prefixes of a
		// three-block file (every prefix would copy gigabytes).
		small := seal(t, testHeader(KindMail), pattern(100), signed)
		for n := 0; n < len(small); n++ {
			f, pt, err := Open(small[:n], openOpts(t, signed))
			if err == nil || f != nil || pt != nil {
				t.Fatalf("signed=%v: prefix of %d bytes accepted", signed, n)
			}
		}
		large := seal(t, testHeader(KindMail), pattern(2*ChunkSize+3), signed)
		for n := 0; n < len(large); n += 1 + n/64 {
			f, pt, err := Open(large[:n], openOpts(t, signed))
			if err == nil || f != nil || pt != nil {
				t.Fatalf("signed=%v: prefix of %d bytes accepted", signed, n)
			}
		}
		for _, n := range []int{len(large) - 1, len(large) - 4, len(large) - 5, len(large) - 20, len(large) - 4 - MaxBlockSize} {
			if f, pt, err := Open(large[:n], openOpts(t, signed)); err == nil || f != nil || pt != nil {
				t.Fatalf("signed=%v: prefix of %d bytes accepted", signed, n)
			}
		}
	}
}

func TestDecryptRejectsBlockManipulation(t *testing.T) {
	pt := pattern(2*ChunkSize + 1)
	data := seal(t, testHeader(KindMail), pt, false)
	p := split(t, data)
	if len(p.blocks) != 3 {
		t.Fatal("expected three blocks")
	}
	exact := split(t, seal(t, testHeader(KindMail), pattern(2*ChunkSize), false))
	cases := map[string]parts{
		"blocks 0 and 1 swapped":     p.with(func(p *parts) { p.blocks[0], p.blocks[1] = p.blocks[1], p.blocks[0] }),
		"block 0 duplicated":         p.with(func(p *parts) { p.blocks = [][]byte{p.blocks[0], p.blocks[0], p.blocks[1], p.blocks[2]} }),
		"block 1 missing":            p.with(func(p *parts) { p.blocks = [][]byte{p.blocks[0], p.blocks[2]} }),
		"last block missing":         p.with(func(p *parts) { p.blocks = p.blocks[:2] }),
		"only last block":            p.with(func(p *parts) { p.blocks = p.blocks[2:] }),
		"flag on wrong block":        exact.with(func(p *parts) { p.blocks[0], p.blocks[1] = p.blocks[1], p.blocks[0] }),
		"last block of exact repeat": exact.with(func(p *parts) { p.blocks = [][]byte{p.blocks[1], p.blocks[1]} }),
		"block bit flipped":          p.with(func(p *parts) { p.blocks[1] = append([]byte(nil), p.blocks[1]...); p.blocks[1][100] ^= 1 }),
		"tag bit flipped":            p.with(func(p *parts) { b := append([]byte(nil), p.blocks[2]...); b[len(b)-1] ^= 0x80; p.blocks[2] = b }),
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			mustFail(t, q.build(), false, ErrDecrypt)
		})
	}
}

func TestDecryptRejectsHeaderAndRecipientManipulation(t *testing.T) {
	a := seal(t, testHeader(KindMail), pattern(100), false)
	hdrB := testHeader(KindMail)
	hdrB.FileID = id16("file B")
	bData, err := Seal(hdrB, []Recipient{testRecipient(t)}, pattern(100), &SealOptions{Rand: fixedRand(9)})
	if err != nil {
		t.Fatal(err)
	}
	pa, pb := split(t, a), split(t, bData)
	fa, _ := Parse(a)
	hdr := fa.Header
	entry := fa.Recipients[0]
	lowOrder := make([]byte, 32)

	reHeader := func(f func(h *Header)) parts {
		return pa.with(func(p *parts) { h := hdr; f(&h); p.header = reencodeHeader(t, h) })
	}
	reEntry := func(f func(e *RecipientEntry)) parts {
		return pa.with(func(p *parts) {
			e := entry
			e.Enc = append([]byte(nil), e.Enc...)
			e.WrappedKey = append([]byte(nil), e.WrappedKey...)
			f(&e)
			p.recipients, _ = encodeRecipients([]RecipientEntry{e})
		})
	}
	cases := []struct {
		name string
		p    parts
		err  error
	}{
		{"mailbox id changed", reHeader(func(h *Header) { h.MailboxID[0] ^= 1 }), ErrUnwrap},
		{"epoch changed", reHeader(func(h *Header) { h.Epoch++ }), ErrUnwrap},
		{"file id changed", reHeader(func(h *Header) { h.FileID[15] ^= 1 }), ErrUnwrap},
		{"kind changed", reHeader(func(h *Header) { h.Kind = KindMeta }), ErrUnwrap},
		{"created changed", reHeader(func(h *Header) { h.Created++ }), ErrUnwrap},
		{"nonce prefix changed", reHeader(func(h *Header) { h.NoncePrefix[3] ^= 1 }), ErrUnwrap},
		{"header of A with blocks of B", pa.with(func(p *parts) { p.blocks = pb.blocks }), ErrDecrypt},
		{"header and recipients of B with blocks of A", pb.with(func(p *parts) { p.blocks = pa.blocks }), ErrDecrypt},
		{"header of B with recipients and blocks of A", pa.with(func(p *parts) { p.header = pb.header }), ErrUnwrap},
		{"recipients of B with header and blocks of A", pa.with(func(p *parts) { p.recipients = pb.recipients }), ErrUnwrap},
		{"wrapped key bit flipped", reEntry(func(e *RecipientEntry) { e.WrappedKey[0] ^= 1 }), ErrUnwrap},
		{"wrapped key tag flipped", reEntry(func(e *RecipientEntry) { e.WrappedKey[47] ^= 1 }), ErrUnwrap},
		{"enc bit flipped", reEntry(func(e *RecipientEntry) { e.Enc[0] ^= 1 }), ErrUnwrap},
		{"enc low-order point", reEntry(func(e *RecipientEntry) { copy(e.Enc, lowOrder) }), ErrUnwrap},
		{"enc low-order point 1", reEntry(func(e *RecipientEntry) { copy(e.Enc, lowOrder); e.Enc[0] = 1 }), ErrUnwrap},
		{"entry id changed", reEntry(func(e *RecipientEntry) { e.ID[0] ^= 1 }), ErrNoRecipient},
		{"entry type changed", reEntry(func(e *RecipientEntry) { e.Type = RecipientEpochMeta }), ErrNoRecipient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, tc.p.build(), false, tc.err)
		})
	}
	// Differing info: the entry says generation 2, and the holder of the
	// same private key presents it as generation 2. HPKE's info differs
	// from the one used for wrapping, so unwrapping fails.
	gen2 := reEntry(func(e *RecipientEntry) { e.Gen = 2 }).build()
	k := testRecipientKey(t)
	k.Gen = 2
	_, _, err = Open(gen2, OpenOptions{ExpectedSuite: Suite1, Key: k, AllowUnsigned: true})
	if !errors.Is(err, ErrUnwrap) {
		t.Fatalf("info mismatch: %v", err)
	}
	// Sanity: the untouched file still opens.
	if got := mustOpen(t, pa.build(), false); !bytes.Equal(got, pattern(100)) {
		t.Fatal("rebuilt file must open")
	}
}

func TestTwoMailsSwapped(t *testing.T) {
	// Two mails of the same mailbox and epoch, with different file ids.
	// Exchanging their content (blocks) under each other's header is
	// detected because the header is bound into the wrapping and every
	// block.
	h1 := testHeader(KindMail)
	h2 := testHeader(KindMail)
	h2.FileID = id16("second mail")
	m1, _ := Seal(h1, []Recipient{testRecipient(t)}, []byte("mail one"), &SealOptions{Rand: fixedRand(1)})
	m2, _ := Seal(h2, []Recipient{testRecipient(t)}, []byte("mail two"), &SealOptions{Rand: fixedRand(2)})
	p1, p2 := split(t, m1), split(t, m2)
	mustFail(t, p1.with(func(p *parts) { p.blocks = p2.blocks }).build(), false, ErrDecrypt)
	mustFail(t, p2.with(func(p *parts) { p.header = p1.header; p.recipients = p1.recipients }).build(), false, ErrDecrypt)
	// Renaming: the file id in the header is checked by the caller against
	// the file name; the envelope only guarantees the id is authentic.
	f, _ := Parse(m2)
	if f.Header.FileID != h2.FileID {
		t.Fatal("file id must survive")
	}
}

func TestSignatureNegatives(t *testing.T) {
	data := seal(t, testHeader(KindMeta), pattern(10), true)
	p := split(t, data)
	tr, _ := decodeTrailer(p.trailer)
	cases := map[string]parts{
		"signature bit flipped": p.with(func(p *parts) {
			t2 := *tr
			t2.Signature = append([]byte(nil), tr.Signature...)
			t2.Signature[10] ^= 1
			p.trailer, _ = t2.encode()
		}),
		"signer id changed":   p.with(func(p *parts) { t2 := *tr; t2.Signer.ID[0] ^= 1; p.trailer, _ = t2.encode() }),
		"signer gen changed":  p.with(func(p *parts) { t2 := *tr; t2.Signer.Gen = 2; p.trailer, _ = t2.encode() }),
		"signer type changed": p.with(func(p *parts) { t2 := *tr; t2.Signer.Type = SignerUser; p.trailer, _ = t2.encode() }),
		"block changed":       p.with(func(p *parts) { b := append([]byte(nil), p.blocks[0]...); b[0] ^= 1; p.blocks[0] = b }),
		"recipient changed":   p.with(func(p *parts) { r := append([]byte(nil), p.recipients...); r[len(r)-1] ^= 1; p.recipients = r }),
		"header changed":      p.with(func(p *parts) { h := append([]byte(nil), p.header...); h[len(h)-1] ^= 1; p.header = h }),
		"trailer removed":     p.with(func(p *parts) { p.trailer = nil }),
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			f, pt, err := Open(q.build(), openOpts(t, true))
			if err == nil || f != nil || pt != nil {
				t.Fatal("accepted")
			}
			if name != "trailer removed" && !errors.Is(err, ErrSignature) && !errors.Is(err, ErrSigner) {
				t.Fatalf("expected a signature error, got %v", err)
			}
		})
	}
	// Signature of another file (same signer) is rejected.
	other := split(t, seal(t, testHeader(KindMeta), pattern(11), true))
	mustFail(t, p.with(func(p *parts) { p.trailer = other.trailer }).build(), true, ErrSignature)
	// A foreign signer with a valid signature over this file is rejected
	// by the resolver.
	f, _ := Parse(data)
	foreign := Signer{Type: SignerUser, ID: id16("someone"), Gen: 1, Key: edKey("someone")}
	signed, _ := f.signedBytes(foreign.ref(), nil)
	sig, _ := keysSign(foreign.Key, KindMeta, signed)
	forged := p.with(func(p *parts) { p.trailer, _ = (&Trailer{Signer: foreign.ref(), Signature: sig}).encode() }).build()
	mustFail(t, forged, true, ErrSigner)
	// VerifySignature on an unsigned file.
	fu, _ := Parse(seal(t, testHeader(KindMail), nil, false))
	if err := fu.VerifySignature(nil, nil); !errors.Is(err, ErrUnsigned) {
		t.Fatal("unsigned file must report ErrUnsigned")
	}
}
