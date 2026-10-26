package envelope

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestElementSequence covers every deviation from the only accepted
// element sequence ElemBlock* ElemLastBlock ElemTrailer? (3.1, version
// 1.1): missing last block, two last blocks, a block after the last
// block, two trailers, unknown type bytes, and bytes after the trailer.
func TestElementSequence(t *testing.T) {
	// Three blocks: two full ones and a short last one; signed and not.
	pt := pattern(2*ChunkSize + 1)
	unsigned := split(t, seal(t, testHeader(KindMail), pt, false))
	signed := split(t, seal(t, testHeader(KindMeta), pt, true))
	full0, full1, last := unsigned.blocks[0], unsigned.blocks[1], unsigned.blocks[2]
	sfull0, sfull1, slast := signed.blocks[0], signed.blocks[1], signed.blocks[2]
	tr := signed.trailer

	cases := []struct {
		name  string
		data  []byte
		err   error
		other error // alternatively acceptable
	}{
		{"missing 0x02: end of file after 0x01 blocks", unsigned.buildElems(elem(ElemBlock, full0), elem(ElemBlock, full1)), ErrTruncated, nil},
		{"missing 0x02: trailer after 0x01 blocks", signed.buildElems(elem(ElemBlock, sfull0), elem(ElemBlock, sfull1), elem(ElemTrailer, tr)), ErrElement, nil},
		{"missing 0x02: last block framed as 0x01", unsigned.buildElems(elem(ElemBlock, full0), elem(ElemBlock, full1), elem(ElemBlock, last)), ErrBlockSize, nil},
		{"missing 0x02: nothing after recipients", unsigned.buildElems(), ErrTruncated, nil},
		{"missing 0x02: only a trailer", signed.buildElems(elem(ElemTrailer, tr)), ErrElement, nil},
		{"two 0x02", unsigned.buildElems(elem(ElemBlock, full0), elem(ElemLastBlock, full1), elem(ElemLastBlock, last)), ErrElement, nil},
		{"two 0x02 signed", signed.buildElems(elem(ElemBlock, sfull0), elem(ElemLastBlock, sfull1), elem(ElemLastBlock, slast), elem(ElemTrailer, tr)), ErrElement, nil},
		{"0x01 after 0x02", unsigned.buildElems(elem(ElemBlock, full0), elem(ElemLastBlock, last), elem(ElemBlock, full1)), ErrElement, nil},
		{"0x01 after 0x02 and trailer", signed.buildElems(elem(ElemBlock, sfull0), elem(ElemLastBlock, slast), elem(ElemTrailer, tr), elem(ElemBlock, sfull1)), ErrElement, nil},
		{"two trailers", signed.buildElems(elem(ElemBlock, sfull0), elem(ElemBlock, sfull1), elem(ElemLastBlock, slast), elem(ElemTrailer, tr), elem(ElemTrailer, tr)), ErrElement, nil},
		{"unknown type 0x00 first", unsigned.buildElems(elem(0x00, full0), elem(ElemBlock, full1), elem(ElemLastBlock, last)), ErrElementType, nil},
		{"unknown type 0x04 in the middle", unsigned.buildElems(elem(ElemBlock, full0), elem(0x04, full1), elem(ElemLastBlock, last)), ErrElementType, nil},
		{"unknown type 0xff after last block", unsigned.buildElems(elem(ElemBlock, full0), elem(ElemBlock, full1), elem(ElemLastBlock, last), elem(0xff, nil)), ErrElementType, nil},
		{"unknown type 0x04 instead of trailer", signed.buildElems(elem(ElemBlock, sfull0), elem(ElemBlock, sfull1), elem(ElemLastBlock, slast), elem(0x04, tr)), ErrElementType, nil},
		{"bytes after trailer: one zero byte", append(signed.build(), 0), ErrElement, nil},
		{"bytes after trailer: a whole element", append(signed.build(), elem(ElemLastBlock, slast)...), ErrElement, nil},
		{"bytes after trailer: four bytes", append(signed.build(), 0, 0, 0, 0), ErrElement, nil},
		{"bytes after last block of unsigned file", append(unsigned.build(), 0, 0, 0, 0, 0), ErrElementType, nil},
		{"type byte only after last block", append(unsigned.build(), ElemTrailer), ErrTruncated, nil},
		{"trailer with empty payload", signed.buildElems(elem(ElemBlock, sfull0), elem(ElemBlock, sfull1), elem(ElemLastBlock, slast), elem(ElemTrailer, nil)), ErrTrailer, nil},
		{"0x01 block short", unsigned.buildElems(elem(ElemBlock, full0[:ChunkSize]), elem(ElemLastBlock, last)), ErrBlockSize, nil},
		{"0x01 block empty", unsigned.buildElems(elem(ElemBlock, nil), elem(ElemLastBlock, last)), ErrBlockSize, nil},
		{"0x02 block shorter than tag", unsigned.buildElems(elem(ElemBlock, full0), elem(ElemLastBlock, last[:TagSize-1])), ErrBlockSize, nil},
		{"0x02 block longer than full", unsigned.buildElems(elem(ElemLastBlock, append(append([]byte(nil), full0...), 0))), ErrBlockSize, nil},
		{"0x02 empty after 0x01", unsigned.buildElems(elem(ElemBlock, full0), elem(ElemLastBlock, make([]byte, TagSize))), ErrEmptyBlock, nil},
		{"phase 0 framing: no type bytes", unsigned.buildElems(u32(len(full0)), full0, u32(len(last)), last, u32(0)), ErrElementType, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Parse(tc.data)
			if err == nil {
				t.Fatalf("accepted: %+v", f.Header)
			}
			if !errors.Is(err, tc.err) && (tc.other == nil || !errors.Is(err, tc.other)) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if f != nil {
				t.Fatal("no file on error")
			}
			// Open must fail too and return nothing.
			for _, s := range []bool{false, true} {
				if pf, pt, err := Open(tc.data, openOpts(t, s)); err == nil || pf != nil || pt != nil {
					t.Fatalf("Open(signed=%v) accepted", s)
				}
			}
		})
	}
	// Sanity: the untouched sequences are accepted.
	for _, p := range []parts{unsigned, signed} {
		if _, err := Parse(p.build()); err != nil {
			t.Fatal(err)
		}
	}
}

// TestElementTypeMatchesNonceFlag: the type byte of a block element must
// agree with the last-block flag in the nonce the block was encrypted
// with. A block encrypted with flag 0x00 framed as ElemLastBlock, or one
// encrypted with flag 0x01 framed as ElemBlock, is structurally valid
// but fails authentication, so the file is rejected as a whole.
func TestElementTypeMatchesNonceFlag(t *testing.T) {
	// Exactly two full blocks: block 0 has flag 0x00, block 1 flag 0x01,
	// and both have the full size, so either can be framed either way.
	p := split(t, seal(t, testHeader(KindMail), pattern(2*ChunkSize), false))
	if len(p.blocks) != 2 || len(p.blocks[0]) != MaxBlockSize || len(p.blocks[1]) != MaxBlockSize {
		t.Fatal("expected two full blocks")
	}
	b0, b1 := p.blocks[0], p.blocks[1]
	cases := map[string][]byte{
		"flag 0x00 framed as 0x02":            p.buildElems(elem(ElemLastBlock, b0)),
		"flag 0x01 framed as 0x01, then 0x02": p.buildElems(elem(ElemBlock, b1), elem(ElemLastBlock, b1)),
		"both swapped":                        p.buildElems(elem(ElemBlock, b1), elem(ElemLastBlock, b0)),
		"flag 0x00 twice, second as 0x02":     p.buildElems(elem(ElemBlock, b0), elem(ElemLastBlock, b0)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err != nil {
				t.Fatalf("structure must be accepted, got %v", err)
			}
			mustFail(t, data, false, ErrDecrypt)
		})
	}
	// Untouched: accepted.
	if _, _, err := Open(p.buildElems(elem(ElemBlock, b0), elem(ElemLastBlock, b1)), openOpts(t, false)); err != nil {
		t.Fatal(err)
	}
}

// TestPhase0FilesRejected keeps the phase 0 vector files (format without
// element type bytes) as rejection cases: none of them parses under the
// version 1.1 framing.
func TestPhase0FilesRejected(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "phase0", "*.gml"))
	if err != nil || len(files) != 10 {
		t.Fatalf("expected ten phase 0 files, got %d (%v)", len(files), err)
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := Parse(data)
		if err == nil || f != nil {
			t.Fatalf("%s: phase 0 file accepted", name)
		}
		if !errors.Is(err, ErrElementType) && !errors.Is(err, ErrElement) && !errors.Is(err, ErrTruncated) && !errors.Is(err, ErrBlockSize) {
			t.Logf("%s: rejected with %v", name, err)
		}
	}
}

// TestFiveRecipients: the recipient section holds at most four entries
// (3.1, version 1.1), at Seal and at Parse.
func TestFiveRecipients(t *testing.T) {
	var recs []Recipient
	for i := 0; i < 5; i++ {
		r := testRecipient(t)
		r.Gen = uint32(i + 1)
		recs = append(recs, r)
	}
	if _, err := Seal(testHeader(KindMail), recs, []byte("x"), nil); !errors.Is(err, ErrRecipients) {
		t.Fatalf("Seal with five recipients: %v", err)
	}
	if _, err := Seal(testHeader(KindMail), recs[:4], []byte("x"), nil); err != nil {
		t.Fatalf("Seal with four recipients: %v", err)
	}
	// Parse: build a section with five entries by hand.
	data := seal(t, testHeader(KindMail), []byte("x"), false)
	f, _ := Parse(data)
	var entries []RecipientEntry
	for i := 0; i < 5; i++ {
		e := f.Recipients[0]
		e.Gen = uint32(i + 1)
		entries = append(entries, e)
	}
	five := fiveEntries(t, entries)
	p := split(t, data)
	if _, err := Parse(p.with(func(p *parts) { p.recipients = five }).build()); !errors.Is(err, ErrRecipients) {
		t.Fatalf("Parse with five entries: %v", err)
	}
	four, err := encodeRecipients(entries[:4])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(p.with(func(p *parts) { p.recipients = four }).build()); err != nil {
		t.Fatalf("Parse with four entries: %v", err)
	}
}
