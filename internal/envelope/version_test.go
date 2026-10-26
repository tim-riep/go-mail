package envelope

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/tim-riep/go-mail/internal/rec"
)

// rawHeader encodes a header record directly with package rec, bypassing
// the rule of Header.encode, so tests can build headers the writer
// refuses. version nil leaves field 8 out; otherwise it is written with
// the given value, whatever the kind.
func rawHeader(t testing.TB, h Header, version *uint32) []byte {
	t.Helper()
	r := rec.New(HeaderSchema).
		SetU8(1, uint8(h.Kind)).
		SetBytes(2, h.MailboxID[:]).
		SetU32(3, h.Epoch).
		SetBytes(4, h.FileID[:]).
		SetBytes(5, h.NoncePrefix[:]).
		SetU32(6, h.ChunkSize).
		SetI64(7, h.Created)
	if version != nil {
		r.SetU32(8, *version)
	}
	b, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func u32p(v uint32) *uint32 { return &v }

// hasField8 reports whether an encoded header record contains field 8.
func hasField8(t testing.TB, header []byte) bool {
	t.Helper()
	r, err := rec.Decode(HeaderSchema, header)
	if err != nil {
		t.Fatal(err)
	}
	return r.Has(8)
}

func isVersionError(err error) bool {
	return errors.Is(err, ErrHeader) && errors.Is(err, ErrHeaderVersion)
}

// TestHeaderVersionRule is the table test of 3.1 field 8 (version 1.4):
// required and at least 1 for kind meta, forbidden (even with the value
// 0) for every other kind, checked when writing (Seal and NewWriter) and
// when reading (Parse and Open).
//
// The Header struct cannot tell "field absent" from "field 0": for
// writing, Version 0 means absent. A meta header with Version 0 is
// therefore the writing case of both "meta without field 8" and "meta
// with 0", and a non-meta header with Version 0 is written without the
// field, so the writer can never produce "other kind with field 8 = 0".
// Reading covers all cases with headers built by rawHeader.
func TestHeaderVersionRule(t *testing.T) {
	type versionCase struct {
		name    string
		kind    Kind
		field   *uint32 // field 8 in the encoding; nil = absent
		version uint32  // Header.Version for writing
		ok      bool
	}
	cases := []versionCase{
		{"meta without field 8", KindMeta, nil, 0, false},
		{"meta with 0", KindMeta, u32p(0), 0, false},
		{"meta with 1", KindMeta, u32p(1), 1, true},
		{"meta with 2", KindMeta, u32p(2), 2, true},
		{"meta with MaxUint32", KindMeta, u32p(math.MaxUint32), math.MaxUint32, true},
	}
	for _, k := range []Kind{KindMail, KindPending, KindWrap, KindIndex} {
		cases = append(cases,
			versionCase{k.String() + " without field 8", k, nil, 0, true},
			versionCase{k.String() + " with 0", k, u32p(0), 0, false},
			versionCase{k.String() + " with 1", k, u32p(1), 1, false},
			versionCase{k.String() + " with MaxUint32", k, u32p(math.MaxUint32), math.MaxUint32, false},
		)
	}
	// A valid file whose header is replaced for the reading cases. The
	// header is part of the AAD, so a replaced header never decrypts;
	// what matters here is whether Parse accepts its structure.
	base := split(t, seal(t, testHeader(KindMail), []byte("x"), false))
	pt := []byte("version rule")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Writing.
			hdr := testHeader(tc.kind)
			hdr.Version = tc.version
			writeOK := tc.ok || (tc.kind != KindMeta && tc.version == 0)
			for _, signed := range []bool{false, true} {
				opts := &SealOptions{Rand: fixedRand(5)}
				if signed {
					opts.Signer = testSigner()
				}
				data, err := Seal(hdr, []Recipient{testRecipient(t)}, pt, opts)
				var buf bytes.Buffer
				w, werr := NewWriter(&buf, hdr, []Recipient{testRecipient(t)}, &SealOptions{Rand: fixedRand(5)})
				if !writeOK {
					if !isVersionError(err) || data != nil {
						t.Fatalf("Seal(signed=%v): expected ErrHeader and ErrHeaderVersion, got %v", signed, err)
					}
					if !isVersionError(werr) || w != nil || buf.Len() != 0 {
						t.Fatalf("NewWriter: expected ErrHeader and ErrHeaderVersion with nothing written, got %v (%d bytes)", werr, buf.Len())
					}
					continue
				}
				if err != nil || werr != nil {
					t.Fatalf("writing must succeed: Seal %v, NewWriter %v", err, werr)
				}
				f, err := Parse(data)
				if err != nil {
					t.Fatal(err)
				}
				if f.Header.Version != tc.version {
					t.Fatalf("version %d read back, want %d", f.Header.Version, tc.version)
				}
				if hasField8(t, f.headerBytes) != (tc.kind == KindMeta) {
					t.Fatal("field 8 must be written for kind meta and only for it")
				}
				got := mustOpen(t, data, signed)
				if !bytes.Equal(got, pt) {
					t.Fatal("plaintext differs")
				}
			}

			// Reading.
			h := hdr
			h.ChunkSize = ChunkSize
			raw := rawHeader(t, h, tc.field)
			data := base.with(func(p *parts) { p.header = raw }).build()
			f, err := Parse(data)
			if !tc.ok {
				if !isVersionError(err) || f != nil {
					t.Fatalf("Parse: expected ErrHeader and ErrHeaderVersion, got %v", err)
				}
				for _, signed := range []bool{false, true} {
					pf, got, err := Open(data, openOpts(t, signed))
					if !isVersionError(err) || pf != nil || got != nil {
						t.Fatalf("Open(signed=%v): expected ErrHeader and ErrHeaderVersion, got %v", signed, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if f.Header.Version != tc.version || !bytes.Equal(f.Bytes(), data) {
				t.Fatalf("version %d, re-serialization equal %v", f.Header.Version, bytes.Equal(f.Bytes(), data))
			}
		})
	}
}

// TestHeaderVersionEncoding pins the encoding of field 8: the last field
// of a meta header, "0x08 || uint32 length 4 || uint32 big endian".
func TestHeaderVersionEncoding(t *testing.T) {
	h := testHeader(KindMeta)
	h.ChunkSize = ChunkSize
	h.Version = 0x01020304
	withVersion, err := h.encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(withVersion, rawHeader(t, h, u32p(0x01020304))) {
		t.Fatal("encode differs from the record")
	}
	without := rawHeader(t, h, nil)
	want := append(append([]byte(nil), without...), 8, 0, 0, 0, 4, 1, 2, 3, 4)
	if !bytes.Equal(withVersion, want) {
		t.Fatalf("header %x, want %x", withVersion, want)
	}
	// Header.encode refuses what the writer refuses.
	h.Version = 0
	if _, err := h.encode(); !isVersionError(err) {
		t.Fatalf("meta with version 0: %v", err)
	}
	m := testHeader(KindMail)
	m.ChunkSize = ChunkSize
	m.Version = 1
	if _, err := m.encode(); !isVersionError(err) {
		t.Fatalf("mail with version: %v", err)
	}
}

// TestHeaderVersionTampered: a manipulated field 8 (any single bit) is
// rejected through the AAD, because the header is part of the AAD of the
// wrapping and of every block, and in addition through the signature,
// which covers every byte before the trailer. A flip that turns the
// version into 0 is already rejected by the parser.
func TestHeaderVersionTampered(t *testing.T) {
	const version = 0x80000001 // no single bit flip gives 0
	hdr := testHeader(KindMeta)
	hdr.Version = version
	pt := pattern(ChunkSize + 7)
	data, err := Seal(hdr, []Recipient{testRecipient(t)}, pt, &SealOptions{Rand: fixedRand(6), Signer: testSigner()})
	if err != nil {
		t.Fatal(err)
	}
	p := split(t, data)
	pub := ingestKey.Public().(ed25519.PublicKey)
	key := testRecipientKey(t)
	// Sanity: the untouched file passes both checks.
	f, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.VerifySignature(pub, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Decrypt(key); err != nil {
		t.Fatal(err)
	}
	// Field 8 is the last field: its value is the last four header bytes.
	vpos := len(p.header) - 4
	if binary.BigEndian.Uint32(p.header[vpos:]) != version {
		t.Fatal("field 8 is not where expected")
	}
	for bit := 0; bit < 32; bit++ {
		q := p.with(func(p *parts) {
			h := append([]byte(nil), p.header...)
			h[vpos+3-bit/8] ^= 1 << (bit % 8)
			p.header = h
		})
		mutated := q.build()
		f, err := Parse(mutated)
		if err != nil {
			t.Fatalf("bit %d: the structure must stay valid, got %v", bit, err)
		}
		if f.Header.Version != version^(1<<bit) {
			t.Fatalf("bit %d: version %#x", bit, f.Header.Version)
		}
		// Through the AAD, without looking at the signature.
		if got, err := f.Decrypt(key); !errors.Is(err, ErrUnwrap) || got != nil {
			t.Fatalf("bit %d: Decrypt: expected ErrUnwrap, got %v", bit, err)
		}
		// Through the signature, without decrypting.
		if err := f.VerifySignature(pub, nil); !errors.Is(err, ErrSignature) {
			t.Fatalf("bit %d: VerifySignature: expected ErrSignature, got %v", bit, err)
		}
		// Open checks the signature first.
		if pf, got, err := Open(mutated, openOpts(t, true)); !errors.Is(err, ErrSignature) || pf != nil || got != nil {
			t.Fatalf("bit %d: Open: expected ErrSignature, got %v", bit, err)
		}
		// The same flip in an unsigned meta file is caught by the AAD.
		if pf, got, err := Open(q.with(func(p *parts) { p.trailer = nil }).build(), openOpts(t, false)); !errors.Is(err, ErrUnwrap) || pf != nil || got != nil {
			t.Fatalf("bit %d: Open unsigned: expected ErrUnwrap, got %v", bit, err)
		}
	}
	// The block AAD binds the header as well: blocks of this file under
	// the header and recipients of a file that differs only in field 8
	// do not decrypt.
	other := hdr
	other.Version = version + 1
	od, err := Seal(other, []Recipient{testRecipient(t)}, pt, &SealOptions{Rand: fixedRand(6), Signer: testSigner()})
	if err != nil {
		t.Fatal(err)
	}
	op := split(t, od)
	mixed := op.with(func(q *parts) { q.blocks = p.blocks; q.trailer = nil }).build()
	if pf, got, err := Open(mixed, openOpts(t, false)); !errors.Is(err, ErrDecrypt) || pf != nil || got != nil {
		t.Fatalf("blocks under another version: expected ErrDecrypt, got %v", err)
	}
	// Version 1 with its lowest bit flipped is 0: rejected by the parser.
	one := split(t, seal(t, func() Header { h := testHeader(KindMeta); h.Version = 1; return h }(), []byte("x"), true))
	zero := one.with(func(p *parts) {
		h := append([]byte(nil), p.header...)
		h[len(h)-1] ^= 1
		p.header = h
	}).build()
	if f, err := Parse(zero); !isVersionError(err) || f != nil {
		t.Fatalf("version 0 after a bit flip: %v", err)
	}
}

// TestV12FilesRejected: the signed vector files of specification 1.2
// (kind meta without header field 8) are rejected by Parse and Open. Their
// headers are exactly the headers of the current signed vectors without
// field 8: the new vectors only append "0x08 || 4 || version".
func TestV12FilesRejected(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "v12", "*.gml"))
	if err != nil || len(files) != 5 {
		t.Fatalf("expected five version 1.2 files, got %d (%v)", len(files), err)
	}
	v := loadVectors(t)
	key, resolve := vectorKeys(t, v)
	current := map[string]int{}
	for i, fv := range v.Files {
		current[fv.File] = i
	}
	for _, name := range files {
		t.Run(filepath.Base(name), func(t *testing.T) {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if f, err := Parse(data); !isVersionError(err) || f != nil {
				t.Fatalf("Parse: expected ErrHeader and ErrHeaderVersion, got %v", err)
			}
			if f, pt, err := Open(data, OpenOptions{ExpectedSuite: Suite1, Key: key, ResolveSigner: resolve}); !isVersionError(err) || f != nil || pt != nil {
				t.Fatalf("Open: expected ErrHeader and ErrHeaderVersion, got %v", err)
			}
			// The old header record: kind meta, no field 8.
			n := binary.BigEndian.Uint32(data[6:10])
			oldHeader := data[10 : 10+n]
			r, err := rec.Decode(HeaderSchema, oldHeader)
			if err != nil {
				t.Fatal(err)
			}
			if Kind(r.U8(1)) != KindMeta || r.Has(8) {
				t.Fatal("expected a meta header without field 8")
			}
			i, ok := current[filepath.Base(name)]
			if !ok {
				t.Fatal("no current vector of the same name")
			}
			fv := v.Files[i]
			want := append(append([]byte(nil), oldHeader...), 8, 0, 0, 0, 4)
			want = binary.BigEndian.AppendUint32(want, fv.Version)
			if hex.EncodeToString(want) != fv.HeaderBytes {
				t.Fatal("the current header is not the old header with field 8 appended")
			}
		})
	}
}

// TestVectorSet: the ten vector files are exactly five unsigned mail
// files without field 8 and five signed meta files with a version.
func TestVectorSet(t *testing.T) {
	v := loadVectors(t)
	if len(v.Files) != 10 {
		t.Fatalf("expected ten vector files, got %d", len(v.Files))
	}
	signed, unsigned := 0, 0
	for _, fv := range v.Files {
		data, err := os.ReadFile(filepath.Join("testdata", fv.File))
		if err != nil {
			t.Fatal(err)
		}
		f, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", fv.File, err)
		}
		switch {
		case fv.Signed && f.Header.Kind == KindMeta && fv.Version >= 1 && hasField8(t, f.headerBytes):
			signed++
		case !fv.Signed && f.Header.Kind == KindMail && fv.Version == 0 && !hasField8(t, f.headerBytes):
			unsigned++
		default:
			t.Fatalf("%s: unexpected combination of kind %d, signed %v, version %d", fv.File, f.Header.Kind, fv.Signed, fv.Version)
		}
	}
	if signed != 5 || unsigned != 5 {
		t.Fatalf("%d signed, %d unsigned", signed, unsigned)
	}
}
