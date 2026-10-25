package rec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// testSchema covers every field kind once. It is the schema used by the
// negative tests below and by the fuzz target.
var (
	elemSchema = MustSchema("gomail/test/elem",
		Field{Num: 1, Name: "x", Kind: U32, Required: true},
		Field{Num: 2, Name: "name", Kind: String, MaxLen: 64},
	)
	testSchema = MustSchema("gomail/test/all",
		Field{Num: 1, Name: "u8", Kind: U8, Required: true},
		Field{Num: 2, Name: "u32", Kind: U32, Required: true},
		Field{Num: 3, Name: "i64", Kind: I64, Required: true},
		Field{Num: 4, Name: "fixed", Kind: Bytes, Size: 4, Required: true},
		Field{Num: 5, Name: "var", Kind: Bytes, MaxLen: 16},
		Field{Num: 6, Name: "str", Kind: String, MaxLen: 32},
		Field{Num: 7, Name: "list", Kind: List, Elem: elemSchema, MaxCount: 3},
		Field{Num: 9, Name: "opt", Kind: U8},
	)
)

func fullRecord(t testing.TB) *Record {
	t.Helper()
	e1 := New(elemSchema).SetU32(1, 7).SetString(2, "sieben")
	e2 := New(elemSchema).SetU32(1, 8)
	r := New(testSchema).
		SetU8(1, 0xab).
		SetU32(2, 0xdeadbeef).
		SetI64(3, -2).
		SetBytes(4, []byte{1, 2, 3, 4}).
		SetBytes(5, []byte("var")).
		SetString(6, "Grüße").
		SetList(7, []*Record{e1, e2}).
		SetU8(9, 1)
	if err := r.Err(); err != nil {
		t.Fatalf("building record: %v", err)
	}
	return r
}

func mustEncode(t testing.TB, r *Record) []byte {
	t.Helper()
	b, err := r.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

// field builds one raw field for hand-made encodings.
func field(num uint8, value []byte) []byte {
	out := []byte{num}
	out = binary.BigEndian.AppendUint32(out, uint32(len(value)))
	return append(out, value...)
}

func prefix(s *Schema) []byte {
	return append([]byte(s.Type), 0)
}

// minimal is a hand-built valid encoding with only the required fields.
func minimal() []byte {
	b := prefix(testSchema)
	b = append(b, field(1, []byte{1})...)
	b = append(b, field(2, []byte{0, 0, 0, 2})...)
	b = append(b, field(3, []byte{0, 0, 0, 0, 0, 0, 0, 3})...)
	b = append(b, field(4, []byte{4, 4, 4, 4})...)
	return b
}

func TestRoundTrip(t *testing.T) {
	r := fullRecord(t)
	enc := mustEncode(t, r)
	dec, err := Decode(testSchema, enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	enc2, err := dec.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(enc, enc2) {
		t.Fatalf("re-encoding differs:\n%x\n%x", enc, enc2)
	}
	if dec.U8(1) != 0xab || dec.U32(2) != 0xdeadbeef || dec.I64(3) != -2 {
		t.Fatal("integer values differ")
	}
	if !bytes.Equal(dec.Bytes(4), []byte{1, 2, 3, 4}) || !bytes.Equal(dec.Bytes(5), []byte("var")) {
		t.Fatal("byte values differ")
	}
	if dec.String(6) != "Grüße" {
		t.Fatal("string differs")
	}
	l := dec.List(7)
	if len(l) != 2 || l[0].U32(1) != 7 || l[0].String(2) != "sieben" || l[1].U32(1) != 8 || l[1].Has(2) {
		t.Fatal("list differs")
	}
	if !dec.Has(9) || dec.U8(9) != 1 || dec.Has(8) {
		t.Fatal("optional field handling wrong")
	}
}

func TestMinimalRoundTrip(t *testing.T) {
	enc := minimal()
	dec, err := Decode(testSchema, enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if dec.Has(5) || dec.Has(6) || dec.Has(7) || dec.Has(9) {
		t.Fatal("absent optional fields reported present")
	}
	if dec.List(7) != nil || dec.Bytes(5) != nil || dec.String(6) != "" {
		t.Fatal("absent fields must read as zero values")
	}
	enc2 := mustEncode(t, dec)
	if !bytes.Equal(enc, enc2) {
		t.Fatal("hand-built encoding does not round-trip")
	}
}

func TestEncodingLayout(t *testing.T) {
	// The layout must match the specification exactly: type string, NUL,
	// then (num, u32 BE length, value) per field in ascending order.
	r := New(elemSchema).SetU32(1, 0x01020304).SetString(2, "ab")
	got := mustEncode(t, r)
	want := []byte("gomail/test/elem\x00" +
		"\x01\x00\x00\x00\x04\x01\x02\x03\x04" +
		"\x02\x00\x00\x00\x02ab")
	if !bytes.Equal(got, want) {
		t.Fatalf("layout mismatch:\n got %x\nwant %x", got, want)
	}
	// A list is count || (len || element)*.
	lst := New(testSchema).SetU8(1, 0).SetU32(2, 0).SetI64(3, 0).SetBytes(4, make([]byte, 4)).
		SetList(7, []*Record{New(elemSchema).SetU32(1, 1)})
	got = mustEncode(t, lst)
	elem := []byte("gomail/test/elem\x00\x01\x00\x00\x00\x04\x00\x00\x00\x01")
	wantList := []byte{0, 0, 0, 1}
	wantList = binary.BigEndian.AppendUint32(wantList, uint32(len(elem)))
	wantList = append(wantList, elem...)
	if !bytes.HasSuffix(got, field(7, wantList)) {
		t.Fatalf("list layout mismatch: %x", got)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		err  error
	}{
		{"empty", nil, ErrBadType},
		{"wrong type", append([]byte("gomail/test/other\x00"), minimal()[len(prefix(testSchema)):]...), ErrBadType},
		{"missing NUL after type", []byte("gomail/test/all"), ErrBadType},
		{"type prefix only, required missing", prefix(testSchema), ErrMissingField},
		{"truncated field header", append(minimal(), 9, 0, 0), ErrTruncated},
		{"length exceeds data", append(minimal(), 9, 0, 0, 0, 2, 1), ErrTruncated},
		{"duplicate field", append(minimal(), field(4, []byte{1, 2, 3, 4})...), ErrFieldOrder},
		{"descending order", func() []byte {
			b := prefix(testSchema)
			b = append(b, field(2, []byte{0, 0, 0, 2})...)
			b = append(b, field(1, []byte{1})...)
			b = append(b, field(3, make([]byte, 8))...)
			b = append(b, field(4, make([]byte, 4))...)
			return b
		}(), ErrFieldOrder},
		{"unknown field number", append(minimal(), field(8, []byte{1})...), ErrUnknownField},
		{"field number zero", append(minimal(), field(0, []byte{1})...), ErrUnknownField},
		{"u8 wrong length", func() []byte {
			b := prefix(testSchema)
			b = append(b, field(1, []byte{1, 1})...)
			return b
		}(), ErrBadLength},
		{"u32 wrong length", func() []byte {
			b := prefix(testSchema)
			b = append(b, field(1, []byte{1})...)
			b = append(b, field(2, []byte{0, 2})...)
			return b
		}(), ErrBadLength},
		{"i64 wrong length", func() []byte {
			b := prefix(testSchema)
			b = append(b, field(1, []byte{1})...)
			b = append(b, field(2, []byte{0, 0, 0, 2})...)
			b = append(b, field(3, make([]byte, 9))...)
			return b
		}(), ErrBadLength},
		{"fixed bytes wrong length", func() []byte {
			b := prefix(testSchema)
			b = append(b, field(1, []byte{1})...)
			b = append(b, field(2, []byte{0, 0, 0, 2})...)
			b = append(b, field(3, make([]byte, 8))...)
			b = append(b, field(4, make([]byte, 3))...)
			return b
		}(), ErrBadLength},
		{"variable bytes too long", append(minimal(), field(5, make([]byte, 17))...), ErrTooLong},
		{"string too long", append(minimal(), field(6, bytes.Repeat([]byte("a"), 33))...), ErrTooLong},
		{"string invalid utf8", append(minimal(), field(6, []byte{0xff, 0xfe})...), ErrBadString},
		{"string overlong utf8", append(minimal(), field(6, []byte{0xc0, 0x80})...), ErrBadString},
		{"string surrogate", append(minimal(), field(6, []byte{0xed, 0xa0, 0x80})...), ErrBadString},
		{"string with NUL", append(minimal(), field(6, []byte("a\x00b"))...), ErrBadString},
		{"string not NFC (decomposed e-acute)", append(minimal(), field(6, []byte(rs('e', 0x0301)))...), ErrNotNormalized},
		{"string not NFC (singleton)", append(minimal(), field(6, []byte(rs(0x212b)))...), ErrNotNormalized},
		{"string not NFC (hangul jamo)", append(minimal(), field(6, []byte(rs(0x1100, 0x1161)))...), ErrNotNormalized},
		{"list count exceeds max", append(minimal(), field(7, []byte{0, 0, 0, 4})...), ErrTooMany},
		{"list count exceeds data", append(minimal(), field(7, []byte{0, 0, 0, 1})...), ErrTruncated},
		{"list value shorter than count", append(minimal(), field(7, []byte{0, 0})...), ErrBadLength},
		{"list count mismatch (count 2, one element)", func() []byte {
			elem := mustEncode(t, New(elemSchema).SetU32(1, 1))
			v := []byte{0, 0, 0, 2}
			v = binary.BigEndian.AppendUint32(v, uint32(len(elem)))
			v = append(v, elem...)
			return append(minimal(), field(7, v)...)
		}(), ErrTruncated},
		{"list trailing bytes after elements", func() []byte {
			elem := mustEncode(t, New(elemSchema).SetU32(1, 1))
			v := []byte{0, 0, 0, 1}
			v = binary.BigEndian.AppendUint32(v, uint32(len(elem)))
			v = append(v, elem...)
			v = append(v, 0)
			return append(minimal(), field(7, v)...)
		}(), ErrBadLength},
		{"list element length exceeds list", func() []byte {
			v := []byte{0, 0, 0, 1, 0, 0, 1, 0, 'x'}
			return append(minimal(), field(7, v)...)
		}(), ErrTruncated},
		{"list element wrong type", func() []byte {
			elem := mustEncode(t, New(elemSchema).SetU32(1, 1))
			elem[0] = 'G'
			v := []byte{0, 0, 0, 1}
			v = binary.BigEndian.AppendUint32(v, uint32(len(elem)))
			v = append(v, elem...)
			return append(minimal(), field(7, v)...)
		}(), ErrBadType},
		{"list element missing required", func() []byte {
			elem := prefix(elemSchema)
			v := []byte{0, 0, 0, 1}
			v = binary.BigEndian.AppendUint32(v, uint32(len(elem)))
			v = append(v, elem...)
			return append(minimal(), field(7, v)...)
		}(), ErrMissingField},
		{"list element with trailing garbage inside its length", func() []byte {
			elem := mustEncode(t, New(elemSchema).SetU32(1, 1))
			elem = append(elem, 0)
			v := []byte{0, 0, 0, 1}
			v = binary.BigEndian.AppendUint32(v, uint32(len(elem)))
			v = append(v, elem...)
			return append(minimal(), field(7, v)...)
		}(), ErrTruncated},
		{"list element length zero", func() []byte {
			v := []byte{0, 0, 0, 1, 0, 0, 0, 0}
			v = append(v, make([]byte, 40)...) // enough bytes for one element
			return append(minimal(), field(7, v)...)
		}(), ErrBadType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Decode(testSchema, tc.data)
			if err == nil {
				t.Fatalf("expected error %v, got record %v", tc.err, r)
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if r != nil {
				t.Fatal("decoder must not return a partial record on error")
			}
		})
	}
}

func TestEncodeRejects(t *testing.T) {
	base := func() *Record {
		return New(testSchema).SetU8(1, 1).SetU32(2, 2).SetI64(3, 3).SetBytes(4, []byte{1, 2, 3, 4})
	}
	cases := []struct {
		name string
		r    *Record
		err  error
	}{
		{"missing required", New(testSchema).SetU8(1, 1), ErrMissingField},
		{"unknown field", base().SetU8(8, 1), ErrUnknownField},
		{"wrong kind", base().SetU32(1, 1), ErrKind},
		{"set twice", base().SetU8(1, 2), ErrFieldOrder},
		{"fixed size wrong", New(testSchema).SetU8(1, 1).SetU32(2, 2).SetI64(3, 3).SetBytes(4, []byte{1}), ErrBadLength},
		{"variable too long", base().SetBytes(5, make([]byte, 17)), ErrTooLong},
		{"string too long", base().SetString(6, strings.Repeat("ä", 17)), ErrTooLong},
		{"string NUL", base().SetString(6, "a\x00"), ErrBadString},
		{"string invalid utf8", base().SetString(6, "\xff"), ErrBadString},
		{"string not NFC", base().SetString(6, rs('a', 0x0301)), ErrNotNormalized},
		{"list too many", base().SetList(7, []*Record{New(elemSchema).SetU32(1, 1), New(elemSchema).SetU32(1, 1), New(elemSchema).SetU32(1, 1), New(elemSchema).SetU32(1, 1)}), ErrTooMany},
		{"list wrong element schema", base().SetList(7, []*Record{New(testSchema)}), ErrKind},
		{"list element invalid", base().SetList(7, []*Record{New(elemSchema)}), ErrMissingField},
		{"list nil element", base().SetList(7, []*Record{nil}), ErrKind},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.r.Encode()
			if err == nil {
				t.Fatalf("expected %v, got %x", tc.err, b)
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if b != nil {
				t.Fatal("no bytes on error")
			}
		})
	}
}

func TestOptionalStringAndBytesEmpty(t *testing.T) {
	// Empty but present optional values are encoded as zero-length fields
	// and must survive a round trip as "present".
	r := New(testSchema).SetU8(1, 1).SetU32(2, 2).SetI64(3, 3).SetBytes(4, []byte{1, 2, 3, 4}).
		SetBytes(5, []byte{}).SetString(6, "").SetList(7, nil)
	enc := mustEncode(t, r)
	dec, err := Decode(testSchema, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Has(5) || !dec.Has(6) || !dec.Has(7) {
		t.Fatal("empty optional values must be present after decoding")
	}
	if len(dec.List(7)) != 0 || len(dec.Bytes(5)) != 0 || dec.String(6) != "" {
		t.Fatal("empty values differ")
	}
	if !bytes.Equal(mustEncode(t, dec), enc) {
		t.Fatal("round trip differs")
	}
}

func TestGettersOnAbsentOrWrongKind(t *testing.T) {
	dec, err := Decode(testSchema, minimal())
	if err != nil {
		t.Fatal(err)
	}
	// Absent fields read as zero values, never panic.
	if dec.U8(9) != 0 || dec.U32(9) != 0 || dec.I64(9) != 0 || dec.Bytes(9) != nil || dec.String(9) != "" || dec.List(9) != nil {
		t.Fatal("absent fields must read as zero values")
	}
	// Reading a present field with the wrong getter is a programming
	// error; it also yields the zero value instead of a foreign value.
	if dec.U32(1) != 0 || dec.String(1) != "" {
		t.Fatal("wrong-kind getter must return zero value")
	}
	// Bytes returns a copy; mutating it must not change the record.
	b := dec.Bytes(4)
	b[0] = 99
	if dec.Bytes(4)[0] == 99 {
		t.Fatal("Bytes must return a copy")
	}
}

func TestSchemaValidation(t *testing.T) {
	bad := []struct {
		name   string
		typ    string
		fields []Field
	}{
		{"empty type", "", []Field{{Num: 1, Kind: U8}}},
		{"NUL in type", "a\x00b", []Field{{Num: 1, Kind: U8}}},
		{"non-ascii type", "gomail/ä", []Field{{Num: 1, Kind: U8}}},
		{"field num zero", "t", []Field{{Num: 0, Kind: U8}}},
		{"duplicate num", "t", []Field{{Num: 1, Kind: U8}, {Num: 1, Kind: U8}}},
		{"unknown kind", "t", []Field{{Num: 1, Kind: Kind(99)}}},
		{"bytes without size or max", "t", []Field{{Num: 1, Kind: Bytes}}},
		{"bytes with size and max", "t", []Field{{Num: 1, Kind: Bytes, Size: 1, MaxLen: 1}}},
		{"string without max", "t", []Field{{Num: 1, Kind: String}}},
		{"list without elem", "t", []Field{{Num: 1, Kind: List, MaxCount: 1}}},
		{"list without max count", "t", []Field{{Num: 1, Kind: List, Elem: elemSchema}}},
		{"u8 with size", "t", []Field{{Num: 1, Kind: U8, Size: 1}}},
		{"max len too large", "t", []Field{{Num: 1, Kind: Bytes, MaxLen: MaxValueLen + 1}}},
		{"fixed size too large", "t", []Field{{Num: 1, Kind: Bytes, Size: MaxValueLen + 1}}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSchema(tc.typ, tc.fields...); err == nil {
				t.Fatal("expected schema error")
			}
			defer func() {
				if recover() == nil {
					t.Fatal("MustSchema must panic on an invalid schema")
				}
			}()
			MustSchema(tc.typ, tc.fields...)
		})
	}
	// Fields may be given in any order; they are sorted by number.
	s, err := NewSchema("t", Field{Num: 2, Kind: U8}, Field{Num: 1, Kind: U8})
	if err != nil {
		t.Fatal(err)
	}
	if s.Fields[0].Num != 1 {
		t.Fatal("fields must be sorted")
	}
}

func TestDecodeSizeLimit(t *testing.T) {
	big := make([]byte, MaxRecordSize+1)
	if _, err := Decode(testSchema, big); !errors.Is(err, ErrTooLong) {
		t.Fatalf("oversized input must be rejected before parsing, got %v", err)
	}
}

func TestNilRecord(t *testing.T) {
	var r *Record
	if r.Has(1) || r.U8(1) != 0 || r.Bytes(1) != nil || r.List(1) != nil || r.Err() == nil {
		t.Fatal("nil record must be inert")
	}
	if _, err := r.Encode(); err == nil {
		t.Fatal("nil record must not encode")
	}
}

func TestMiscAccessors(t *testing.T) {
	r := New(testSchema)
	if r.Schema() != testSchema {
		t.Fatal("Schema()")
	}
	var nilRec *Record
	if nilRec.Schema() != nil {
		t.Fatal("nil Schema()")
	}
	if New(nil).Err() == nil {
		t.Fatal("New(nil) must record an error")
	}
	if _, err := Decode(nil, nil); !errors.Is(err, ErrSchema) {
		t.Fatal("Decode with nil schema")
	}
	for k, name := range map[Kind]string{U8: "u8", U32: "u32", I64: "i64", Bytes: "bytes", String: "string", List: "list", Kind(0): "kind(0)"} {
		if k.String() != name {
			t.Fatalf("%v", k)
		}
	}
	if _, err := NewSchema("t"); err == nil {
		t.Fatal("schema without fields")
	}
	if _, err := NewSchema("t", Field{Num: 1, Kind: U8, MaxLen: -1}); err == nil {
		t.Fatal("negative limit")
	}
	if _, err := NewSchema("t", Field{Num: 1, Kind: Bytes, Size: 1, Elem: elemSchema}); err == nil {
		t.Fatal("bytes with elem")
	}
	if _, err := NewSchema("t", Field{Num: 1, Kind: U8, Elem: elemSchema}); err == nil {
		t.Fatal("u8 with elem")
	}
	long := strings.Repeat("a", MaxTypeLen+1)
	if _, err := NewSchema(long, Field{Num: 1, Kind: U8}); err == nil {
		t.Fatal("type too long")
	}
}

func TestDecodeListElementTruncation(t *testing.T) {
	// A first element large enough to pass the minimum-size estimate, then
	// a second element whose length field is missing or lies.
	big := mustEncode(t, New(elemSchema).SetU32(1, 1).SetString(2, strings.Repeat("x", 60)))
	v := []byte{0, 0, 0, 2}
	v = binary.BigEndian.AppendUint32(v, uint32(len(big)))
	v = append(v, big...)
	short := append(append([]byte(nil), v...), 1, 2, 3) // 3 bytes: no length field
	if _, err := Decode(testSchema, append(minimal(), field(7, short)...)); !errors.Is(err, ErrTruncated) {
		t.Fatalf("missing element length: %v", err)
	}
	lying := append(append([]byte(nil), v...), 0, 0, 1, 0, 'x') // claims 256 bytes
	if _, err := Decode(testSchema, append(minimal(), field(7, lying)...)); !errors.Is(err, ErrTruncated) {
		t.Fatalf("lying element length: %v", err)
	}
}

func TestEncodeSizeLimits(t *testing.T) {
	bigElem := MustSchema("gomail/test/big", Field{Num: 1, Kind: Bytes, MaxLen: MaxValueLen})
	s := MustSchema("gomail/test/biglist", Field{Num: 1, Kind: List, Elem: bigElem, MaxCount: 3})
	half := make([]byte, MaxValueLen/2+100)
	r := New(s).SetList(1, []*Record{New(bigElem).SetBytes(1, half), New(bigElem).SetBytes(1, half)})
	if _, err := r.Encode(); !errors.Is(err, ErrTooLong) {
		t.Fatalf("list value above MaxValueLen: %v", err)
	}
	two := MustSchema("gomail/test/two", Field{Num: 1, Kind: Bytes, MaxLen: MaxValueLen}, Field{Num: 2, Kind: Bytes, MaxLen: MaxValueLen})
	r2 := New(two).SetBytes(1, half).SetBytes(2, half)
	if _, err := r2.Encode(); !errors.Is(err, ErrTooLong) {
		t.Fatalf("record above MaxRecordSize: %v", err)
	}
}

func TestSetOnNilAndFailedRecord(t *testing.T) {
	var r *Record
	if r.SetU8(1, 1) != nil {
		t.Fatal("Set on nil must return nil")
	}
	f := New(testSchema).SetU8(8, 1) // unknown field: sticky error
	f.SetU8(1, 1)
	if _, err := f.Encode(); !errors.Is(err, ErrUnknownField) {
		t.Fatal("first error must stick")
	}
}
