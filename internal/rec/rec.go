// Package rec implements the canonical binary encoding of go-mail records
// as defined in section 3.6 of the specification.
//
// A record is the type string of its schema, a NUL byte, and a sequence of
// fields in strictly ascending field number. Every field is encoded as the
// field number (uint8), the length of the value (uint32, big endian) and
// the value itself. Integers have a fixed width and are big endian. Strings
// are UTF-8 in Normalization Form C without NUL bytes. A list is a field
// whose value is an element count (uint32) followed by the elements, each
// as a length (uint32) and an embedded record of the element schema.
//
// Encoding is driven by a Schema that fixes, per field number, the kind of
// value, whether it is required, and its size limits. The decoder accepts
// exactly one byte sequence per value: it rejects unknown or duplicated
// field numbers, fields out of order, wrong lengths, missing required
// fields, strings that are not NFC or contain NUL, and any trailing bytes.
// Decoding and re-encoding therefore always yields the identical bytes.
//
// Inputs to Decode are untrusted. All length and count fields are checked
// against the schema's limits and the remaining input before any memory is
// allocated, and no input causes a panic. The only panics in this package
// are those of MustSchema on a malformed schema, which is a programming
// error, not an input error.
package rec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Limits of the encoding. They bound memory allocation during decoding.
const (
	// MaxRecordSize is the largest encoded record Decode accepts.
	MaxRecordSize = 1 << 20
	// MaxValueLen is the largest value length a schema may allow for a
	// single Bytes or String field.
	MaxValueLen = MaxRecordSize
	// MaxTypeLen is the longest type string a schema may have.
	MaxTypeLen = 64
)

// Exported errors. Errors returned by this package wrap exactly one of
// them, so callers can use errors.Is. Error messages never contain field
// values.
var (
	ErrBadType       = errors.New("rec: wrong or malformed type string")
	ErrTruncated     = errors.New("rec: input ends inside a field")
	ErrFieldOrder    = errors.New("rec: field out of order or duplicated")
	ErrUnknownField  = errors.New("rec: unknown field number")
	ErrBadLength     = errors.New("rec: value has the wrong length")
	ErrTooLong       = errors.New("rec: value longer than the schema allows")
	ErrTooMany       = errors.New("rec: list has more elements than the schema allows")
	ErrMissingField  = errors.New("rec: required field missing")
	ErrBadString     = errors.New("rec: string is not valid UTF-8 or contains NUL")
	ErrNotNormalized = errors.New("rec: string is not in Unicode NFC")
	ErrKind          = errors.New("rec: value kind does not match the schema")
	ErrSchema        = errors.New("rec: invalid schema")
)

// Kind is the kind of value a field holds.
type Kind uint8

const (
	U8     Kind = 1 + iota // uint8, 1 byte
	U32                    // uint32, 4 bytes big endian
	I64                    // int64, 8 bytes big endian two's complement
	Bytes                  // byte string, fixed Size or variable up to MaxLen
	String                 // UTF-8 NFC without NUL, up to MaxLen bytes
	List                   // uint32 count, then elements of schema Elem
)

func (k Kind) String() string {
	switch k {
	case U8:
		return "u8"
	case U32:
		return "u32"
	case I64:
		return "i64"
	case Bytes:
		return "bytes"
	case String:
		return "string"
	case List:
		return "list"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Field describes one field of a schema.
type Field struct {
	Num      uint8   // field number, 1 to 255
	Name     string  // for documentation and error messages only
	Kind     Kind    // value kind
	Required bool    // a record without this field is invalid
	Size     int     // Bytes: fixed length in bytes; 0 for a variable length
	MaxLen   int     // Bytes (variable) and String: maximum length in bytes
	Elem     *Schema // List: schema of the elements
	MaxCount int     // List: maximum number of elements
}

// Schema fixes the type string and the fields of a record type. Build one
// with NewSchema or MustSchema; do not modify it afterwards.
type Schema struct {
	Type   string
	Fields []Field // sorted by Num
}

// NewSchema validates and returns a schema. Fields may be given in any
// order and are sorted by number.
func NewSchema(typ string, fields ...Field) (*Schema, error) {
	if typ == "" || len(typ) > MaxTypeLen {
		return nil, fmt.Errorf("%w: type string length %d", ErrSchema, len(typ))
	}
	for i := 0; i < len(typ); i++ {
		if c := typ[i]; c < 0x21 || c > 0x7e {
			return nil, fmt.Errorf("%w: type string must be printable ASCII without spaces", ErrSchema)
		}
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("%w: schema has no fields", ErrSchema)
	}
	fs := append([]Field(nil), fields...)
	sort.Slice(fs, func(i, j int) bool { return fs[i].Num < fs[j].Num })
	for i, f := range fs {
		if f.Num == 0 {
			return nil, fmt.Errorf("%w: field %q has number 0", ErrSchema, f.Name)
		}
		if i > 0 && fs[i-1].Num == f.Num {
			return nil, fmt.Errorf("%w: field number %d used twice", ErrSchema, f.Num)
		}
		if f.MaxLen < 0 || f.Size < 0 || f.MaxCount < 0 {
			return nil, fmt.Errorf("%w: field %d has a negative limit", ErrSchema, f.Num)
		}
		switch f.Kind {
		case U8, U32, I64:
			if f.Size != 0 || f.MaxLen != 0 || f.Elem != nil || f.MaxCount != 0 {
				return nil, fmt.Errorf("%w: field %d: integer kinds take no limits", ErrSchema, f.Num)
			}
		case Bytes:
			if (f.Size == 0) == (f.MaxLen == 0) {
				return nil, fmt.Errorf("%w: field %d: bytes need exactly one of Size and MaxLen", ErrSchema, f.Num)
			}
			if f.Size > MaxValueLen || f.MaxLen > MaxValueLen {
				return nil, fmt.Errorf("%w: field %d: limit exceeds MaxValueLen", ErrSchema, f.Num)
			}
			if f.Elem != nil || f.MaxCount != 0 {
				return nil, fmt.Errorf("%w: field %d: bytes take no list limits", ErrSchema, f.Num)
			}
		case String:
			if f.MaxLen == 0 || f.MaxLen > MaxValueLen || f.Size != 0 || f.Elem != nil || f.MaxCount != 0 {
				return nil, fmt.Errorf("%w: field %d: strings need MaxLen and nothing else", ErrSchema, f.Num)
			}
		case List:
			if f.Elem == nil || f.MaxCount == 0 || f.Size != 0 || f.MaxLen != 0 {
				return nil, fmt.Errorf("%w: field %d: lists need Elem and MaxCount and nothing else", ErrSchema, f.Num)
			}
		default:
			return nil, fmt.Errorf("%w: field %d has unknown kind %v", ErrSchema, f.Num, f.Kind)
		}
	}
	return &Schema{Type: typ, Fields: fs}, nil
}

// MustSchema is NewSchema for package-level schema variables; it panics on
// an invalid schema.
func MustSchema(typ string, fields ...Field) *Schema {
	s, err := NewSchema(typ, fields...)
	if err != nil {
		panic(err)
	}
	return s
}

func (s *Schema) field(num uint8) *Field {
	i := sort.Search(len(s.Fields), func(i int) bool { return s.Fields[i].Num >= num })
	if i < len(s.Fields) && s.Fields[i].Num == num {
		return &s.Fields[i]
	}
	return nil
}

// prefix returns the type string followed by NUL.
func (s *Schema) prefix() []byte {
	return append([]byte(s.Type), 0)
}

// minElemSize is the smallest possible encoding of an element of s: its
// length prefix, its type string and the NUL.
func (s *Schema) minElemSize() int {
	return 4 + len(s.Type) + 1
}

type value struct {
	num  uint8
	kind Kind
	u    uint64 // U8, U32 and I64 (as uint64)
	b    []byte // Bytes and String
	list []*Record
}

// Record is a record under construction or the result of Decode. Values
// are set with the Set methods and read with the typed getters.
type Record struct {
	schema *Schema
	vals   []value // in the order they were set; sorted by Encode
	err    error   // first error of a Set method
}

// New returns an empty record of schema s.
func New(s *Schema) *Record {
	if s == nil {
		return &Record{err: fmt.Errorf("%w: nil schema", ErrSchema)}
	}
	return &Record{schema: s}
}

// Schema returns the schema of r.
func (r *Record) Schema() *Schema {
	if r == nil {
		return nil
	}
	return r.schema
}

// Err returns the first error recorded by a Set method, if any.
func (r *Record) Err() error {
	if r == nil {
		return errors.New("rec: nil record")
	}
	return r.err
}

func (r *Record) set(num uint8, kind Kind, v value) *Record {
	if r == nil || r.err != nil {
		return r
	}
	f := r.schema.field(num)
	if f == nil {
		r.err = fmt.Errorf("%w: %d", ErrUnknownField, num)
		return r
	}
	if f.Kind != kind {
		r.err = fmt.Errorf("%w: field %d is %v, not %v", ErrKind, num, f.Kind, kind)
		return r
	}
	if r.lookup(num) != nil {
		r.err = fmt.Errorf("%w: field %d set twice", ErrFieldOrder, num)
		return r
	}
	if err := checkValue(f, &v); err != nil {
		r.err = err
		return r
	}
	v.num = num
	v.kind = kind
	r.vals = append(r.vals, v)
	return r
}

// checkValue validates a value against its field definition.
func checkValue(f *Field, v *value) error {
	switch f.Kind {
	case Bytes:
		if f.Size != 0 && len(v.b) != f.Size {
			return fmt.Errorf("%w: field %d needs %d bytes", ErrBadLength, f.Num, f.Size)
		}
		if f.Size == 0 && len(v.b) > f.MaxLen {
			return fmt.Errorf("%w: field %d", ErrTooLong, f.Num)
		}
	case String:
		if len(v.b) > f.MaxLen {
			return fmt.Errorf("%w: field %d", ErrTooLong, f.Num)
		}
		s := string(v.b)
		if strings.IndexByte(s, 0) >= 0 {
			return fmt.Errorf("%w: field %d", ErrBadString, f.Num)
		}
		if !isNFC(s) {
			if !validUTF8(s) {
				return fmt.Errorf("%w: field %d", ErrBadString, f.Num)
			}
			return fmt.Errorf("%w: field %d", ErrNotNormalized, f.Num)
		}
	case List:
		if len(v.list) > f.MaxCount {
			return fmt.Errorf("%w: field %d", ErrTooMany, f.Num)
		}
		for i, e := range v.list {
			if e == nil || e.schema != f.Elem {
				return fmt.Errorf("%w: field %d element %d is not of schema %q", ErrKind, f.Num, i, f.Elem.Type)
			}
		}
	}
	return nil
}

// SetU8 sets field num to v.
func (r *Record) SetU8(num uint8, v uint8) *Record {
	return r.set(num, U8, value{u: uint64(v)})
}

// SetU32 sets field num to v.
func (r *Record) SetU32(num uint8, v uint32) *Record {
	return r.set(num, U32, value{u: uint64(v)})
}

// SetI64 sets field num to v.
func (r *Record) SetI64(num uint8, v int64) *Record {
	return r.set(num, I64, value{u: uint64(v)})
}

// SetBytes sets field num to a copy of v. A nil v is an empty value.
func (r *Record) SetBytes(num uint8, v []byte) *Record {
	return r.set(num, Bytes, value{b: append([]byte{}, v...)})
}

// SetString sets field num to v, which must be NFC without NUL.
func (r *Record) SetString(num uint8, v string) *Record {
	return r.set(num, String, value{b: []byte(v)})
}

// SetList sets field num to the elements v, which must all be records of
// the element schema. The elements are validated when r is encoded.
func (r *Record) SetList(num uint8, v []*Record) *Record {
	return r.set(num, List, value{list: append([]*Record{}, v...)})
}

func (r *Record) lookup(num uint8) *value {
	if r == nil {
		return nil
	}
	for i := range r.vals {
		if r.vals[i].num == num {
			return &r.vals[i]
		}
	}
	return nil
}

func (r *Record) get(num uint8, kind Kind) *value {
	v := r.lookup(num)
	if v == nil || v.kind != kind {
		return nil
	}
	return v
}

// Has reports whether field num is present.
func (r *Record) Has(num uint8) bool { return r.lookup(num) != nil }

// U8 returns field num, or 0 if it is absent or of another kind.
func (r *Record) U8(num uint8) uint8 {
	if v := r.get(num, U8); v != nil {
		return uint8(v.u)
	}
	return 0
}

// U32 returns field num, or 0 if it is absent or of another kind.
func (r *Record) U32(num uint8) uint32 {
	if v := r.get(num, U32); v != nil {
		return uint32(v.u)
	}
	return 0
}

// I64 returns field num, or 0 if it is absent or of another kind.
func (r *Record) I64(num uint8) int64 {
	if v := r.get(num, I64); v != nil {
		return int64(v.u)
	}
	return 0
}

// Bytes returns a copy of field num, or nil if it is absent or of another
// kind. A present empty value yields a non-nil empty slice.
func (r *Record) Bytes(num uint8) []byte {
	if v := r.get(num, Bytes); v != nil {
		return append([]byte{}, v.b...)
	}
	return nil
}

// String returns field num, or "" if it is absent or of another kind.
func (r *Record) String(num uint8) string {
	if v := r.get(num, String); v != nil {
		return string(v.b)
	}
	return ""
}

// List returns the elements of field num, or nil if it is absent or of
// another kind. A present empty list yields a non-nil empty slice.
func (r *Record) List(num uint8) []*Record {
	if v := r.get(num, List); v != nil {
		return append([]*Record{}, v.list...)
	}
	return nil
}

// Encode returns the canonical encoding of r. It fails if a Set method
// failed, a required field is missing, or a list element is invalid.
func (r *Record) Encode() ([]byte, error) {
	if r == nil {
		return nil, errors.New("rec: nil record")
	}
	if r.err != nil {
		return nil, r.err
	}
	for _, f := range r.schema.Fields {
		if f.Required && r.lookup(f.Num) == nil {
			return nil, fmt.Errorf("%w: field %d (%s) of %q", ErrMissingField, f.Num, f.Name, r.schema.Type)
		}
	}
	vals := append([]value(nil), r.vals...)
	sort.Slice(vals, func(i, j int) bool { return vals[i].num < vals[j].num })
	out := r.schema.prefix()
	for _, v := range vals {
		var enc []byte
		switch v.kind {
		case U8:
			enc = []byte{uint8(v.u)}
		case U32:
			enc = binary.BigEndian.AppendUint32(nil, uint32(v.u))
		case I64:
			enc = binary.BigEndian.AppendUint64(nil, v.u)
		case Bytes, String:
			enc = v.b
		case List:
			f := r.schema.field(v.num)
			// Re-validate: elements may have changed since SetList.
			if err := checkValue(f, &v); err != nil {
				return nil, err
			}
			enc = binary.BigEndian.AppendUint32(nil, uint32(len(v.list)))
			for _, e := range v.list {
				eb, err := e.Encode()
				if err != nil {
					return nil, err
				}
				enc = binary.BigEndian.AppendUint32(enc, uint32(len(eb)))
				enc = append(enc, eb...)
			}
			if len(enc) > MaxValueLen {
				return nil, fmt.Errorf("%w: field %d", ErrTooLong, v.num)
			}
		}
		out = append(out, v.num)
		out = binary.BigEndian.AppendUint32(out, uint32(len(enc)))
		out = append(out, enc...)
	}
	if len(out) > MaxRecordSize {
		return nil, fmt.Errorf("%w: record exceeds MaxRecordSize", ErrTooLong)
	}
	return out, nil
}

// Decode parses data as a record of schema s. It is strict: any deviation
// from the canonical encoding is an error, and on error no record is
// returned. The returned record re-encodes to exactly data.
func Decode(s *Schema, data []byte) (*Record, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil schema", ErrSchema)
	}
	if len(data) > MaxRecordSize {
		return nil, fmt.Errorf("%w: input exceeds MaxRecordSize", ErrTooLong)
	}
	return decode(s, data)
}

func decode(s *Schema, data []byte) (*Record, error) {
	p := s.prefix()
	if len(data) < len(p) || string(data[:len(p)]) != string(p) {
		return nil, fmt.Errorf("%w: expected %q", ErrBadType, s.Type)
	}
	rest := data[len(p):]
	r := &Record{schema: s}
	last := 0 // number of the previous field; field numbers start at 1
	for len(rest) > 0 {
		if len(rest) < 5 {
			return nil, fmt.Errorf("%w: field header in %q", ErrTruncated, s.Type)
		}
		num := rest[0]
		n := binary.BigEndian.Uint32(rest[1:5])
		rest = rest[5:]
		if num == 0 {
			return nil, fmt.Errorf("%w: 0 in %q", ErrUnknownField, s.Type)
		}
		if int(num) <= last {
			return nil, fmt.Errorf("%w: field %d after %d in %q", ErrFieldOrder, num, last, s.Type)
		}
		last = int(num)
		f := s.field(num)
		if f == nil {
			return nil, fmt.Errorf("%w: %d in %q", ErrUnknownField, num, s.Type)
		}
		if uint64(n) > uint64(len(rest)) {
			return nil, fmt.Errorf("%w: field %d in %q", ErrTruncated, num, s.Type)
		}
		val := rest[:n]
		rest = rest[n:]
		v := value{num: num, kind: f.Kind}
		switch f.Kind {
		case U8:
			if n != 1 {
				return nil, fmt.Errorf("%w: field %d in %q", ErrBadLength, num, s.Type)
			}
			v.u = uint64(val[0])
		case U32:
			if n != 4 {
				return nil, fmt.Errorf("%w: field %d in %q", ErrBadLength, num, s.Type)
			}
			v.u = uint64(binary.BigEndian.Uint32(val))
		case I64:
			if n != 8 {
				return nil, fmt.Errorf("%w: field %d in %q", ErrBadLength, num, s.Type)
			}
			v.u = binary.BigEndian.Uint64(val)
		case Bytes, String:
			// checkValue enforces Size and MaxLen before the copy below;
			// val is already bounded by the input length.
			v.b = val
			if err := checkValue(f, &v); err != nil {
				return nil, err
			}
			v.b = append([]byte{}, val...)
		case List:
			list, err := decodeList(f, val)
			if err != nil {
				return nil, err
			}
			v.list = list
		}
		r.vals = append(r.vals, v)
	}
	for _, f := range s.Fields {
		if f.Required && r.lookup(f.Num) == nil {
			return nil, fmt.Errorf("%w: field %d (%s) of %q", ErrMissingField, f.Num, f.Name, s.Type)
		}
	}
	return r, nil
}

func decodeList(f *Field, val []byte) ([]*Record, error) {
	if len(val) < 4 {
		return nil, fmt.Errorf("%w: list field %d", ErrBadLength, f.Num)
	}
	count := binary.BigEndian.Uint32(val)
	val = val[4:]
	if uint64(count) > uint64(f.MaxCount) {
		return nil, fmt.Errorf("%w: list field %d", ErrTooMany, f.Num)
	}
	// Every element needs at least its length prefix and type string.
	if uint64(count)*uint64(f.Elem.minElemSize()) > uint64(len(val)) {
		return nil, fmt.Errorf("%w: list field %d", ErrTruncated, f.Num)
	}
	list := make([]*Record, 0, count)
	for i := uint32(0); i < count; i++ {
		if len(val) < 4 {
			return nil, fmt.Errorf("%w: list field %d element %d", ErrTruncated, f.Num, i)
		}
		n := binary.BigEndian.Uint32(val)
		val = val[4:]
		if uint64(n) > uint64(len(val)) {
			return nil, fmt.Errorf("%w: list field %d element %d", ErrTruncated, f.Num, i)
		}
		e, err := decode(f.Elem, val[:n])
		if err != nil {
			return nil, err
		}
		val = val[n:]
		list = append(list, e)
	}
	if len(val) != 0 {
		return nil, fmt.Errorf("%w: list field %d has trailing bytes", ErrBadLength, f.Num)
	}
	return list, nil
}
