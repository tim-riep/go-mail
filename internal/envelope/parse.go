package envelope

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// File is a parsed .gml file. It holds its own copy of the bytes, so the
// caller may modify the input afterwards.
type File struct {
	Suite      Suite
	Header     Header
	Recipients []RecipientEntry
	Trailer    *Trailer // nil when the file is unsigned

	raw            []byte
	preamble       []byte   // raw[:6]
	headerBytes    []byte   // the header record
	recipientBytes []byte   // the recipient section record
	blocks         [][]byte // ciphertext of every block, in order; the last one is the ElemLastBlock
	recipientPos   int      // offset of the recipient section record in raw
	trailerOffset  int      // offset of the trailer element, or len(raw) when unsigned
	trailerBytes   []byte   // the trailer record, or nil
}

// Parse checks the structure of data and returns the parsed file. It
// needs no keys and verifies nothing cryptographic; see Decrypt and
// VerifySignature. On any deviation from the format it returns an error
// and no file.
//
// After the recipient section the file is a sequence of elements, each
// "type || uint32 length || payload" (3.1). Exactly the sequence
// ElemBlock* ElemLastBlock ElemTrailer? followed by the end of the file
// is accepted. Every ElemBlock is a full block; the ElemLastBlock may be
// shorter and is empty only when it is the only block (3.3, rules 3 to
// 7).
func Parse(data []byte) (*File, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(data))
	}
	if len(data) < PreambleSize {
		return nil, fmt.Errorf("%w: preamble", ErrTruncated)
	}
	if string(data[:4]) != Magic {
		return nil, ErrMagic
	}
	if data[4] != FormatVersion {
		return nil, fmt.Errorf("%w: %d", ErrVersion, data[4])
	}
	if Suite(data[5]) != Suite1 {
		return nil, fmt.Errorf("%w: suite %d", ErrSuite, data[5])
	}
	raw := append([]byte(nil), data...)
	f := &File{Suite: Suite1, raw: raw, preamble: raw[:PreambleSize]}
	pos := PreambleSize

	// Header.
	n, ok := readLen(raw, pos)
	if !ok {
		return nil, fmt.Errorf("%w: header length", ErrTruncated)
	}
	if n > MaxHeaderSize {
		return nil, fmt.Errorf("%w: %d", ErrHeaderSize, n)
	}
	if uint64(n) > uint64(len(raw)-pos-4) {
		return nil, fmt.Errorf("%w: header", ErrTruncated)
	}
	f.headerBytes = raw[pos+4 : pos+4+int(n)]
	hdr, err := decodeHeader(f.headerBytes)
	if err != nil {
		return nil, err
	}
	f.Header = hdr
	pos += 4 + int(n)

	// Recipient section.
	n, ok = readLen(raw, pos)
	if !ok {
		return nil, fmt.Errorf("%w: recipient section length", ErrTruncated)
	}
	if n > MaxRecipientsSize {
		return nil, fmt.Errorf("%w: %d", ErrRecipientsSize, n)
	}
	if uint64(n) > uint64(len(raw)-pos-4) {
		return nil, fmt.Errorf("%w: recipient section", ErrTruncated)
	}
	f.recipientPos = pos + 4
	f.recipientBytes = raw[pos+4 : pos+4+int(n)]
	f.Recipients, err = decodeRecipients(f.recipientBytes)
	if err != nil {
		return nil, err
	}
	pos += 4 + int(n)

	// Elements: ElemBlock* ElemLastBlock ElemTrailer? then end of file.
	// The type byte decides what an element is; the length never does.
	for pos < len(raw) {
		if f.trailerBytes != nil {
			return nil, fmt.Errorf("%w: data after the trailer", ErrElement)
		}
		typ := raw[pos]
		switch typ {
		case ElemBlock, ElemLastBlock:
			if f.lastSeen() {
				return nil, fmt.Errorf("%w: block after the last block", ErrElement)
			}
		case ElemTrailer:
			if !f.lastSeen() {
				return nil, fmt.Errorf("%w: trailer before the last block", ErrElement)
			}
		default:
			return nil, fmt.Errorf("%w: 0x%02x", ErrElementType, typ)
		}
		n, ok = readLen(raw, pos+1)
		if !ok {
			return nil, fmt.Errorf("%w: element length", ErrTruncated)
		}
		rest := uint64(len(raw) - pos - elemHeaderSize)
		if typ == ElemTrailer {
			if n > MaxTrailerSize {
				return nil, fmt.Errorf("%w: %d", ErrTrailerSize, n)
			}
			if uint64(n) > rest {
				return nil, fmt.Errorf("%w: trailer", ErrTruncated)
			}
			f.trailerBytes = raw[pos+elemHeaderSize : pos+elemHeaderSize+int(n)]
			f.Trailer, err = decodeTrailer(f.trailerBytes)
			if err != nil {
				return nil, err
			}
			pos += elemHeaderSize + int(n)
			continue
		}
		// A block element (3.3, rules 3 to 6).
		if n > MaxBlockSize || n < TagSize {
			return nil, fmt.Errorf("%w: block %d has %d bytes", ErrBlockSize, len(f.blocks), n)
		}
		if typ == ElemBlock && n != MaxBlockSize {
			return nil, fmt.Errorf("%w: block %d is not full but not last", ErrBlockSize, len(f.blocks))
		}
		if typ == ElemLastBlock && n == TagSize && len(f.blocks) > 0 {
			return nil, ErrEmptyBlock
		}
		if len(f.blocks) >= MaxBlocks {
			return nil, fmt.Errorf("%w: more than %d blocks", ErrTooLarge, MaxBlocks)
		}
		if uint64(n) > rest {
			return nil, fmt.Errorf("%w: block %d", ErrTruncated, len(f.blocks))
		}
		f.blocks = append(f.blocks, raw[pos+elemHeaderSize:pos+elemHeaderSize+int(n)])
		pos += elemHeaderSize + int(n)
		if typ == ElemLastBlock {
			f.trailerOffset = pos
		}
	}
	if !f.lastSeen() {
		return nil, fmt.Errorf("%w: last block is missing", ErrTruncated)
	}
	return f, nil
}

// lastSeen reports whether the ElemLastBlock has been parsed. It is set
// by recording where the trailer would start.
func (f *File) lastSeen() bool { return f.trailerOffset != 0 }

// readLen reads the uint32 length field at pos. The value stays unsigned
// until it has been checked against the limits: converting it to int
// first would turn values of 2^31 and above negative on 32-bit platforms
// and defeat the checks.
func readLen(raw []byte, pos int) (uint32, bool) {
	if pos < 0 || len(raw)-pos < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(raw[pos:]), true
}

// FileHash returns the SHA-256 over every byte of the file before the
// trailer element: the value signed in the trailer (3.4). For an
// unsigned file it covers the whole file.
func (f *File) FileHash() [sha256.Size]byte {
	return sha256.Sum256(f.raw[:f.trailerOffset])
}

// Bytes re-serializes the parsed structure. For a file accepted by Parse
// the result is identical to the input.
func (f *File) Bytes() []byte {
	hdr, err := f.Header.encode()
	if err != nil {
		return nil
	}
	recs, err := encodeRecipients(f.Recipients)
	if err != nil {
		return nil
	}
	out := make([]byte, 0, len(f.raw))
	out = append(out, Magic...)
	out = append(out, FormatVersion, byte(f.Suite))
	out = binary.BigEndian.AppendUint32(out, uint32(len(hdr)))
	out = append(out, hdr...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(recs)))
	out = append(out, recs...)
	for i, b := range f.blocks {
		typ := byte(ElemBlock)
		if i == len(f.blocks)-1 {
			typ = ElemLastBlock
		}
		out = append(out, element(typ, b)...)
	}
	if f.Trailer == nil {
		return out
	}
	tb, err := f.Trailer.encode()
	if err != nil {
		return nil
	}
	return append(out, element(ElemTrailer, tb)...)
}

// recipientRanges returns the byte ranges [start, end) of the value bytes
// of every recipient entry within the file. Used by tests.
func (f *File) recipientRanges() [][2]int {
	// RecipientsSchema: type string, NUL, field 1 header (5 bytes), count
	// (4 bytes), then per entry a 4-byte length and the entry.
	pos := f.recipientPos + len(RecipientsSchema.Type) + 1 + 5 + 4
	var out [][2]int
	for range f.Recipients {
		n, _ := readLen(f.raw, pos)
		out = append(out, [2]int{pos + 4, pos + 4 + int(n)})
		pos += 4 + int(n)
	}
	return out
}
