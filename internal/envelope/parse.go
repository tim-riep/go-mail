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
	blocks         [][]byte // ciphertext of every block, in order
	recipientPos   int      // offset of the recipient section record in raw
	trailerOffset  int      // offset of the trailer length field
	trailerBytes   []byte   // the trailer record, or nil
}

// Parse checks the structure of data and returns the parsed file. It
// needs no keys and verifies nothing cryptographic; see Decrypt and
// VerifySignature. On any deviation from the format it returns an error
// and no file.
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

	// Blocks, then the trailer. A length field whose value equals the
	// number of remaining bytes is the trailer length: a block is always
	// followed by at least the four bytes of the trailer length, so it can
	// never satisfy that condition. See DECISIONS.md on this rule.
	for {
		n, ok = readLen(raw, pos)
		if !ok {
			return nil, fmt.Errorf("%w: block or trailer length", ErrTruncated)
		}
		rest := uint64(len(raw) - pos - 4)
		if uint64(n) == rest {
			break
		}
		if uint64(n) > rest {
			return nil, fmt.Errorf("%w: block %d", ErrTruncated, len(f.blocks))
		}
		if n < TagSize || n > MaxBlockSize {
			return nil, fmt.Errorf("%w: block %d has %d bytes", ErrBlockSize, len(f.blocks), n)
		}
		if len(f.blocks) >= MaxBlocks {
			return nil, fmt.Errorf("%w: more than %d blocks", ErrTooLarge, MaxBlocks)
		}
		if k := len(f.blocks); k > 0 && len(f.blocks[k-1]) != MaxBlockSize {
			return nil, fmt.Errorf("%w: block %d is short but not last", ErrBlockSize, k-1)
		}
		f.blocks = append(f.blocks, raw[pos+4:pos+4+int(n)])
		pos += 4 + int(n)
	}
	if len(f.blocks) == 0 {
		return nil, ErrNoBlocks
	}
	if k := len(f.blocks); k > 1 && len(f.blocks[k-1]) == TagSize {
		return nil, ErrEmptyBlock
	}
	f.trailerOffset = pos
	if n > MaxTrailerSize {
		return nil, fmt.Errorf("%w: %d", ErrTrailerSize, n)
	}
	if n > 0 {
		f.trailerBytes = raw[pos+4 : pos+4+int(n)]
		f.Trailer, err = decodeTrailer(f.trailerBytes)
		if err != nil {
			return nil, err
		}
	}
	return f, nil
}

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

// FileHash returns the SHA-256 over the file up to the trailer length
// field: the value signed in the trailer.
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
	for _, b := range f.blocks {
		out = binary.BigEndian.AppendUint32(out, uint32(len(b)))
		out = append(out, b...)
	}
	if f.Trailer == nil {
		return append(out, 0, 0, 0, 0)
	}
	tb, err := f.Trailer.encode()
	if err != nil {
		return nil
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(tb)))
	return append(out, tb...)
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
