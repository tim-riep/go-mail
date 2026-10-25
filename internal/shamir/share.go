package shamir

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/tim-riep/go-mail/internal/keys"
)

// Share is one share of a split secret.
//
// Binary form (ShareSize bytes):
//
//	version    uint8   = 1
//	id         uint16  big endian, random, identical for all shares of a split
//	threshold  uint8   shares needed for reconstruction
//	index      uint8   x coordinate, 1..255
//	y          32 bytes
//
// Word form: the binary form followed by a 4-byte checksum, the first four
// bytes of SHA-256("gomail/v1/share" || 0x00 || binary form), is 328 bits
// and is written as 30 words of 11 bits from the BIP-39 English list; the
// two remaining bits are zero. The identifier lets a holder notice shares
// of different splits being mixed; the checksum catches transcription
// errors. Neither protects the secret: a share is as confidential as the
// seed it belongs to.
type Share struct {
	ID        uint16
	Threshold uint8
	Index     uint8
	Y         [SecretSize]byte
}

const (
	// ShareSize is the length of the binary form of a share.
	ShareSize = 1 + 2 + 1 + 1 + SecretSize
	// ShareWords is the number of words in the word form.
	ShareWords = 30

	shareVersion      = 1
	shareChecksumSize = 4
	shareChecksumAAD  = "gomail/v1/share"
)

func (s *Share) validate() error {
	if s == nil {
		return fmt.Errorf("%w: nil", ErrShare)
	}
	if s.Threshold < 2 {
		return fmt.Errorf("%w: threshold below 2", ErrShare)
	}
	if s.Index == 0 {
		return fmt.Errorf("%w: index 0", ErrShare)
	}
	return nil
}

// Bytes returns the binary form, or nil for a nil share.
func (s *Share) Bytes() []byte {
	if s == nil {
		return nil
	}
	b := make([]byte, 0, ShareSize)
	b = append(b, shareVersion)
	b = binary.BigEndian.AppendUint16(b, s.ID)
	b = append(b, s.Threshold, s.Index)
	return append(b, s.Y[:]...)
}

// ShareFromBytes parses the binary form.
func ShareFromBytes(b []byte) (*Share, error) {
	if len(b) != ShareSize {
		return nil, fmt.Errorf("%w: length %d", ErrShare, len(b))
	}
	if b[0] != shareVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrShare, b[0])
	}
	s := &Share{ID: binary.BigEndian.Uint16(b[1:3]), Threshold: b[3], Index: b[4]}
	copy(s.Y[:], b[5:])
	if err := s.validate(); err != nil {
		s.Zero()
		return nil, err
	}
	return s, nil
}

func checksum(payload []byte) []byte {
	h := sha256.New()
	h.Write([]byte(shareChecksumAAD))
	h.Write([]byte{0})
	h.Write(payload)
	return h.Sum(nil)[:shareChecksumSize]
}

// Words returns the word form, or nil for a nil share.
func (s *Share) Words() []string {
	if s == nil {
		return nil
	}
	payload := s.Bytes()
	bits := append(payload, checksum(payload)...)
	words := make([]string, ShareWords)
	for i := range words {
		w, _ := keys.Word(bitsAt(bits, i*11))
		words[i] = w
	}
	return words
}

// bitsAt returns the 11 bits of b starting at bit offset off (MSB first);
// bits beyond the end of b read as zero.
func bitsAt(b []byte, off int) int {
	var v int
	for i := 0; i < 11; i++ {
		bit := off + i
		var x int
		if bit/8 < len(b) {
			x = int(b[bit/8]>>(7-bit%8)) & 1
		}
		v = v<<1 | x
	}
	return v
}

// ShareFromWords parses the word form and verifies the checksum.
func ShareFromWords(words []string) (*Share, error) {
	if len(words) != ShareWords {
		return nil, fmt.Errorf("%w: got %d", ErrWordCount, len(words))
	}
	const total = ShareSize + shareChecksumSize
	var bits [total + 1]byte // 41 bytes of payload and checksum, 2 padding bits
	for i, w := range words {
		idx, ok := keys.LookupWord(w)
		if !ok {
			return nil, fmt.Errorf("%w: word %d", ErrUnknownWord, i+1)
		}
		for j := 0; j < 11; j++ {
			if idx>>(10-j)&1 == 1 {
				bit := i*11 + j
				bits[bit/8] |= 1 << (7 - bit%8)
			}
		}
	}
	if bits[total] != 0 {
		return nil, fmt.Errorf("%w: padding bits set", ErrChecksum)
	}
	payload := bits[:ShareSize]
	if subtle.ConstantTimeCompare(bits[ShareSize:total], checksum(payload)) != 1 {
		wipe(bits[:])
		return nil, ErrChecksum
	}
	s, err := ShareFromBytes(payload)
	wipe(bits[:])
	return s, err
}

// Zero overwrites the share.
func (s *Share) Zero() {
	if s == nil {
		return
	}
	*s = Share{}
}
