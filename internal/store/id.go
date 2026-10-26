package store

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
)

// ID is a random 128-bit identifier (section 4: users, mailboxes,
// folders, mails, batches, invitations). Its text form is lowercase
// base32 without padding, 26 characters.
type ID [16]byte

// IDLen is the length of the text form of an ID.
const IDLen = 26

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ErrID reports a malformed ID.
var ErrID = errors.New("store: malformed id")

// NewID draws a random ID from r, or from crypto/rand if r is nil.
func NewID(r io.Reader) (ID, error) {
	if r == nil {
		r = rand.Reader
	}
	var id ID
	if _, err := io.ReadFull(r, id[:]); err != nil {
		return ID{}, fmt.Errorf("store: random id: %w", err)
	}
	return id, nil
}

// String returns the text form of the ID.
func (id ID) String() string { return idEncoding.EncodeToString(id[:]) }

// IsZero reports whether the ID is all zero.
func (id ID) IsZero() bool { return id == ID{} }

// ParseID parses the text form strictly: exactly 26 characters of the
// lowercase alphabet, and the canonical encoding (the unused low bits of
// the last character are zero). Every ID therefore has exactly one text
// form, and a text form can never name a path outside its directory.
func ParseID(s string) (ID, error) {
	if len(s) != IDLen {
		return ID{}, fmt.Errorf("%w: length %d", ErrID, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return ID{}, fmt.Errorf("%w: invalid character", ErrID)
		}
	}
	b, err := idEncoding.DecodeString(s)
	if err != nil || len(b) != 16 {
		return ID{}, fmt.Errorf("%w: not base32", ErrID)
	}
	var id ID
	copy(id[:], b)
	if id.String() != s {
		return ID{}, fmt.Errorf("%w: not canonical", ErrID)
	}
	return id, nil
}

// idFromBytes converts a 16-byte record field.
func idFromBytes(b []byte) ID {
	var id ID
	copy(id[:], b)
	return id
}
