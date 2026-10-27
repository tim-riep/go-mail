package store

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
)

// MaxOrigin bounds the origin of a checkpoint and of a pin (the name of
// the log, translog.MaxOrigin).
const MaxOrigin = 128

// MaxCheckpointSize bounds the tree size of a checkpoint
// (translog.MaxTreeSize); the smallest is 1.
const MaxCheckpointSize int64 = 1 << 40

// CheckpointSchema is mailboxes/<id>/checkpoints/<user-id>-<device-id>.rec
// (2.7 "Abgleich zwischen Clients", section 4): the tree head a device of
// a member saw last, signed by the member's identity under the short name
// "checkpoint" (3.7) over the record without field 8. Fields: user,
// device, origin of the log, tree size, root hash, time of the head in
// milliseconds, generation of the identity. What the fields mean for the
// log is fixed by task 03; store fixes format and bounds only.
var CheckpointSchema = rec.MustSchema("gomail/v1/rec/checkpoint",
	id16(1, "user_id", true),
	id16(2, "device_id", true),
	rec.Field{Num: 3, Name: "origin", Kind: rec.String, MaxLen: MaxOrigin, Required: true},
	rec.Field{Num: 4, Name: "size", Kind: rec.I64, Required: true},
	bytes32(5, "root_hash", true),
	rec.Field{Num: 6, Name: "head_time", Kind: rec.I64, Required: true},
	rec.Field{Num: 7, Name: "user_gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 8, Name: "sig", Kind: rec.Bytes, Size: ed25519.SignatureSize},
)

// Checkpoint is a decoded client checkpoint.
type Checkpoint struct {
	UserID   ID
	DeviceID ID
	Origin   string
	Size     int64 // tree size
	RootHash [32]byte
	HeadTime int64 // milliseconds since 1970 UTC
	UserGen  uint32
	// Signature by the identity of generation UserGen under "checkpoint".
	Signature []byte
}

func (c *Checkpoint) check() error {
	switch {
	case c.UserID.IsZero() || c.DeviceID.IsZero() || c.UserGen == 0:
		return fmt.Errorf("%w: incomplete checkpoint", ErrRecord)
	case c.Origin == "":
		return fmt.Errorf("%w: checkpoint without origin", ErrRecord)
	case c.Size < 1 || c.Size > MaxCheckpointSize || c.HeadTime < 0:
		// A head of the empty log is never signed (translog.Head).
		return fmt.Errorf("%w: tree size or time out of range", ErrRecord)
	}
	return nil
}

func (c *Checkpoint) record(withSig bool) *rec.Record {
	r := rec.New(CheckpointSchema).SetBytes(1, c.UserID[:]).SetBytes(2, c.DeviceID[:]).SetString(3, c.Origin).
		SetI64(4, c.Size).SetBytes(5, c.RootHash[:]).SetI64(6, c.HeadTime).SetU32(7, c.UserGen)
	if withSig {
		r.SetBytes(8, c.Signature)
	}
	return r
}

// Sign signs the checkpoint with the identity key of generation UserGen.
func (c *Checkpoint) Sign(identity ed25519.PrivateKey) error {
	if err := c.check(); err != nil {
		return err
	}
	tbs, err := c.record(false).Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRecord, err)
	}
	c.Signature, err = keys.Sign(identity, keys.DomainCheckpoint, tbs)
	return err
}

// Verify checks the signature with the identity key of the user (UserID,
// UserGen); finding that key is the caller's task.
func (c *Checkpoint) Verify(identity ed25519.PublicKey) error {
	if err := c.check(); err != nil {
		return err
	}
	tbs, err := c.record(false).Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRecord, err)
	}
	if !keys.Verify(identity, keys.DomainCheckpoint, tbs, c.Signature) {
		return fmt.Errorf("%w: checkpoint", keys.ErrSignature)
	}
	return nil
}

// Encode returns the canonical encoding of a signed checkpoint.
func (c *Checkpoint) Encode() ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: checkpoint is not signed", ErrRecord)
	}
	return c.record(true).Encode()
}

// DecodeCheckpoint decodes a checkpoint. The signature must be verified
// separately with the user's key.
func DecodeCheckpoint(data []byte) (*Checkpoint, error) {
	r, err := rec.Decode(CheckpointSchema, data)
	if err != nil {
		return nil, err
	}
	if !r.Has(8) {
		return nil, fmt.Errorf("%w: checkpoint is not signed", ErrRecord)
	}
	c := &Checkpoint{UserID: idFromBytes(r.Bytes(1)), DeviceID: idFromBytes(r.Bytes(2)), Origin: r.String(3),
		Size: r.I64(4), HeadTime: r.I64(6), UserGen: r.U32(7), Signature: r.Bytes(8)}
	copy(c.RootHash[:], r.Bytes(5))
	if err := c.check(); err != nil {
		return nil, err
	}
	return c, nil
}

// CheckpointRef names one checkpoint file of a mailbox.
type CheckpointRef struct {
	User   ID
	Device ID
}

// CheckpointDir is mailboxes/<id>/checkpoints.
func (s *Store) CheckpointDir(id ID) string { return filepath.Join(s.MailboxDir(id), "checkpoints") }

// CheckpointFile is mailboxes/<id>/checkpoints/<user-id>-<device-id>.rec.
func (s *Store) CheckpointFile(id, user, device ID) string {
	return filepath.Join(s.CheckpointDir(id), user.String()+"-"+device.String()+".rec")
}

// WriteCheckpoint replaces the checkpoint of c.UserID and c.DeviceID in
// mailbox id: each device keeps exactly its newest one.
func (s *Store) WriteCheckpoint(id ID, c *Checkpoint) error {
	data, err := c.Encode()
	if err != nil {
		return err
	}
	if err := MkdirAll(s.CheckpointDir(id)); err != nil {
		return err
	}
	return WriteFileAtomic(s.CheckpointFile(id, c.UserID, c.DeviceID), data)
}

// ReadCheckpoint reads the checkpoint of user and device in mailbox id
// and checks that it names them. The signature is checked by the caller.
func (s *Store) ReadCheckpoint(id, user, device ID) (*Checkpoint, error) {
	data, err := ReadFileLimited(s.CheckpointFile(id, user, device), MaxRecordFile)
	if err != nil {
		return nil, err
	}
	c, err := DecodeCheckpoint(data)
	if err != nil {
		return nil, err
	}
	if c.UserID != user || c.DeviceID != device {
		return nil, fmt.Errorf("%w: checkpoint of %s-%s names another device", ErrRecord, user, device)
	}
	return c, nil
}

// ListCheckpoints returns the checkpoint files of a mailbox, sorted by
// user and device. Names that are not "<user-id>-<device-id>.rec" with
// canonical IDs are ignored.
func (s *Store) ListCheckpoints(id ID) ([]CheckpointRef, error) {
	entries, err := os.ReadDir(s.CheckpointDir(id))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []CheckpointRef
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".rec")
		if !ok || !e.Type().IsRegular() || len(name) != 2*IDLen+1 || name[IDLen] != '-' {
			continue
		}
		user, err1 := ParseID(name[:IDLen])
		device, err2 := ParseID(name[IDLen+1:])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, CheckpointRef{User: user, Device: device})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].User != out[j].User {
			return string(out[i].User[:]) < string(out[j].User[:])
		}
		return string(out[i].Device[:]) < string(out[j].Device[:])
	})
	return out, nil
}
