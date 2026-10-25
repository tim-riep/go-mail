package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/tim-riep/go-mail/internal/rec"
)

// The key store of the client (2.2) holds the identity and unwrap keys of
// the current generation, encrypted with AES-256-GCM under a key derived
// from the passphrase with Argon2id. Layout of the file:
//
//	"GMKS"                      4 bytes
//	header length               uint32 big endian
//	header                      record KeystoreHeaderSchema
//	ciphertext                  AES-256-GCM of record KeystoreContentSchema
//
// The header carries the format version and every KDF parameter and is
// authenticated as associated data:
// "gomail/v1/aad/keystore" || 0x00 || "GMKS" || header length || header.
const (
	KeystoreMagic   = "GMKS"
	KeystoreVersion = 1
	// MaxKeystoreSize bounds what ReadKeystoreFile and OpenKeystore accept.
	MaxKeystoreSize = 64 << 10
	// maxKeystoreHeader bounds the header length field.
	maxKeystoreHeader = 256

	kdfArgon2id = 1
	keystoreAAD = "gomail/v1/aad/keystore"
)

// KDFParams are the Argon2id parameters. The specification fixes 64 MiB,
// 3 passes and 4 threads. A key store is opened with the parameters from
// its header, within the bounds below, so parameters can be raised later
// without a format change but can never be lowered below the fixed ones.
type KDFParams struct {
	MemoryKiB uint32
	Passes    uint32
	Threads   uint8
}

// DefaultKDFParams are the parameters of the specification, used for
// sealing.
var DefaultKDFParams = KDFParams{MemoryKiB: 64 * 1024, Passes: 3, Threads: 4}

// Bounds for parameters read from a key store header. The lower bounds
// are the specification's values; the upper bounds protect the client
// from a hostile file that would make it allocate gigabytes.
const (
	MinKDFMemoryKiB = 64 * 1024
	MaxKDFMemoryKiB = 1024 * 1024
	MinKDFPasses    = 3
	MaxKDFPasses    = 32
	MaxKDFThreads   = 64
)

func (p KDFParams) check() error {
	if p.MemoryKiB < MinKDFMemoryKiB || p.MemoryKiB > MaxKDFMemoryKiB ||
		p.Passes < MinKDFPasses || p.Passes > MaxKDFPasses ||
		p.Threads < 1 || p.Threads > MaxKDFThreads {
		return ErrKDFParams
	}
	return nil
}

// KeystoreHeaderSchema is the authenticated header of the key store file.
var KeystoreHeaderSchema = rec.MustSchema("gomail/v1/rec/keystore",
	rec.Field{Num: 1, Name: "version", Kind: rec.U8, Required: true},
	rec.Field{Num: 2, Name: "kdf", Kind: rec.U8, Required: true},
	rec.Field{Num: 3, Name: "memory_kib", Kind: rec.U32, Required: true},
	rec.Field{Num: 4, Name: "passes", Kind: rec.U32, Required: true},
	rec.Field{Num: 5, Name: "threads", Kind: rec.U8, Required: true},
	rec.Field{Num: 6, Name: "salt", Kind: rec.Bytes, Size: 16, Required: true},
	rec.Field{Num: 7, Name: "nonce", Kind: rec.Bytes, Size: 12, Required: true},
)

// KeystoreContentSchema is the encrypted content of the key store.
var KeystoreContentSchema = rec.MustSchema("gomail/v1/rec/keystore-content",
	rec.Field{Num: 1, Name: "gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 2, Name: "identity_seed", Kind: rec.Bytes, Size: ed25519.SeedSize, Required: true},
	rec.Field{Num: 3, Name: "unwrap_priv", Kind: rec.Bytes, Size: 32, Required: true},
)

// Keystore is the decrypted content of the key store: the private keys of
// the user's current generation.
type Keystore struct {
	Generation uint32
	Identity   ed25519.PrivateKey
	Unwrap     *ecdh.PrivateKey
}

// Zero overwrites the identity key and drops the unwrap key. The bytes
// inside ecdh.PrivateKey cannot be overwritten through its API; they stay
// in memory until collected.
func (k *Keystore) Zero() {
	if k == nil {
		return
	}
	Wipe(k.Identity)
	k.Unwrap = nil
}

type kdfFunc func(passphrase, salt []byte, p KDFParams) []byte

func argon2idKDF(passphrase, salt []byte, p KDFParams) []byte {
	return argon2.IDKey(passphrase, salt, p.Passes, p.MemoryKiB, p.Threads, 32)
}

type keystoreHeader struct {
	version uint8
	kdf     uint8
	params  KDFParams
	salt    [16]byte
	nonce   [12]byte
}

func (h *keystoreHeader) record() *rec.Record {
	return rec.New(KeystoreHeaderSchema).
		SetU8(1, h.version).
		SetU8(2, h.kdf).
		SetU32(3, h.params.MemoryKiB).
		SetU32(4, h.params.Passes).
		SetU8(5, h.params.Threads).
		SetBytes(6, h.salt[:]).
		SetBytes(7, h.nonce[:])
}

func headerFromRecord(r *rec.Record) *keystoreHeader {
	h := &keystoreHeader{
		version: r.U8(1),
		kdf:     r.U8(2),
		params:  KDFParams{MemoryKiB: r.U32(3), Passes: r.U32(4), Threads: r.U8(5)},
	}
	copy(h.salt[:], r.Bytes(6))
	copy(h.nonce[:], r.Bytes(7))
	return h
}

// keystoreContent encodes the content record.
func keystoreContent(gen uint32, identitySeed, unwrapPriv []byte) ([]byte, error) {
	b, err := rec.New(KeystoreContentSchema).
		SetU32(1, gen).
		SetBytes(2, identitySeed).
		SetBytes(3, unwrapPriv).
		Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeystore, err)
	}
	return b, nil
}

func aad(hdrLen uint32, hdr []byte) []byte {
	a := []byte(keystoreAAD)
	a = append(a, 0)
	a = append(a, KeystoreMagic...)
	a = binary.BigEndian.AppendUint32(a, hdrLen)
	return append(a, hdr...)
}

// Seal encrypts the key store under passphrase with the specification's
// KDF parameters. Salt and nonce come from r, or crypto/rand if r is nil.
func (k *Keystore) Seal(passphrase []byte, r io.Reader) ([]byte, error) {
	return k.seal(passphrase, r, DefaultKDFParams, argon2idKDF)
}

func (k *Keystore) seal(passphrase []byte, r io.Reader, p KDFParams, kdf kdfFunc) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil key store", ErrKeystore)
	}
	if err := checkGeneration(k.Generation); err != nil {
		return nil, err
	}
	if len(k.Identity) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: identity key has wrong length", ErrKeystore)
	}
	if k.Unwrap == nil || k.Unwrap.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("%w: unwrap key is not X25519", ErrKeystore)
	}
	body, err := keystoreContent(k.Generation, k.Identity.Seed(), k.Unwrap.Bytes())
	if err != nil {
		return nil, err
	}
	defer Wipe(body)
	return sealBody(body, passphrase, r, p, kdf)
}

// sealBody encrypts an already encoded content record.
func sealBody(body, passphrase []byte, r io.Reader, p KDFParams, kdf kdfFunc) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("%w: empty passphrase", ErrPassphrase)
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	if r == nil {
		r = rand.Reader
	}
	h := &keystoreHeader{version: KeystoreVersion, kdf: kdfArgon2id, params: p}
	if _, err := io.ReadFull(r, h.salt[:]); err != nil {
		return nil, fmt.Errorf("keys: reading salt: %w", err)
	}
	if _, err := io.ReadFull(r, h.nonce[:]); err != nil {
		return nil, fmt.Errorf("keys: reading nonce: %w", err)
	}
	hdr, err := h.record().Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeystore, err)
	}
	key := kdf(passphrase, h.salt[:], p)
	defer Wipe(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := []byte(KeystoreMagic)
	out = binary.BigEndian.AppendUint32(out, uint32(len(hdr)))
	out = append(out, hdr...)
	return gcm.Seal(out, h.nonce[:], body, aad(uint32(len(hdr)), hdr)), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	return gcm, nil
}

// parseKeystore splits data into the decoded header and the ciphertext,
// checking every length before use. It does not validate header values.
func parseKeystore(data []byte) (*rec.Record, []byte, error) {
	if len(data) > MaxKeystoreSize {
		return nil, nil, fmt.Errorf("%w: file too large", ErrKeystore)
	}
	if len(data) < len(KeystoreMagic)+4 || string(data[:len(KeystoreMagic)]) != KeystoreMagic {
		return nil, nil, fmt.Errorf("%w: bad magic", ErrKeystore)
	}
	hdrLen := binary.BigEndian.Uint32(data[4:8])
	if hdrLen > maxKeystoreHeader || uint64(hdrLen) > uint64(len(data)-8) {
		return nil, nil, fmt.Errorf("%w: header length", ErrKeystore)
	}
	hdr := data[8 : 8+hdrLen]
	ct := data[8+hdrLen:]
	if len(ct) < 16 {
		return nil, nil, fmt.Errorf("%w: ciphertext too short", ErrKeystore)
	}
	r, err := rec.Decode(KeystoreHeaderSchema, hdr)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: header: %v", ErrKeystore, err)
	}
	return r, ct, nil
}

// OpenKeystore decrypts a key store with passphrase.
func OpenKeystore(data, passphrase []byte) (*Keystore, error) {
	return openKeystore(data, passphrase, argon2idKDF)
}

func openKeystore(data, passphrase []byte, kdf kdfFunc) (*Keystore, error) {
	r, ct, err := parseKeystore(data)
	if err != nil {
		return nil, err
	}
	h := headerFromRecord(r)
	if h.version != KeystoreVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrKeystore, h.version)
	}
	if h.kdf != kdfArgon2id {
		return nil, fmt.Errorf("%w: unsupported KDF %d", ErrKeystore, h.kdf)
	}
	if err := h.params.check(); err != nil {
		return nil, err
	}
	hdr := data[8 : len(data)-len(ct)]
	key := kdf(passphrase, h.salt[:], h.params)
	defer Wipe(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	body, err := gcm.Open(nil, h.nonce[:], ct, aad(uint32(len(hdr)), hdr))
	if err != nil {
		return nil, ErrPassphrase
	}
	defer Wipe(body)
	c, err := rec.Decode(KeystoreContentSchema, body)
	if err != nil {
		return nil, fmt.Errorf("%w: content: %v", ErrKeystore, err)
	}
	gen := c.U32(1)
	if err := checkGeneration(gen); err != nil {
		return nil, err
	}
	idSeed := c.Bytes(2)
	defer Wipe(idSeed)
	uwBytes := c.Bytes(3)
	defer Wipe(uwBytes)
	uw, err := ecdh.X25519().NewPrivateKey(uwBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: unwrap key: %v", ErrKeystore, err)
	}
	return &Keystore{Generation: gen, Identity: ed25519.NewKeyFromSeed(idSeed), Unwrap: uw}, nil
}

// WriteKeystoreFile writes data to path with mode 0600, atomically: it
// writes a temporary file in the same directory, syncs it, renames it
// over path and syncs the directory.
func WriteKeystoreFile(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keystore-*.tmp")
	if err != nil {
		return fmt.Errorf("keys: creating temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("keys: setting permissions: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("keys: writing: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("keys: syncing: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("keys: closing: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("keys: renaming: %w", err)
	}
	if d, derr := os.Open(dir); derr == nil {
		// Best effort: not every file system supports syncing a directory.
		d.Sync()
		d.Close()
	}
	return nil
}

// ReadKeystoreFile reads a key store file of at most MaxKeystoreSize
// bytes. It does not decrypt; pass the result to OpenKeystore.
func ReadKeystoreFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", ErrKeystore)
	}
	if fi.Size() > MaxKeystoreSize {
		return nil, fmt.Errorf("%w: file too large", ErrKeystore)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxKeystoreSize+1))
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	if len(data) > MaxKeystoreSize {
		return nil, fmt.Errorf("%w: file too large", ErrKeystore)
	}
	return data, nil
}

var _ = errors.New
