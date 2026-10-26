package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/tim-riep/go-mail/internal/keys"
)

// Recipient is a key the file key is wrapped for.
type Recipient struct {
	Type      RecipientType
	ID        [16]byte
	Gen       uint32
	PublicKey *ecdh.PublicKey // X25519
}

// Signer signs the trailer. Extra carries kind-specific fields of the
// signed structure (3.4, section 7), already canonically encoded by the
// caller; it must be given again when verifying.
type Signer struct {
	Type  SignerType
	ID    [16]byte
	Gen   uint32
	Key   ed25519.PrivateKey
	Extra []byte
}

func (s *Signer) validate() error {
	if !s.Type.valid() {
		return fmt.Errorf("%w: unknown signer type %d", ErrSigner, s.Type)
	}
	if s.Gen == 0 {
		return fmt.Errorf("%w: generation 0", ErrSigner)
	}
	if len(s.Key) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: private key has wrong length", ErrSigner)
	}
	if len(s.Extra) > MaxExtraSize {
		return fmt.Errorf("%w: extra fields too long", ErrSigner)
	}
	return nil
}

func (s *Signer) ref() SignerRef { return SignerRef{Type: s.Type, ID: s.ID, Gen: s.Gen} }

// SealOptions configure Seal and NewWriter.
type SealOptions struct {
	// Rand supplies the nonce prefix (7 bytes) and the file key (32
	// bytes), in that order. nil means crypto/rand. HPKE draws its
	// ephemeral keys from crypto/rand regardless.
	Rand io.Reader
	// Signer adds a signed trailer element. nil writes no trailer.
	Signer *Signer
}

// Seal encrypts plaintext into a complete .gml file.
func Seal(hdr Header, recipients []Recipient, plaintext []byte, opts *SealOptions) ([]byte, error) {
	if len(plaintext) > MaxContentSize {
		return nil, fmt.Errorf("%w: %d bytes of content", ErrTooLarge, len(plaintext))
	}
	var buf bytes.Buffer
	w, err := NewWriter(&buf, hdr, recipients, opts)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Writer streams a .gml file to an io.Writer. Content is written with
// Write and the file is completed with Close, which writes the last block
// and the trailer. The writer always holds one block back until it knows
// whether more content follows, so that the last block carries the end
// flag (3.3, rule 5).
type Writer struct {
	out    io.Writer
	hash   hash.Hash
	aead   cipher.AEAD
	aad    []byte
	prefix [7]byte
	kind   Kind
	signer *Signer
	buf    []byte
	count  uint32
	total  int64
	closed bool
	err    error
}

// NewWriter writes the preamble, header and recipient section to w and
// returns a Writer for the content.
func NewWriter(w io.Writer, hdr Header, recipients []Recipient, opts *SealOptions) (*Writer, error) {
	if w == nil {
		return nil, fmt.Errorf("envelope: nil writer")
	}
	if opts == nil {
		opts = &SealOptions{}
	}
	if !hdr.Kind.valid() {
		return nil, fmt.Errorf("%w: unknown kind %d", ErrHeader, hdr.Kind)
	}
	if hdr.ChunkSize != 0 && hdr.ChunkSize != ChunkSize {
		return nil, fmt.Errorf("%w: chunk size must be %d", ErrHeader, ChunkSize)
	}
	if len(recipients) == 0 || len(recipients) > MaxRecipients {
		return nil, fmt.Errorf("%w: %d recipients", ErrRecipients, len(recipients))
	}
	seen := make(map[recipientRef]bool, len(recipients))
	for _, r := range recipients {
		if !r.Type.valid() || r.Gen == 0 {
			return nil, fmt.Errorf("%w: invalid type or generation", ErrRecipients)
		}
		if r.PublicKey == nil || r.PublicKey.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("%w: public key is not X25519", ErrRecipients)
		}
		ref := recipientRef{r.Type, r.ID, r.Gen}
		if seen[ref] {
			return nil, fmt.Errorf("%w: duplicate recipient", ErrRecipients)
		}
		seen[ref] = true
	}
	if opts.Signer != nil {
		if err := opts.Signer.validate(); err != nil {
			return nil, err
		}
	}
	rnd := opts.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	if _, err := io.ReadFull(rnd, hdr.NoncePrefix[:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRandom, err)
	}
	fileKey := make([]byte, FileKeySize)
	defer wipe(fileKey)
	if _, err := io.ReadFull(rnd, fileKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRandom, err)
	}
	hdr.ChunkSize = ChunkSize
	headerBytes, err := hdr.encode()
	if err != nil {
		return nil, err
	}
	preamble := []byte{Magic[0], Magic[1], Magic[2], Magic[3], FormatVersion, byte(Suite1)}

	// Wrap the file key for every recipient (3.2).
	wrapAAD := aadHash(aadWrap, preamble, headerBytes)
	entries := make([]RecipientEntry, len(recipients))
	for i, r := range recipients {
		pk, err := hpke.NewDHKEMPublicKey(r.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrWrap, err)
		}
		ref := recipientRef{r.Type, r.ID, r.Gen}
		enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), wrapInfo(ref))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrWrap, err)
		}
		wrapped, err := sender.Seal(wrapAAD, fileKey)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrWrap, err)
		}
		entries[i] = RecipientEntry{Type: r.Type, ID: r.ID, Gen: r.Gen, Enc: enc, WrappedKey: wrapped}
	}
	recipientBytes, err := encodeRecipients(entries)
	if err != nil {
		return nil, err
	}
	if len(recipientBytes) > MaxRecipientsSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrRecipientsSize, len(recipientBytes))
	}

	// Content key and AEAD (3.3).
	aead, err := contentAEAD(fileKey, hdr.NoncePrefix)
	if err != nil {
		return nil, err
	}
	wr := &Writer{
		out:    w,
		hash:   sha256.New(),
		aead:   aead,
		aad:    aadHash(aadBlock, preamble, headerBytes),
		prefix: hdr.NoncePrefix,
		kind:   hdr.Kind,
		signer: opts.Signer,
	}
	var head []byte
	head = append(head, preamble...)
	head = binary.BigEndian.AppendUint32(head, uint32(len(headerBytes)))
	head = append(head, headerBytes...)
	head = binary.BigEndian.AppendUint32(head, uint32(len(recipientBytes)))
	head = append(head, recipientBytes...)
	if err := wr.emit(head); err != nil {
		return nil, err
	}
	return wr, nil
}

// contentAEAD derives the content key from the file key and nonce prefix
// and returns the AES-256-GCM instance. The key schedule inside the AEAD
// cannot be wiped; the derived key bytes are.
func contentAEAD(fileKey []byte, prefix [7]byte) (cipher.AEAD, error) {
	contentKey, err := hkdf.Key(sha256.New, fileKey, prefix[:], infoContent, 32)
	if err != nil {
		return nil, fmt.Errorf("envelope: deriving content key: %w", err)
	}
	defer wipe(contentKey)
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	return aead, nil
}

// emit writes b to the output and the running hash.
func (w *Writer) emit(b []byte) error {
	if w.err != nil {
		return w.err
	}
	if _, err := w.out.Write(b); err != nil {
		w.err = fmt.Errorf("envelope: write: %w", err)
		return w.err
	}
	w.hash.Write(b)
	return nil
}

// Write buffers content and emits every block that is known not to be
// the last one. At most one block of plaintext is held in memory.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, ErrClosed
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.total+int64(len(p)) > MaxContentSize {
		w.err = fmt.Errorf("%w: content exceeds %d bytes", ErrTooLarge, MaxContentSize)
		return 0, w.err
	}
	w.total += int64(len(p))
	if w.buf == nil {
		w.buf = make([]byte, 0, ChunkSize)
	}
	written := 0
	for len(p) > 0 {
		// A full buffer followed by more data is not the last block.
		if len(w.buf) == ChunkSize {
			if err := w.block(w.buf, false); err != nil {
				return written, err
			}
			wipe(w.buf)
			w.buf = w.buf[:0]
		}
		n := min(ChunkSize-len(w.buf), len(p))
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		written += n
	}
	return written, nil
}

// block encrypts and emits one block element. The element type and the
// flag in the nonce always agree: ElemLastBlock carries flag 0x01, every
// ElemBlock flag 0x00.
func (w *Writer) block(pt []byte, last bool) error {
	if w.count >= MaxBlocks {
		w.err = fmt.Errorf("%w: more than %d blocks", ErrTooLarge, MaxBlocks)
		return w.err
	}
	ct := w.aead.Seal(nil, blockNonce(w.prefix, w.count, last), pt, w.aad)
	w.count++
	typ := byte(ElemBlock)
	if last {
		typ = ElemLastBlock
	}
	return w.emit(element(typ, ct))
}

// element frames payload as "typ || uint32 length || payload".
func element(typ byte, payload []byte) []byte {
	out := make([]byte, 0, elemHeaderSize+len(payload))
	out = append(out, typ)
	out = binary.BigEndian.AppendUint32(out, uint32(len(payload)))
	return append(out, payload...)
}

// Close writes the last block (with the end flag) and, if a signer is
// set, the trailer element. The signed hash covers every byte written
// before the trailer element.
func (w *Writer) Close() error {
	if w.closed {
		return ErrClosed
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if err := w.block(w.buf, true); err != nil {
		return err
	}
	wipe(w.buf)
	w.buf = nil
	if w.signer == nil {
		return nil
	}
	var fileHash [sha256.Size]byte
	w.hash.Sum(fileHash[:0])
	signed, err := signedStructure(fileHash, w.signer.ref(), w.signer.Extra)
	if err != nil {
		w.err = err
		return err
	}
	sig, err := keys.Sign(w.signer.Key, w.kind.String(), signed)
	if err != nil {
		w.err = fmt.Errorf("%w: %v", ErrSigner, err)
		return w.err
	}
	tr := Trailer{Signer: w.signer.ref(), Signature: sig}
	tb, err := tr.encode()
	if err != nil {
		w.err = err
		return err
	}
	return w.emit(element(ElemTrailer, tb))
}
