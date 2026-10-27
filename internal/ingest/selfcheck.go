package ingest

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/store"
)

// ErrSignature reports that a metadata file or a term list does not carry
// a valid ingest signature (section 7). The cause is wrapped as well
// (envelope.ErrUnsigned, envelope.ErrSignature, a parse error, ...).
var ErrSignature = errors.New("ingest: invalid ingest signature")

// ErrSelfCheck reports that a file the server has just signed and written
// does not verify with its own public ingest key (section 7, "Was die
// Ingest-Signatur aussagt"). The mail is refused with 451 before the
// journal; a term list is not kept and the markers stay.
var ErrSelfCheck = errors.New("ingest: self-check of the ingest signature failed")

// VerifyMeta checks the ingest signature of a metadata file
// <mail-id>.meta.gml without any private key and without decrypting
// anything (section 7): data must be a structurally valid .gml file of
// kind meta with a trailer of signer type ingest and the zero signer ID,
// and the signature must verify with pub over meta-signed, which is
// rebuilt from the clear header alone (store.MetaSignedExtra: mailbox,
// epoch, file_id, created, version) and mailHash, the SHA-256 of the
// whole mail file. pub is the public ingest key of generation gen, and
// the trailer must name exactly that generation (signer_gen), so a key is
// never applied to a file that claims another generation; the generation
// itself is covered by the signature. Every error wraps ErrSignature.
func VerifyMeta(data []byte, mailHash [32]byte, gen uint32, pub ed25519.PublicKey) error {
	_, err := verifyMeta(data, mailHash, gen, pub)
	return err
}

// VerifyPending checks the ingest signature of a term list or a marker
// pending/<n>/<file>.gml in the same way (5.2 step 3, 5.4): kind pending,
// signer type ingest with the zero signer ID and generation gen, and a
// signature with pub, the public ingest key of generation gen, over the
// file with the kind-specific fields sealPending uses (pendingSignedExtra,
// built from the clear header alone). Every error wraps ErrSignature.
func VerifyPending(data []byte, gen uint32, pub ed25519.PublicKey) error {
	_, err := verifyPending(data, gen, pub)
	return err
}

func verifyMeta(data []byte, mailHash [32]byte, gen uint32, pub ed25519.PublicKey) (*envelope.File, error) {
	f, err := parseIngestSigned(data, envelope.KindMeta, gen)
	if err != nil {
		return nil, err
	}
	extra, err := store.MetaSignedExtra(f.Header, mailHash)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	if err := f.VerifySignature(pub, extra); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return f, nil
}

func verifyPending(data []byte, gen uint32, pub ed25519.PublicKey) (*envelope.File, error) {
	f, err := parseIngestSigned(data, envelope.KindPending, gen)
	if err != nil {
		return nil, err
	}
	if err := f.VerifySignature(pub, pendingSignedExtra(f.Header)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return f, nil
}

// parseIngestSigned parses data and checks the kind and that the trailer
// names the ingest key of generation gen (signer type ingest, zero signer
// ID, signer_gen gen, as the client requires it).
func parseIngestSigned(data []byte, kind envelope.Kind, gen uint32) (*envelope.File, error) {
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	if f.Header.Kind != kind {
		return nil, fmt.Errorf("%w: kind %s, want %s", ErrSignature, f.Header.Kind, kind)
	}
	if f.Trailer == nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, envelope.ErrUnsigned)
	}
	if f.Trailer.Signer.Type != envelope.SignerIngest || f.Trailer.Signer.ID != ([16]byte{}) {
		return nil, fmt.Errorf("%w: %w: not signed by the ingest key", ErrSignature, envelope.ErrSigner)
	}
	if gen == 0 || f.Trailer.Signer.Gen != gen {
		return nil, fmt.Errorf("%w: %w: signer generation %d, key of generation %d", ErrSignature, envelope.ErrSigner, f.Trailer.Signer.Gen, gen)
	}
	return f, nil
}

// pendingSignedExtra returns the kind-specific signed fields of a term
// list or marker. Section 7 defines a signed record only for kind meta;
// a pending file is signed over its file hash and the signer alone, so
// the extra fields are empty. It takes the header to keep the rule that
// everything signed comes from the clear header or is a hash over
// ciphertext, and so that sealPending and VerifyPending cannot diverge.
func pendingSignedExtra(envelope.Header) []byte { return nil }

// selfCheck reads back the file the server has just written to path and
// checks it without keys (section 7): the ingest signature with the
// public key of the server's own generation (the certified one), the
// generation in the trailer, and the clear header against the header the
// server sealed (want). mailHash is used for kind meta only. The result
// wraps ErrSelfCheck; only IDs go to the log.
func (in *Ingest) selfCheck(path string, want envelope.Header, mailHash [32]byte) error {
	limit := int64(store.MaxPendingFile)
	if want.Kind == envelope.KindMeta {
		limit = store.MaxMetaFile
	}
	data, err := store.ReadFileLimited(path, limit)
	if err != nil {
		return in.selfCheckFailed(want, err)
	}
	return in.selfCheckBytes(data, want, mailHash)
}

// selfCheckBytes is selfCheck on bytes in memory.
func (in *Ingest) selfCheckBytes(data []byte, want envelope.Header, mailHash [32]byte) error {
	var f *envelope.File
	var err error
	switch want.Kind {
	case envelope.KindMeta:
		f, err = verifyMeta(data, mailHash, in.cfg.IngestGen, in.pub)
	case envelope.KindPending:
		f, err = verifyPending(data, in.cfg.IngestGen, in.pub)
	default:
		err = fmt.Errorf("%w: kind %s", ErrSignature, want.Kind)
	}
	if err != nil {
		return in.selfCheckFailed(want, err)
	}
	h := f.Header
	if h.Kind != want.Kind || h.MailboxID != want.MailboxID || h.Epoch != want.Epoch ||
		h.FileID != want.FileID || h.Created != want.Created || h.Version != want.Version {
		return in.selfCheckFailed(want, errors.New("header differs"))
	}
	return nil
}

func (in *Ingest) selfCheckFailed(want envelope.Header, err error) error {
	in.log.Info("ingest self-check of a signature failed", "kind", want.Kind.String(), "mailbox", store.ID(want.MailboxID).String(),
		"epoch", want.Epoch, "file", store.ID(want.FileID).String())
	return fmt.Errorf("%w: %w", ErrSelfCheck, err)
}
