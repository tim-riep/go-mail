package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// signerKeyPrefix starts every note signer key.
const signerKeyPrefix = "PRIVATE+KEY+"

// Keygen creates a witness key named name (CheckName) with randomness
// from r (crypto/rand if nil), writes the signer key to keyFile (0600,
// exclusive) and returns the verifier key line.
//
// The key file holds the signer key "PRIVATE+KEY+<name>+<hash>+<base64>"
// followed by one newline and nothing else; an existing file is never
// replaced (ErrKey wrapping store.ErrExists).
func Keygen(name, keyFile string, r io.Reader) (vkey string, err error) {
	if err := CheckName(name); err != nil {
		return "", fmt.Errorf("%w: %w", ErrKey, err)
	}
	if keyFile == "" {
		return "", fmt.Errorf("%w: no key file", ErrKey)
	}
	if r == nil {
		r = rand.Reader
	}
	skey, vkey, err := note.GenerateKey(r, name)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKey, err)
	}
	if err := store.CreatePrivateFileAtomic(keyFile, []byte(skey+"\n")); err != nil {
		return "", fmt.Errorf("%w: %w", ErrKey, err)
	}
	return vkey, nil
}

// loadKey reads a key file written by Keygen: owner-only rights, at most
// MaxKeyFile bytes, exactly one signer key line with a valid witness
// name. It returns the signer and the verifier of the same key.
func loadKey(path string) (note.Signer, note.Verifier, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrKey, err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, nil, fmt.Errorf("%w: rights %04o, the key file must be 0600", ErrKey, fi.Mode().Perm())
	}
	data, err := store.ReadFileLimited(path, MaxKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrKey, err)
	}
	defer keys.Wipe(data)
	line, ok := strings.CutSuffix(string(data), "\n")
	if !ok || strings.ContainsAny(line, "\r\n") || !strings.HasPrefix(line, signerKeyPrefix) {
		return nil, nil, fmt.Errorf("%w: not a note signer key line", ErrKey)
	}
	signer, err := note.NewSigner(line)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: malformed signer key", ErrKey)
	}
	if err := CheckName(signer.Name()); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrKey, err)
	}
	// note.NewSigner has checked the form "<name>+<hash>+<data>" and the
	// hash; the name contains no "+" (CheckName), so the key data is the
	// third field. It is the algorithm byte 1 and the Ed25519 seed.
	parts := strings.SplitN(strings.TrimPrefix(line, signerKeyPrefix), "+", 3)
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("%w: malformed signer key", ErrKey)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 1+ed25519.SeedSize || raw[0] != 1 {
		keys.Wipe(raw)
		return nil, nil, fmt.Errorf("%w: malformed signer key", ErrKey)
	}
	priv := ed25519.NewKeyFromSeed(raw[1:])
	pub := priv.Public().(ed25519.PublicKey)
	keys.Wipe(raw)
	keys.Wipe(priv)
	v, err := translog.NewWitnessVerifier(signer.Name(), pub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	if v.KeyHash() != signer.KeyHash() {
		return nil, nil, fmt.Errorf("%w: key hash does not match the key", ErrKey)
	}
	return signer, v, nil
}
