// Package ceremony implements "gomail-ceremony init --dev" (2.3): a
// platform root without Shamir for development. It derives identity,
// admin and ingest keys of generation 1, certifies admin and ingest with
// the identity, writes the public parts into the data directory and the
// private keys into a separate key directory, which must not be inside
// the data directory. The root is written as a file that is clearly
// marked insecure. The pin it writes for clients carries the development
// flag; clients accept it only with --insecure-no-log.
package ceremony

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// File names in the key directory.
const (
	RootFile      = "platform-root.INSECURE-DEV-ONLY.txt"
	AdminKeyFile  = "admin-1.key"
	IngestKeyFile = "ingest-1.key"
	PinFile       = "identity-1.pin"
)

// ErrKeyDir reports a key directory inside the data directory or one
// that already holds keys.
var ErrKeyDir = errors.New("ceremony: unusable key directory")

// Result names what InitDev wrote.
type Result struct {
	KeyDir      string
	IdentityPub ed25519.PublicKey
	Pin         *store.PlatformPin
}

func inside(dir, root string) bool {
	rel, err := filepath.Rel(root, dir)
	return err == nil && (rel == "." || filepath.IsLocal(rel))
}

// InitDev runs the development ceremony. log receives the certificates
// (phase 1: translog.Unverified, which ignores them).
func InitDev(dataDir, keyDir string, now time.Time, log translog.Log) (*Result, error) {
	st, err := store.Init(dataDir)
	if err != nil {
		return nil, err
	}
	keyDir, err = filepath.Abs(keyDir)
	if err != nil {
		return nil, err
	}
	if inside(keyDir, st.Root) || inside(st.Root, keyDir) {
		return nil, fmt.Errorf("%w: the key directory must be separate from the data directory", ErrKeyDir)
	}
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(keyDir, RootFile)); err == nil {
		return nil, fmt.Errorf("%w: it already holds a platform root", ErrKeyDir)
	}
	seed, err := keys.NewSeed(nil)
	if err != nil {
		return nil, err
	}
	defer seed.Zero()
	p := keys.DerivePlatform(seed)
	defer p.Zero()
	identity, err := p.IdentityKey(1)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(identity)
	admin, err := p.AdminKey(1)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(admin)
	ingest, err := p.IngestKey(1)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(ingest)

	words, err := seed.Words()
	if err != nil {
		return nil, err
	}
	rootText := "UNSICHER - NUR FÜR DIE ENTWICKLUNG / INSECURE - DEVELOPMENT ONLY\n" +
		"Plattform-Root ohne Shamir-Aufteilung (gomail-ceremony init --dev).\n" +
		"Wer diese Datei hat, kann jeden Plattformschlüssel ableiten.\n\n" +
		"seed: " + hex.EncodeToString(seed[:]) + "\n" +
		"words: " + strings.Join(words, " ") + "\n"
	if err := store.CreateFileAtomic(filepath.Join(keyDir, RootFile), []byte(rootText)); err != nil {
		return nil, err
	}
	for _, k := range []struct {
		name string
		role uint8
		key  ed25519.PrivateKey
	}{{AdminKeyFile, store.KeyRoleAdmin, admin}, {IngestKeyFile, store.KeyRoleIngest, ingest}} {
		data, err := store.EncodePlatformKey(k.role, 1, k.key)
		if err != nil {
			return nil, err
		}
		err = store.CreateFileAtomic(filepath.Join(keyDir, k.name), data)
		keys.Wipe(data)
		if err != nil {
			return nil, err
		}
	}
	idPub := identity.Public().(ed25519.PublicKey)
	pin := &store.PlatformPin{Gen: 1, Pub: idPub, Dev: true}
	pinData, err := pin.Encode()
	if err != nil {
		return nil, err
	}
	if err := store.CreateFileAtomic(filepath.Join(keyDir, PinFile), pinData); err != nil {
		return nil, err
	}

	validFrom := now.UnixMilli()
	files := map[string][]byte{store.PlatformFileName("identity", 1, "pub"): idPub}
	for _, c := range []struct {
		name string
		role keys.Role
		key  ed25519.PrivateKey
	}{{"admin", keys.RoleAdmin, admin}, {"ingest", keys.RoleIngest, ingest}} {
		pub := c.key.Public().(ed25519.PublicKey)
		cert, err := keys.NewPlatformCert(identity, 1, c.role, 1, pub, validFrom)
		if err != nil {
			return nil, err
		}
		cd, err := cert.Encode()
		if err != nil {
			return nil, err
		}
		files[store.PlatformFileName(c.name, 1, "pub")] = pub
		files[store.PlatformFileName(c.name, 1, "cert")] = cd
	}
	for name, data := range files {
		if err := st.WritePlatformFile(name, data); err != nil {
			return nil, err
		}
		if strings.HasSuffix(name, ".cert") {
			if err := log.AppendPlatform(name, data); err != nil {
				return nil, err
			}
		}
	}
	return &Result{KeyDir: keyDir, IdentityPub: idPub, Pin: pin}, nil
}

// ReadKey reads a private platform key file and checks its role.
func ReadKey(path string, role uint8) (ed25519.PrivateKey, uint32, error) {
	data, err := store.ReadFileLimited(path, 4096)
	if err != nil {
		return nil, 0, err
	}
	defer keys.Wipe(data)
	r, gen, priv, err := store.DecodePlatformKey(data)
	if err != nil {
		return nil, 0, err
	}
	if r != role {
		return nil, 0, fmt.Errorf("ceremony: %s is not a key of the expected role", filepath.Base(path))
	}
	return priv, gen, nil
}

// ReadPin reads a platform pin.
func ReadPin(path string) (*store.PlatformPin, error) {
	data, err := store.ReadFileLimited(path, 4096)
	if err != nil {
		return nil, err
	}
	return store.DecodePlatformPin(data)
}
