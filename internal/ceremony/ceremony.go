// Package ceremony implements gomail-ceremony (2.3): the real ceremony
// with a Shamir-split platform root (api.go: Init, IngestRotate, Reshare,
// Succeed, Publish) and, only in a test build, the development ceremony
// InitDev.
//
// InitDev ("gomail-ceremony init --dev") creates a platform root without
// Shamir for development and tests. It derives identity, admin and
// ingest keys of generation 1, certifies admin and ingest with the
// identity, writes the public parts into the data directory and the
// private keys into a separate key directory, which must not be inside
// the data directory. The root is written as a file that is clearly
// marked insecure. The pin it writes for clients carries the development
// flag, the origin DevOrigin, the witnesses and the identity list (pin
// fields 4 to 6 and 8, translog doc.go "Pin"); clients accept it only
// with client.Config.AllowDevIdentity (task 14), which no command line
// flag sets: gomailctl only in a test build with
// GOMAIL_TEST_DEV_IDENTITY=1, and gomail-server refuses it in a build
// without the tag gomail_dev (task 15k).
//
// InitDev exists only in a build with the tag gomail_dev
// (initdev_dev.go, task 15b point 4); without it InitDev returns ErrDev
// and writes nothing (initdev.go), so that a production build of
// gomail-ceremony contains no path that writes a platform root into a
// file. The tests that run on a development platform (package testenv
// and the packages that use it, the end-to-end tests, the tests of the
// programs) build with "-tags gomail_dev,gomail_test" and skip without
// the tag.
//
// plan9 and js/wasm are not supported targets: commit needs
// syscall.Rename (rename(2) replaces an empty export directory), which
// the syscall package of plan9 lacks, and gomail-ceremony needs
// syscall.SIGHUP, which js/wasm lacks (task 10e finding 6).
package ceremony

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// File names in the key directory.
const (
	RootFile      = "platform-root.INSECURE-DEV-ONLY.txt"
	AdminKeyFile  = "admin-1.key"
	IngestKeyFile = "ingest-1.key"
	PinFile       = "identity-1.pin"
	// WitnessKeyFile is the note signer key of the development witness
	// that InitDev creates when no witness is given.
	WitnessKeyFile = "witness-dev.key"
)

// Pin fields of the development ceremony (translog doc.go "Pin").
const (
	// DevOrigin is the log origin of a development platform.
	DevOrigin = "gomail-dev"
	// DevWitnessName is the name of the development witness that InitDev
	// creates when no witness is given.
	DevWitnessName = "gomail-dev-witness"
)

// ErrKeyDir reports a key directory inside the data directory, one that
// already holds keys, or (real ceremony) one that is not a directory of
// mode 0700 owned by the current user or was replaced by a symbolic link.
var ErrKeyDir = errors.New("ceremony: unusable key directory")

// ErrDev reports the development ceremony in a build without the tag
// gomail_dev: InitDev exists only in test builds (task 15b point 4).
var ErrDev = errors.New("ceremony: the development ceremony exists only in test builds (-tags gomail_dev)")

// Result names what InitDev, Init or Succeed wrote.
type Result struct {
	KeyDir      string // empty for Succeed
	IdentityPub ed25519.PublicKey
	// Pin is the pin written, with its identity list (pin field 8,
	// translog doc.go "Pin").
	Pin *store.PlatformPin
	// Out is the export directory (Init, Succeed).
	Out string
}

func inside(dir, root string) bool {
	rel, err := filepath.Rel(root, dir)
	return err == nil && (rel == "." || filepath.IsLocal(rel))
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

// ReadPin reads a platform pin (read limit store.MaxPinFile).
func ReadPin(path string) (*store.PlatformPin, error) { return store.ReadPlatformPin(path) }
