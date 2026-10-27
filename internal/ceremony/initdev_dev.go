//go:build gomail_dev

package ceremony

// The development ceremony, only in a build with the tag gomail_dev
// (task 15b point 4): it writes the platform root into a file.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// DevBuild reports whether this build has the development ceremony
// (tag gomail_dev): here it has.
const DevBuild = true

// InitDev runs the development ceremony.
//
// The certificates admin-1.cert and ingest-1.cert are appended to the
// operator log of the new data directory (translog.Open with the
// identity list of the pin; translog doc.go "Who writes": the ceremony
// writes platform entries), and the pinned witnesses with their quorum
// are written to platform/witnesses.rec, the server's working copy, so
// that gomail-server, which always runs with the log since task 15,
// starts on a development platform. Since task 15b InitDev exists only
// in a build with the tag gomail_dev, and "gomail-ceremony init --dev"
// has no --insecure-no-log any more (the accepting placeholder of the
// log is gone with it).
//
// The pin carries the origin DevOrigin, the witnesses and their quorum
// (CheckWitnesses: 1 <= minWitnesses <= len(witnesses) and
// 2*minWitnesses > len(witnesses), refused before anything is written)
// and the identity list with generation 1. With no witnesses and
// minWitnesses 0, InitDev creates one development witness key
// (DevWitnessName, note signer key in keyDir/WitnessKeyFile, 0600) and
// pins it with quorum 1 of 1. TODO(ask): 9.2 names no witness option
// for "gomail-ceremony init --dev"; until the real ceremony (task 10)
// the command uses that development witness.
func InitDev(dataDir, keyDir string, now time.Time, witnesses []witness.Key, minWitnesses int) (*Result, error) {
	devWitness := len(witnesses) == 0 && minWitnesses == 0
	pinned := make([]store.Witness, 0, len(witnesses))
	for _, w := range witnesses {
		pinned = append(pinned, store.Witness{Name: w.Name, Pub: w.Pub})
	}
	if !devWitness {
		if err := store.CheckWitnesses(pinned, minWitnesses); err != nil {
			return nil, err
		}
	}
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
	if err := store.CreatePrivateFileAtomic(filepath.Join(keyDir, RootFile), []byte(rootText)); err != nil {
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
		err = store.CreatePrivateFileAtomic(filepath.Join(keyDir, k.name), data)
		keys.Wipe(data)
		if err != nil {
			return nil, err
		}
	}
	if devWitness {
		w, err := devWitnessKey(keyDir)
		if err != nil {
			return nil, err
		}
		pinned, minWitnesses = []store.Witness{w}, 1
	}
	idPub := identity.Public().(ed25519.PublicKey)
	pin := &store.PlatformPin{Gen: 1, Pub: idPub, Dev: true, Origin: DevOrigin, Witnesses: pinned, MinWitnesses: minWitnesses,
		Identities: []store.PlatformIdentity{{Gen: 1, Pub: idPub}}}
	pinData, err := pin.Encode()
	if err != nil {
		return nil, err
	}
	if err := store.CreatePrivateFileAtomic(filepath.Join(keyDir, PinFile), pinData); err != nil {
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
	}
	// The certificates into the operator log of the data directory
	// (2.7), admin before ingest; the anchor is the identity list of the
	// pin just written.
	oplog, err := translog.Open(translog.Options{Store: st, Identities: []translog.Identity{{Gen: 1, Pub: idPub}}})
	if err != nil {
		return nil, err
	}
	for _, name := range []string{store.PlatformFileName("admin", 1, "cert"), store.PlatformFileName("ingest", 1, "cert")} {
		if err := oplog.AppendPlatform(name, files[name]); err != nil {
			return nil, err
		}
	}
	// platform/witnesses.rec, the server's working copy of the pinned
	// witnesses (translog doc.go "Heads").
	ws := witness.Witnesses{Min: minWitnesses}
	for _, w := range pinned {
		ws.List = append(ws.List, witness.Key{Name: w.Name, Pub: w.Pub})
	}
	wr, err := ws.Encode()
	if err != nil {
		return nil, err
	}
	if err := st.WritePlatformFile("witnesses.rec", wr); err != nil {
		return nil, err
	}
	return &Result{KeyDir: keyDir, IdentityPub: idPub, Pin: pin}, nil
}

// devWitnessKey creates the development witness: a note signer key in
// keyDir/WitnessKeyFile and the pinned public key.
func devWitnessKey(keyDir string) (store.Witness, error) {
	skey, vkey, err := note.GenerateKey(rand.Reader, DevWitnessName)
	if err != nil {
		return store.Witness{}, err
	}
	// vkey is <name>+<hash>+base64(0x01 || Ed25519 public key); the
	// name has no "+", the base64 part may.
	raw, err := base64.StdEncoding.DecodeString(vkeyData(vkey))
	if err != nil || len(raw) != 1+ed25519.PublicKeySize || raw[0] != 1 {
		return store.Witness{}, fmt.Errorf("ceremony: unexpected witness key format")
	}
	if err := store.CreatePrivateFileAtomic(filepath.Join(keyDir, WitnessKeyFile), []byte(skey+"\n")); err != nil {
		return store.Witness{}, err
	}
	return store.Witness{Name: DevWitnessName, Pub: ed25519.PublicKey(raw[1:])}, nil
}

// vkeyData returns the key part of a note verifier key
// <name>+<hash>+<base64>.
func vkeyData(vkey string) string {
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return ""
	}
	return parts[2]
}
