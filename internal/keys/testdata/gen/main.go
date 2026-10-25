// Command gen writes the test vectors of package keys into the testdata
// directory. Run it from internal/keys:
//
//	go run ./testdata/gen
//
// Every vector is derived from fixed seeds and fixed randomness, so the
// output is reproducible. Randomness is injected through io.Reader
// arguments; the global crypto/rand is never modified.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tim-riep/go-mail/internal/keys"
)

type keyVector struct {
	Gen    uint32 `json:"gen,omitempty"`
	Secret string `json:"secret"`
	Public string `json:"public"`
}

type seedVector struct {
	Name  string `json:"name"`
	Seed  string `json:"seed"`
	Words string `json:"words"`
	User  struct {
		Root     keyVector   `json:"root"`
		Identity []keyVector `json:"identity"`
		Unwrap   []keyVector `json:"unwrap"`
	} `json:"user"`
	Platform struct {
		Identity []keyVector `json:"identity"`
		Admin    []keyVector `json:"admin"`
		Ingest   []keyVector `json:"ingest"`
	} `json:"platform"`
}

type certVectors struct {
	Comment     string   `json:"comment"`
	Seed        string   `json:"seed"`
	RootPub     string   `json:"root_pub"`
	Generations []string `json:"generations"` // hex encodings of generation certificates 1..3
	// Platform certificates signed by platform identity generation 1
	// derived from the same seed.
	PlatformIdentityPub string `json:"platform_identity_pub"`
	IngestCert          string `json:"ingest_cert"`
	AdminCert           string `json:"admin_cert"`
	IdentitySuccession  string `json:"identity_succession"`
}

type keystoreVector struct {
	Comment    string `json:"comment"`
	Passphrase string `json:"passphrase"`
	Generation uint32 `json:"generation"`
	Identity   string `json:"identity_seed"`
	Unwrap     string `json:"unwrap_priv"`
	Random     string `json:"random"`
	File       string `json:"file"`
}

const created = int64(1761400000000) // 2025-10-25T13:46:40Z in milliseconds

// seeds returns the three fixed seeds used throughout the vectors.
func seeds() []struct {
	name string
	seed keys.Seed
} {
	var s1, s2, s3 keys.Seed
	for i := range s2 {
		s2[i] = byte(i + 1)
	}
	s3 = sha256.Sum256([]byte("gomail/v1/test-seed-3"))
	return []struct {
		name string
		seed keys.Seed
	}{{"zero", s1}, {"counter", s2}, {"sha256-of-label", s3}}
}

func main() {
	out := flag.String("out", "testdata", "output directory")
	flag.Parse()

	var dv struct {
		Comment string       `json:"comment"`
		Seeds   []seedVector `json:"seeds"`
	}
	dv.Comment = "HKDF derivation of specification 2.2 and 2.3 from three fixed seeds. secret is the 32 derived bytes (Ed25519 seed or X25519 scalar), public the public key."
	for _, s := range seeds() {
		seed := s.seed
		var v seedVector
		v.Name = s.name
		v.Seed = hex.EncodeToString(seed[:])
		words, err := seed.Words()
		check(err)
		v.Words = strings.Join(words, " ")
		u := keys.DeriveUser(&seed)
		root, err := u.RootKey()
		check(err)
		v.User.Root = edVec(0, root)
		p := keys.DerivePlatform(&seed)
		for g := uint32(1); g <= 2; g++ {
			id, err := u.IdentityKey(g)
			check(err)
			v.User.Identity = append(v.User.Identity, edVec(g, id))
			uw, err := u.UnwrapKey(g)
			check(err)
			v.User.Unwrap = append(v.User.Unwrap, xVec(g, uw))
			pid, err := p.IdentityKey(g)
			check(err)
			v.Platform.Identity = append(v.Platform.Identity, edVec(g, pid))
			pa, err := p.AdminKey(g)
			check(err)
			v.Platform.Admin = append(v.Platform.Admin, edVec(g, pa))
			pi, err := p.IngestKey(g)
			check(err)
			v.Platform.Ingest = append(v.Platform.Ingest, edVec(g, pi))
		}
		dv.Seeds = append(dv.Seeds, v)
	}
	writeJSON(filepath.Join(*out, "derive_vectors.json"), dv)

	// Certificates from the "counter" seed.
	seed := seeds()[1].seed
	u := keys.DeriveUser(&seed)
	root, err := u.RootKey()
	check(err)
	cv := certVectors{
		Comment: "Generation certificates 1..3 of the user derived from seed, signed by the root key; platform certificates signed by platform identity generation 1 of the same seed. created = 1761400000000 ms (+gen).",
		Seed:    hex.EncodeToString(seed[:]),
		RootPub: hex.EncodeToString(root.Public().(ed25519.PublicKey)),
	}
	for g := uint32(1); g <= 3; g++ {
		id, err := u.IdentityKey(g)
		check(err)
		uw, err := u.UnwrapKey(g)
		check(err)
		c, err := keys.NewGenerationCert(root, g, id.Public().(ed25519.PublicKey), uw.PublicKey(), created+int64(g))
		check(err)
		enc, err := c.Encode()
		check(err)
		cv.Generations = append(cv.Generations, hex.EncodeToString(enc))
	}
	p := keys.DerivePlatform(&seed)
	pid, err := p.IdentityKey(1)
	check(err)
	cv.PlatformIdentityPub = hex.EncodeToString(pid.Public().(ed25519.PublicKey))
	ingest, err := p.IngestKey(1)
	check(err)
	ic, err := keys.NewPlatformCert(pid, 1, keys.RoleIngest, 1, ingest.Public().(ed25519.PublicKey), created)
	check(err)
	cv.IngestCert = hexEncode(ic.Encode())
	admin, err := p.AdminKey(1)
	check(err)
	ac, err := keys.NewPlatformCert(pid, 1, keys.RoleAdmin, 1, admin.Public().(ed25519.PublicKey), created)
	check(err)
	cv.AdminCert = hexEncode(ac.Encode())
	pid2, err := p.IdentityKey(2)
	check(err)
	succ, err := keys.NewIdentitySuccession(pid, 2, pid2.Public().(ed25519.PublicKey), created)
	check(err)
	cv.IdentitySuccession = hexEncode(succ.Encode())
	writeJSON(filepath.Join(*out, "cert_vectors.json"), cv)

	// Key store with fixed salt and nonce (28 bytes of injected randomness).
	id, err := u.IdentityKey(1)
	check(err)
	uw, err := u.UnwrapKey(1)
	check(err)
	random := bytes.Repeat([]byte{0xa5}, 28)
	ks := &keys.Keystore{Generation: 1, Identity: id, Unwrap: uw}
	file, err := ks.Seal([]byte("phase0 test passphrase"), bytes.NewReader(random))
	check(err)
	writeJSON(filepath.Join(*out, "keystore_vector.json"), keystoreVector{
		Comment:    "Key store of generation 1 of the counter seed, sealed with the default Argon2id parameters, salt and nonce taken from the fixed random bytes.",
		Passphrase: "phase0 test passphrase",
		Generation: 1,
		Identity:   hex.EncodeToString(id.Seed()),
		Unwrap:     hex.EncodeToString(uw.Bytes()),
		Random:     hex.EncodeToString(random),
		File:       hex.EncodeToString(file),
	})
}

func edVec(gen uint32, k ed25519.PrivateKey) keyVector {
	return keyVector{Gen: gen, Secret: hex.EncodeToString(k.Seed()), Public: hex.EncodeToString(k.Public().(ed25519.PublicKey))}
}

func xVec(gen uint32, k *ecdh.PrivateKey) keyVector {
	return keyVector{Gen: gen, Secret: hex.EncodeToString(k.Bytes()), Public: hex.EncodeToString(k.PublicKey().Bytes())}
}

func hexEncode(b []byte, err error) string {
	check(err)
	return hex.EncodeToString(b)
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", " ")
	check(err)
	check(os.WriteFile(path, append(b, '\n'), 0o644))
	fmt.Println("wrote", path)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
