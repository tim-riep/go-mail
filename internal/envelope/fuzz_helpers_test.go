package envelope

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func hexKey(s string) (*ecdh.PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(b)
}

func signerPublic(seedHex string) ed25519.PublicKey {
	b, _ := hex.DecodeString(seedHex)
	return ed25519.NewKeyFromSeed(b).Public().(ed25519.PublicKey)
}

type edPublicKey = ed25519.PublicKey

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
