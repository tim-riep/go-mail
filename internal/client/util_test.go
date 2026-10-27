package client_test

import (
	"testing"

	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"github.com/tim-riep/go-mail/internal/envelope"
)

type ecdhPriv = ecdh.PrivateKey

func ecdhGen() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

func parse(t *testing.T, data []byte) *envelope.File {
	t.Helper()
	f, err := envelope.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
