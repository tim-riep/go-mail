package client_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
)

type ecdhPriv = ecdh.PrivateKey

func ecdhGen() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
