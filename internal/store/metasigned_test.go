package store

import (
	"bytes"
	"errors"
	"testing"

	"github.com/tim-riep/go-mail/internal/envelope"
)

// TestMetaSignedExtra checks that meta-signed built from the header alone
// equals the one built from consistent metadata, and that every value of
// it is bound (section 7).
func TestMetaSignedExtra(t *testing.T) {
	m := testMeta()
	m.Version = 3
	mbx := ID{1, 2}
	h := envelope.Header{Kind: envelope.KindMeta, MailboxID: mbx, Epoch: 2, FileID: m.MailID, Created: m.Received, ChunkSize: envelope.ChunkSize, Version: m.Version}
	fromHeader, err := MetaSignedExtra(h, m.MailHash)
	if err != nil {
		t.Fatal(err)
	}
	fromMeta, err := m.SignedExtra(mbx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromHeader, fromMeta) {
		t.Fatal("meta-signed from the header differs from the metadata")
	}
	// The nonce prefix and the chunk size are not part of it.
	h2 := h
	h2.NoncePrefix[0] ^= 1
	if b, _ := MetaSignedExtra(h2, m.MailHash); !bytes.Equal(b, fromHeader) {
		t.Fatal("nonce prefix in meta-signed")
	}
	// Every other value is bound.
	for name, f := range map[string]func(h *envelope.Header, hash *[32]byte){
		"mailbox": func(h *envelope.Header, _ *[32]byte) { h.MailboxID[0] ^= 1 },
		"epoch":   func(h *envelope.Header, _ *[32]byte) { h.Epoch++ },
		"file id": func(h *envelope.Header, _ *[32]byte) { h.FileID[0] ^= 1 },
		"created": func(h *envelope.Header, _ *[32]byte) { h.Created++ },
		"hash":    func(_ *envelope.Header, hash *[32]byte) { hash[0] ^= 1 },
		"version": func(h *envelope.Header, _ *[32]byte) { h.Version++ },
	} {
		hc, hash := h, m.MailHash
		f(&hc, &hash)
		b, err := MetaSignedExtra(hc, hash)
		if err != nil || bytes.Equal(b, fromHeader) {
			t.Fatalf("%s not bound: %v", name, err)
		}
	}
	// Only complete meta headers.
	for name, f := range map[string]func(h *envelope.Header){
		"kind mail":    func(h *envelope.Header) { h.Kind = envelope.KindMail },
		"kind wrap":    func(h *envelope.Header) { h.Kind = envelope.KindWrap },
		"version 0":    func(h *envelope.Header) { h.Version = 0 },
		"epoch 0":      func(h *envelope.Header) { h.Epoch = 0 },
		"zero mailbox": func(h *envelope.Header) { h.MailboxID = [16]byte{} },
		"zero file id": func(h *envelope.Header) { h.FileID = [16]byte{} },
	} {
		hc := h
		f(&hc)
		if _, err := MetaSignedExtra(hc, m.MailHash); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s accepted", name)
		}
	}
}
