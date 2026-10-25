package envelope

import (
	"bytes"
	"crypto/ecdh"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
)

func keysSign(key []byte, kind Kind, body []byte) ([]byte, error) {
	return keys.Sign(key, kind.String(), body)
}

// flipEvery runs check for every single-bit modification of data (or of a
// sample of positions when sample > 1).
func flipEvery(t *testing.T, data []byte, sample int, check func(pos int, mutated []byte)) {
	t.Helper()
	buf := append([]byte(nil), data...)
	for i := 0; i < len(data); i++ {
		if sample > 1 && i%sample != 0 && i >= 512 && i < len(data)-512 {
			continue
		}
		for bit := 0; bit < 8; bit++ {
			buf[i] ^= 1 << bit
			check(i, buf)
			buf[i] ^= 1 << bit
		}
	}
}

// TestBitFlipSigned: on a signed file every single-bit change anywhere is
// rejected, because the signature covers everything before the trailer
// and the trailer itself is the signature.
func TestBitFlipSigned(t *testing.T) {
	pt := pattern(17)
	data := seal(t, testHeader(KindMeta), pt, true)
	opts := openOpts(t, true)
	flipEvery(t, data, 1, func(pos int, m []byte) {
		if f, got, err := Open(m, opts); err == nil || f != nil || got != nil {
			t.Fatalf("bit flip at byte %d accepted", pos)
		}
	})
}

// TestBitFlipUnsigned: on an unsigned file with one recipient every
// single-bit change is rejected.
func TestBitFlipUnsigned(t *testing.T) {
	pt := pattern(17)
	data := seal(t, testHeader(KindMail), pt, false)
	opts := openOpts(t, false)
	flipEvery(t, data, 1, func(pos int, m []byte) {
		if f, got, err := Open(m, opts); err == nil || f != nil || got != nil {
			t.Fatalf("bit flip at byte %d accepted", pos)
		}
	})
}

// TestBitFlipLarge samples positions of a three-block file.
func TestBitFlipLarge(t *testing.T) {
	pt := pattern(2*ChunkSize + 1)
	data := seal(t, testHeader(KindMail), pt, false)
	opts := openOpts(t, false)
	flipEvery(t, data, 4099, func(pos int, m []byte) {
		if f, got, err := Open(m, opts); err == nil || f != nil || got != nil {
			t.Fatalf("bit flip at byte %d accepted", pos)
		}
	})
}

// TestBitFlipForeignRecipient documents the one exception: in an unsigned
// file, bits inside the entry of another recipient are not covered by
// anything the opening key can check. A flip there is either rejected
// (when it breaks the structure or makes the entry collide with the
// opener's own) or yields exactly the original plaintext, never anything
// else. Bits anywhere else, including the opener's own entry, are always
// rejected. With a signature every flip is rejected (TestBitFlipSigned
// covers one recipient; this test covers two).
func TestBitFlipForeignRecipient(t *testing.T) {
	other := x25519Key(t, "other recipient")
	recs := []Recipient{
		testRecipient(t),
		{Type: RecipientEpochMeta, ID: epochID, Gen: 1, PublicKey: other.PublicKey()},
	}
	pt := pattern(9)
	for _, signed := range []bool{false, true} {
		opts := &SealOptions{Rand: fixedRand(4)}
		if signed {
			opts.Signer = testSigner()
		}
		data, err := Seal(testHeader(KindWrap), recs, pt, opts)
		if err != nil {
			t.Fatal(err)
		}
		f, _ := Parse(data)
		ranges := f.recipientRanges()
		if len(ranges) != 2 || f.Recipients[1].Type != RecipientEpochMeta {
			t.Fatal("expected the foreign entry second")
		}
		foreign := ranges[1]
		// Everything inside the foreign entry (its type, id, gen, enc and
		// wrapped_key) is uncheckable for the opener as long as the entry
		// stays structurally valid and does not collide with the opener's
		// own (type, id, gen). The entry's length prefix and the list
		// count lie outside the range and are structure.
		inForeign := func(pos int) bool {
			return pos >= foreign[0] && pos < foreign[1]
		}
		o := openOpts(t, signed)
		accepted, rejected := 0, 0
		flipEvery(t, data, 1, func(pos int, m []byte) {
			_, got, err := Open(m, o)
			if err != nil {
				rejected++
				return
			}
			accepted++
			if signed {
				t.Fatalf("signed: flip at %d accepted", pos)
			}
			if !inForeign(pos) {
				t.Fatalf("unsigned: flip at %d outside the foreign entry accepted", pos)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("flip at %d changed the plaintext", pos)
			}
		})
		if !signed && accepted == 0 {
			t.Fatal("expected some flips in the foreign entry to go unnoticed")
		}
		if signed && accepted != 0 {
			t.Fatal("signed file must reject everything")
		}
		t.Logf("signed=%v: %d flips rejected, %d unnoticed (foreign entry only)", signed, rejected, accepted)
	}
}

func TestOpenNeverReturnsPartialPlaintext(t *testing.T) {
	// Corrupt only the last block of a three-block file: the first two
	// blocks decrypt fine, but nothing is returned.
	pt := pattern(2*ChunkSize + 1)
	data := seal(t, testHeader(KindMail), pt, false)
	p := split(t, data)
	q := p.with(func(p *parts) { b := append([]byte(nil), p.blocks[2]...); b[0] ^= 1; p.blocks[2] = b })
	f, _ := Parse(q.build())
	got, err := f.Decrypt(testRecipientKey(t))
	if err == nil || got != nil {
		t.Fatal("partial plaintext returned")
	}
}

var _ = ecdh.X25519
