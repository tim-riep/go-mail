package envelope

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
)

// Test fixtures. All keys and randomness are fixed so failures are
// reproducible; HPKE's ephemeral keys are the only nondeterministic part.

func x25519Key(t testing.TB, label string) *ecdh.PrivateKey {
	t.Helper()
	s := sha256.Sum256([]byte("envelope test x25519 " + label))
	k, err := ecdh.X25519().NewPrivateKey(s[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func edKey(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("envelope test ed25519 " + label))
	return ed25519.NewKeyFromSeed(s[:])
}

func id16(label string) (out [16]byte) {
	s := sha256.Sum256([]byte("envelope test id " + label))
	copy(out[:], s[:16])
	return
}

// pattern returns n bytes of deterministic, non-repeating content.
func pattern(n int) []byte {
	out := make([]byte, n)
	var block [32]byte
	for i := 0; i < n; i += 32 {
		block = sha256.Sum256(binary.BigEndian.AppendUint32([]byte("envelope pattern"), uint32(i/32)))
		copy(out[i:], block[:])
	}
	return out
}

// fixedRand returns an io.Reader with enough fixed bytes for one Seal.
func fixedRand(seed byte) io.Reader {
	b := make([]byte, 64)
	for i := range b {
		b[i] = seed ^ byte(i*17)
	}
	return bytes.NewReader(b)
}

func testHeader(kind Kind) Header {
	return Header{Kind: kind, MailboxID: id16("mailbox"), Epoch: 7, FileID: id16("file"), Created: 1761400000000}
}

var (
	contentKey = func(t testing.TB) *ecdh.PrivateKey { return x25519Key(t, "epoch content") }
	epochID    = id16("epoch")
)

func testRecipient(t testing.TB) Recipient {
	return Recipient{Type: RecipientEpochContent, ID: epochID, Gen: 1, PublicKey: contentKey(t).PublicKey()}
}

func testRecipientKey(t testing.TB) RecipientKey {
	return RecipientKey{Type: RecipientEpochContent, ID: epochID, Gen: 1, PrivateKey: contentKey(t)}
}

var ingestKey = edKey("ingest")

func testSigner() *Signer {
	return &Signer{Type: SignerIngest, ID: id16("ingest"), Gen: 1, Key: ingestKey}
}

func resolveIngest(ref SignerRef) (ed25519.PublicKey, error) {
	if ref.Type == SignerIngest && ref.ID == id16("ingest") && ref.Gen == 1 {
		return ingestKey.Public().(ed25519.PublicKey), nil
	}
	return nil, errors.New("unknown signer")
}

func seal(t testing.TB, hdr Header, plaintext []byte, signed bool) []byte {
	t.Helper()
	opts := &SealOptions{Rand: fixedRand(1)}
	if signed {
		opts.Signer = testSigner()
	}
	data, err := Seal(hdr, []Recipient{testRecipient(t)}, plaintext, opts)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func openOpts(t testing.TB, signed bool) OpenOptions {
	o := OpenOptions{ExpectedSuite: Suite1, Key: testRecipientKey(t)}
	if signed {
		o.ResolveSigner = resolveIngest
	} else {
		o.AllowUnsigned = true
	}
	return o
}

func mustOpen(t testing.TB, data []byte, signed bool) []byte {
	t.Helper()
	_, pt, err := Open(data, openOpts(t, signed))
	if err != nil {
		t.Fatal(err)
	}
	return pt
}

func mustFail(t testing.TB, data []byte, signed bool, want error) {
	t.Helper()
	f, pt, err := Open(data, openOpts(t, signed))
	if err == nil {
		t.Fatalf("expected %v, got success with %d plaintext bytes", want, len(pt))
	}
	if want != nil && !errors.Is(err, want) {
		t.Fatalf("expected %v, got %v", want, err)
	}
	if pt != nil || f != nil {
		t.Fatal("nothing may be returned on error")
	}
}

func TestRoundTripSizes(t *testing.T) {
	sizes := map[string]int{
		"empty":           0,
		"one byte":        1,
		"one block":       ChunkSize,
		"one block + 1":   ChunkSize + 1,
		"two blocks":      2 * ChunkSize,
		"two blocks + 1":  2*ChunkSize + 1,
		"three blocks -1": 3*ChunkSize - 1,
	}
	for name, n := range sizes {
		for _, signed := range []bool{false, true} {
			t.Run(name, func(t *testing.T) {
				pt := pattern(n)
				data := seal(t, testHeader(KindMail), pt, signed)
				f, err := Parse(data)
				if err != nil {
					t.Fatal(err)
				}
				wantBlocks := (n + ChunkSize - 1) / ChunkSize
				if n == 0 {
					wantBlocks = 1
				}
				if len(f.blocks) != wantBlocks {
					t.Fatalf("%d blocks, want %d", len(f.blocks), wantBlocks)
				}
				if (f.Trailer != nil) != signed {
					t.Fatal("trailer presence")
				}
				got := mustOpen(t, data, signed)
				if !bytes.Equal(got, pt) {
					t.Fatal("plaintext differs")
				}
				if !bytes.Equal(f.Bytes(), data) {
					t.Fatal("re-serialization differs")
				}
			})
		}
	}
}

func TestHeaderFields(t *testing.T) {
	hdr := testHeader(KindMeta)
	data := seal(t, hdr, []byte("x"), true)
	f, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if f.Suite != Suite1 || f.Header.Kind != KindMeta || f.Header.MailboxID != hdr.MailboxID || f.Header.Epoch != 7 || f.Header.FileID != hdr.FileID || f.Header.ChunkSize != ChunkSize || f.Header.Created != hdr.Created {
		t.Fatalf("header differs: %+v", f.Header)
	}
	if f.Header.NoncePrefix == ([7]byte{}) {
		t.Fatal("nonce prefix must be set")
	}
	if len(f.Recipients) != 1 || f.Recipients[0].Type != RecipientEpochContent || f.Recipients[0].ID != epochID || f.Recipients[0].Gen != 1 || len(f.Recipients[0].Enc) != 32 || len(f.Recipients[0].WrappedKey) != 48 {
		t.Fatalf("recipients differ: %+v", f.Recipients)
	}
	if f.Trailer.Signer.Type != SignerIngest || f.Trailer.Signer.ID != id16("ingest") || f.Trailer.Signer.Gen != 1 || len(f.Trailer.Signature) != 64 {
		t.Fatalf("trailer differs: %+v", f.Trailer)
	}
	// The preamble is exactly as specified.
	if !bytes.Equal(data[:6], []byte("GOML\x01\x01")) {
		t.Fatalf("preamble %x", data[:6])
	}
	// The file hash covers everything before the trailer length.
	h := sha256.Sum256(data[:f.trailerOffset])
	if f.FileHash() != h {
		t.Fatal("file hash")
	}
}

func TestDeterministicParts(t *testing.T) {
	// With the same injected randomness, preamble, header and all blocks
	// are identical. Recipient entries differ because HPKE draws its
	// ephemeral key from crypto/rand, and the trailer differs because
	// the signature covers the recipient section.
	pt := pattern(ChunkSize + 5)
	a := seal(t, testHeader(KindMail), pt, true)
	b := seal(t, testHeader(KindMail), pt, true)
	fa, _ := Parse(a)
	fb, _ := Parse(b)
	if !bytes.Equal(fa.headerBytes, fb.headerBytes) || !bytes.Equal(a[:6], b[:6]) {
		t.Fatal("header must be deterministic")
	}
	if len(fa.blocks) != len(fb.blocks) {
		t.Fatal("block count")
	}
	for i := range fa.blocks {
		if !bytes.Equal(fa.blocks[i], fb.blocks[i]) {
			t.Fatalf("block %d must be deterministic", i)
		}
	}
	if bytes.Equal(fa.Recipients[0].Enc, fb.Recipients[0].Enc) {
		t.Fatal("HPKE encapsulations must differ between seals")
	}
	// Different randomness gives different nonce prefix and ciphertext.
	c, _ := Seal(testHeader(KindMail), []Recipient{testRecipient(t)}, pt, &SealOptions{Rand: fixedRand(2)})
	fc, _ := Parse(c)
	if fc.Header.NoncePrefix == fa.Header.NoncePrefix || bytes.Equal(fc.blocks[0], fa.blocks[0]) {
		t.Fatal("randomness must come from the injected reader")
	}
}

func TestStreamingWriterMatchesSeal(t *testing.T) {
	pt := pattern(2*ChunkSize + 333)
	want := seal(t, testHeader(KindPending), pt, true)
	var buf bytes.Buffer
	w, err := NewWriter(&buf, testHeader(KindPending), []Recipient{testRecipient(t)}, &SealOptions{Rand: fixedRand(1), Signer: testSigner()})
	if err != nil {
		t.Fatal(err)
	}
	// Many odd-sized writes, including empty ones.
	for i := 0; i < len(pt); {
		n := (i*7)%1000 + 1
		if i+n > len(pt) {
			n = len(pt) - i
		}
		if _, err := w.Write(pt[i : i+n]); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(nil); err != nil {
			t.Fatal(err)
		}
		i += n
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	fw, err := Parse(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := Parse(want)
	if !bytes.Equal(fw.headerBytes, fs.headerBytes) || len(fw.blocks) != len(fs.blocks) {
		t.Fatal("streamed file differs in header or block count")
	}
	for i := range fw.blocks {
		if !bytes.Equal(fw.blocks[i], fs.blocks[i]) {
			t.Fatalf("block %d differs", i)
		}
	}
	if got := mustOpen(t, buf.Bytes(), true); !bytes.Equal(got, pt) {
		t.Fatal("streamed plaintext differs")
	}
	// Writer misuse.
	if _, err := w.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatal("write after close must fail")
	}
	if err := w.Close(); !errors.Is(err, ErrClosed) {
		t.Fatal("double close must fail")
	}
}

func TestWriterLimits(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, testHeader(KindMail), []Recipient{testRecipient(t)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, ChunkSize)
	for i := 0; i < MaxBlocks; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
	}
	// The 800 blocks are complete; one more byte exceeds the limit.
	if _, err := w.Write([]byte{1}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
	if _, err := Seal(testHeader(KindMail), []Recipient{testRecipient(t)}, make([]byte, MaxContentSize+1), nil); !errors.Is(err, ErrTooLarge) {
		t.Fatal("Seal must enforce the size limit")
	}
	// Exactly the maximum works.
	var buf2 bytes.Buffer
	w2, _ := NewWriter(&buf2, testHeader(KindMail), []Recipient{testRecipient(t)}, nil)
	for i := 0; i < MaxBlocks; i++ {
		w2.Write(chunk)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := Parse(buf2.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.blocks) != MaxBlocks {
		t.Fatal("block count at the limit")
	}
}

func TestSealRejects(t *testing.T) {
	r := testRecipient(t)
	lowOrder, _ := ecdh.X25519().NewPublicKey(make([]byte, 32))
	many := make([]Recipient, MaxRecipients+1)
	for i := range many {
		many[i] = r
		many[i].Gen = uint32(i + 1)
	}
	cases := []struct {
		name string
		hdr  Header
		recs []Recipient
		opts *SealOptions
		err  error
	}{
		{"kind 0", Header{}, []Recipient{r}, nil, ErrHeader},
		{"kind 6", Header{Kind: 6}, []Recipient{r}, nil, ErrHeader},
		{"chunk size 1024", func() Header { h := testHeader(KindMail); h.ChunkSize = 1024; return h }(), []Recipient{r}, nil, ErrHeader},
		{"no recipients", testHeader(KindMail), nil, nil, ErrRecipients},
		{"too many recipients", testHeader(KindMail), many, nil, ErrRecipients},
		{"duplicate recipient", testHeader(KindMail), []Recipient{r, r}, nil, ErrRecipients},
		{"recipient type 0", testHeader(KindMail), []Recipient{{Type: 0, ID: r.ID, Gen: 1, PublicKey: r.PublicKey}}, nil, ErrRecipients},
		{"recipient type 4", testHeader(KindMail), []Recipient{{Type: 4, ID: r.ID, Gen: 1, PublicKey: r.PublicKey}}, nil, ErrRecipients},
		{"recipient gen 0", testHeader(KindMail), []Recipient{{Type: r.Type, ID: r.ID, Gen: 0, PublicKey: r.PublicKey}}, nil, ErrRecipients},
		{"nil public key", testHeader(KindMail), []Recipient{{Type: r.Type, ID: r.ID, Gen: 1}}, nil, ErrRecipients},
		{"low-order public key", testHeader(KindMail), []Recipient{{Type: r.Type, ID: r.ID, Gen: 1, PublicKey: lowOrder}}, nil, ErrWrap},
		{"signer type 0", testHeader(KindMail), []Recipient{r}, &SealOptions{Signer: &Signer{Type: 0, Gen: 1, Key: ingestKey}}, ErrSigner},
		{"signer type 3", testHeader(KindMail), []Recipient{r}, &SealOptions{Signer: &Signer{Type: 3, Gen: 1, Key: ingestKey}}, ErrSigner},
		{"signer gen 0", testHeader(KindMail), []Recipient{r}, &SealOptions{Signer: &Signer{Type: SignerUser, Gen: 0, Key: ingestKey}}, ErrSigner},
		{"signer bad key", testHeader(KindMail), []Recipient{r}, &SealOptions{Signer: &Signer{Type: SignerUser, Gen: 1, Key: ingestKey[:10]}}, ErrSigner},
		{"signer extra too long", testHeader(KindMail), []Recipient{r}, &SealOptions{Signer: &Signer{Type: SignerUser, Gen: 1, Key: ingestKey, Extra: make([]byte, MaxExtraSize+1)}}, ErrSigner},
		{"short random", testHeader(KindMail), []Recipient{r}, &SealOptions{Rand: bytes.NewReader([]byte{1, 2, 3})}, ErrRandom},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := Seal(tc.hdr, tc.recs, []byte("x"), tc.opts)
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if data != nil {
				t.Fatal("no data on error")
			}
			if _, err := NewWriter(io.Discard, tc.hdr, tc.recs, tc.opts); err == nil {
				t.Fatal("NewWriter must reject the same input")
			}
		})
	}
	if _, err := NewWriter(nil, testHeader(KindMail), []Recipient{r}, nil); err == nil {
		t.Fatal("nil writer must be rejected")
	}
}

func TestOpenPolicy(t *testing.T) {
	unsigned := seal(t, testHeader(KindMail), []byte("x"), false)
	signed := seal(t, testHeader(KindMeta), []byte("x"), true)
	key := testRecipientKey(t)
	cases := []struct {
		name string
		data []byte
		opts OpenOptions
		err  error
	}{
		{"suite not given", unsigned, OpenOptions{Key: key, AllowUnsigned: true}, ErrSuite},
		{"suite 2 expected", unsigned, OpenOptions{ExpectedSuite: 2, Key: key, AllowUnsigned: true}, ErrSuite},
		{"unsigned not allowed", unsigned, OpenOptions{ExpectedSuite: Suite1, Key: key}, ErrUnsigned},
		{"signed without resolver", signed, OpenOptions{ExpectedSuite: Suite1, Key: key, AllowUnsigned: true}, ErrSignaturePolicy},
		{"resolver rejects", signed, OpenOptions{ExpectedSuite: Suite1, Key: key, ResolveSigner: func(SignerRef) (ed25519.PublicKey, error) { return nil, errors.New("no") }}, ErrSigner},
		{"resolver returns wrong key", signed, OpenOptions{ExpectedSuite: Suite1, Key: key, ResolveSigner: func(SignerRef) (ed25519.PublicKey, error) { return edKey("other").Public().(ed25519.PublicKey), nil }}, ErrSignature},
		{"resolver returns short key", signed, OpenOptions{ExpectedSuite: Suite1, Key: key, ResolveSigner: func(SignerRef) (ed25519.PublicKey, error) { return ed25519.PublicKey{1}, nil }}, ErrSignature},
		{"extra mismatch", signed, OpenOptions{ExpectedSuite: Suite1, Key: key, ResolveSigner: resolveIngest, Extra: []byte("e")}, ErrSignature},
		{"no key", unsigned, OpenOptions{ExpectedSuite: Suite1, AllowUnsigned: true}, ErrNoRecipient},
		{"wrong recipient id", unsigned, OpenOptions{ExpectedSuite: Suite1, AllowUnsigned: true, Key: RecipientKey{Type: key.Type, ID: id16("other"), Gen: 1, PrivateKey: key.PrivateKey}}, ErrNoRecipient},
		{"wrong recipient gen", unsigned, OpenOptions{ExpectedSuite: Suite1, AllowUnsigned: true, Key: RecipientKey{Type: key.Type, ID: key.ID, Gen: 2, PrivateKey: key.PrivateKey}}, ErrNoRecipient},
		{"wrong recipient type", unsigned, OpenOptions{ExpectedSuite: Suite1, AllowUnsigned: true, Key: RecipientKey{Type: RecipientEpochMeta, ID: key.ID, Gen: 1, PrivateKey: key.PrivateKey}}, ErrNoRecipient},
		{"wrong private key", unsigned, OpenOptions{ExpectedSuite: Suite1, AllowUnsigned: true, Key: RecipientKey{Type: key.Type, ID: key.ID, Gen: 1, PrivateKey: x25519Key(t, "other")}}, ErrUnwrap},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, pt, err := Open(tc.data, tc.opts)
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if f != nil || pt != nil {
				t.Fatal("nothing may be returned on error")
			}
		})
	}
	// A signed file with the right resolver and the matching extra works;
	// a file sealed with extra needs the same extra to verify.
	data, err := Seal(testHeader(KindMeta), []Recipient{testRecipient(t)}, []byte("x"), &SealOptions{Signer: &Signer{Type: SignerIngest, ID: id16("ingest"), Gen: 1, Key: ingestKey, Extra: []byte("meta fields")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(data, OpenOptions{ExpectedSuite: Suite1, Key: key, ResolveSigner: resolveIngest, Extra: []byte("meta fields")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(data, OpenOptions{ExpectedSuite: Suite1, Key: key, ResolveSigner: resolveIngest}); !errors.Is(err, ErrSignature) {
		t.Fatal("missing extra must fail")
	}
}

func TestSuiteTransition(t *testing.T) {
	if err := CheckSuiteTransition(Suite1, Suite1); err != nil {
		t.Fatal(err)
	}
	if err := CheckSuiteTransition(Suite1, 2); err != nil {
		t.Fatal("a newer suite is allowed")
	}
	if err := CheckSuiteTransition(2, Suite1); !errors.Is(err, ErrSuite) {
		t.Fatal("a downgrade must be rejected")
	}
	if err := CheckSuiteTransition(0, Suite1); !errors.Is(err, ErrSuite) {
		t.Fatal("suite 0 is invalid")
	}
	if err := CheckSuiteTransition(Suite1, 0); !errors.Is(err, ErrSuite) {
		t.Fatal("suite 0 is invalid")
	}
}

func TestMultipleRecipients(t *testing.T) {
	metaKey := x25519Key(t, "epoch meta")
	userKey := x25519Key(t, "user unwrap")
	recs := []Recipient{
		testRecipient(t),
		{Type: RecipientEpochMeta, ID: epochID, Gen: 1, PublicKey: metaKey.PublicKey()},
		{Type: RecipientUserUnwrap, ID: id16("user"), Gen: 3, PublicKey: userKey.PublicKey()},
	}
	pt := pattern(100)
	data, err := Seal(testHeader(KindWrap), recs, pt, &SealOptions{Rand: fixedRand(3), Signer: testSigner()})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []RecipientKey{
		testRecipientKey(t),
		{Type: RecipientEpochMeta, ID: epochID, Gen: 1, PrivateKey: metaKey},
		{Type: RecipientUserUnwrap, ID: id16("user"), Gen: 3, PrivateKey: userKey},
	} {
		_, got, err := Open(data, OpenOptions{ExpectedSuite: Suite1, Key: k, ResolveSigner: resolveIngest})
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("recipient %d: %v", k.Type, err)
		}
	}
	// The same key material under another (type, id, gen) is not accepted.
	_, _, err = Open(data, OpenOptions{ExpectedSuite: Suite1, Key: RecipientKey{Type: RecipientUserUnwrap, ID: id16("user"), Gen: 4, PrivateKey: userKey}, ResolveSigner: resolveIngest})
	if !errors.Is(err, ErrNoRecipient) {
		t.Fatal("generation must match")
	}
}

func TestSignatureDomainBinding(t *testing.T) {
	// A trailer signed under the domain of another file kind is rejected
	// even if everything else matches.
	pt := []byte("content")
	data := seal(t, testHeader(KindWrap), pt, true)
	f, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := f.signedBytes(f.Trailer.Signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Re-sign the correct structure under the wrong domain ("meta").
	sig, err := keys.Sign(ingestKey, KindMeta.String(), signed)
	if err != nil {
		t.Fatal(err)
	}
	forged := replaceTrailer(t, data, f, sig)
	mustFail(t, forged, true, ErrSignature)
	// Sanity: re-signing under the right domain is accepted.
	sig, _ = keys.Sign(ingestKey, KindWrap.String(), signed)
	if got := mustOpen(t, replaceTrailer(t, data, f, sig), true); !bytes.Equal(got, pt) {
		t.Fatal("re-signed file must open")
	}
}

// replaceTrailer rebuilds data with a new signature in the trailer.
func replaceTrailer(t testing.TB, data []byte, f *File, sig []byte) []byte {
	t.Helper()
	tr := *f.Trailer
	tr.Signature = sig
	tb, err := tr.encode()
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte(nil), data[:f.trailerOffset]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(tb)))
	return append(out, tb...)
}

func TestKindNames(t *testing.T) {
	names := map[Kind]string{KindMail: "mail", KindMeta: "meta", KindPending: "pending", KindWrap: "wrap", KindIndex: "index"}
	for k, n := range names {
		if k.String() != n {
			t.Fatalf("%d: %q", k, k.String())
		}
	}
	if Kind(0).String() == "" || Kind(9).String() == "" {
		t.Fatal("unknown kinds need a name too")
	}
}
