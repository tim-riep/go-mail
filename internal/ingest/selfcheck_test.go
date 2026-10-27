package ingest

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// sealSigned seals a file of hdr signed by key as signer (type, id) of
// generation 1 with extra.
func sealSigned(t *testing.T, hdr envelope.Header, key ed25519.PrivateKey, typ envelope.SignerType, id [16]byte, extra []byte) []byte {
	t.Helper()
	return sealSignedGen(t, hdr, key, typ, id, 1, extra)
}

// sealSignedGen is sealSigned with signer generation signerGen in the
// trailer.
func sealSignedGen(t *testing.T, hdr envelope.Header, key ed25519.PrivateKey, typ envelope.SignerType, id [16]byte, signerGen uint32, extra []byte) []byte {
	t.Helper()
	pk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gen := hdr.Epoch
	if gen == 0 {
		gen = 1
	}
	var opts *envelope.SealOptions
	if key != nil {
		opts = &envelope.SealOptions{Signer: &envelope.Signer{Type: typ, ID: id, Gen: signerGen, Key: key, Extra: extra}}
	}
	data, err := envelope.Seal(hdr, []envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: hdr.MailboxID, Gen: gen, PublicKey: pk.PublicKey()}},
		[]byte("ciphertext only"), opts)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func metaExtra(t *testing.T, h envelope.Header, mailHash [32]byte) []byte {
	t.Helper()
	extra, err := store.MetaSignedExtra(h, mailHash)
	if err != nil {
		t.Fatal(err)
	}
	return extra
}

// TestVerifyMeta: the ingest signature of metadata is checked from the
// clear header and the hash of the mail file alone (section 7).
func TestVerifyMeta(t *testing.T) {
	env := testenv.New(t)
	key := env.IngestKey
	pub := key.Public().(ed25519.PublicKey)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	mailHash := sha256.Sum256([]byte("the mail file"))
	hdr := envelope.Header{Kind: envelope.KindMeta, MailboxID: [16]byte{1}, Epoch: 3, FileID: [16]byte{2}, Created: testenv.Start.UnixMilli(), Version: 1}
	valid := sealSigned(t, hdr, key, envelope.SignerIngest, [16]byte{}, metaExtra(t, hdr, mailHash))

	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-1] ^= 1 // last byte of the signature in the trailer

	v2 := hdr
	v2.Version = 2
	otherVersion := sealSigned(t, v2, key, envelope.SignerIngest, [16]byte{}, metaExtra(t, hdr, mailHash))
	later := hdr
	later.Created++
	otherReceipt := sealSigned(t, later, key, envelope.SignerIngest, [16]byte{}, metaExtra(t, hdr, mailHash))
	otherHash := sealSigned(t, hdr, key, envelope.SignerIngest, [16]byte{}, metaExtra(t, hdr, sha256.Sum256([]byte("another mail"))))
	otherMailbox := hdr
	otherMailbox.MailboxID = [16]byte{9}
	otherBox := sealSigned(t, otherMailbox, key, envelope.SignerIngest, [16]byte{}, metaExtra(t, hdr, mailHash))
	noExtra := sealSigned(t, hdr, key, envelope.SignerIngest, [16]byte{}, nil)
	unsigned := sealSigned(t, hdr, nil, 0, [16]byte{}, nil)
	userSigned := sealSigned(t, hdr, key, envelope.SignerUser, [16]byte{3}, metaExtra(t, hdr, mailHash))
	ph := envelope.Header{Kind: envelope.KindPending, MailboxID: hdr.MailboxID, Epoch: hdr.Epoch, FileID: hdr.FileID, Created: hdr.Created}
	pending := sealSigned(t, ph, key, envelope.SignerIngest, [16]byte{}, nil)
	// Signed by the key of generation 1, but the trailer claims signer_gen 2.
	gen2 := sealSignedGen(t, hdr, key, envelope.SignerIngest, [16]byte{}, 2, metaExtra(t, hdr, mailHash))

	for _, tc := range []struct {
		name  string
		data  []byte
		hash  [32]byte
		gen   uint32
		pub   ed25519.PublicKey
		cause error
	}{
		{"valid", valid, mailHash, 1, pub, nil},
		{"trailer signer_gen 2, key of generation 1", gen2, mailHash, 1, pub, envelope.ErrSigner},
		{"trailer signer_gen 1, key given as generation 2", valid, mailHash, 2, pub, envelope.ErrSigner},
		{"generation 0", valid, mailHash, 0, pub, envelope.ErrSigner},
		{"trailer manipulated", tampered, mailHash, 1, pub, envelope.ErrSignature},
		{"other mail hash", valid, sha256.Sum256([]byte("x")), 1, pub, envelope.ErrSignature},
		{"extra of another mail hash", otherHash, mailHash, 1, pub, envelope.ErrSignature},
		{"extra of another version", otherVersion, mailHash, 1, pub, envelope.ErrSignature},
		{"extra of another receipt", otherReceipt, mailHash, 1, pub, envelope.ErrSignature},
		{"extra of another mailbox", otherBox, mailHash, 1, pub, envelope.ErrSignature},
		{"signed without extra", noExtra, mailHash, 1, pub, envelope.ErrSignature},
		{"wrong key", valid, mailHash, 1, other.Public().(ed25519.PublicKey), envelope.ErrSignature},
		{"short key", valid, mailHash, 1, pub[:31], envelope.ErrSignature},
		{"no key", valid, mailHash, 1, nil, envelope.ErrSignature},
		{"unsigned", unsigned, mailHash, 1, pub, envelope.ErrUnsigned},
		{"user signer", userSigned, mailHash, 1, pub, envelope.ErrSigner},
		{"kind pending", pending, mailHash, 1, pub, nil},
		{"garbage", []byte("GOML junk"), mailHash, 1, pub, nil},
		{"empty", nil, mailHash, 1, pub, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyMeta(tc.data, tc.hash, tc.gen, tc.pub)
			if tc.name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrSignature) {
				t.Fatalf("accepted or wrong error: %v", err)
			}
			if tc.cause != nil && !errors.Is(err, tc.cause) {
				t.Fatalf("cause: %v", err)
			}
		})
	}
	// A header without version cannot even be sealed as meta; a meta
	// header that MetaSignedExtra refuses (epoch 0) is refused as well.
	zero := hdr
	zero.Epoch = 0
	if err := VerifyMeta(sealSigned(t, zero, key, envelope.SignerIngest, [16]byte{}, metaExtra(t, hdr, mailHash)), mailHash, 1, pub); !errors.Is(err, ErrSignature) || !errors.Is(err, store.ErrRecord) {
		t.Fatalf("epoch 0: %v", err)
	}
}

// TestVerifyPending: term lists and markers carry no kind-specific
// fields; their signature is checked over the file alone.
func TestVerifyPending(t *testing.T) {
	env := testenv.New(t)
	key := env.IngestKey
	pub := key.Public().(ed25519.PublicKey)
	hdr := envelope.Header{Kind: envelope.KindPending, MailboxID: [16]byte{1}, Epoch: 3, FileID: [16]byte{2}, Created: testenv.Start.UnixMilli()}
	valid := sealSigned(t, hdr, key, envelope.SignerIngest, [16]byte{}, pendingSignedExtra(hdr))
	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-1] ^= 1
	withExtra := sealSigned(t, hdr, key, envelope.SignerIngest, [16]byte{}, []byte{1})
	unsigned := sealSigned(t, hdr, nil, 0, [16]byte{}, nil)
	userSigned := sealSigned(t, hdr, key, envelope.SignerUser, [16]byte{3}, nil)
	mh := envelope.Header{Kind: envelope.KindMeta, MailboxID: [16]byte{1}, Epoch: 3, FileID: [16]byte{2}, Created: hdr.Created, Version: 1}
	meta := sealSigned(t, mh, key, envelope.SignerIngest, [16]byte{}, nil)
	if err := VerifyPending(valid, 1, pub); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"tampered": tampered, "extra": withExtra, "unsigned": unsigned, "user": userSigned, "meta": meta, "garbage": []byte("x")} {
		if err := VerifyPending(data, 1, pub); !errors.Is(err, ErrSignature) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// The key is bound to the generation in the trailer: signer_gen 2 with
	// the key of generation 1 is refused, and so is the reverse.
	gen2 := sealSignedGen(t, hdr, key, envelope.SignerIngest, [16]byte{}, 2, pendingSignedExtra(hdr))
	if err := VerifyPending(gen2, 1, pub); !errors.Is(err, ErrSignature) || !errors.Is(err, envelope.ErrSigner) {
		t.Fatalf("signer_gen 2, key of generation 1: %v", err)
	}
	if err := VerifyPending(valid, 2, pub); !errors.Is(err, ErrSignature) || !errors.Is(err, envelope.ErrSigner) {
		t.Fatalf("signer_gen 1, generation 2: %v", err)
	}
	if err := VerifyPending(gen2, 2, pub); err != nil {
		t.Fatalf("signer_gen 2, generation 2: %v", err)
	}
	if err := VerifyPending(valid, 1, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey)); !errors.Is(err, envelope.ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
}

// Every file a delivery leaves verifies with the public key of
// ingest-1.cert and the hash of its mail file.
func TestDeliveredFilesVerify(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	in := newIngest(t, env)
	for _, msg := range []string{message("one", "x"), "no header end"} {
		if err := deliver(t, in, "s@x", []string{"a@example.org"}, msg); err != nil {
			t.Fatal(err)
		}
	}
	if err := in.Flush(); err != nil {
		t.Fatal(err)
	}
	cert, err := env.Store.ReadPlatformCert(keys.RoleIngest, 1)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := env.Store.ReadMailbox(mbx)
	list, err := u.Client.List(mbx, store.ID{})
	if err != nil || len(list) != 2 {
		t.Fatalf("%d mails: %v", len(list), err)
	}
	for _, mail := range list {
		meta := mustRead(t, env.Store.MetaFile(mbx, m.Inbox, mail.ID))
		hash := sha256.Sum256(mustRead(t, env.Store.MailFile(mbx, m.Inbox, mail.ID)))
		if err := VerifyMeta(meta, hash, cert.Gen, cert.Pub); err != nil {
			t.Fatal(err)
		}
		if err := VerifyMeta(meta, sha256.Sum256(nil), cert.Gen, cert.Pub); !errors.Is(err, ErrSignature) {
			t.Fatal("another mail file accepted")
		}
	}
	ids, _ := env.Store.ListPending(mbx, 1)
	if len(ids) != 2 { // one term list, one marker
		t.Fatalf("pending files %d", len(ids))
	}
	for _, id := range ids {
		data, err := env.Store.ReadPending(mbx, 1, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyPending(data, cert.Gen, cert.Pub); err != nil {
			t.Fatal(err)
		}
	}
}

// selfCheckEnv is a server whose log is kept, and a hook that records the
// points of a delivery.
type selfCheckEnv struct {
	env    *testenv.Env
	u      *testenv.User
	mbx    store.ID
	in     *Ingest
	log    *syncBuffer
	points []string
}

func newSelfCheckEnv(t *testing.T) *selfCheckEnv {
	t.Helper()
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	buf := &syncBuffer{}
	in := newIngest(t, env, func(c *Config) { c.Logger = slog.New(slog.NewTextHandler(buf, nil)); c.BatchAge = 1 << 62 })
	x := &selfCheckEnv{env: env, u: u, mbx: mbx, in: in, log: buf}
	t.Cleanup(func() { crashHook = nil })
	return x
}

// hook records every point; at point at it calls f.
func (x *selfCheckEnv) hook(at string, f func()) {
	x.points = nil
	crashHook = func(p string) bool {
		x.points = append(x.points, p)
		if p == at && f != nil {
			f()
		}
		return false
	}
}

func (x *selfCheckEnv) reached(p string) bool {
	for _, q := range x.points {
		if q == p {
			return true
		}
	}
	return false
}

// spoolFile returns the only file name in spool/<txn>/<mailbox>/.
func (x *selfCheckEnv) spoolFile(t *testing.T, name string) string {
	t.Helper()
	txns, _ := os.ReadDir(x.env.Store.SpoolDir())
	if len(txns) != 1 {
		t.Fatalf("spool: %d transactions", len(txns))
	}
	return x.env.Store.Path("spool", txns[0].Name(), x.mbx.String(), name)
}

func flip(t *testing.T, path string) {
	t.Helper()
	data := mustRead(t, path)
	data[len(data)-1] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The self-check refuses the delivery before the journal (451) and leaves
// nothing in the mailbox or the spool: with a signer whose key is not the
// certified one, and with metadata or marker changed on disk after they
// were written.
func TestSelfCheckRefusesDelivery(t *testing.T) {
	for _, tc := range []string{"signer", "meta", "marker"} {
		t.Run(tc, func(t *testing.T) {
			x := newSelfCheckEnv(t)
			switch tc {
			case "signer":
				x.in.signer = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
				x.hook("", nil)
			case "meta":
				x.hook("meta-written", func() { flip(t, x.spoolFile(t, "meta.gml")) })
			case "marker":
				x.hook("marker-written", func() { flip(t, x.spoolFile(t, "marker.gml")) })
			}
			err := deliver(t, x.in, "s@x", []string{"a@example.org"}, message("secret subject", "x"))
			crashHook = nil
			if !errors.Is(err, smtpd.ErrTemporary) || !errors.Is(err, ErrSelfCheck) || errors.Is(err, smtpd.ErrDiskFull) {
				t.Fatalf("delivery: %v", err)
			}
			if x.reached("spooled") || x.reached("journal") {
				t.Fatalf("went on after the self-check: %v", x.points)
			}
			if got := deliveredFiles(t, x.env, x.mbx); len(got) != 0 {
				t.Fatalf("files in the mailbox: %v", got)
			}
			if f := files(t, x.env.Store.SpoolDir()); len(f) != 0 {
				t.Fatalf("spool: %v", f)
			}
			l := x.log.take()
			if !strings.Contains(l, "self-check of a signature failed") || strings.Contains(l, "secret") {
				t.Fatalf("log %q", l)
			}
			// With the right signer and untouched files the next delivery
			// succeeds.
			x.in.signer = x.env.IngestKey
			if err := deliver(t, x.in, "s@x", []string{"a@example.org"}, message("again", "x")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A term list that fails the self-check is not written (signer) or not
// kept (changed on disk); the markers stay and a later flush with the
// right key replaces them.
func TestSelfCheckTermList(t *testing.T) {
	for _, tc := range []string{"signer", "disk"} {
		t.Run(tc, func(t *testing.T) {
			x := newSelfCheckEnv(t)
			for _, s := range []string{"a", "b"} {
				if err := deliver(t, x.in, "s@x", []string{"a@example.org"}, message(s, "x")); err != nil {
					t.Fatal(err)
				}
			}
			markers, _ := x.env.Store.ListPending(x.mbx, 1)
			if len(markers) != 2 {
				t.Fatalf("markers %d", len(markers))
			}
			switch tc {
			case "signer":
				x.in.signer = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
				x.hook("", nil)
			case "disk":
				x.hook("batch-written", func() {
					ids, _ := x.env.Store.ListPending(x.mbx, 1)
					for _, id := range ids {
						if id != markers[0] && id != markers[1] {
							flip(t, x.env.Store.PendingFile(x.mbx, 1, id))
						}
					}
				})
			}
			if err := x.in.Flush(); !errors.Is(err, ErrSelfCheck) {
				t.Fatalf("flush: %v", err)
			}
			crashHook = nil
			if x.reached("batch-written") != (tc == "disk") {
				t.Fatalf("points %v", x.points)
			}
			ids, _ := x.env.Store.ListPending(x.mbx, 1)
			if len(ids) != 2 || !(ids[0] == markers[0] && ids[1] == markers[1] || ids[0] == markers[1] && ids[1] == markers[0]) {
				t.Fatalf("pending files %v, markers %v", ids, markers)
			}
			if !strings.Contains(x.log.take(), "self-check of a signature failed") {
				t.Fatal("not logged")
			}
			// The mails are still preprocessed later.
			x.in.signer = x.env.IngestKey
			if err := deliver(t, x.in, "s@x", []string{"a@example.org"}, message("c", "x")); err != nil {
				t.Fatal(err)
			}
			if err := x.in.Flush(); err != nil {
				t.Fatal(err)
			}
			ids, _ = x.env.Store.ListPending(x.mbx, 1)
			if len(ids) != 3 {
				t.Fatalf("pending files %d", len(ids))
			}
		})
	}
}

// selfCheckBytes compares the header and the signer generation, and
// selfCheck fails closed when the file cannot be read.
func TestSelfCheckDetails(t *testing.T) {
	x := newSelfCheckEnv(t)
	in := x.in
	hdr := envelope.Header{Kind: envelope.KindPending, MailboxID: x.mbx, Epoch: 1, FileID: [16]byte{2}, Created: testenv.Start.UnixMilli()}
	data := sealSigned(t, hdr, in.signer, envelope.SignerIngest, [16]byte{}, nil)
	if err := in.selfCheckBytes(data, hdr, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(h *envelope.Header){
		"kind":    func(h *envelope.Header) { h.Kind = envelope.KindMeta; h.Version = 1 },
		"mailbox": func(h *envelope.Header) { h.MailboxID[0] ^= 1 },
		"epoch":   func(h *envelope.Header) { h.Epoch++ },
		"file":    func(h *envelope.Header) { h.FileID[0] ^= 1 },
		"created": func(h *envelope.Header) { h.Created++ },
		"version": func(h *envelope.Header) { h.Version = 1 },
		"wrap":    func(h *envelope.Header) { h.Kind = envelope.KindWrap },
	} {
		want := hdr
		mod(&want)
		if err := in.selfCheckBytes(data, want, [32]byte{}); !errors.Is(err, ErrSelfCheck) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Another generation in the trailer than the server's own.
	in.cfg.IngestGen = 2
	if err := in.selfCheckBytes(data, hdr, [32]byte{}); !errors.Is(err, ErrSelfCheck) {
		t.Fatalf("generation: %v", err)
	}
	in.cfg.IngestGen = 1
	if err := in.selfCheck(x.env.Store.Path("spool", "missing"), hdr, [32]byte{}); !errors.Is(err, ErrSelfCheck) || !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing file: %v", err)
	}
}
