package ingest

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// openKeystore opens the key store of u.
func openKeystore(tb testing.TB, u *testenv.User) *keys.Keystore {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join(u.Dir, "keystore"))
	if err != nil {
		tb.Fatal(err)
	}
	ks, err := keys.OpenKeystore(data, testenv.Passphrase)
	if err != nil {
		tb.Fatal(err)
	}
	return ks
}

// appendPlanned appends count planned epochs to mbx, one day apart after
// the head, signed by u, logged, with mailbox.rec pointing to the last.
// The server needs no wraps or folders for them.
func appendPlanned(tb testing.TB, env *testenv.Env, u *testenv.User, mbx store.ID, count int) {
	tb.Helper()
	ks := openKeystore(tb, u)
	defer ks.Zero()
	m, err := env.Store.ReadMailbox(mbx)
	if err != nil {
		tb.Fatal(err)
	}
	head, data, err := env.Store.ReadEpoch(mbx, m.Epoch)
	if err != nil {
		tb.Fatal(err)
	}
	for i := 0; i < count; i++ {
		content, _ := ecdh.X25519().GenerateKey(rand.Reader)
		meta, _ := ecdh.X25519().GenerateKey(rand.Reader)
		e := &store.Epoch{MailboxID: mbx, Number: head.Number + 1, Begin: head.Begin + int64(24*time.Hour/time.Millisecond),
			Reason: store.ReasonRegular, Suite: envelope.Suite1, ContentPub: content.PublicKey(), MetaPub: meta.PublicKey(),
			Members: head.Members, PrevHash: store.EpochHash(data), SignerID: u.ID, SignerGen: ks.Generation}
		if err := e.Sign(ks.Identity); err != nil {
			tb.Fatal(err)
		}
		if data, err = env.Store.WriteEpoch(e); err != nil {
			tb.Fatal(err)
		}
		if err := env.Log.AppendEpoch(mbx, e.Number, data); err != nil {
			tb.Fatal(err)
		}
		head = e
	}
	m.Epoch = head.Number
	if err := env.Store.WriteMailbox(m); err != nil {
		tb.Fatal(err)
	}
}

// resign replaces epoch n of mbx by a copy with change applied, signed
// with the identity key of by (the signer fields stay as they are).
func resign(t *testing.T, env *testenv.Env, by *testenv.User, mbx store.ID, n uint32, change func(e *store.Epoch)) {
	t.Helper()
	e, _, err := env.Store.ReadEpoch(mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	change(e)
	ks := openKeystore(t, by)
	defer ks.Zero()
	if err := e.Sign(ks.Identity); err != nil {
		t.Fatal(err)
	}
	data, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.Store.EpochFile(mbx, n), data, 0o660); err != nil {
		t.Fatal(err)
	}
}

func readMailbox(t *testing.T, env *testenv.Env, mbx store.ID) *store.Mailbox {
	t.Helper()
	m, err := env.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestChainCache: the verified chain is reused only while every file it
// was verified from is unchanged; any change verifies again in full.
func TestChainCache(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	in := newIngest(t, env)
	full := func() int { return in.chains.fullChecks() }

	m := readMailbox(t, env, mbx)
	c1, h1, err := in.verifyChain(m)
	if err != nil || full() != 1 {
		t.Fatalf("first: %v, %d full", err, full())
	}
	c2, h2, err := in.verifyChain(m)
	if err != nil || full() != 1 || c2 != c1 || h2 != h1 {
		t.Fatalf("cached: %v, %d full", err, full())
	}
	// A delivery verifies at DATA and at the commit, both from the cache.
	if err := deliver(t, in, "s@x", []string{"a@example.org"}, message("a", "x")); err != nil || full() != 1 {
		t.Fatalf("delivery: %v, %d full", err, full())
	}

	// The same head, epoch 3 replaced by another validly signed epoch.rec
	// (a later begin): the hash changes, the chain is verified again and
	// refused, here because epoch 4 names the old epoch 3.
	orig3 := mustRead(t, env.Store.EpochFile(mbx, 3))
	resign(t, env, u, mbx, 3, func(e *store.Epoch) { e.Begin++ })
	if _, _, err := in.verifyChain(m); !errors.Is(err, store.ErrChain) || full() != 2 {
		t.Fatalf("replaced epoch 3: %v, %d full", err, full())
	}
	if _, err := in.Begin(smtpd.Session{}, "s@x", []string{"a@example.org"}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("delivery with a replaced epoch: %v", err)
	}
	os.WriteFile(env.Store.EpochFile(mbx, 3), orig3, 0o660)
	if _, _, err := in.verifyChain(m); err != nil || full() != 4 {
		t.Fatalf("restored: %v, %d full", err, full())
	}
	// The same head, the head epoch.rec replaced by one that only the
	// signature check can refuse: another content key, alice named as
	// the signer, signed by bob. The chain links hold (nothing follows
	// the head), so a skipped signature check would accept it.
	bob := env.NewUser("bob")
	head := mustRead(t, env.Store.EpochFile(mbx, 4))
	resign(t, env, bob, mbx, 4, func(e *store.Epoch) {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		e.ContentPub = k.PublicKey()
	})
	if _, _, err := in.verifyChain(m); !errors.Is(err, keys.ErrSignature) || full() != 5 {
		t.Fatalf("forged head: %v, %d full", err, full())
	}
	if _, err := in.Begin(smtpd.Session{}, "s@x", []string{"a@example.org"}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("delivery with a forged head: %v", err)
	}
	os.WriteFile(env.Store.EpochFile(mbx, 4), head, 0o660)
	n := full()
	if _, _, err := in.verifyChain(m); err != nil || full() != n+1 {
		t.Fatalf("restored head: %v, %d full", err, full())
	}
	if _, _, err := in.verifyChain(m); err != nil || full() != n+1 {
		t.Fatalf("cached again: %v, %d full", err, full())
	}

	// A missing epoch.rec.
	os.Rename(env.Store.EpochFile(mbx, 2), env.Store.EpochFile(mbx, 2)+".x")
	if _, _, err := in.verifyChain(m); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing epoch 2: %v", err)
	}
	os.Rename(env.Store.EpochFile(mbx, 2)+".x", env.Store.EpochFile(mbx, 2))

	// Another head in mailbox.rec: verified again.
	n = full()
	m3 := *m
	m3.Epoch = 3
	if _, _, err := in.verifyChain(&m3); err != nil || full() != n+1 {
		t.Fatalf("head 3: %v, %d full", err, full())
	}
	if _, _, err := in.verifyChain(m); err != nil || full() != n+2 {
		t.Fatalf("head 4: %v, %d full", err, full())
	}

	// user.rec of the signer changed (here only rewritten with another
	// byte at the end, which DecodeUser refuses): verified again, refused.
	n = full()
	urec := mustRead(t, env.Store.UserFile(u.ID))
	os.WriteFile(env.Store.UserFile(u.ID), append(append([]byte(nil), urec...), 0), 0o660)
	if _, _, err := in.verifyChain(m); err == nil || full() != n+1 {
		t.Fatalf("changed user.rec: %v, %d full", err, full())
	}
	os.Remove(env.Store.UserFile(u.ID))
	if _, _, err := in.verifyChain(m); err == nil || full() != n+2 {
		t.Fatalf("missing user.rec: %v, %d full", err, full())
	}
	os.WriteFile(env.Store.UserFile(u.ID), urec, 0o660)
	if _, _, err := in.verifyChain(m); err != nil || full() != n+3 {
		t.Fatalf("restored user.rec: %v, %d full", err, full())
	}

	// A log that no longer accepts the epoch: the cached chain is not
	// used, the full verification refuses.
	n = full()
	in.cfg.Log = refusingLog{env.Log}
	if _, _, err := in.verifyChain(m); !errors.Is(err, errRefused) || full() != n+1 {
		t.Fatalf("log refuses: %v, %d full", err, full())
	}
	in.cfg.Log = env.Log
	if _, _, err := in.verifyChain(m); err != nil {
		t.Fatal(err)
	}

	// Switched off, every call verifies in full.
	in.chains.off = true
	n = full()
	in.verifyChain(m)
	in.verifyChain(m)
	if full() != n+2 {
		t.Fatalf("cache off: %d full", full()-n)
	}
}

var errRefused = errors.New("test: refused by the log")

// refusingLog refuses every epoch.
type refusingLog struct{ translog.Log }

func (refusingLog) CheckEpoch(store.ID, uint32, []byte) error { return errRefused }

// The cache holds at most chainCacheSize mailboxes.
func TestChainCacheBound(t *testing.T) {
	var c chainCache
	c.init()
	for i := 0; i < chainCacheSize+10; i++ {
		c.put(store.ID{byte(i), byte(i >> 8)}, &chainEntry{})
	}
	if len(c.entries) != chainCacheSize {
		t.Fatalf("%d entries", len(c.entries))
	}
	c.put(store.ID{1, 0}, &chainEntry{head: 9})
	if len(c.entries) > chainCacheSize {
		t.Fatalf("%d entries", len(c.entries))
	}
}

// A chain verified with a generation that is no longer the signer's
// current one is checked against the log on every use.
func TestChainCacheRevokedGeneration(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	in := newIngest(t, env)
	m := readMailbox(t, env, mbx)
	if _, _, err := in.verifyChain(m); err != nil {
		t.Fatal(err)
	}
	e, _ := in.chains.entries[mbx]
	if e == nil || len(e.epochs) != 4 || e.epochs[0].revoked {
		t.Fatalf("entry %+v", e)
	}
	// Mark the entry as relying on a revoked generation; the log refuses
	// revoked signatures.
	cp := *e
	cp.epochs = append([]epochCheck(nil), e.epochs...)
	cp.epochs[1].revoked = true
	in.chains.entries[mbx] = &cp
	in.cfg.Log = revokedLog{env.Log}
	if _, _, ok := in.cachedChain(m); ok {
		t.Fatal("cache used although the log refuses the revoked signature")
	}
	in.cfg.Log = env.Log
	if _, _, ok := in.cachedChain(m); !ok {
		t.Fatal("cache not used")
	}
}

type revokedLog struct{ translog.Log }

func (revokedLog) CheckRevokedSignature(store.ID, uint32, []byte) error { return errRefused }

// BenchmarkChooseEpoch chooses the epoch of a mailbox with 40 epochs,
// with the chain cache and without it.
func BenchmarkChooseEpoch(b *testing.B) {
	env := testenv.New(b)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	appendPlanned(b, env, u, mbx, 36)
	cfg := Config{Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1, Now: env.Clock.Now}
	in, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	defer in.Close()
	m, err := env.Store.ReadMailbox(mbx)
	if err != nil || m.Epoch != 40 {
		b.Fatalf("head %d: %v", m.Epoch, err)
	}
	when := time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, cached := range []bool{true, false} {
		b.Run(fmt.Sprintf("cache=%v", cached), func(b *testing.B) {
			in.chains.off = !cached
			if _, _, _, err := in.chooseEpoch(m, when); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, _, err := in.chooseEpoch(m, when); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
