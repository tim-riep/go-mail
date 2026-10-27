package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// chainFixture (task 15g, taken over from the review of task 15f): init
// published into a data directory with the real operator log, two
// regular successions 1 to 2 (out2) and 2 to 3 (out3), not published.
type chainFixture struct {
	f          *fixture
	st         *store.Store
	out2, out3 string
	res2, res3 *Result
}

func newChain(t *testing.T) *chainFixture {
	t.Helper()
	f := newFixture(t)
	st := newData(t, filepath.Join(f.base, "data"))
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	u, _ := f.unlock(1, 2, 3)
	out2 := filepath.Join(f.base, "s2")
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out2, Pin: f.res.Pin})
	if err != nil {
		t.Fatal(err)
	}
	u, _ = f.unlock(2, 3, 4)
	u.IdentityGen, u.IdentityPub = 2, res2.IdentityPub
	out3 := filepath.Join(f.base, "s3")
	res3, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out3, Pin: res2.Pin})
	if err != nil {
		t.Fatal(err)
	}
	return &chainFixture{f: f, st: st, out2: out2, out3: out3, res2: res2, res3: res3}
}

func (c *chainFixture) file(t *testing.T, out, name string) []byte {
	t.Helper()
	return mustReadFile(t, filepath.Join(out, "platform", name))
}

// logIndex returns the index of the valid platform entry name in the
// operator log of the data directory judged with pin, -1 if none.
func (c *chainFixture) logIndex(t *testing.T, pin *store.PlatformPin, name string) int64 {
	t.Helper()
	l, err := OpenLog(c.st, pin)
	if err != nil {
		t.Fatal(err)
	}
	es, err := l.Lookup(translog.KindPlatform, []byte(name))
	if err != nil {
		t.Fatal(err)
	}
	if len(es) == 0 {
		return -1
	}
	return es[0].Index
}

// pin1Log opens the log of the data directory as a client with pin 1
// judges it (anchor: generation 1 only).
func (c *chainFixture) pin1Log(t *testing.T) translog.Log {
	t.Helper()
	l, err := translog.Open(translog.Options{Store: c.st, Identities: []translog.Identity{{Gen: 1, Pub: c.f.res.IdentityPub}}})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// state is the content of data/platform/ and the size of the log.
func (c *chainFixture) state(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, n := range listDir(t, filepath.Join(c.st.Root, "platform")) {
		fmt.Fprintf(&b, "%s:%x ", n, mustReadFile(t, filepath.Join(c.st.Root, "platform", n)))
	}
	ents, _ := os.ReadDir(c.st.Path("log", "entries"))
	fmt.Fprintf(&b, "log:%d", len(ents))
	return b.String()
}

// TestPublishIdentityPubNeedsSuccession (task 15g point 1): an export
// with identity-2.pub but without identity-2.succ, which is neither in
// data/platform/ nor in the log, is refused with
// translog.ErrPrerequisite before anything is written; it would leave
// the data directory in the state of the locked compromise case (Q19).
// Generation 1 needs no succession. The gap cannot be carried over to
// the next export either, and closing it in order works.
func TestPublishIdentityPubNeedsSuccession(t *testing.T) {
	c := newChain(t)
	before := c.state(t)
	pub2 := c.file(t, c.out2, "identity-2.pub")
	dir := writeExport(t, filepath.Join(c.f.base, "nosucc"), map[string][]byte{"identity-2.pub": pub2})
	err := Publish(PublishOptions{From: dir, Data: c.st, Pin: c.res2.Pin})
	if !errors.Is(err, translog.ErrPrerequisite) || !strings.Contains(err.Error(), "identity-2.pub needs identity-2.succ") {
		t.Fatalf("identity-2.pub without succession: %v", err)
	}
	if after := c.state(t); after != before {
		t.Fatalf("written: %s", after)
	}
	err = Publish(PublishOptions{From: c.out3, Data: c.st, Pin: c.res3.Pin})
	if !errors.Is(err, translog.ErrPrerequisite) || !strings.Contains(err.Error(), "identity-2.succ") {
		t.Fatalf("generation 3 after the refused key: %v", err)
	}
	// Generation 1 needs none.
	one := writeExport(t, filepath.Join(c.f.base, "one"), map[string][]byte{"identity-1.pub": c.f.res.IdentityPub})
	if err := Publish(PublishOptions{From: one, Data: c.st, Pin: c.res3.Pin}); err != nil {
		t.Fatalf("identity-1.pub: %v", err)
	}
	// In order: generation 2, then 3.
	for _, out := range []string{c.out2, c.out3} {
		if err := Publish(PublishOptions{From: out, Data: c.st, Pin: c.res3.Pin}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.pin1Log(t).CheckPlatform("identity-3.succ", c.file(t, c.out3, "identity-3.succ")); err != nil {
		t.Fatalf("pin-1 log: %v", err)
	}
	// With the succession logged, the key alone is fine, also when the
	// file of the succession is gone from data/platform/.
	if err := removePlatformFile(c.st, "identity-2.succ"); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: dir, Data: c.st, Pin: c.res3.Pin}); err != nil {
		t.Fatalf("identity-2.pub with the succession in the log: %v", err)
	}
}

// TestPublishCertNeedsSuccession (task 15g points 1 and 2): a
// certificate issued by identity generation 2 needs identity-2.succ in
// the export or the log, logged before it.
func TestPublishCertNeedsSuccession(t *testing.T) {
	c := newChain(t)
	before := c.state(t)
	pub, cert := c.f.cert(t, 2, keys.RoleIngest, 2)
	certOnly := map[string][]byte{"ingest-2.pub": pub, "ingest-2.cert": cert}
	err := Publish(PublishOptions{From: writeExport(t, filepath.Join(c.f.base, "c"), certOnly), Data: c.st, Pin: c.res2.Pin})
	if !errors.Is(err, translog.ErrPrerequisite) || !strings.Contains(err.Error(), "ingest-2.cert needs identity-2.succ") {
		t.Fatalf("certificate of generation 2 without succession: %v", err)
	}
	if after := c.state(t); after != before {
		t.Fatalf("written: %s", after)
	}
	with := map[string][]byte{"ingest-2.pub": pub, "ingest-2.cert": cert,
		"identity-2.pub": c.file(t, c.out2, "identity-2.pub"), "identity-2.succ": c.file(t, c.out2, "identity-2.succ")}
	log := newLog(t)
	if err := Publish(PublishOptions{From: writeExport(t, filepath.Join(c.f.base, "cs"), with), Data: c.st, Log: log, Pin: c.res2.Pin}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(log.names) != "[identity-2.succ ingest-2.cert]" {
		t.Fatalf("log %v", log.names)
	}
}

// TestPublishForgedPredecessorInPlatform (task 15g point 2): a
// succession in data/platform/ whose signature does not verify with the
// pin (here: right generation and key, signed by a random key) counts
// for nothing: publish refuses with translog.ErrMismatch whatever the
// export, before anything is written or logged, until the operator
// removes the file; then the chain is published in order.
func TestPublishForgedPredecessorInPlatform(t *testing.T) {
	c := newChain(t)
	_, junk, _ := ed25519.GenerateKey(rand.Reader)
	s, err := keys.NewPlatformSuccession(junk, 2, c.res2.IdentityPub, testNow.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := s.Encode()
	if err := c.st.WritePlatformFile("identity-2.succ", forged); err != nil {
		t.Fatal(err)
	}
	before := c.state(t)
	empty := writeExport(t, filepath.Join(c.f.base, "empty"), nil)
	for _, from := range []string{c.out3, c.out2, empty} {
		err := Publish(PublishOptions{From: from, Data: c.st, Pin: c.res3.Pin})
		if !errors.Is(err, translog.ErrMismatch) || !errors.Is(err, keys.ErrSignature) || !strings.Contains(err.Error(), "platform/identity-2.succ") {
			t.Fatalf("%s with a forged platform/identity-2.succ: %v", from, err)
		}
		if after := c.state(t); after != before {
			t.Fatalf("written: %s", after)
		}
	}
	if c.logIndex(t, c.res3.Pin, "identity-3.succ") != -1 {
		t.Fatal("identity-3.succ logged")
	}
	if err := removePlatformFile(c.st, "identity-2.succ"); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{c.out2, c.out3} {
		if err := Publish(PublishOptions{From: out, Data: c.st, Pin: c.res3.Pin}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.pin1Log(t).CheckPlatform("identity-3.succ", c.file(t, c.out3, "identity-3.succ")); err != nil {
		t.Fatalf("pin-1 log: %v", err)
	}
}

// TestPublishForgedCertInPlatform (task 15g point 2b): a certificate in
// data/platform/ that does not verify with the pin's key of its
// identity_gen, or certifies another key than its name says, is
// translog.ErrMismatch.
func TestPublishForgedCertInPlatform(t *testing.T) {
	f := newFixture(t)
	pub2, cert2 := f.cert(t, 1, keys.RoleIngest, 2)
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	fc, _ := keys.NewPlatformCert(foreign, 1, keys.RoleIngest, 2, pub2, testNow.UnixMilli())
	forged, _ := fc.Encode()
	for name, files := range map[string]map[string][]byte{
		"foreign signature": {"ingest-2.pub": pub2, "ingest-2.cert": forged},
		"other name":        {"ingest-3.pub": pub2, "ingest-3.cert": cert2},
	} {
		st := newData(t, filepath.Join(f.base, strings.ReplaceAll(name, " ", "-")))
		for n, b := range files {
			if err := st.WritePlatformFile(n, b); err != nil {
				t.Fatal(err)
			}
		}
		log := newLog(t)
		err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Log: log, Pin: f.res.Pin})
		if !errors.Is(err, translog.ErrMismatch) || len(log.names) != 0 {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// TestPublishUnloggedPredecessorInPlatform (task 15g point 2a): the
// genuine identity-2.succ in data/platform/ without its log entry (a
// crash between file and log entry) does not count by itself: publish
// of identity-3.succ logs it first, so that a client with pin 1 can
// follow the chain. A succession of data/platform/ whose own
// predecessor is missing is translog.ErrPrerequisite.
func TestPublishUnloggedPredecessorInPlatform(t *testing.T) {
	c := newChain(t)
	for _, n := range []string{"identity-2.succ", "identity-2.pub"} {
		if err := c.st.WritePlatformFile(n, c.file(t, c.out2, n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := Publish(PublishOptions{From: c.out3, Data: c.st, Pin: c.res3.Pin}); err != nil {
		t.Fatal(err)
	}
	i2, i3 := c.logIndex(t, c.res3.Pin, "identity-2.succ"), c.logIndex(t, c.res3.Pin, "identity-3.succ")
	if i2 < 0 || i3 < 0 || i2 >= i3 {
		t.Fatalf("log order: identity-2.succ at %d, identity-3.succ at %d", i2, i3)
	}
	if err := c.pin1Log(t).CheckPlatform("identity-3.succ", c.file(t, c.out3, "identity-3.succ")); err != nil {
		t.Fatalf("pin-1 log: %v", err)
	}
	// The order with the recording log: the relogged succession first.
	d := newChain(t)
	for _, n := range []string{"identity-2.succ", "identity-2.pub"} {
		if err := d.st.WritePlatformFile(n, d.file(t, d.out2, n)); err != nil {
			t.Fatal(err)
		}
	}
	log := newLog(t)
	if err := Publish(PublishOptions{From: d.out3, Data: d.st, Log: log, Pin: d.res3.Pin}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(log.names) != "[identity-2.succ identity-3.succ]" {
		t.Fatalf("log %v", log.names)
	}

	// identity-3.succ unlogged in data/platform/, identity-2.succ nowhere:
	// a certificate of generation 3 is refused.
	e := newChain(t)
	for _, n := range []string{"identity-3.succ", "identity-3.pub"} {
		if err := e.st.WritePlatformFile(n, e.file(t, e.out3, n)); err != nil {
			t.Fatal(err)
		}
	}
	before := e.state(t)
	pub, cert := e.f.cert(t, 3, keys.RoleAdmin, 2)
	dir := writeExport(t, filepath.Join(e.f.base, "a2"), map[string][]byte{"admin-2.pub": pub, "admin-2.cert": cert})
	err := Publish(PublishOptions{From: dir, Data: e.st, Pin: e.res3.Pin})
	if !errors.Is(err, translog.ErrPrerequisite) || !strings.Contains(err.Error(), "admin-2.cert needs identity-2.succ") {
		t.Fatalf("certificate of 3 with identity-2.succ missing: %v", err)
	}
	if after := e.state(t); after != before {
		t.Fatalf("written: %s", after)
	}
	// With out2 in the export all three go in, in order.
	both := writeExport(t, filepath.Join(e.f.base, "a2s2"), map[string][]byte{"admin-2.pub": pub, "admin-2.cert": cert,
		"identity-2.pub": e.file(t, e.out2, "identity-2.pub"), "identity-2.succ": e.file(t, e.out2, "identity-2.succ")})
	if err := Publish(PublishOptions{From: both, Data: e.st, Pin: e.res3.Pin}); err != nil {
		t.Fatal(err)
	}
	i2, i3 = e.logIndex(t, e.res3.Pin, "identity-2.succ"), e.logIndex(t, e.res3.Pin, "identity-3.succ")
	ia := e.logIndex(t, e.res3.Pin, "admin-2.cert")
	if i2 < 0 || !(i2 < i3 && i3 < ia) {
		t.Fatalf("log order: %d %d %d", i2, i3, ia)
	}
	if err := e.pin1Log(t).CheckPlatform("admin-2.cert", cert); err != nil {
		t.Fatalf("pin-1 log: %v", err)
	}
}

// TestPublishOldPinAfterFileRemoval (task 15g point 3): after generation
// 2 is published (with other witnesses), the old pin 1 with
// ReplaceWitnesses is refused (translog.ErrMismatch), also when the
// files of generation 2 are removed from data/platform/: the succession
// in the log names the generation.
func TestPublishOldPinAfterFileRemoval(t *testing.T) {
	c := newChain(t)
	u, _ := c.f.unlock(1, 2, 3)
	out := filepath.Join(c.f.base, "sw")
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out, Pin: c.f.res.Pin, Witnesses: c.f.w[:1], MinWitnesses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: out, Data: c.st, Pin: res2.Pin, ReplaceWitnesses: true}); err != nil {
		t.Fatal(err)
	}
	cur := mustReadFile(t, c.st.Path("platform", WitnessesFile))
	empty := writeExport(t, filepath.Join(c.f.base, "empty"), nil)
	if err := Publish(PublishOptions{From: empty, Data: c.st, Pin: c.f.res.Pin, ReplaceWitnesses: true}); !errors.Is(err, translog.ErrMismatch) {
		t.Fatalf("old pin: %v", err)
	}
	for _, n := range []string{"identity-2.succ", "identity-2.pub"} {
		if err := removePlatformFile(c.st, n); err != nil {
			t.Fatal(err)
		}
	}
	err = Publish(PublishOptions{From: empty, Data: c.st, Pin: c.f.res.Pin, ReplaceWitnesses: true})
	if !errors.Is(err, translog.ErrMismatch) || !strings.Contains(err.Error(), "log entry identity-2.succ") {
		t.Fatalf("old pin, files of generation 2 removed: %v", err)
	}
	if !bytes.Equal(mustReadFile(t, c.st.Path("platform", WitnessesFile)), cur) {
		t.Fatal("witnesses.rec replaced")
	}
	// The pin of generation 2 still goes through.
	if err := Publish(PublishOptions{From: empty, Data: c.st, Pin: res2.Pin}); err != nil {
		t.Fatal(err)
	}
}

// TestPublishForeignPinReplace (task 15g points 2b and 3): the pin of
// another platform never replaces witnesses.rec, also when
// identity-1.pub was removed from data/platform/: the certificates there
// do not verify with its identity list.
func TestPublishForeignPinReplace(t *testing.T) {
	c := newChain(t)
	g := newFixture(t)
	u, _ := g.unlock(1, 2, 3)
	gres, err := Succeed(SucceedOptions{UnlockOptions: u, Out: filepath.Join(g.base, "gs2"), Pin: g.res.Pin, Witnesses: g.w[:1], MinWitnesses: 1})
	if err != nil {
		t.Fatal(err)
	}
	before := mustReadFile(t, c.st.Path("platform", WitnessesFile))
	empty := writeExport(t, filepath.Join(c.f.base, "empty"), nil)
	check := func(what string, pin *store.PlatformPin) {
		t.Helper()
		err := Publish(PublishOptions{From: empty, Data: c.st, Pin: pin, ReplaceWitnesses: true})
		if !errors.Is(err, translog.ErrMismatch) {
			t.Fatalf("%s: %v", what, err)
		}
		if !bytes.Equal(mustReadFile(t, c.st.Path("platform", WitnessesFile)), before) {
			t.Fatalf("%s: witnesses.rec replaced", what)
		}
	}
	check("foreign pin 2", gres.Pin)
	check("foreign pin 1", g.res.Pin)
	if err := removePlatformFile(c.st, "identity-1.pub"); err != nil {
		t.Fatal(err)
	}
	check("foreign pin 2 without identity-1.pub", gres.Pin)
	check("foreign pin 1 without identity-1.pub", g.res.Pin)
}
