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
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 22 point 1 (attack review 21c R-low): running the same
// publish again heals data/platform/ when a file there was written over
// a logged one; a valid entry is never replaced by other content.

// compromise publishes the fixture, lets the thief log ingest-2.cert at
// index N under pin 1, runs succeed --compromised at the confirmed head
// and publishes its export; returns the data directory, pin 2 and the
// thief's public key and certificate.
func (f *fixture) compromise(t *testing.T) (*store.Store, *Result, []byte, []byte) {
	t.Helper()
	st, h := f.published(t, "data")
	tp, tc := f.thiefCert(t, 1, keys.RoleIngest, 2, headAt.Add(time.Hour))
	thief := writeExport(t, filepath.Join(f.base, "thief"), map[string][]byte{"ingest-2.cert": tc, "ingest-2.pub": tp})
	if err := Publish(PublishOptions{From: thief, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	u, _ := f.unlock(1, 2, 3)
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: filepath.Join(f.base, "succ2"), Pin: f.res.Pin, Compromised: true, HeadSize: h.Size, HeadTime: h.Time})
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "succ2"), Data: st, Pin: res2.Pin}); err != nil {
		t.Fatal(err)
	}
	return st, res2, tp, tc
}

// reissue writes the export of ingest generation gen under identity 2
// of res2 with valid_from at (ms) into base/name.
func (f *fixture) reissue(t *testing.T, res2 *Result, gen uint32, at int64, name string) string {
	t.Helper()
	u, _ := f.unlock(2, 3, 4)
	u.IdentityGen, u.IdentityPub = 2, res2.IdentityPub
	out := filepath.Join(f.base, name)
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: out, KeyDir: filepath.Join(f.base, "k-"+name), Gen: gen, ValidFrom: time.UnixMilli(at), Revoked: res2.Pin.Revoked}); err != nil {
		t.Fatal(err)
	}
	return out
}

// samePlatform fails unless platform/<n> of st equals the export's file
// n of out for every n.
func samePlatform(t *testing.T, st *store.Store, out string, names ...string) {
	t.Helper()
	for _, n := range names {
		if !bytes.Equal(mustReadFile(t, st.Path("platform", n)), mustReadFile(t, filepath.Join(out, "platform", n))) {
			t.Fatalf("platform/%s is not the export's", n)
		}
	}
}

// lookupCert returns the valid entries of name in the log of st under
// pin.
func lookupCert(t *testing.T, st *store.Store, pin *store.PlatformPin, name string) []translog.Entry {
	t.Helper()
	es, err := mustOpenLog(t, st, pin).Lookup(translog.KindPlatform, []byte(name))
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// TestPublishHealsPlatform: without any revocation, a foreign
// certificate verifying with the identity and a foreign public key
// written over the logged files of the fixture's Init are put back by
// running the same publish again; the log stays as it was.
func TestPublishHealsPlatform(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	before := lookupCert(t, st, f.res.Pin, "ingest-1.cert")
	if len(before) != 1 {
		t.Fatalf("entries %d", len(before))
	}
	// A foreign public key under the logged admin-1.cert.
	kpub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.Path("platform", "admin-1.pub"), kpub, 0o644); err != nil {
		t.Fatal(err)
	}
	// A foreign certificate and key under the name of the logged
	// ingest-1.cert, signed with identity 1 (it passes the check of
	// data/platform/ against the pin).
	tp, tc := f.thiefCert(t, 1, keys.RoleIngest, 1, headAt.Add(time.Hour))
	for n, b := range map[string][]byte{"ingest-1.cert": tc, "ingest-1.pub": tp} {
		if err := os.WriteFile(st.Path("platform", n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files := listDir(t, st.Path("platform"))
	if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatalf("publish again: %v", err)
	}
	samePlatform(t, st, out, "admin-1.pub", "ingest-1.cert", "ingest-1.pub")
	if fmt.Sprint(listDir(t, st.Path("platform"))) != fmt.Sprint(files) {
		t.Fatalf("files: %v", listDir(t, st.Path("platform")))
	}
	after := lookupCert(t, st, f.res.Pin, "ingest-1.cert")
	if len(after) != 1 || after[0].Index != before[0].Index || !bytes.Equal(after[0].Content, before[0].Content) {
		t.Fatalf("log changed: %+v", after)
	}
	l := mustOpenLog(t, st, f.res.Pin)
	h, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	if h.Size != 2 {
		t.Fatalf("log size %d", h.Size)
	}
}

// TestPublishHealsOverwrittenCert (attack review 21c R3): after the
// revocation the thief (stolen identity 1, write access to
// data/platform/) plants an unlogged ingest-2.cert over another key and
// its public key; the honest reissue replaces them, and nothing of his
// is logged. When he overwrites the honest, logged certificate after
// that, the same publish run again puts it back.
func TestPublishHealsOverwrittenCert(t *testing.T) {
	f := newFixture(t)
	st, res2, _, _ := f.compromise(t)
	tp2, tc2 := f.thiefCert(t, 1, keys.RoleIngest, 2, headAt.Add(2*time.Hour))
	for n, b := range map[string][]byte{"ingest-2.cert": tc2, "ingest-2.pub": tp2} {
		if err := os.WriteFile(st.Path("platform", n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rot := f.reissue(t, res2, 2, res2.Pin.Revoked[0].AtTime, "rot2")
	if err := Publish(PublishOptions{From: rot, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatalf("honest reissue over the planted files: %v", err)
	}
	samePlatform(t, st, rot, "ingest-2.cert", "ingest-2.pub")
	honest := mustReadFile(t, filepath.Join(rot, "platform", "ingest-2.cert"))
	es := lookupCert(t, st, res2.Pin, "ingest-2.cert")
	if len(es) != 1 || !bytes.Equal(es[0].Content, honest) {
		t.Fatalf("log: %+v", es)
	}
	// The thief overwrites the honest, logged certificate (and, in a
	// second round, its public key too): the operator's repeat of the
	// same publish puts both back; the log keeps the honest entry.
	for _, planted := range []map[string][]byte{
		{"ingest-2.cert": tc2},
		{"ingest-2.cert": tc2, "ingest-2.pub": tp2},
	} {
		for n, b := range planted {
			if err := os.WriteFile(st.Path("platform", n), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := Publish(PublishOptions{From: rot, Data: st, Pin: res2.Pin}); err != nil {
			t.Fatalf("re-run after the thief overwrote %d files: %v", len(planted), err)
		}
		samePlatform(t, st, rot, "ingest-2.cert", "ingest-2.pub")
		es := lookupCert(t, st, res2.Pin, "ingest-2.cert")
		if len(es) != 1 || !bytes.Equal(es[0].Content, honest) {
			t.Fatalf("log: %+v", es)
		}
	}
}

// TestPublishHealsForeignPub (attack review 21c R1): a foreign
// ingest-2.pub without any certificate is refused (no valid entry names
// it, and no certificate of the data directory is replaced: the public
// key is not replaced alone; nothing written); under the honest, logged
// ingest-2.cert the same publish run again replaces it.
func TestPublishHealsForeignPub(t *testing.T) {
	f := newFixture(t)
	st, res2, tp, _ := f.compromise(t)
	rot := f.reissue(t, res2, 2, res2.Pin.Revoked[0].AtTime, "rot2")
	// The thief removes his certificate and leaves his public key.
	if err := removePlatformFile(st, "ingest-2.cert"); err != nil {
		t.Fatal(err)
	}
	before := listDir(t, st.Path("platform"))
	err := Publish(PublishOptions{From: rot, Data: st, Pin: res2.Pin})
	if !errors.Is(err, store.ErrExists) || errors.Is(err, translog.ErrDuplicate) || !strings.Contains(err.Error(), st.Path("platform", "ingest-2.pub")) ||
		!strings.Contains(err.Error(), "replaced only together with its certificate") {
		t.Fatalf("lone foreign ingest-2.pub: %v", err)
	}
	if fmt.Sprint(listDir(t, st.Path("platform"))) != fmt.Sprint(before) || !bytes.Equal(mustReadFile(t, st.Path("platform", "ingest-2.pub")), tp) {
		t.Fatal("written")
	}
	if es := lookupCert(t, st, res2.Pin, "ingest-2.cert"); len(es) != 0 {
		t.Fatalf("logged: %+v", es)
	}
	// Once the honest certificate is logged, a foreign public key under
	// it is replaced by running the same publish again.
	if err := removePlatformFile(st, "ingest-2.pub"); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: rot, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.Path("platform", "ingest-2.pub"), tp, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: rot, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatalf("foreign ingest-2.pub under the honest, logged ingest-2.cert: %v", err)
	}
	samePlatform(t, st, rot, "ingest-2.cert", "ingest-2.pub")
}

// TestPublishValidEntryKept (attack review 21c R2): a valid entry is
// never replaced by other content: a second certificate of the same
// name (the same key, another valid_from) against the honest, logged
// one is refused, also when a foreign file lies in data/platform/, and
// neither the files nor the log change.
func TestPublishValidEntryKept(t *testing.T) {
	f := newFixture(t)
	st, res2, _, tc := f.compromise(t)
	if err := removePlatformFile(st, "ingest-2.cert"); err != nil {
		t.Fatal(err)
	}
	if err := removePlatformFile(st, "ingest-2.pub"); err != nil {
		t.Fatal(err)
	}
	rot := f.reissue(t, res2, 2, res2.Pin.Revoked[0].AtTime, "rot2")
	if err := Publish(PublishOptions{From: rot, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatal(err)
	}
	honest := mustReadFile(t, filepath.Join(rot, "platform", "ingest-2.cert"))
	newPub := mustReadFile(t, filepath.Join(rot, "platform", "ingest-2.pub"))
	id2, _ := f.platform(t).IdentityKey(2)
	c, err := keys.NewPlatformCert(id2, 2, keys.RoleIngest, 2, ed25519.PublicKey(newPub), testNow.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	other, _ := c.Encode()
	otherExp := writeExport(t, filepath.Join(f.base, "other"), map[string][]byte{"ingest-2.cert": other, "ingest-2.pub": newPub})
	for _, foreign := range [][]byte{nil, tc} {
		if foreign != nil {
			if err := os.WriteFile(st.Path("platform", "ingest-2.cert"), foreign, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		have := mustReadFile(t, st.Path("platform", "ingest-2.cert"))
		before := listDir(t, st.Path("platform"))
		err = Publish(PublishOptions{From: otherExp, Data: st, Pin: res2.Pin})
		if !errors.Is(err, store.ErrExists) || !errors.Is(err, translog.ErrDuplicate) || !strings.Contains(err.Error(), "a valid entry is never replaced") {
			t.Fatalf("second certificate of the same name against the valid one: %v", err)
		}
		if !bytes.Equal(mustReadFile(t, st.Path("platform", "ingest-2.cert")), have) || fmt.Sprint(listDir(t, st.Path("platform"))) != fmt.Sprint(before) {
			t.Fatal("replaced")
		}
		if es := lookupCert(t, st, res2.Pin, "ingest-2.cert"); len(es) != 1 || !bytes.Equal(es[0].Content, honest) {
			t.Fatalf("log changed: %+v", es)
		}
	}
	// The honest export heals it.
	if err := Publish(PublishOptions{From: rot, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatal(err)
	}
	samePlatform(t, st, rot, "ingest-2.cert", "ingest-2.pub")
}
