package ceremony

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/translog/translogtest"
	"github.com/tim-riep/go-mail/internal/witness"
)

func TestInitDev(t *testing.T) {
	log, _ := translogtest.NewUnverified(true)
	base := t.TempDir()
	data, kd := filepath.Join(base, "data"), filepath.Join(base, "keys")
	now := time.Unix(1_800_000_000, 0)
	res, err := InitDev(data, kd, now, log, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Pin.Dev || res.Pin.Gen != 1 {
		t.Fatal("pin must carry the development flag")
	}
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []keys.Role{keys.RoleAdmin, keys.RoleIngest} {
		c, err := st.ReadPlatformCert(role, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Verify(res.IdentityPub); err != nil || c.ValidFrom != now.UnixMilli() {
			t.Fatal("certificate")
		}
	}
	ingest, gen, err := ReadKey(filepath.Join(kd, IngestKeyFile), store.KeyRoleIngest)
	if err != nil || gen != 1 {
		t.Fatal(err)
	}
	c, _ := st.ReadPlatformCert(keys.RoleIngest, 1)
	if !c.Pub.Equal(ingest.Public()) {
		t.Fatal("ingest key does not match its certificate")
	}
	if _, _, err := ReadKey(filepath.Join(kd, IngestKeyFile), store.KeyRoleAdmin); err == nil {
		t.Fatal("wrong role accepted")
	}
	if _, _, err := ReadKey(filepath.Join(kd, "missing"), store.KeyRoleAdmin); err == nil {
		t.Fatal("missing key")
	}
	pin, err := ReadPin(filepath.Join(kd, PinFile))
	if err != nil || !pin.Pub.Equal(res.IdentityPub) {
		t.Fatal("pin")
	}
	if _, err := ReadPin(filepath.Join(kd, "missing")); err == nil {
		t.Fatal("missing pin")
	}
	root, _ := os.ReadFile(filepath.Join(kd, RootFile))
	if !strings.HasPrefix(string(root), "UNSICHER") {
		t.Fatal("root file must be marked insecure")
	}
	for _, f := range []string{AdminKeyFile, IngestKeyFile, RootFile} {
		fi, _ := os.Stat(filepath.Join(kd, f))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, fi.Mode())
		}
	}
	// No private key in the data directory: no file there decodes as a
	// platform key, and the root seed does not occur.
	filepath.Walk(data, func(p string, fi os.FileInfo, err error) error {
		if fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			if _, _, _, err := store.DecodePlatformKey(b); err == nil {
				t.Fatalf("private key in the data directory: %s", p)
			}
		}
		return nil
	})
	// A second run into the same key directory is refused.
	if _, err := InitDev(filepath.Join(base, "data2"), kd, now, log, nil, 0); !errors.Is(err, ErrKeyDir) {
		t.Fatal("second ceremony into the same key directory")
	}
	// The key directory must not be inside the data directory, nor the
	// other way round.
	if _, err := InitDev(data, filepath.Join(data, "keys"), now, log, nil, 0); !errors.Is(err, ErrKeyDir) {
		t.Fatal("key directory inside the data directory")
	}
	if _, err := InitDev(filepath.Join(base, "k2", "data"), filepath.Join(base, "k2"), now, log, nil, 0); !errors.Is(err, ErrKeyDir) {
		t.Fatal("data directory inside the key directory")
	}
}

// TestInitDevLog: InitDev appends both certificates to the operator log
// of the new data directory, where they are valid against the pin's
// identity list, passes them to a given log as well, and writes
// platform/witnesses.rec with the pinned witnesses (task 15).
func TestInitDevLog(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "data")
	rec := &recordingLog{}
	res, err := InitDev(data, filepath.Join(base, "keys"), time.Now(), rec, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.names) != 2 || rec.names[0] != "admin-1.cert" || rec.names[1] != "ingest-1.cert" {
		t.Fatalf("given log: %v", rec.names)
	}
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	l, err := translog.Open(translog.Options{Store: st, Identities: []translog.Identity{{Gen: 1, Pub: res.IdentityPub}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"admin-1.cert", "ingest-1.cert"} {
		raw, err := st.ReadPlatformFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.CheckPlatform(name, raw); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	wr, err := st.ReadPlatformFile("witnesses.rec")
	if err != nil {
		t.Fatal(err)
	}
	ws, err := witness.DecodeWitnesses(wr)
	if err != nil || ws.Min != 1 || len(ws.List) != 1 || ws.List[0].Name != DevWitnessName || !ws.List[0].Pub.Equal(res.Pin.Witnesses[0].Pub) {
		t.Fatalf("witnesses.rec: %+v %v", ws, err)
	}
}

// recordingLog records the names AppendPlatform received.
type recordingLog struct {
	translogtest.Unverified
	names []string
}

func (r *recordingLog) AppendPlatform(name string, _ []byte) error {
	r.names = append(r.names, name)
	return nil
}

// TestInitDevWitnesses: the pin carries origin, witnesses, quorum and
// identity list (translog doc.go "Pin"); an inadmissible quorum is
// refused before anything is written.
func TestInitDevWitnesses(t *testing.T) {
	log, _ := translogtest.NewUnverified(true)
	base := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	ws := []witness.Key{{Name: "w1", Pub: pub}, {Name: "w2", Pub: pub2}}
	data := filepath.Join(base, "data")
	if _, err := InitDev(data, filepath.Join(base, "keys"), time.Now(), log, ws, 1); !errors.Is(err, store.ErrRecord) {
		t.Fatalf("1 of 2: %v", err)
	}
	if _, err := os.Stat(data); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("data directory written despite the refused quorum")
	}
	res, err := InitDev(data, filepath.Join(base, "keys"), time.Now(), log, ws, 2)
	if err != nil {
		t.Fatal(err)
	}
	p := res.Pin
	if p.Origin != DevOrigin || p.MinWitnesses != 2 || len(p.Witnesses) != 2 || len(p.Identities) != 1 ||
		!p.Identities[0].Pub.Equal(res.IdentityPub) {
		t.Fatalf("pin %+v", p)
	}
	// Without witnesses a development witness is created and pinned.
	res, err = InitDev(filepath.Join(base, "d2"), filepath.Join(base, "k2"), time.Now(), log, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pin.Witnesses) != 1 || res.Pin.Witnesses[0].Name != DevWitnessName || res.Pin.MinWitnesses != 1 {
		t.Fatal("development witness")
	}
	if info, err := os.Stat(filepath.Join(base, "k2", WitnessKeyFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("development witness key file")
	}
}
