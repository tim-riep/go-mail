package ceremony

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

func TestInitDev(t *testing.T) {
	log, _ := translog.NewUnverified(true)
	base := t.TempDir()
	data, kd := filepath.Join(base, "data"), filepath.Join(base, "keys")
	now := time.Unix(1_800_000_000, 0)
	res, err := InitDev(data, kd, now, log)
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
	if _, err := InitDev(filepath.Join(base, "data2"), kd, now, log); !errors.Is(err, ErrKeyDir) {
		t.Fatal("second ceremony into the same key directory")
	}
	// The key directory must not be inside the data directory, nor the
	// other way round.
	if _, err := InitDev(data, filepath.Join(data, "keys"), now, log); !errors.Is(err, ErrKeyDir) {
		t.Fatal("key directory inside the data directory")
	}
	if _, err := InitDev(filepath.Join(base, "k2", "data"), filepath.Join(base, "k2"), now, log); !errors.Is(err, ErrKeyDir) {
		t.Fatal("data directory inside the key directory")
	}
}
