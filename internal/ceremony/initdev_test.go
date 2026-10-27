//go:build !gomail_dev

package ceremony

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestInitDevProduction: a build without the tag gomail_dev has no
// development ceremony (task 15b point 4): InitDev returns ErrDev and
// writes nothing, neither the data directory nor the key directory.
func TestInitDevProduction(t *testing.T) {
	base := t.TempDir()
	data, kd := filepath.Join(base, "data"), filepath.Join(base, "keys")
	if res, err := InitDev(data, kd, time.Now(), nil, 0); !errors.Is(err, ErrDev) || res != nil {
		t.Fatalf("InitDev: %v %v", res, err)
	}
	for _, d := range []string{data, kd} {
		if _, err := os.Lstat(d); err == nil {
			t.Fatalf("%s written", d)
		}
	}
}
