//go:build !gomail_dev

package ceremony

import (
	"time"

	"github.com/tim-riep/go-mail/internal/witness"
)

// DevBuild reports whether this build has the development ceremony
// (tag gomail_dev): a build without the tag has none.
const DevBuild = false

// InitDev is the development ceremony of a test build (initdev_dev.go,
// tag gomail_dev). This build has none: it returns ErrDev and writes
// nothing, so that no path of a production build writes a platform root
// into a file (task 15b point 4).
func InitDev(dataDir, keyDir string, now time.Time, witnesses []witness.Key, minWitnesses int) (*Result, error) {
	return nil, ErrDev
}
