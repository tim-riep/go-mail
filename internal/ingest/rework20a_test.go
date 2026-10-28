package ingest

import (
	"errors"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// TestNotYetValid (task 20a point 1): New refuses an ingest key whose
// certificate is valid only from a time after Config.Now
// (ErrNotYetValid with ErrConfig), even by a millisecond and without
// tolerance, and takes no server lock then; from valid_from on it
// starts.
func TestNotYetValid(t *testing.T) {
	env := testenv.New(t)
	cert, err := env.Store.ReadPlatformCert(keys.RoleIngest, 1)
	if err != nil {
		t.Fatal(err)
	}
	from := time.UnixMilli(cert.ValidFrom)
	for _, before := range []time.Duration{time.Millisecond, time.Minute, 24 * time.Hour} {
		at := from.Add(-before)
		_, err := New(Config{Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1,
			Now: func() time.Time { return at }})
		if !errors.Is(err, ErrNotYetValid) || !errors.Is(err, ErrConfig) {
			t.Fatalf("%v before valid_from: %v", before, err)
		}
	}
	// No lock left behind, and valid_from itself is valid.
	in := newIngest(t, env, func(c *Config) { c.Now = func() time.Time { return from } })
	in.Close()
}
