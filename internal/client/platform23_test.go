package client_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 23: ingestKeyFor reads ingest-<gen>.cert once. The
// signature, the key and the comparison with the log (Log.CheckPlatform)
// work on the same bytes, so a file replaced right after the read can
// neither make the client take a key the log does not hold nor change
// what it checked.

// TestPlatformIngestCertSwapped: an attacker with write access to
// platform/ and the stolen, not yet revoked identity key 1 puts a
// certificate of ingest generation 1 for his own key, signed validly
// but not logged, into ingest-1.cert and ingest-1.pub and delivers a
// mail signed with that key; right after the client read the
// certificate (the test hook), he puts the logged files back. The
// client never takes his key: the log check rejects the certificate it
// read (translog.ErrMismatch, as for any certificate the log does not
// hold) and never shows his mail. The other way round (the logged
// certificate when read, the forged one right after) the client takes
// the logged key and shows only the genuine mail.
//
// List checks the mails in the order of their random IDs, and the hook
// swaps the files at the first read only: the mail checked first is
// rejected by the log check, the next one reads ingest-1.cert again,
// now the logged one. So in the first case the genuine mail is shown
// exactly when it was not checked first, that is when the one warning
// of the log check does not name it (task 23b: the test expected it
// never shown and failed whenever the attacker's mail had the smaller
// ID, on every platform).
func TestPlatformIngestCertSwapped(t *testing.T) {
	f := newFixture(t)
	genuineID := f.deliver(t, "genuine", "x").ID.String()

	certPath := f.env.Store.Path("platform", store.PlatformFileName("ingest", 1, "cert"))
	pubPath := f.env.Store.Path("platform", store.PlatformFileName("ingest", 1, "pub"))
	loggedCert, loggedPub := mustRead(t, certPath), mustRead(t, pubPath)
	lc, err := keys.DecodePlatformCert(loggedCert)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := platformKeys(t, f.env, 1)
	defer keys.Wipe(identity)
	roguePub, rogue, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fc, err := keys.NewPlatformCert(identity, lc.IdentityGen, keys.RoleIngest, 1, roguePub, lc.ValidFrom)
	if err != nil {
		t.Fatal(err)
	}
	forgedCert, err := fc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	put := func(cert, pub []byte) {
		t.Helper()
		if err := store.WriteFileAtomic(certPath, cert); err != nil {
			t.Fatal(err)
		}
		if err := store.WriteFileAtomic(pubPath, pub); err != nil {
			t.Fatal(err)
		}
	}

	// The attacker's mail: a server with his key while his files are in
	// place (the server side of testenv.New does not check the log).
	put(forgedCert, roguePub)
	f.in.Close()
	in, err := ingest.New(ingest.Config{Store: f.env.Store, Log: f.env.Log, IngestKey: rogue, IngestGen: 1, Now: f.env.Clock.Now,
		DiskSpace: func(string) (uint64, uint64, error) { return 1, 2, nil }})
	if err != nil {
		t.Fatal(err)
	}
	f.in = in
	deliverTo(t, f, "a@example.org", "rogue")
	in.Close()

	for _, tc := range []struct {
		name              string
		first, firstPub   []byte // on disk when the client reads
		second, secondPub []byte // put in place right after the read
		wantErr           bool
	}{
		{"forged then logged", forgedCert, roguePub, loggedCert, loggedPub, true},
		{"logged then forged", loggedCert, loggedPub, forgedCert, roguePub, false},
	} {
		t.Run(strings.ReplaceAll(tc.name, " ", "_"), func(t *testing.T) {
			for _, op := range []string{"key", "list"} {
				put(tc.first, tc.firstPub)
				c := f.env.Reopen(f.u)
				calls := 0
				client.SetCertReadHook(t, func(gen uint32) {
					calls++
					if gen == 1 && calls == 1 {
						put(tc.second, tc.secondPub)
					}
				})
				switch op {
				case "key":
					pub, err := c.IngestKeyFor(1)
					if bytes.Equal(pub, roguePub) {
						t.Fatal("the client took the key of the certificate that is not in the log")
					}
					if tc.wantErr {
						// The certificate read is not in the log: the log
						// check rejects it (as for any unlogged certificate,
						// translog.ErrMismatch), or ErrPlatform.
						if !errors.Is(err, client.ErrPlatform) && !errors.Is(err, translog.ErrMismatch) && !errors.Is(err, translog.ErrNotInLog) {
							t.Fatalf("ingestKeyFor: %v", err)
						}
					} else if err != nil || !bytes.Equal(pub, loggedPub) {
						t.Fatalf("ingestKeyFor: %v", err)
					}
				case "list":
					f.env.Warnings.Take()
					list, err := c.List(f.mbx, store.ID{})
					if err != nil {
						t.Fatal(err)
					}
					s, warnings := subjects(list), f.env.Warnings.Take()
					if strings.Contains(s, "rogue") {
						t.Fatalf("the mail signed with the key that is not in the log is shown: %s", s)
					}
					// The warnings of the log check: with the forged
					// certificate read first exactly one (the mail
					// checked first), else none.
					var logWarnings []string
					for _, w := range warnings {
						if strings.Contains(w, "nicht im Transparenzlog oder im Widerspruch dazu") {
							logWarnings = append(logWarnings, w)
						}
					}
					wantGenuine := true
					if tc.wantErr {
						if len(logWarnings) != 1 {
							t.Fatalf("listed: %s, warnings %q: want one warning of the log check", s, warnings)
						}
						wantGenuine = !strings.Contains(logWarnings[0], genuineID)
					} else if len(logWarnings) != 0 {
						t.Fatalf("listed: %s, warnings %q", s, warnings)
					}
					if strings.Contains(s, "genuine") != wantGenuine {
						t.Fatalf("listed: %s, warnings %q", s, warnings)
					}
				}
				if calls == 0 {
					t.Fatal("ingest-1.cert not read")
				}
				client.SetCertReadHook(t, nil)
			}
		})
	}
}
