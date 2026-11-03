package client

import (
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// TestIngestRevocation (task 21b, D93 (2) and its addendum): an ingest
// generation ends at the revoked_at_time of its own revocation or of the
// revocation of the identity generation that certified it, the earlier
// of both (revokedFor through Verifier.RevokedCertAtTime, with the
// issuer from the certificate); revocations of other generations and
// roles do not touch it.
func TestIngestRevocation(t *testing.T) {
	v := &translog.Verifier{Revoked: []translog.Revoked{
		{Role: store.KeyRoleIdentity, Gen: 1, AtSize: 5, AtTime: 300},
		{Role: store.KeyRoleIdentity, Gen: 2, AtSize: 9, AtTime: 900},
		{Role: store.KeyRoleAdmin, Gen: 3, AtSize: 7, AtTime: 50},
		{Role: store.KeyRoleIngest, Gen: 1, AtSize: 6, AtTime: 400},
		{Role: store.KeyRoleIngest, Gen: 2, AtSize: 6, AtTime: 100},
	}}
	for _, tc := range []struct {
		gen, issuer uint32
		from        int64 // first receipt time revoked; 0: never
	}{
		{1, 1, 300}, // the identity's revocation is earlier
		{2, 1, 100}, // its own is earlier
		{1, 3, 400}, // its own only
		{3, 2, 900}, // the issuer's only
		{3, 3, 0},   // admin 3 is no ingest generation
		{4, 4, 0},
	} {
		k := ingestKey{gen: tc.gen, issuer: tc.issuer}
		if tc.from == 0 {
			if k.revokedFor(v, 1<<40) {
				t.Errorf("ingest %d by identity %d revoked", tc.gen, tc.issuer)
			}
			continue
		}
		if k.revokedFor(v, tc.from-1) || !k.revokedFor(v, tc.from) || !k.revokedFor(v, tc.from+1) {
			t.Errorf("ingest %d by identity %d: not revoked exactly from %d", tc.gen, tc.issuer, tc.from)
		}
	}
	if (ingestKey{gen: 1, issuer: 1}).revokedFor(&translog.Verifier{}, 1<<40) {
		t.Error("without field 7")
	}
}
