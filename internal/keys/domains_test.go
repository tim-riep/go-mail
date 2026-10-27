package keys

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/rec"
)

// TestDomainsOfVersion13 covers the short names added in specification
// 1.3 (3.7): user, invite and wrap-accept.
func TestDomainsOfVersion13(t *testing.T) {
	added := map[string]string{DomainUser: "user", DomainInvite: "invite", DomainWrapAccept: "wrap-accept"}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	pub := key.Public().(ed25519.PublicKey)
	for d, want := range added {
		if d != want || !KnownDomain(d) {
			t.Fatalf("domain %q not known as %q", d, want)
		}
		msg, err := signedMessage(d, []byte("body"))
		if err != nil || string(msg) != "gomail/v1/sig/"+want+"\x00body" {
			t.Fatalf("signed message of %q: %q %v", d, msg, err)
		}
		sig, err := Sign(key, d, []byte("body"))
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(pub, d, []byte("body"), sig) {
			t.Fatalf("signature under %q rejected", d)
		}
		// The signature holds under no other domain of the table.
		for _, other := range domains {
			if other != d && Verify(pub, other, []byte("body"), sig) {
				t.Fatalf("signature under %q verifies under %q", d, other)
			}
		}
		// The record type gomail/v1/rec/<name> carries the short name.
		s := rec.MustSchema("gomail/v1/rec/"+want, rec.Field{Num: 1, Name: "a", Kind: rec.U8})
		if got, err := RecordDomain(s); err != nil || got != want {
			t.Fatalf("RecordDomain(%s) = %q, %v", s.Type, got, err)
		}
	}
	// "user" is a prefix of "user-gen", but the NUL byte after the short
	// name keeps the signed messages apart: no domain followed by NUL is a
	// prefix of another domain followed by NUL.
	for _, a := range domains {
		for _, b := range domains {
			if a != b && strings.HasPrefix(b+"\x00", a+"\x00") {
				t.Fatalf("%q and %q are not separated", a, b)
			}
		}
	}
	sig, _ := Sign(key, DomainUser, []byte("-gen\x00body"))
	if Verify(pub, DomainUserGen, []byte("body"), sig) {
		t.Fatal("user and user-gen signatures collide")
	}
	// Similar names that are not in the table stay unknown.
	for _, d := range []string{"users", "User", "wrap_accept", "wrapaccept", "accept", "invites", "user/"} {
		if KnownDomain(d) {
			t.Fatalf("%q must not be a domain", d)
		}
	}
}
