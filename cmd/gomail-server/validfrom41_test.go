package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 24, package C: valid_from of "address add" after the
// last logged assignment (backlog item 41, D80 addendum 20j) and the two
// low points left from the review of the patch series of item 63.

// setAddressClock makes addressNow return the time ms (Unix
// milliseconds) until the test ends.
func setAddressClock(t *testing.T, ms int64) {
	t.Helper()
	addressNow = func() time.Time { return time.UnixMilli(ms) }
	t.Cleanup(func() { addressNow = time.Now })
}

// addressValidFroms returns the valid_from of every valid assignment of
// addr in the operator log, in log order.
func (s *logSetup) addressValidFroms(t *testing.T, addr string) []int64 {
	t.Helper()
	es, err := s.operator(t).Lookup(translog.KindAddress, []byte(addr))
	if err != nil {
		t.Fatal(err)
	}
	var out []int64
	for _, e := range es {
		a, err := store.DecodeAddressAssignment(e.Content)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, a.ValidFrom)
	}
	return out
}

// addAt runs "address add" for addr and s.mbx with the clock at ms and
// returns its exit status and standard error.
func (s *logSetup) addAt(t *testing.T, addr string, ms int64) (int, string) {
	t.Helper()
	setAddressClock(t, ms)
	var out, errb bytes.Buffer
	code := run(context.Background(), s.addArgs(addr, s.mbx), &out, &errb, nil)
	return code, errb.String()
}

func equalInt64s(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestAddressAddValidFromFirst (item 41): without an earlier assignment
// of the address, valid_from is the clock of this computer.
func TestAddressAddValidFromFirst(t *testing.T) {
	s := newLogSetup(t)
	now := time.Now().UnixMilli()
	if code, msg := s.addAt(t, "first@example.org", now); code != 0 {
		t.Fatalf("exit status %d: %q", code, msg)
	}
	if got := s.addressValidFroms(t, "first@example.org"); !equalInt64s(got, []int64{now}) {
		t.Fatalf("valid_from %v, want [%d]", got, now)
	}
}

// TestAddressAddValidFromAfterLogged (item 41): a logged assignment of
// the address whose valid_from is not before the clock, up to
// translog.MaxClockSkew - 1 ms ahead of it (the clock went back, or
// another computer's runs ahead), is followed with its valid_from + 1 ms
// instead of failing with ErrOrder; in the same millisecond as well.
// Two further assignments with the clock unchanged: the second follows
// the newest assignment, not the first; in the case "at the bound" it
// gets valid_from = clock + MaxClockSkew exactly.
func TestAddressAddValidFromAfterLogged(t *testing.T) {
	s := newLogSetup(t)
	now := time.Now().UnixMilli()
	skew := translog.MaxClockSkew.Milliseconds()
	for _, tc := range []struct {
		name  string
		ahead int64
	}{
		{"same millisecond", 0},
		{"one minute ahead", 60_000},
		{"at the bound", skew - 2},
	} {
		addr := strings.ReplaceAll(tc.name, " ", "-") + "@example.org"
		if code, msg := s.addAt(t, addr, now+tc.ahead); code != 0 {
			t.Fatalf("%s: first assignment: exit status %d: %q", tc.name, code, msg)
		}
		for i := 0; i < 2; i++ {
			if code, msg := s.addAt(t, addr, now); code != 0 {
				t.Fatalf("%s: %d: exit status %d: %q", tc.name, i, code, msg)
			}
		}
		want := []int64{now + tc.ahead, now + tc.ahead + 1, now + tc.ahead + 2}
		if got := s.addressValidFroms(t, addr); !equalInt64s(got, want) {
			t.Fatalf("%s: valid_from %v, want %v", tc.name, got, want)
		}
	}
}

// TestAddressAddValidFromBeyondSkew (item 41, Q9, F3 of the attack
// review of task 21a): a logged assignment of the address dated
// translog.MaxClockSkew or more ahead of the clock is not carried on: the
// log refuses with ErrOrder as before 41 (exit status 1), nothing is
// logged and addresses.json stays as it was. A raised valid_from that the
// log refuses for another reason fails the same way (fail closed): one
// within the bound but after the valid_from of a logged successor
// admin-2.cert (D93 (3)).
func TestAddressAddValidFromBeyondSkew(t *testing.T) {
	s := newLogSetup(t)
	now := time.Now().UnixMilli()
	skew := translog.MaxClockSkew.Milliseconds()
	check := func(name, addr string, at int64, want []int64, cause string) {
		t.Helper()
		before, err := os.ReadFile(s.st.AddressesFile())
		if err != nil {
			t.Fatal(err)
		}
		size := s.treeSize(t)
		code, msg := s.addAt(t, addr, at)
		if code != 1 || !strings.Contains(msg, cause) || strings.Contains(msg, "example.org") {
			t.Fatalf("%s: exit status %d: %q", name, code, msg)
		}
		if got := s.addressValidFroms(t, addr); !equalInt64s(got, want) {
			t.Fatalf("%s: valid_from %v, want %v", name, got, want)
		}
		if n := s.treeSize(t); n != size {
			t.Fatalf("%s: logged: %d entries, before %d", name, n, size)
		}
		if after, _ := os.ReadFile(s.st.AddressesFile()); !bytes.Equal(before, after) {
			t.Fatalf("%s: addresses.json changed", name)
		}
	}
	for _, ahead := range []int64{skew, skew + 1, 24 * 3600 * 1000} {
		addr := "far@example.org"
		if ahead != skew {
			addr = "farther" + time.Duration(ahead*int64(time.Millisecond)).String() + "@example.org"
		}
		if code, msg := s.addAt(t, addr, now+ahead); code != 0 {
			t.Fatalf("ahead %d ms: first assignment: exit status %d: %q", ahead, code, msg)
		}
		check("ahead "+time.Duration(ahead*int64(time.Millisecond)).String(), addr, now, []int64{now + ahead}, "valid_from does not increase")
	}

	// admin-2.cert, valid from now + 1 minute and logged: admin
	// generation 1 assigns only before it. An assignment of generation 1
	// at now + 1 minute - 1 ms stands; the next would be raised to the
	// successor's valid_from, which the log refuses.
	idPriv := s.identityPriv(t)
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := keys.NewPlatformCert(idPriv, 1, keys.RoleAdmin, 2, pub2, now+60_000)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.operator(t).AppendPlatform(store.PlatformFileName("admin", 2, "cert"), enc); err != nil {
		t.Fatal(err)
	}
	if code, msg := s.addAt(t, "succ@example.org", now+60_000-1); code != 0 {
		t.Fatalf("before admin-2: exit status %d: %q", code, msg)
	}
	check("raised onto admin-2", "succ@example.org", now, []int64{now + 60_000 - 1}, "after its successor's valid_from")
}

// TestAddressAddParallelUnderLock (item 41, from the attack review of
// package C): eight parallel runs of "address add" for the same address
// and mailbox with a frozen clock all succeed, and their valid_from are
// now, now+1, ..., now+7 in log order. The last logged assignment and
// the clock are read under addresses.lock; read before it, two runs
// would sign the same valid_from and the later one would fail with
// ErrOrder.
func TestAddressAddParallelUnderLock(t *testing.T) {
	s := newLogSetup(t)
	now := time.Now().UnixMilli()
	setAddressClock(t, now)
	const n = 8
	var wg sync.WaitGroup
	codes := make([]int, n)
	msgs := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var out, errb bytes.Buffer
			codes[i] = run(context.Background(), s.addArgs("parallel@example.org", s.mbx), &out, &errb, nil)
			msgs[i] = errb.String()
		}(i)
	}
	wg.Wait()
	for i := range codes {
		if codes[i] != 0 {
			t.Fatalf("run %d: exit status %d: %q", i, codes[i], msgs[i])
		}
	}
	want := make([]int64, n)
	for i := range want {
		want[i] = now + int64(i)
	}
	if got := s.addressValidFroms(t, "parallel@example.org"); !equalInt64s(got, want) {
		t.Fatalf("valid_from %v, want %v", got, want)
	}
}

// identityPriv returns the private key of platform identity generation
// 1 of the development platform s, derived from the root seed InitDev
// writes into the key directory (as devPlatformRoot in internal/e2e).
func (s *logSetup) identityPriv(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(s.keys, ceremony.RootFile))
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(text), "seed: ")
	if i < 0 {
		t.Fatal("no seed in the root file")
	}
	b, err := hex.DecodeString(strings.Fields(string(text[i+len("seed: "):]))[0])
	if err != nil || len(b) != len(keys.Seed{}) {
		t.Fatal("seed", err)
	}
	var seed keys.Seed
	copy(seed[:], b)
	p := keys.DerivePlatform(&seed)
	t.Cleanup(p.Zero)
	priv, err := p.IdentityKey(1)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(s.p.Pub) {
		t.Fatal("derived identity key differs from the pin")
	}
	return priv
}
