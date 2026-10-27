package client_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Task 06c: an epoch.rec beyond the head of mailbox.rec that can never
// become valid no longer blocks the mailbox; a user member replaces it
// under the mailbox lock. A valid one is adopted and never replaced.

// headOf returns the head of mailbox.rec of mbx.
func headOf(t *testing.T, env *testenv.Env, mbx store.ID) uint32 {
	t.Helper()
	m, err := env.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	return m.Epoch
}

// beyondEpoch returns epoch head+1 of mailbox.rec as alice would create
// it, an immediate member-added epoch beginning now with the members of
// the head and complete discards, changed by change and signed with key.
func beyondEpoch(t *testing.T, f *fixture, change func(e *store.Epoch), key ed25519.PrivateKey) []byte {
	t.Helper()
	h := headOf(t, f.env, f.mbx)
	links := store.NewChain()
	var head *store.Epoch
	var headData []byte
	for n := uint32(1); n <= h; n++ {
		e, d, err := f.env.Store.ReadEpoch(f.mbx, n)
		if err != nil {
			t.Fatal(err)
		}
		if err := links.Add(e, d); err != nil {
			t.Fatal(err)
		}
		head, headData = e, d
	}
	now := f.env.Clock.Now().UnixMilli()
	var discards []uint32
	for n := uint32(1); n <= h; n++ {
		if !links.Discarded(n) && links.Epoch(n).Begin > now {
			discards = append(discards, n)
		}
	}
	content, _ := ecdh.X25519().GenerateKey(rand.Reader)
	meta, _ := ecdh.X25519().GenerateKey(rand.Reader)
	e := &store.Epoch{
		MailboxID: f.mbx, Number: h + 1, Begin: now, Reason: store.ReasonMemberAdded, Suite: envelope.Suite1,
		ContentPub: content.PublicKey(), MetaPub: meta.PublicKey(),
		Members: append([]store.Member(nil), head.Members...), Discards: discards,
		PrevHash: store.EpochHash(headData), SignerID: f.u.ID, SignerGen: 1,
	}
	if change != nil {
		change(e)
	}
	if err := e.Sign(key); err != nil {
		t.Fatal(err)
	}
	data, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// plantEpoch writes an epoch.rec of the given kind at head+1 of
// mailbox.rec, as someone with write access to the data directory could,
// with a wrap for alice and a folders.gml beside it; mailbox.rec stays.
// It returns the number and the planted bytes.
func plantEpoch(t *testing.T, f *fixture, kind string) (uint32, []byte) {
	t.Helper()
	h := headOf(t, f.env, f.mbx)
	ks := f.env.Keystore(f.u)
	defer ks.Zero()
	var data []byte
	switch kind {
	case "empty":
		data = []byte{}
	case "junk":
		data = []byte("this is not an epoch.rec")
	case "oversized":
		data = make([]byte, store.MaxRecordFile+1)
	case "number":
		// The head itself, at the next number.
		_, data, _ = f.env.Store.ReadEpoch(f.mbx, h)
	case "chain":
		// Signed by alice, but naming another predecessor.
		data = beyondEpoch(t, f, func(e *store.Epoch) { e.PrevHash[0] ^= 1 }, ks.Identity)
	case "signature":
		// A valid structure signed with the identity of another user.
		_, mallory, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		data = beyondEpoch(t, f, nil, mallory)
	case "generation":
		// Signed by alice with a generation her user.rec does not have.
		data = beyondEpoch(t, f, func(e *store.Epoch) {
			e.SignerGen = 2
			for i := range e.Members {
				if e.Members[i].ID == f.u.ID {
					e.Members[i].Gen = 2
				}
			}
		}, ks.Identity)
	default:
		t.Fatalf("kind %s", kind)
	}
	n := h + 1
	if err := os.MkdirAll(filepath.Join(f.env.Store.EpochDir(f.mbx, n), "members"), 0o700); err != nil {
		t.Fatal(err)
	}
	for p, b := range map[string][]byte{
		f.env.Store.EpochFile(f.mbx, n):                              data,
		f.env.Store.WrapFile(f.mbx, n, f.u.ID):                       []byte("wrap"),
		f.env.Store.FoldersFile(f.mbx, n):                            []byte("folders"),
		filepath.Join(f.env.Store.EpochDir(f.mbx, n), "content.pub"): []byte("pub"),
	} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return n, data
}

// checkStored checks the stored chain up to the head of mailbox.rec like
// a reader: structure and the signature of every epoch with the key of
// its signer in user.rec.
func checkStored(t *testing.T, env *testenv.Env, mbx store.ID) {
	t.Helper()
	links := store.NewChain()
	for n := uint32(1); n <= headOf(t, env, mbx); n++ {
		e, d, err := env.Store.ReadEpoch(mbx, n)
		if err != nil {
			t.Fatalf("epoch %d: %v", n, err)
		}
		if err := links.Add(e, d); err != nil {
			t.Fatal(err)
		}
		u, _, err := env.Store.ReadUser(e.SignerID)
		if err != nil {
			t.Fatal(err)
		}
		g := u.Generation(e.SignerGen)
		if g == nil {
			t.Fatalf("epoch %d: generation %d", n, e.SignerGen)
		}
		if err := e.VerifySignature(g.IdentityPub); err != nil {
			t.Fatalf("epoch %d: %v", n, err)
		}
	}
}

// checkReplaced checks that the planted epoch.rec n is gone, a valid epoch
// of the chain stands in its place, its directory holds only the files of
// the replacement, and the replacement was reported with number and
// mailbox only.
func checkReplaced(t *testing.T, f *fixture, n uint32, planted []byte) {
	t.Helper()
	if headOf(t, f.env, f.mbx) < n {
		t.Fatalf("head %d below the replaced epoch %d", headOf(t, f.env, f.mbx), n)
	}
	got, err := os.ReadFile(f.env.Store.EpochFile(f.mbx, n))
	if err != nil || bytes.Equal(got, planted) {
		t.Fatalf("epoch %d not replaced: %v", n, err)
	}
	checkStored(t, f.env, f.mbx)
	if _, err := f.env.Store.ReadFolders(f.mbx, n); err != nil {
		t.Fatal(err)
	}
	if b, _ := f.env.Store.ReadFolders(f.mbx, n); string(b) == "folders" {
		t.Fatal("planted folders.gml kept")
	}
	if b, _ := f.env.Store.ReadWrap(f.mbx, n, f.u.ID); string(b) == "wrap" {
		t.Fatal("planted wrap kept")
	}
	want := "Die ungültige Epoche " + strconv.FormatUint(uint64(n), 10) + " von " + f.mbx.String() + " wurde ersetzt."
	found := false
	for _, w := range f.env.Warnings.Take() {
		if strings.Contains(w, "wurde ersetzt") {
			if !strings.HasSuffix(w, want) {
				t.Fatalf("warning %q", w)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("replacement not reported")
	}
	if _, err := f.env.Reopen(f.u).List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
}

// An epoch.rec at head+1 of mailbox.rec that does not decode, names
// another number, breaks the chain, carries a foreign signature or an
// unknown generation, or is oversized blocks neither Revoke, Share nor
// Sync: it is replaced, and the chain is valid afterwards.
func TestInvalidEpochBeyondHeadIsReplaced(t *testing.T) {
	for _, kind := range []string{"empty", "junk", "oversized", "number", "chain", "signature", "generation"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			bob := f.env.NewUser("bob")
			f.env.Clock.Advance(time.Hour)
			f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
			f.env.Clock.Advance(time.Minute)

			before := chainOf(t, f.env, f.mbx)
			n, planted := plantEpoch(t, f, kind)
			f.env.Warnings.Take()
			revokedAt := f.env.Clock.Now()
			if err := f.u.Client.Revoke(f.mbx, bob.ID); err != nil {
				t.Fatal(err)
			}
			checkReplaced(t, f, n, planted)
			// The replacement is the revoking epoch, with discards
			// complete against the chain without the planted file.
			e := checkImmediate(t, before, chainOf(t, f.env, f.mbx), revokedAt, store.ReasonMemberRemoved)
			if e.Number != n || kindOf(e, bob.ID) != 0 {
				t.Fatal("revoking epoch")
			}

			f.env.Clock.Advance(time.Minute)
			before = chainOf(t, f.env, f.mbx)
			n, planted = plantEpoch(t, f, kind)
			sharedAt := f.env.Clock.Now()
			if _, err := f.u.Client.Share(f.mbx, bob.ID, client.ShareOptions{}); err != nil {
				t.Fatal(err)
			}
			checkReplaced(t, f, n, planted)
			if e := checkImmediate(t, before, chainOf(t, f.env, f.mbx), sharedAt, store.ReasonMemberAdded); e.Number != n || kindOf(e, bob.ID) != store.MemberUser {
				t.Fatal("sharing epoch")
			}

			f.env.Clock.Advance(32 * 24 * time.Hour)
			n, planted = plantEpoch(t, f, kind)
			if err := f.u.Client.Sync(); err != nil {
				t.Fatal(err)
			}
			checkReplaced(t, f, n, planted)
			if _, err := bob.Client.MailboxName(f.mbx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A valid epoch beyond the head of mailbox.rec (as a crash between
// epoch.rec and mailbox.rec leaves it) is adopted, never replaced.
func TestValidEpochBeyondHeadIsAdopted(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	m, err := f.env.Store.ReadMailbox(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	head := chainOf(t, f.env, f.mbx)
	valid := f.env.ForgeEpoch(f.u, f.mbx, f.env.Clock.Now(), store.ReasonMemberAdded, head[len(head)-1].Members, "A")
	if err := f.env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	_, data, err := f.env.Store.ReadEpoch(f.mbx, valid.Number)
	if err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if err := f.u.Client.Revoke(f.mbx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(f.env.Store.EpochFile(f.mbx, valid.Number)); !bytes.Equal(got, data) {
		t.Fatal("valid epoch beyond the head replaced")
	}
	if warned(f.env, "wurde ersetzt") {
		t.Fatal("replacement reported")
	}
	after := chainOf(t, f.env, f.mbx)
	if len(after) != int(valid.Number)+4 {
		t.Fatalf("%d epochs", len(after))
	}
	rev := after[valid.Number]
	if rev.PrevHash != store.EpochHash(data) || rev.Reason != store.ReasonMemberRemoved || kindOf(rev, bob.ID) != 0 {
		t.Fatal("revocation not on top of the adopted epoch")
	}
	checkStored(t, f.env, f.mbx)
}

// A valid epoch that another client writes after this client loaded the
// chain is a race (K2 rule 3): never replaced, the change is created again
// on top of it.
func TestEpochRaceBeforeCreateIsNotReplaced(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	carol := f.env.NewUser("carol")
	dave := f.env.NewUser("dave")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	bob.Client.WithoutMailboxLock()
	fired := false
	var bobErr error
	client.SetCrashHook(t, func(p string) bool {
		if p == "share-wraps" && !fired {
			fired = true
			_, bobErr = bob.Client.Share(f.mbx, dave.ID, client.ShareOptions{})
		}
		return false
	})
	before := chainOf(t, f.env, f.mbx)
	f.env.Warnings.Take()
	if _, err := f.u.Client.Share(f.mbx, carol.ID, client.ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	if bobErr != nil {
		t.Fatal(bobErr)
	}
	ws := f.env.Warnings.Take()
	joined := strings.Join(ws, "\n")
	if !strings.Contains(joined, "zugleich eine Epoche") || strings.Contains(joined, "wurde ersetzt") {
		t.Fatalf("warnings %q", ws)
	}
	after := chainOf(t, f.env, f.mbx)
	n := len(before) + 1
	if len(after) != len(before)+8 {
		t.Fatalf("%d epochs", len(after)-len(before))
	}
	won, retry := after[n-1], after[n+3]
	if won.SignerID != bob.ID || kindOf(won, dave.ID) != store.MemberUser || kindOf(won, carol.ID) != 0 {
		t.Fatal("bob's epoch replaced")
	}
	if retry.SignerID != f.u.ID || kindOf(retry, carol.ID) != store.MemberUser || kindOf(retry, dave.ID) != store.MemberUser {
		t.Fatal("alice's epoch on top of bob's")
	}
	checkStored(t, f.env, f.mbx)
}

// A crash at any point of the replacement, including between the new
// epoch.rec and mailbox.rec, is healed by the next run.
func TestCrashWhileReplacingInvalidEpoch(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	member := true
	for _, point := range []string{"epoch-wraps", "epoch-folders", "epoch-written", "immediate", "supply", "mailbox"} {
		for _, kind := range []string{"junk", "signature"} {
			f.env.Clock.Advance(time.Minute)
			n, planted := plantEpoch(t, f, kind)
			run := func(c *client.Client) error {
				if member {
					return c.Revoke(f.mbx, bob.ID)
				}
				_, err := c.Share(f.mbx, bob.ID, client.ShareOptions{})
				return err
			}
			fired := false
			client.SetCrashHook(t, func(p string) bool {
				if p == point && !fired {
					fired = true
					return true
				}
				return false
			})
			err := run(f.u.Client)
			client.SetCrashHook(t, nil)
			if !errors.Is(err, client.ErrCrashed) {
				t.Fatalf("%s %s: %v", point, kind, err)
			}
			if err := run(f.env.Reopen(f.u)); err != nil {
				t.Fatalf("%s %s, next run: %v", point, kind, err)
			}
			member = !member
			checkReplaced(t, f, n, planted)
			h := chainOf(t, f.env, f.mbx)
			if (kindOf(h[len(h)-1], bob.ID) == store.MemberUser) != member {
				t.Fatalf("%s %s: bob's membership", point, kind)
			}
			ns, _ := f.env.Store.ListEpochs(f.mbx)
			for _, k := range ns {
				if _, err := os.Lstat(f.env.Store.EpochFile(f.mbx, k)); err != nil {
					t.Fatalf("%s %s: epoch %d without epoch.rec", point, kind, k)
				}
			}
		}
	}
}

// An epoch.rec that did not verify but is not known to be invalid for good
// is kept; after the last attempt the error names why.
func TestUnprovenInvalidEpochIsKept(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	n := headOf(t, f.env, f.mbx) + 1
	// A directory in place of epoch.rec cannot be read.
	if err := os.MkdirAll(f.env.Store.EpochFile(f.mbx, n), 0o700); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	err := f.u.Client.Revoke(f.mbx, bob.ID)
	if !errors.Is(err, store.ErrExists) || !strings.Contains(err.Error(), "not a regular file") || !strings.Contains(err.Error(), "3 attempts") {
		t.Fatalf("error %v", err)
	}
	if warned(f.env, "zugleich eine Epoche") {
		t.Fatal("reported as a race")
	}
	if fi, err := os.Lstat(f.env.Store.EpochFile(f.mbx, n)); err != nil || !fi.IsDir() {
		t.Fatal("kept file changed")
	}
}

// Invalid files at several numbers beyond the head are replaced in one
// run: a file after an epoch this change wrote cannot name it as its
// predecessor (store.Chain.Add rule 3), so it never becomes valid either.
func TestStackedInvalidEpochsAreReplaced(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	h := headOf(t, f.env, f.mbx)
	n, planted := plantEpoch(t, f, "signature")
	// A copy of the planted epoch at the following numbers, and junk.
	stacked := map[uint32][]byte{n: planted}
	for k := n + 1; k <= h+6; k++ {
		data := []byte("junk")
		if k%2 == 0 {
			data = planted
		}
		if err := os.MkdirAll(f.env.Store.EpochDir(f.mbx, k), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.env.Store.EpochFile(f.mbx, k), data, 0o600); err != nil {
			t.Fatal(err)
		}
		stacked[k] = data
	}
	f.env.Warnings.Take()
	if err := f.u.Client.Revoke(f.mbx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if got := headOf(t, f.env, f.mbx); got != h+4 {
		t.Fatalf("head %d", got)
	}
	for k := h + 1; k <= h+4; k++ {
		if got, _ := os.ReadFile(f.env.Store.EpochFile(f.mbx, k)); bytes.Equal(got, stacked[k]) {
			t.Fatalf("epoch %d not replaced", k)
		}
	}
	checkStored(t, f.env, f.mbx)
	if warned(f.env, "zugleich eine Epoche") {
		t.Fatal("reported as a race")
	}
	if _, err := f.env.Reopen(f.u).List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
}
