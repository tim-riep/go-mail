package client_test

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// chainOf returns epochs 1 to the head of mailbox.rec as stored.
func chainOf(t *testing.T, env *testenv.Env, mbx store.ID) []*store.Epoch {
	t.Helper()
	m, err := env.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	var out []*store.Epoch
	for n := uint32(1); n <= m.Epoch; n++ {
		e, _, err := env.Store.ReadEpoch(mbx, n)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func kindOf(e *store.Epoch, id store.ID) store.MemberKind {
	for _, m := range e.Members {
		if m.ID == id {
			return m.Kind
		}
	}
	return 0
}

func wrapExists(env *testenv.Env, mbx store.ID, n uint32, user store.ID) bool {
	_, err := os.Lstat(env.Store.WrapFile(mbx, n, user))
	return err == nil
}

func numbers(es []*store.Epoch) []uint32 {
	var out []uint32
	for _, e := range es {
		out = append(out, e.Number)
	}
	return out
}

// checkImmediate checks the epoch created by a change at begin: reason,
// immediate begin, discards exactly the later epochs of before that were
// not discarded (2.4 rule 1), and the supply after it, three regular
// epochs with the same members beginning on the next three first days of
// a month (rule 5).
func checkImmediate(t *testing.T, before, after []*store.Epoch, begin time.Time, reason store.Reason) *store.Epoch {
	t.Helper()
	discarded := map[uint32]bool{}
	for _, e := range before {
		for _, n := range e.Discards {
			discarded[n] = true
		}
	}
	var want []uint32
	for _, e := range before {
		if !discarded[e.Number] && e.Begin > begin.UnixMilli() {
			want = append(want, e.Number)
		}
	}
	if len(after) != len(before)+4 {
		t.Fatalf("%d epochs after the change, %d before", len(after), len(before))
	}
	e := after[len(before)]
	if e.Reason != reason || e.Begin != begin.UnixMilli() || len(e.Discards) != len(want) {
		t.Fatalf("epoch %d: reason %d, begin %v, discards %v, want %v", e.Number, e.Reason, time.UnixMilli(e.Begin).UTC(), e.Discards, want)
	}
	for i := range want {
		if e.Discards[i] != want[i] {
			t.Fatalf("discards %v, want %v", e.Discards, want)
		}
	}
	for k, s := range after[len(before)+1:] {
		start := time.Date(begin.Year(), begin.Month()+time.Month(k+1), 1, 0, 0, 0, 0, time.UTC)
		if s.Reason != store.ReasonRegular || s.Begin != start.UnixMilli() || len(s.Discards) != 0 || len(s.Members) != len(e.Members) {
			t.Fatalf("supply epoch %d: reason %d, begin %v", s.Number, s.Reason, time.UnixMilli(s.Begin).UTC())
		}
		for _, m := range e.Members {
			if kindOf(s, m.ID) != m.Kind {
				t.Fatalf("supply epoch %d lacks member %s", s.Number, m.ID)
			}
		}
	}
	return e
}

func TestShareFromNow(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "before", "old mail")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	before := chainOf(t, f.env, f.mbx)
	if wrapped := f.env.Share(f.u, f.mbx, bob, client.ShareOptions{}); len(wrapped) != 0 {
		t.Fatalf("existing epochs wrapped: %v", wrapped)
	}
	after := chainOf(t, f.env, f.mbx)
	e5 := checkImmediate(t, before, after, f.env.Clock.Now(), store.ReasonMemberAdded)
	if kindOf(e5, bob.ID) != store.MemberUser || kindOf(e5, f.u.ID) != store.MemberUser || e5.SignerID != f.u.ID {
		t.Fatalf("members of the new epoch %+v", e5.Members)
	}
	for _, e := range after {
		if got, want := wrapExists(f.env, f.mbx, e.Number, bob.ID), e.Number >= 5; got != want {
			t.Fatalf("wrap of bob for epoch %d: %v", e.Number, got)
		}
	}
	// Running it again changes nothing.
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	if len(chainOf(t, f.env, f.mbx)) != len(after) {
		t.Fatal("a second share created epochs")
	}

	f.env.Clock.Advance(time.Minute)
	fresh := f.deliver(t, "after", "new mail")
	if fresh.Epoch != 5 {
		t.Fatalf("delivered for epoch %d", fresh.Epoch)
	}
	if _, body, err := bob.Client.Read(f.mbx, fresh.ID); err != nil || string(body) != "Subject: after\r\n\r\nnew mail\r\n" {
		t.Fatalf("bob reads the new mail: %v", err)
	}
	if _, _, err := bob.Client.Read(f.mbx, old.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("bob reads a mail before the share: %v", err)
	}
	list, err := bob.Client.List(f.mbx, store.ID{})
	if err != nil || len(list) != 1 || list[0].ID != fresh.ID {
		t.Fatalf("bob lists %d mails: %v", len(list), err)
	}
	if name, err := bob.Client.MailboxName(f.mbx); err != nil || name != "A" {
		t.Fatal(name, err)
	}
	for _, id := range []store.ID{old.ID, fresh.ID} {
		if _, _, err := f.u.Client.Read(f.mbx, id); err != nil {
			t.Fatal(err)
		}
	}
	// Bob is a member: he may share and creates the supply himself.
	f.env.Clock.Set(time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC))
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	if h := chainOf(t, f.env, f.mbx); len(h) != 10 || h[9].SignerID != bob.ID || kindOf(h[9], f.u.ID) != store.MemberUser {
		t.Fatal("supply of bob")
	}
}

func TestShareWithFrom(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "before", "old mail")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	if _, err := f.u.Client.Share(f.mbx, bob.ID, client.ShareOptions{From: 2}); !errors.Is(err, client.ErrRange) {
		t.Fatalf("from an epoch that has not begun: %v", err)
	}
	if wrapped := f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 1}); len(wrapped) != 1 || wrapped[0] != 1 {
		t.Fatalf("wrapped %v", wrapped)
	}
	if !wrapExists(f.env, f.mbx, 1, bob.ID) || wrapExists(f.env, f.mbx, 2, bob.ID) {
		t.Fatal("wraps of the existing epochs")
	}
	if _, body, err := bob.Client.Read(f.mbx, old.ID); err != nil || !strings.Contains(string(body), "old mail") {
		t.Fatalf("bob reads the old mail: %v", err)
	}
	// The wrap of epoch 1 is signed by alice, a user member of epoch 1.
	w, _ := f.env.Store.ReadWrap(f.mbx, 1, bob.ID)
	if pf := parse(t, w); pf.Trailer == nil || store.ID(pf.Trailer.Signer.ID) != f.u.ID {
		t.Fatal("signer of the wrap")
	}
}

// pastFixture: mails in epochs 1 (October), 2 (November) and 3
// (December); the clock in December.
type pastFixture struct {
	*fixture
	m1, m2, m3 *client.Mail
}

func newPastFixture(t *testing.T) *pastFixture {
	t.Helper()
	f := newFixture(t)
	p := &pastFixture{fixture: f}
	p.m1 = f.deliver(t, "one", "first")
	f.env.Clock.Set(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC))
	p.m2 = f.deliver(t, "two", "second")
	f.env.Clock.Set(time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC))
	p.m3 = f.deliver(t, "three", "third")
	if p.m1.Epoch != 1 || p.m2.Epoch != 2 || p.m3.Epoch != 3 {
		t.Fatal("epochs of the fixture")
	}
	return p
}

func TestSharePastPeriod(t *testing.T) {
	p := newPastFixture(t)
	f := p.fixture
	bob := f.env.NewUser("bob")
	before := chainOf(t, f.env, f.mbx)
	for _, bad := range []client.ShareOptions{{From: 2, To: 3}, {From: 3, To: 2}, {To: 4}, {From: 9}} {
		if _, err := f.u.Client.Share(f.mbx, bob.ID, bad); !errors.Is(err, client.ErrRange) {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
	if wrapped := f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 2, To: 2, Delegate: true}); len(wrapped) != 1 || wrapped[0] != 2 {
		t.Fatalf("wrapped %v", wrapped)
	}
	// Only wraps: no epoch, bob is a member of none.
	after := chainOf(t, f.env, f.mbx)
	if len(after) != len(before) {
		t.Fatal("a share of a past period created an epoch")
	}
	for _, e := range after {
		if kindOf(e, bob.ID) != 0 {
			t.Fatalf("bob listed in epoch %d", e.Number)
		}
		if wrapExists(f.env, f.mbx, e.Number, bob.ID) != (e.Number == 2) {
			t.Fatalf("wrap of epoch %d", e.Number)
		}
	}
	list, err := bob.Client.List(f.mbx, store.ID{})
	if err != nil || len(list) != 1 || list[0].ID != p.m2.ID {
		t.Fatalf("bob lists %d mails: %v", len(list), err)
	}
	for _, id := range []store.ID{p.m1.ID, p.m3.ID} {
		if _, _, err := bob.Client.Read(f.mbx, id); !errors.Is(err, client.ErrWrap) {
			t.Fatalf("bob reads a mail outside the period: %v", err)
		}
	}
	if name, err := bob.Client.MailboxName(f.mbx); err != nil || name != "A" {
		t.Fatal(name, err)
	}
	// Bob creates no epoch: not as a share, a revocation or the supply.
	carol := f.env.NewUser("carol")
	if _, err := bob.Client.Share(f.mbx, carol.ID, client.ShareOptions{}); !errors.Is(err, client.ErrNotMember) {
		t.Fatalf("share by a reader of a past period: %v", err)
	}
	if err := bob.Client.Revoke(f.mbx, f.u.ID); !errors.Is(err, client.ErrNotMember) {
		t.Fatalf("revoke by a reader of a past period: %v", err)
	}
	f.env.Clock.Set(time.Date(2027, 2, 15, 0, 0, 0, 0, time.UTC))
	if err := bob.Client.Sync(); err != nil || len(chainOf(t, f.env, f.mbx)) != len(before) {
		t.Fatalf("sync of a reader of a past period: %v", err)
	}
	// An open lower end starts at epoch 1.
	f.env.Share(f.u, f.mbx, carol, client.ShareOptions{To: 1})
	if !wrapExists(f.env, f.mbx, 1, carol.ID) || wrapExists(f.env, f.mbx, 2, carol.ID) {
		t.Fatal("period up to epoch 1")
	}
	if _, _, err := carol.Client.Read(f.mbx, p.m1.ID); err != nil {
		t.Fatal(err)
	}
	// A wrap that exists is never replaced, and a period without any
	// epoch to wrap is an error.
	w, _ := f.env.Store.ReadWrap(f.mbx, 2, bob.ID)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 2, To: 2})
	if w2, _ := f.env.Store.ReadWrap(f.mbx, 2, bob.ID); string(w2) != string(w) {
		t.Fatal("wrap replaced")
	}
	// An epoch signed by bob is rejected by alice's client (K2 rule 1).
	f.env.ForgeEpoch(bob, f.mbx, f.env.Clock.Now(), store.ReasonMemberAdded, []store.Member{{Kind: store.MemberUser, ID: f.u.ID, Gen: 1}}, "A")
	if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("epoch signed by a reader of a past period: %v", err)
	}
}

func TestShareArguments(t *testing.T) {
	f := newFixture(t)
	if _, err := f.u.Client.Share(f.mbx, f.u.ID, client.ShareOptions{}); !errors.Is(err, client.ErrArgument) {
		t.Fatalf("share with oneself: %v", err)
	}
	if _, err := f.u.Client.Share(f.mbx, store.ID{9}, client.ShareOptions{}); !errors.Is(err, client.ErrArgument) {
		t.Fatalf("share with an unknown user: %v", err)
	}
	bob := f.env.NewUser("bob")
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	if _, err := f.u.Client.Share(f.mbx, bob.ID, client.ShareOptions{Delegate: true}); !errors.Is(err, client.ErrArgument) {
		t.Fatalf("member made a delegate: %v", err)
	}
	// A chain that does not verify is never extended.
	os.Remove(f.env.Store.EpochFile(f.mbx, 3))
	carol := f.env.NewUser("carol")
	if _, err := f.u.Client.Share(f.mbx, carol.ID, client.ShareOptions{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("share on a broken chain: %v", err)
	}
}

func TestRevoke(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 1})
	f.env.Clock.Advance(time.Minute)
	shared := f.deliver(t, "shared", "both read it")
	if _, _, err := bob.Client.Read(f.mbx, shared.ID); err != nil {
		t.Fatal(err)
	}
	if err := bob.Client.Revoke(f.mbx, bob.ID); !errors.Is(err, client.ErrSelfRevoke) {
		t.Fatalf("revoking oneself: %v", err)
	}

	f.env.Clock.Advance(time.Hour)
	revokedAt := f.env.Clock.Now()
	before := chainOf(t, f.env, f.mbx)
	aliceWraps := map[uint32][]byte{}
	for _, e := range before {
		aliceWraps[e.Number], _ = f.env.Store.ReadWrap(f.mbx, e.Number, f.u.ID)
	}
	if err := f.u.Client.Revoke(f.mbx, bob.ID); err != nil {
		t.Fatal(err)
	}
	after := chainOf(t, f.env, f.mbx)
	e9 := checkImmediate(t, before, after, revokedAt, store.ReasonMemberRemoved)
	if kindOf(e9, bob.ID) != 0 || e9.SignerID != f.u.ID {
		t.Fatal("bob is still a member")
	}
	if len(e9.Discards) != 3 || e9.Discards[0] != 6 {
		t.Fatalf("discards %v", e9.Discards)
	}
	// Every wrap of bob is gone, alice's wraps are untouched.
	for _, e := range after {
		if wrapExists(f.env, f.mbx, e.Number, bob.ID) {
			t.Fatalf("wrap of bob for epoch %d", e.Number)
		}
		if w, ok := aliceWraps[e.Number]; ok {
			if now, _ := f.env.Store.ReadWrap(f.mbx, e.Number, f.u.ID); string(now) != string(w) {
				t.Fatalf("wrap of alice for epoch %d replaced", e.Number)
			}
		}
	}
	// A new mail goes to the new epoch; bob finds no wrap for it, and,
	// once his client forgot the keys, none for the old ones either.
	f.env.Clock.Advance(time.Minute)
	later := f.deliver(t, "later", "only alice")
	if later.Epoch != e9.Number {
		t.Fatalf("delivered for epoch %d", later.Epoch)
	}
	bc := f.env.Reopen(bob)
	if _, _, err := bc.Read(f.mbx, later.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("bob reads a mail after the revocation: %v", err)
	}
	if _, _, err := bc.Read(f.mbx, shared.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("bob reads with a deleted wrap: %v", err)
	}
	if _, err := bc.MailboxName(f.mbx); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("bob reads the folders: %v", err)
	}
	if err := bc.Sync(); err != nil {
		t.Fatalf("sync of a former member: %v", err)
	}
	// A mail the server still encrypts for the old epoch 5 after the
	// revocation, and one for the discarded epoch 6, are rejected.
	e5, e6 := after[4], after[5]
	stale := f.forge(t, e5, f.env.Clock.Now(), "stale", 1, f.env.IngestKey, 1)
	if _, _, err := f.u.Client.Read(f.mbx, stale); !errors.Is(err, client.ErrStaleEpoch) {
		t.Fatalf("mail for the old epoch: %v", err)
	}
	gone := f.forge(t, e6, time.UnixMilli(e6.Begin).Add(time.Hour), "gone", 1, f.env.IngestKey, 1)
	if _, _, err := f.u.Client.Read(f.mbx, gone); !errors.Is(err, client.ErrDiscardedEpoch) {
		t.Fatalf("mail for a discarded epoch: %v", err)
	}
	if _, _, err := f.u.Client.Read(f.mbx, shared.ID); err != nil {
		t.Fatal(err)
	}
	// Revoking again changes nothing; the last member does not leave.
	if err := f.u.Client.Revoke(f.mbx, bob.ID); err != nil || len(chainOf(t, f.env, f.mbx)) != len(after) {
		t.Fatalf("second revocation: %v", err)
	}
	if err := f.u.Client.Revoke(f.mbx, f.u.ID); !errors.Is(err, client.ErrSelfRevoke) {
		t.Fatalf("the last member revokes itself: %v", err)
	}
	if err := bc.Revoke(f.mbx, f.u.ID); !errors.Is(err, client.ErrNotMember) {
		t.Fatalf("revocation by a former member: %v", err)
	}
	// Bob signs an epoch after his removal (K2 rules 1 and 2): rejected.
	f.env.ForgeEpoch(bob, f.mbx, f.env.Clock.Now(), store.ReasonMemberRemoved, nil, "A")
	f.env.Warnings.Take()
	if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("epoch signed by the removed member: %v", err)
	}
	if !warned(f.env, "Epochenkette") {
		t.Fatal("no warning")
	}
}

// Bob signs the epoch that removes alice in place of alice's epoch: the
// client that saw alice's epoch notices the replacement, and a client
// without memory rejects bob's epoch after his removal.
func TestRemovedMemberSignsReplacement(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Hour)
	if err := f.u.Client.Revoke(f.mbx, bob.ID); err != nil {
		t.Fatal(err)
	}
	// Bob replaces epochs 9 to 12 with his own epoch 9.
	for n := uint32(9); n <= 12; n++ {
		os.RemoveAll(f.env.Store.EpochDir(f.mbx, n))
	}
	m, _ := f.env.Store.ReadMailbox(f.mbx)
	m.Epoch = 8
	f.env.Store.WriteMailbox(m)
	forged := f.env.ForgeEpoch(bob, f.mbx, f.env.Clock.Now(), store.ReasonMemberRemoved, nil, "A")
	if forged.Number != 9 || kindOf(forged, f.u.ID) != 0 {
		t.Fatal("forgery")
	}
	if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) && !errors.Is(err, client.ErrRollback) {
		t.Fatalf("replaced removal epoch: %v", err)
	}
	carol := f.env.NewUser("carol")
	if _, err := carol.Client.MailboxName(f.mbx); err == nil {
		t.Fatal("carol has access")
	}
	// Bob's epoch is valid in structure; it only shows that bob was still
	// a member of epoch 8. The removal had discarded 6 to 8; without it,
	// Bob's own replacement keeps him (2.7: only the log detects this).
}

func TestDelegate(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	before := chainOf(t, f.env, f.mbx)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{Delegate: true})
	after := chainOf(t, f.env, f.mbx)
	e5 := checkImmediate(t, before, after, f.env.Clock.Now(), store.ReasonMemberAdded)
	if kindOf(e5, bob.ID) != store.MemberDelegate {
		t.Fatal("bob is not a delegate")
	}
	f.env.Clock.Advance(time.Minute)
	m := f.deliver(t, "for the delegate", "x")
	if _, _, err := bob.Client.Read(f.mbx, m.ID); err != nil {
		t.Fatal(err)
	}
	carol := f.env.NewUser("carol")
	if _, err := bob.Client.Share(f.mbx, carol.ID, client.ShareOptions{}); !errors.Is(err, client.ErrNotMember) {
		t.Fatalf("share by a delegate: %v", err)
	}
	if err := bob.Client.Rename(f.mbx, "B"); !errors.Is(err, client.ErrNotMember) {
		t.Fatalf("rename by a delegate: %v", err)
	}
	f.env.Clock.Set(time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC))
	n := len(chainOf(t, f.env, f.mbx))
	if err := bob.Client.Sync(); err != nil || len(chainOf(t, f.env, f.mbx)) != n {
		t.Fatalf("supply by a delegate: %v", err)
	}
	// The supply of alice keeps the delegate.
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	h := chainOf(t, f.env, f.mbx)
	if kindOf(h[len(h)-1], bob.ID) != store.MemberDelegate {
		t.Fatal("delegate missing in the supply")
	}
	// An epoch signed by the delegate, who claims to be a user member, is
	// rejected (K2 rule 1); it is then taken away again.
	m0, _ := f.env.Store.ReadMailbox(f.mbx)
	forged := f.env.ForgeEpoch(bob, f.mbx, f.env.Clock.Now(), store.ReasonMemberAdded, []store.Member{{Kind: store.MemberUser, ID: f.u.ID, Gen: 1}}, "A")
	if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("epoch signed by a delegate: %v", err)
	}
	os.RemoveAll(f.env.Store.EpochDir(f.mbx, forged.Number))
	f.env.Store.WriteMailbox(m0)
	f.env.Clock.Advance(time.Hour)
	before = chainOf(t, f.env, f.mbx)
	if err := f.u.Client.Revoke(f.mbx, bob.ID); err != nil {
		t.Fatal(err)
	}
	after = chainOf(t, f.env, f.mbx)
	end := checkImmediate(t, before, after, f.env.Clock.Now(), store.ReasonDelegationEnded)
	if kindOf(end, bob.ID) != 0 {
		t.Fatal("delegate still listed")
	}
	if _, _, err := f.env.Reopen(bob).Read(f.mbx, m.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("ended delegate reads: %v", err)
	}
	// An epoch signed by the former delegate, who claims to be a user
	// member, is rejected (K2 rule 1).
	f.env.ForgeEpoch(bob, f.mbx, f.env.Clock.Now(), store.ReasonMemberAdded,
		[]store.Member{{Kind: store.MemberUser, ID: f.u.ID, Gen: 1}}, "A")
	if _, err := f.u.Client.List(f.mbx, store.ID{}); err == nil {
		t.Fatal("epoch signed by a delegate")
	}
}

// TestEpochRace: K2 rule 3. While alice creates epoch n (her wraps and
// folders.gml are written), bob creates epoch n as well and wins; alice
// verifies the chain again and creates her change on top of bob's.
func TestEpochRace(t *testing.T) {
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
		if p == "epoch-folders" && !fired {
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
	if !warned(f.env, "zugleich eine Epoche") {
		t.Fatal("lost race not reported")
	}
	after := chainOf(t, f.env, f.mbx)
	n := len(before) + 1
	won, retry := after[n-1], after[n+3]
	if won.SignerID != bob.ID || kindOf(won, dave.ID) != store.MemberUser || kindOf(won, carol.ID) != 0 {
		t.Fatal("bob's epoch")
	}
	if retry.SignerID != f.u.ID || retry.Reason != store.ReasonMemberAdded || kindOf(retry, dave.ID) != store.MemberUser || kindOf(retry, carol.ID) != store.MemberUser {
		t.Fatal("alice's epoch on top of bob's")
	}
	if len(after) != len(before)+8 || len(retry.Discards) != 3 {
		t.Fatalf("%d epochs, discards %v", len(after)-len(before), retry.Discards)
	}
	// Bob's wraps of his epoch survived alice's attempt.
	for _, u := range []*testenv.User{f.u, bob, dave} {
		if !wrapExists(f.env, f.mbx, won.Number, u.ID) {
			t.Fatal("wrap of the winning epoch missing")
		}
	}
	// Both chains are valid, for both clients and for the new members.
	for _, c := range []*client.Client{f.u.Client, f.env.Reopen(bob), carol.Client, dave.Client} {
		if _, err := c.List(f.mbx, store.ID{}); err != nil {
			t.Fatal(err)
		}
	}
}

// A client that loses the race every time gives up after three attempts.
func TestEpochRaceGivesUp(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	carol := f.env.NewUser("carol")
	dave := f.env.NewUser("dave")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	bob.Client.WithoutMailboxLock()
	inside, races := false, 0
	client.SetCrashHook(t, func(p string) bool {
		if p == "epoch-folders" && !inside {
			inside = true
			defer func() { inside = false }()
			races++
			var err error
			if races%2 == 1 {
				_, err = bob.Client.Share(f.mbx, dave.ID, client.ShareOptions{})
			} else {
				err = bob.Client.Revoke(f.mbx, dave.ID)
			}
			if err != nil {
				t.Error(err)
			}
		}
		return false
	})
	_, err := f.u.Client.Share(f.mbx, carol.ID, client.ShareOptions{})
	if !errors.Is(err, store.ErrExists) || races != client.MaxEpochAttempts {
		t.Fatalf("after %d races: %v", races, err)
	}
	client.SetCrashHook(t, nil)
	if _, err := f.env.Reopen(f.u).List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
}

// wrapFiles returns the bytes of every wrap of every epoch that has an
// epoch.rec.
func wrapFiles(t *testing.T, env *testenv.Env, mbx store.ID) map[string]string {
	t.Helper()
	out := map[string]string{}
	ns, _ := env.Store.ListEpochs(mbx)
	for _, n := range ns {
		if _, err := os.Lstat(env.Store.EpochFile(mbx, n)); err != nil {
			continue
		}
		dir := filepath.Join(env.Store.EpochDir(mbx, n), "members")
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err == nil {
				out[filepath.Join(dir, e.Name())] = string(b)
			}
		}
	}
	return out
}

// TestCrashShareAndRevoke crashes sharing and revoking at every injection
// point in turn. The next run (the same call in a new process) completes
// the change or cleans up; no wrap of an existing epoch is ever replaced,
// and no epoch directory without epoch.rec is left behind. mailbox.rec is
// the last file of every change (D57, D61): a crash at any point before
// "mailbox", among them "immediate" and "supply" after the immediate
// epoch, leaves it unchanged.
func TestCrashShareAndRevoke(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	alice := f.u
	current := func() uint32 {
		var cur uint32
		for _, e := range chainOf(t, f.env, f.mbx) {
			if e.Begin <= f.env.Clock.Now().UnixMilli() {
				cur = e.Number
			}
		}
		return cur
	}
	ops := []struct {
		name   string
		run    func(c *client.Client) error
		member bool // bob is a member afterwards
	}{
		{"share", func(c *client.Client) error {
			_, err := c.Share(f.mbx, bob.ID, client.ShareOptions{From: current()})
			return err
		}, true},
		{"revoke", func(c *client.Client) error { return c.Revoke(f.mbx, bob.ID) }, false},
	}
	points := map[string]bool{}
	for i := 0; ; i++ {
		done := 0
		for _, op := range ops {
			f.env.Clock.Advance(time.Minute)
			before := wrapFiles(t, f.env, f.mbx)
			mbxBefore := mustRead(t, f.env.Store.MailboxFile(f.mbx))
			k := 0
			crashedAt := ""
			client.SetCrashHook(t, func(p string) bool {
				k++
				if k == i+1 {
					points[op.name+" "+p] = true
					crashedAt = p
					return true
				}
				return false
			})
			err := op.run(alice.Client)
			client.SetCrashHook(t, nil)
			if err == nil {
				done++
			} else {
				if !errors.Is(err, client.ErrCrashed) {
					t.Fatalf("%s at point %d: %v", op.name, i, err)
				}
				if crashedAt != "mailbox" && string(mustRead(t, f.env.Store.MailboxFile(f.mbx))) != string(mbxBefore) {
					t.Fatalf("%s crashed at %q: mailbox.rec changed before the last step", op.name, crashedAt)
				}
				// The next run, in a new process.
				if err := op.run(f.env.Reopen(alice)); err != nil {
					t.Fatalf("%s after a crash at point %d: %v", op.name, i, err)
				}
			}
			after := wrapFiles(t, f.env, f.mbx)
			for p, b := range before {
				if a, ok := after[p]; ok && a != b {
					t.Fatalf("%s at point %d replaced %s", op.name, i, p)
				} else if !ok && !(op.name == "revoke" && strings.HasSuffix(p, bob.ID.String()+".wrap")) {
					t.Fatalf("%s at point %d removed %s", op.name, i, p)
				}
			}
			ns, _ := f.env.Store.ListEpochs(f.mbx)
			for _, n := range ns {
				if _, err := os.Lstat(f.env.Store.EpochFile(f.mbx, n)); err != nil {
					t.Fatalf("%s at point %d left epoch %d without epoch.rec", op.name, i, n)
				}
			}
			h := chainOf(t, f.env, f.mbx)
			head := h[len(h)-1]
			if (kindOf(head, bob.ID) == store.MemberUser) != op.member || wrapExists(f.env, f.mbx, head.Number, bob.ID) != op.member {
				t.Fatalf("%s at point %d: bob in epoch %d: %v", op.name, i, head.Number, kindOf(head, bob.ID))
			}
			if _, err := alice.Client.List(f.mbx, store.ID{}); err != nil {
				t.Fatalf("%s at point %d: %v", op.name, i, err)
			}
			if _, err := bob.Client.MailboxName(f.mbx); (err == nil) != op.member {
				t.Fatalf("%s at point %d: bob reads the folders: %v", op.name, i, err)
			}
		}
		if done == len(ops) {
			break
		}
		if i > 100 {
			t.Fatal("no end")
		}
	}
	var names []string
	for p := range points {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, want := range []string{"share wrap-existing", "share share-wraps", "share epoch-wraps", "share epoch-folders", "share epoch-written",
		"share immediate", "share supply", "share mailbox", "revoke revoke-wraps", "revoke epoch-wraps", "revoke immediate", "revoke mailbox"} {
		if !points[want] {
			t.Fatalf("point %q not reached: %v", want, names)
		}
	}
}

// TestSharePartial: Share does not report success when a requested epoch
// that is not discarded could not be wrapped (here: the keys of epoch 1
// are not available to alice). The wraps written stay, and a second run
// with the keys back completes the period without replacing them.
func TestSharePartial(t *testing.T) {
	p := newPastFixture(t)
	f := p.fixture
	carol := f.env.NewUser("carol")
	w1 := mustRead(t, f.env.Store.WrapFile(f.mbx, 1, f.u.ID))
	if err := os.Remove(f.env.Store.WrapFile(f.mbx, 1, f.u.ID)); err != nil {
		t.Fatal(err)
	}
	c := f.env.Reopen(f.u)
	wrapped, err := c.Share(f.mbx, carol.ID, client.ShareOptions{From: 1, To: 2})
	if !errors.Is(err, client.ErrPartial) || errors.Is(err, client.ErrWrap) || len(wrapped) != 1 || wrapped[0] != 2 {
		t.Fatalf("share without the keys of epoch 1: %v, wrapped %v", err, wrapped)
	}
	if !strings.Contains(err.Error(), "[1]") {
		t.Fatalf("skipped epochs not named: %v", err)
	}
	if wrapExists(f.env, f.mbx, 1, carol.ID) || !wrapExists(f.env, f.mbx, 2, carol.ID) {
		t.Fatal("wraps of carol")
	}
	w2 := mustRead(t, f.env.Store.WrapFile(f.mbx, 2, carol.ID))
	if _, _, err := carol.Client.Read(f.mbx, p.m2.ID); err != nil {
		t.Fatal(err)
	}
	// The keys are back: the second run wraps epoch 1 as well and keeps
	// the wrap of epoch 2.
	if err := store.WriteFileAtomic(f.env.Store.WrapFile(f.mbx, 1, f.u.ID), w1); err != nil {
		t.Fatal(err)
	}
	c = f.env.Reopen(f.u)
	wrapped, err = c.Share(f.mbx, carol.ID, client.ShareOptions{From: 1, To: 2})
	if err != nil || len(wrapped) != 2 || wrapped[0] != 1 || wrapped[1] != 2 {
		t.Fatalf("second share: %v, wrapped %v", err, wrapped)
	}
	if string(mustRead(t, f.env.Store.WrapFile(f.mbx, 2, carol.ID))) != string(w2) {
		t.Fatal("wrap of epoch 2 replaced")
	}
	if _, _, err := carol.Client.Read(f.mbx, p.m1.ID); err != nil {
		t.Fatal(err)
	}
	// An open share with a skipped epoch is completed and reported.
	dave := f.env.NewUser("dave")
	if err := os.Remove(f.env.Store.WrapFile(f.mbx, 2, f.u.ID)); err != nil {
		t.Fatal(err)
	}
	c = f.env.Reopen(f.u)
	wrapped, err = c.Share(f.mbx, dave.ID, client.ShareOptions{From: 2})
	if !errors.Is(err, client.ErrPartial) || len(wrapped) != 1 || wrapped[0] != 3 {
		t.Fatalf("open share with a skipped epoch: %v, wrapped %v", err, wrapped)
	}
	h := chainOf(t, f.env, f.mbx)
	if kindOf(h[len(h)-1], dave.ID) != store.MemberUser {
		t.Fatal("dave is not a member")
	}
}

// A member wraps only epochs it is a user member of: a reader would not
// accept a wrap of another epoch (2.5, D61). IDs of users and of the
// recovery recipient are not mixed up.
func TestShareOnlyOwnEpochs(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "x")
	bob := f.env.NewUser("bob")
	carol := f.env.NewUser("carol")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Hour)
	f.env.Warnings.Take()
	// Epoch 1 is skipped (epochs 2 to 4 are discarded): the share is
	// completed, but it does not report success (ErrPartial).
	wrapped, err := bob.Client.Share(f.mbx, carol.ID, client.ShareOptions{From: 1})
	if !errors.Is(err, client.ErrPartial) || errors.Is(err, client.ErrWrap) || len(wrapped) != 1 || wrapped[0] != 5 {
		t.Fatalf("share with a skipped epoch: %v, wrapped %v", err, wrapped)
	}
	if !strings.Contains(err.Error(), "[1]") {
		t.Fatalf("skipped epochs not named: %v", err)
	}
	if !warned(f.env, "kein Mitglied") {
		t.Fatal("skipped epoch not reported")
	}
	if wrapExists(f.env, f.mbx, 1, carol.ID) || !wrapExists(f.env, f.mbx, 5, carol.ID) {
		t.Fatal("wraps of carol")
	}
	h := chainOf(t, f.env, f.mbx)
	if kindOf(h[len(h)-1], carol.ID) != store.MemberUser {
		t.Fatal("the partial share was not completed")
	}
	if _, _, err := carol.Client.Read(f.mbx, old.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatal(err)
	}
	// A period without an epoch bob is a member of gives nothing.
	if _, err := bob.Client.Share(f.mbx, carol.ID, client.ShareOptions{To: 1}); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("period without own epochs: %v", err)
	}
	// IDs of the recovery recipient and of users.
	pub, _ := recoveryKey(t)
	same := *pub
	same.ID = bob.ID
	if err := f.u.Client.SetRecovery(f.mbx, &same, yes); !errors.Is(err, client.ErrArgument) {
		t.Fatalf("recovery ID of a member: %v", err)
	}
	same.ID = f.u.ID
	if err := f.u.Client.SetRecovery(f.mbx, &same, yes); !errors.Is(err, client.ErrArgument) {
		t.Fatalf("recovery ID of oneself: %v", err)
	}
	if err := f.u.Client.SetRecovery(f.mbx, pub, yes); err != nil {
		t.Fatal(err)
	}
	if err := f.u.Client.Revoke(f.mbx, pub.ID); !errors.Is(err, client.ErrArgument) {
		t.Fatalf("revoke of the recovery recipient: %v", err)
	}
	if _, err := f.u.Client.Share(f.mbx, pub.ID, client.ShareOptions{}); !errors.Is(err, client.ErrArgument) {
		t.Fatalf("share with the recovery recipient: %v", err)
	}
	// A delegate cannot enter or remove a recovery recipient.
	dave := f.env.NewUser("dave")
	f.env.Share(f.u, f.mbx, dave, client.ShareOptions{Delegate: true})
	if err := dave.Client.ClearRecovery(f.mbx); !errors.Is(err, client.ErrNotMember) {
		t.Fatal(err)
	}
	if err := dave.Client.SetRecovery(f.mbx, pub, yes); !errors.Is(err, client.ErrNotMember) {
		t.Fatal(err)
	}
}
