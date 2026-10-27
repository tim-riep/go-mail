package client_test

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of the two findings of the verification of task 06 (addendum of
// task 06b).

// epochLog refuses CheckEpoch for one epoch number.
type epochLog struct {
	translog.Log
	number uint32
}

func (l *epochLog) CheckEpoch(m store.ID, n uint32, data []byte) error {
	if n == l.number {
		return errLog
	}
	return l.Log.CheckEpoch(m, n, data)
}

// TestBeyondHeadSignerUnreadableKept: a valid epoch beyond the head whose
// signer's user.rec cannot be read (a directory in its place) is not
// proven invalid (readBeyond): it is kept, never replaced, and the change
// stops after maxEpochAttempts attempts with the cause errKept. Once
// user.rec is back, the epoch is adopted and the change goes on top of it.
// Treating an error of userKey or of the log as "invalid for good" would
// replace the epoch and break this test.
func TestBeyondHeadSignerUnreadableKept(t *testing.T) {
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
	valid := f.env.ForgeEpoch(bob, f.mbx, f.env.Clock.Now(), store.ReasonMemberAdded, head[len(head)-1].Members, "A")
	if err := f.env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	// Bob wraps it for alice too, as a client would.
	plain := ownEpochKeys(t, f.env, bob, f.mbx, valid.Number)
	if err := f.env.Store.WriteWrap(f.mbx, valid.Number, f.u.ID, sealWrap(t, f.env, bob, f.u, wrapHeader(f.mbx, valid.Number, f.u), plain)); err != nil {
		t.Fatal(err)
	}
	_, data, err := f.env.Store.ReadEpoch(f.mbx, valid.Number)
	if err != nil {
		t.Fatal(err)
	}
	up := f.env.Store.UserFile(bob.ID)
	orig := mustRead(t, up)
	if err := os.Remove(up); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(up, 0o700); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	err = f.u.Client.Revoke(f.mbx, bob.ID)
	if got := mustRead(t, f.env.Store.EpochFile(f.mbx, valid.Number)); !bytes.Equal(got, data) {
		t.Fatal("epoch beyond the head replaced although its signer's user.rec was only unreadable")
	}
	if !errors.Is(err, client.ErrKept) || !errors.Is(err, store.ErrExists) || !strings.Contains(err.Error(), "3 attempts") {
		t.Fatalf("revoke: %v", err)
	}
	if err := os.RemoveAll(up); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(up, orig); err != nil {
		t.Fatal(err)
	}
	// The same if the log does not (yet) confirm the epoch.
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	cfg.Log = &epochLog{Log: f.env.Log, number: valid.Number}
	c, err := client.Open(cfg, testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	err = c.Revoke(f.mbx, bob.ID)
	c.Close()
	if got := mustRead(t, f.env.Store.EpochFile(f.mbx, valid.Number)); !bytes.Equal(got, data) {
		t.Fatal("epoch beyond the head replaced although only the log did not confirm it")
	}
	if !errors.Is(err, client.ErrKept) || !errors.Is(err, store.ErrExists) {
		t.Fatalf("revoke without the log: %v", err)
	}
	if err := f.env.Reopen(f.u).Revoke(f.mbx, bob.ID); err != nil {
		t.Fatal(err)
	}
	after := chainOf(t, f.env, f.mbx)
	if after[valid.Number-1].SignerID != bob.ID || after[valid.Number].Reason != store.ReasonMemberRemoved {
		t.Fatal("adopted epoch not kept")
	}
}

// TestSetRecoveryReportsPartial: SetRecovery by a member that is not a
// user member of every begun epoch enters the recipient, wraps the epochs
// it can and reports the others with ErrPartial, like Share.
func TestSetRecoveryReportsPartial(t *testing.T) {
	f := newFixture(t)
	f.deliver(t, "old", "x") // epoch 1
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{}) // bob from epoch 5
	f.env.Clock.Advance(time.Hour)
	pub, _ := recoveryKey(t)
	err := bob.Client.SetRecovery(f.mbx, pub, yes)
	if !errors.Is(err, client.ErrPartial) || !strings.Contains(err.Error(), "[1]") {
		t.Fatalf("SetRecovery by bob: %v", err)
	}
	if recoveryWrapFor(t, f.env, f.mbx, 1) == pub.ID {
		t.Fatal("epoch 1 wrapped by bob, who has no keys for it")
	}
	if recoveryWrapFor(t, f.env, f.mbx, 5) != pub.ID {
		t.Fatal("epoch 5 not wrapped")
	}
	head := chainOf(t, f.env, f.mbx)
	if e := head[len(head)-4]; e.Reason != store.ReasonRecoveryChanged || kindOf(e, pub.ID) != store.MemberRecovery {
		t.Fatal("recipient not entered")
	}
	// Running it again completes nothing more and reports the same.
	if err := bob.Client.SetRecovery(f.mbx, pub, yes); !errors.Is(err, client.ErrPartial) {
		t.Fatalf("again: %v", err)
	}
}
