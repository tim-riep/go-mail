package client_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

func recoveryKey(t *testing.T) (*store.RecoveryPub, []string) {
	t.Helper()
	echo := &testenv.Echo{}
	pub, err := client.RecoveryKeygen(echo)
	if err != nil {
		t.Fatal(err)
	}
	return pub, echo.Words()
}

func recoveryWrapFor(t *testing.T, env *testenv.Env, mbx store.ID, n uint32) store.ID {
	t.Helper()
	data, err := env.Store.ReadRecoveryWrap(mbx, n)
	if err != nil {
		return store.ID{}
	}
	f := parse(t, data)
	if len(f.Recipients) != 1 || f.Recipients[0].Type != envelope.RecipientRecovery || f.Recipients[0].Gen != store.RecoveryGen ||
		store.ID(f.Header.FileID) != store.ID(f.Recipients[0].ID) {
		t.Fatalf("recovery.wrap of epoch %d", n)
	}
	return store.ID(f.Recipients[0].ID)
}

func yes(string) bool { return true }

func TestRecoveryRecipient(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "before recovery")
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{}) // epochs 5 to 8

	if _, err := client.RecoveryKeygen(&wrongPrompter{}); !errors.Is(err, client.ErrConfirm) {
		t.Fatalf("words not confirmed: %v", err)
	}
	pub, words := recoveryKey(t)
	fp, _ := pub.Fingerprint()
	var shown string
	if err := f.u.Client.SetRecovery(f.mbx, pub, func(s string) bool { shown = s; return false }); !errors.Is(err, client.ErrRecovery) {
		t.Fatalf("refused fingerprint: %v", err)
	}
	if shown != fp || len(strings.Fields(shown)) != 8 {
		t.Fatalf("fingerprint shown %q", shown)
	}
	if _, err := os.Lstat(f.env.Store.RecoveryPubFile(f.mbx, pub.ID)); err == nil || len(chainOf(t, f.env, f.mbx)) != 8 {
		t.Fatal("written without confirmation")
	}
	if err := f.u.Client.SetRecovery(f.mbx, pub, nil); !errors.Is(err, client.ErrRecovery) {
		t.Fatal(err)
	}
	if err := f.u.Client.SetRecovery(f.mbx, &store.RecoveryPub{}, yes); !errors.Is(err, store.ErrRecovery) {
		t.Fatal(err)
	}

	f.env.Clock.Advance(time.Hour)
	before := chainOf(t, f.env, f.mbx)
	if err := f.u.Client.SetRecovery(f.mbx, pub, yes); err != nil {
		t.Fatal(err)
	}
	after := chainOf(t, f.env, f.mbx)
	e9 := checkImmediate(t, before, after, f.env.Clock.Now(), store.ReasonRecoveryChanged)
	if kindOf(e9, pub.ID) != store.MemberRecovery || kindOf(e9, bob.ID) != store.MemberUser {
		t.Fatal("members of the recovery epoch")
	}
	// Existing epochs that have begun get a wrap as well (2.4), the
	// discarded ones do not.
	for _, e := range after {
		want := e.Number == 1 || e.Number == 5 || e.Number >= 9
		if got := recoveryWrapFor(t, f.env, f.mbx, e.Number) == pub.ID; got != want {
			t.Fatalf("recovery.wrap of epoch %d: %v", e.Number, got)
		}
	}
	// Again: nothing new.
	if err := f.u.Client.SetRecovery(f.mbx, pub, yes); err != nil || len(chainOf(t, f.env, f.mbx)) != len(after) {
		t.Fatalf("second SetRecovery: %v", err)
	}
	f.env.Clock.Advance(time.Minute)
	fresh := f.deliver(t, "fresh", "after recovery")

	// The recovery recipient reads, and only reads.
	rc, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, words)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if rc.UserID() != pub.ID {
		t.Fatal("recovery ID")
	}
	list, err := rc.List(f.mbx, store.ID{})
	if err != nil || len(list) != 2 {
		t.Fatalf("recovery lists %d mails: %v", len(list), err)
	}
	for _, m := range []*client.Mail{old, fresh} {
		if _, body, err := rc.Read(f.mbx, m.ID); err != nil || !strings.Contains(string(body), m.Meta.Subject) {
			t.Fatalf("recovery reads %s: %v", m.Meta.Subject, err)
		}
	}
	if name, err := rc.MailboxName(f.mbx); err != nil || name != "A" {
		t.Fatal(name, err)
	}
	for name, err := range map[string]error{
		"share":    func() error { _, err := rc.Share(f.mbx, bob.ID, client.ShareOptions{}); return err }(),
		"revoke":   rc.Revoke(f.mbx, bob.ID),
		"sync":     rc.Sync(),
		"rename":   rc.Rename(f.mbx, "X"),
		"folders":  rc.SetFolders(f.mbx, nil),
		"set":      rc.SetRecovery(f.mbx, pub, yes),
		"clear":    rc.ClearRecovery(f.mbx),
		"confirm":  rc.ConfirmRecovery(f.mbx, yes),
		"create":   func() error { _, err := rc.CreateMailbox("X"); return err }(),
		"recovery": func() error { _, err := rc.Folders(f.mbx); return err }(),
	} {
		if name == "recovery" {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		if !errors.Is(err, client.ErrReadOnly) {
			t.Fatalf("%s by the recovery recipient: %v", name, err)
		}
	}
	// Another seed matches no recovery recipient; invalid words fail.
	_, otherWords := recoveryKey(t)
	if _, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, otherWords); !errors.Is(err, client.ErrRecovery) {
		t.Fatalf("foreign seed: %v", err)
	}
	if _, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, words[:23]); err == nil {
		t.Fatal("23 words")
	}
	if _, err := client.RecoverRead(client.Config{}, f.mbx, words); err == nil {
		t.Fatal("incomplete configuration")
	}

	// recovery.wrap is the only file with recipient type 4 (3.1, S09).
	filepath.WalkDir(f.env.Store.MailboxDir(f.mbx), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".gml") && !strings.HasSuffix(p, ".wrap") || strings.HasSuffix(p, "recovery.wrap") {
			return err
		}
		data, _ := os.ReadFile(p)
		for _, r := range parse(t, data).Recipients {
			if r.Type == envelope.RecipientRecovery || store.ID(r.ID) == pub.ID {
				t.Fatalf("recovery recipient in %s", p)
			}
		}
		return nil
	})

	// Bob has not confirmed the key: his client does not wrap for it.
	if _, err := bob.Client.MailboxName(f.mbx); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Set(time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC))
	if err := bob.Client.Sync(); !errors.Is(err, client.ErrRecovery) {
		t.Fatalf("supply with an unconfirmed recovery key: %v", err)
	}
	if err := bob.Client.ConfirmRecovery(f.mbx, func(s string) bool { return false }); !errors.Is(err, client.ErrRecovery) {
		t.Fatal(err)
	}
	if err := bob.Client.ConfirmRecovery(f.mbx, func(s string) bool { shown = s; return true }); err != nil || shown != fp {
		t.Fatal(err)
	}
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	h := chainOf(t, f.env, f.mbx)
	if top := h[len(h)-1]; top.SignerID != bob.ID || kindOf(top, pub.ID) != store.MemberRecovery || recoveryWrapFor(t, f.env, f.mbx, top.Number) != pub.ID {
		t.Fatal("supply of bob without the recovery recipient")
	}
	// A changed record in the data directory is never used.
	pubFile := f.env.Store.RecoveryPubFile(f.mbx, pub.ID)
	orig := mustRead(t, pubFile)
	evil, _ := ecdh.X25519().GenerateKey(rand.Reader)
	swapped := *pub
	swapped.UnwrapPub = evil.PublicKey()
	sd, _ := swapped.Encode()
	os.WriteFile(pubFile, sd, 0o600)
	f.env.Clock.Set(time.Date(2027, 2, 15, 0, 0, 0, 0, time.UTC))
	f.env.Warnings.Take()
	if err := bob.Client.Sync(); !errors.Is(err, client.ErrRecovery) || !warned(f.env, "weicht vom bestätigten ab") {
		t.Fatalf("swapped recovery key: %v", err)
	}
	os.Remove(pubFile)
	if err := bob.Client.Sync(); !errors.Is(err, client.ErrRecovery) {
		t.Fatalf("missing recovery key: %v", err)
	}
	if err := bob.Client.ConfirmRecovery(f.mbx, yes); !errors.Is(err, client.ErrRecovery) {
		t.Fatal(err)
	}
	os.WriteFile(pubFile, orig, 0o600)
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}

	// A change of the recovery key: the old key's wraps go, the new key
	// gets the existing epochs.
	pub2, words2 := recoveryKey(t)
	f.env.Clock.Advance(time.Hour)
	if err := f.u.Client.SetRecovery(f.mbx, pub2, yes); err != nil {
		t.Fatal(err)
	}
	if recoveryWrapFor(t, f.env, f.mbx, 1) != pub2.ID {
		t.Fatal("epoch 1 not wrapped for the new recovery key")
	}
	h = chainOf(t, f.env, f.mbx)
	if top := h[len(h)-1]; kindOf(top, pub.ID) != 0 || kindOf(top, pub2.ID) != store.MemberRecovery {
		t.Fatal("recovery recipient not changed")
	}
	rc2, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, words2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rc2.Read(f.mbx, old.ID); err != nil {
		t.Fatal(err)
	}
	rc1, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, words)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rc1.Read(f.mbx, old.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("old recovery key reads: %v", err)
	}

	// Removing the recovery recipient.
	f.env.Clock.Advance(time.Hour)
	before = chainOf(t, f.env, f.mbx)
	if err := f.u.Client.ClearRecovery(f.mbx); err != nil {
		t.Fatal(err)
	}
	after = chainOf(t, f.env, f.mbx)
	cleared := checkImmediate(t, before, after, f.env.Clock.Now(), store.ReasonRecoveryChanged)
	if kindOf(cleared, pub2.ID) != 0 {
		t.Fatal("recovery recipient still listed")
	}
	for _, e := range after {
		if recoveryWrapFor(t, f.env, f.mbx, e.Number) == pub2.ID {
			found := false
			for _, x := range after {
				for _, d := range x.Discards {
					found = found || d == e.Number
				}
			}
			if !found {
				t.Fatalf("recovery.wrap of epoch %d left", e.Number)
			}
		}
	}
	if err := f.u.Client.ClearRecovery(f.mbx); err != nil || len(chainOf(t, f.env, f.mbx)) != len(after) {
		t.Fatalf("second ClearRecovery: %v", err)
	}
	rc3, err := client.RecoverRead(f.env.ClientConfig(""), f.mbx, words2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rc3.Read(f.mbx, old.ID); !errors.Is(err, client.ErrWrap) {
		t.Fatalf("removed recovery key reads: %v", err)
	}
	if err := bob.Client.ConfirmRecovery(f.mbx, yes); !errors.Is(err, client.ErrRecovery) {
		t.Fatalf("confirm without a recovery recipient: %v", err)
	}
}

// The recovery recipient cannot create an epoch (K2 rule 1): not as a
// recovery member (the record itself forbids it) and not by claiming to
// be a user member.
func TestRecoveryCannotCreateEpochs(t *testing.T) {
	f := newFixture(t)
	pub, words := recoveryKey(t)
	if err := f.u.Client.SetRecovery(f.mbx, pub, yes); err != nil {
		t.Fatal(err)
	}
	seed, err := keys.SeedFromWords(words)
	if err != nil {
		t.Fatal(err)
	}
	d := keys.DeriveUser(seed)
	identity, _ := d.IdentityKey(1)
	h := chainOf(t, f.env, f.mbx)
	head := h[len(h)-1]
	_, headData, _ := f.env.Store.ReadEpoch(f.mbx, head.Number)
	e := *head
	e.Number, e.PrevHash, e.Discards = head.Number+1, store.EpochHash(headData), nil
	e.Reason, e.Begin = store.ReasonRegular, head.Begin+1
	e.SignerID, e.SignerGen = pub.ID, 1
	if err := e.Sign(identity); !errors.Is(err, store.ErrRecord) {
		t.Fatalf("epoch signed by the recovery member: %v", err)
	}
	var members []store.Member
	for _, m := range head.Members {
		if m.Kind != store.MemberRecovery {
			members = append(members, m)
		}
	}
	e.Members = append(members, store.Member{Kind: store.MemberUser, ID: pub.ID, Gen: 1})
	if err := e.Sign(identity); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Store.WriteEpoch(&e); err != nil {
		t.Fatal(err)
	}
	m, _ := f.env.Store.ReadMailbox(f.mbx)
	m.Epoch = e.Number
	f.env.Store.WriteMailbox(m)
	if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("epoch signed by the recovery key: %v", err)
	}
}

func TestInspectRecoveryPub(t *testing.T) {
	pub, _ := recoveryKey(t)
	data, _ := pub.Encode()
	out, err := client.Inspect(data)
	if err != nil || !strings.Contains(string(out), "recovery_id") || !strings.Contains(string(out), "unwrap_pub") {
		t.Fatalf("%s %v", out, err)
	}
}

// TestCrashRecoveryWraps crashes SetRecovery (replacing the recovery
// recipient) and ClearRecovery at "recovery-wraps": the recovery.wrap
// files of the old recipient are deleted, the epoch recovery-changed is
// not yet written. mailbox.rec, the last file of a change (D57, D61), and
// the chain are unchanged; the next run in a new process completes the
// change.
func TestCrashRecoveryWraps(t *testing.T) {
	f := newFixture(t)
	f.env.Clock.Advance(time.Hour)
	r1, _ := recoveryKey(t)
	if err := f.u.Client.SetRecovery(f.mbx, r1, yes); err != nil {
		t.Fatal(err)
	}
	head := func() *store.Epoch {
		h := chainOf(t, f.env, f.mbx)
		return h[len(h)-1]
	}
	crash := func(name string, run func(c *client.Client) error) {
		t.Helper()
		f.env.Clock.Advance(time.Minute)
		mbxBefore := mustRead(t, f.env.Store.MailboxFile(f.mbx))
		epochsBefore, _ := f.env.Store.ListEpochs(f.mbx)
		fired := false
		client.SetCrashHook(t, func(p string) bool {
			if p == "recovery-wraps" && !fired {
				fired = true
				return true
			}
			return false
		})
		err := run(f.u.Client)
		client.SetCrashHook(t, nil)
		if !fired || !errors.Is(err, client.ErrCrashed) {
			t.Fatalf("%s: crash at recovery-wraps: %v", name, err)
		}
		if string(mustRead(t, f.env.Store.MailboxFile(f.mbx))) != string(mbxBefore) {
			t.Fatalf("%s: mailbox.rec changed before the last step", name)
		}
		if epochs, _ := f.env.Store.ListEpochs(f.mbx); len(epochs) != len(epochsBefore) {
			t.Fatalf("%s: epochs %v after the crash, %v before", name, epochs, epochsBefore)
		}
		for _, e := range chainOf(t, f.env, f.mbx) {
			if _, err := f.env.Store.ReadRecoveryWrap(f.mbx, e.Number); err == nil {
				t.Fatalf("%s: recovery.wrap of epoch %d left after the crash", name, e.Number)
			}
		}
		if _, err := f.u.Client.List(f.mbx, store.ID{}); err != nil {
			t.Fatalf("%s: after the crash: %v", name, err)
		}
		// The next run, in a new process.
		if err := run(f.env.Reopen(f.u)); err != nil {
			t.Fatalf("%s after the crash: %v", name, err)
		}
		if _, err := f.u.Client.List(f.mbx, store.ID{}); err != nil {
			t.Fatal(err)
		}
	}

	r2, words2 := recoveryKey(t)
	crash("SetRecovery", func(c *client.Client) error { return c.SetRecovery(f.mbx, r2, yes) })
	if h := head(); kindOf(h, r2.ID) != store.MemberRecovery || kindOf(h, r1.ID) != 0 || h.Reason != store.ReasonRegular {
		t.Fatal("recovery recipient after the repeated SetRecovery")
	}
	if recoveryWrapFor(t, f.env, f.mbx, head().Number) != r2.ID {
		t.Fatal("recovery.wrap of the new recipient")
	}
	rc, err := client.RecoverRead(f.env.ClientConfig(t.TempDir()), f.mbx, words2)
	if err != nil {
		t.Fatal(err)
	}
	if name, err := rc.MailboxName(f.mbx); err != nil || name != "A" {
		t.Fatal(name, err)
	}

	crash("ClearRecovery", func(c *client.Client) error { return c.ClearRecovery(f.mbx) })
	h := chainOf(t, f.env, f.mbx)
	for _, e := range h[len(h)-4:] {
		if _, ok := e.Member(r2.ID); ok || kindOf(e, r2.ID) != 0 {
			t.Fatalf("recovery recipient in epoch %d", e.Number)
		}
		if _, err := f.env.Store.ReadRecoveryWrap(f.mbx, e.Number); err == nil {
			t.Fatalf("recovery.wrap of epoch %d", e.Number)
		}
	}
	if h[len(h)-4].Reason != store.ReasonRecoveryChanged {
		t.Fatal("no epoch recovery-changed")
	}
}
