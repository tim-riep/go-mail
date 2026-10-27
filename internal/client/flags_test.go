package client_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// forgeVersion writes metadata version version of mail base, changed by
// change, signed by signer (nil: the ingest key) over meta-signed.
func (f *fixture) forgeVersion(t *testing.T, signer *testenv.User, base *store.MailMeta, epoch uint32, version uint32, change func(m *store.MailMeta)) {
	t.Helper()
	e, _, err := f.env.Store.ReadEpoch(f.mbx, epoch)
	if err != nil {
		t.Fatal(err)
	}
	m := *base
	m.Version = version
	if change != nil {
		change(&m)
	}
	plain, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	extra, _ := m.SignedExtra(f.mbx, epoch)
	s := &envelope.Signer{Type: envelope.SignerIngest, Gen: 1, Key: f.env.IngestKey, Extra: extra}
	if signer != nil {
		ks := f.env.Keystore(signer)
		defer ks.Zero()
		s = &envelope.Signer{Type: envelope.SignerUser, ID: signer.ID, Gen: ks.Generation, Key: ks.Identity, Extra: extra}
	}
	data, err := envelope.Seal(envelope.Header{Kind: envelope.KindMeta, MailboxID: f.mbx, Epoch: epoch, FileID: m.MailID, Created: m.Received, Version: version},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: f.mbx, Gen: epoch, PublicKey: e.MetaPub}}, plain, &envelope.SealOptions{Signer: s})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, m.Folder, m.MailID), data); err != nil {
		t.Fatal(err)
	}
}

func TestSetFlags(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	c := f.u.Client
	m, err := c.SetFlags(f.mbx, a.ID, []string{"seen", "flagged"}, nil)
	if err != nil || m.Meta.Version != 2 || !reflect.DeepEqual(client.FlagNames(m.Meta.Flags), []string{"flagged", "seen"}) {
		t.Fatalf("set: %+v: %v", m, err)
	}
	if m.Meta.Received != a.Meta.Received || m.Meta.MailHash != a.Meta.MailHash || m.Meta.Subject != "a" {
		t.Fatal("receipt, mail hash and header values stay")
	}
	data, _ := f.env.Store.ReadMeta(f.mbx, f.inbox(t), a.ID)
	pf := parse(t, data)
	if pf.Header.Version != 2 || pf.Header.Created != a.Meta.Received || pf.Trailer.Signer.Type != envelope.SignerUser || pf.Trailer.Signer.ID != f.u.ID {
		t.Fatalf("header %+v trailer %+v", pf.Header, pf.Trailer.Signer)
	}
	m, err = c.SetFlags(f.mbx, a.ID, nil, []string{"seen"})
	if err != nil || m.Meta.Version != 3 || !reflect.DeepEqual(client.FlagNames(m.Meta.Flags), []string{"flagged"}) {
		t.Fatalf("clear: %+v: %v", m, err)
	}
	// Nothing changes: nothing is written.
	if m, err = c.SetFlags(f.mbx, a.ID, []string{"flagged"}, []string{"seen"}); err != nil || m.Meta.Version != 3 {
		t.Fatalf("no change: %v", err)
	}
	for _, args := range [][2][]string{{{"bogus"}, nil}, {nil, {"Seen"}}, {{"seen"}, {"seen"}}} {
		if _, err := c.SetFlags(f.mbx, a.ID, args[0], args[1]); !errors.Is(err, client.ErrArgument) {
			t.Fatalf("%v accepted: %v", args, err)
		}
	}
	if _, err := c.SetFlags(f.mbx, store.ID{7}, []string{"seen"}, nil); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("unknown mail: %v", err)
	}
	// A new process lists and reads the new version.
	c = f.env.Reopen(f.u)
	list, err := c.List(f.mbx, store.ID{})
	if err != nil || len(list) != 1 || list[0].Meta.Version != 3 || list[0].Meta.Flags != m.Meta.Flags {
		t.Fatalf("list: %v", err)
	}
	if _, body, err := c.Read(f.mbx, a.ID); err != nil || !bytes.Contains(body, []byte("x")) {
		t.Fatalf("read: %v", err)
	}
	if got := client.FlagNames(1<<31 | 1); !reflect.DeepEqual(got, []string{"seen"}) {
		t.Fatalf("unknown bits: %v", got)
	}
}

// TestSetFlagsDelegate: a delegate reads but does not change flags; only
// user signatures of user members are accepted.
func TestSetFlagsDelegate(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{Delegate: true})
	f.env.Clock.Advance(time.Minute)
	a := f.deliver(t, "a", "x")
	if _, _, err := bob.Client.Read(f.mbx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Client.SetFlags(f.mbx, a.ID, []string{"seen"}, nil); !errors.Is(err, client.ErrNotMember) {
		t.Fatalf("delegate changes flags: %v", err)
	}
	// Metadata signed by the delegate are rejected.
	f.forgeVersion(t, bob, a.Meta, a.Epoch, 2, func(m *store.MailMeta) { m.Flags = 1 })
	f.env.Warnings.Take()
	if _, _, err := f.u.Client.Read(f.mbx, a.ID); !errors.Is(err, client.ErrSigner) {
		t.Fatalf("delegate signature: %v", err)
	}
}

// TestSetFlagsRace: two clients change the flags of the same mail at the
// same time; the loser reads the newer version and applies its change
// again, so both changes stay (K4 point 1 to 3).
func TestSetFlagsRace(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Clock.Advance(time.Hour)
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	f.env.Clock.Advance(time.Minute)
	a := f.deliver(t, "a", "x")
	once := false
	client.SetFlagsHook(t, func() {
		if once {
			return
		}
		once = true
		if m, err := bob.Client.SetFlags(f.mbx, a.ID, []string{"flagged"}, nil); err != nil || m.Meta.Version != 2 {
			t.Errorf("bob: %v", err)
		}
	})
	m, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"seen"}, nil)
	if err != nil || m.Meta.Version != 3 || !reflect.DeepEqual(client.FlagNames(m.Meta.Flags), []string{"flagged", "seen"}) {
		t.Fatalf("alice: %+v: %v", m, err)
	}
	list, err := bob.Client.List(f.mbx, store.ID{})
	if err != nil || len(list) != 1 || list[0].Meta.Version != 3 || !reflect.DeepEqual(client.FlagNames(list[0].Meta.Flags), []string{"flagged", "seen"}) {
		t.Fatalf("bob lists: %v", err)
	}
	// A client that loses every attempt gives up.
	n, inHook := 0, false
	client.SetFlagsHook(t, func() {
		if inHook {
			return // bob's own change
		}
		inHook = true
		defer func() { inHook = false }()
		n++
		set, clear := []string{"answered"}, []string(nil)
		if n%2 == 0 {
			set, clear = nil, set
		}
		if _, err := bob.Client.SetFlags(f.mbx, a.ID, set, clear); err != nil {
			t.Errorf("bob: %v", err)
		}
	})
	if _, err := f.u.Client.SetFlags(f.mbx, a.ID, []string{"draft"}, nil); !errors.Is(err, client.ErrConflict) || n != 5 {
		t.Fatalf("after %d attempts: %v", n, err)
	}
}

// TestFlagsReplayAndForgery: an older version put back, a user signature
// of a non-member, a changed created or mail hash, a user signature on
// version 1 and an ingest signature on a later version are rejected.
func TestFlagsReplayAndForgery(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	a := f.deliver(t, "a", "x")
	inbox := f.inbox(t)
	c := f.u.Client
	v1, _ := f.env.Store.ReadMeta(f.mbx, inbox, a.ID)
	if _, err := c.SetFlags(f.mbx, a.ID, []string{"seen"}, nil); err != nil {
		t.Fatal(err)
	}
	v2, _ := f.env.Store.ReadMeta(f.mbx, inbox, a.ID)
	put := func(data []byte) { store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, inbox, a.ID), data) }
	expect := func(name string, want error) {
		t.Helper()
		f.env.Warnings.Take()
		if _, _, err := c.Read(f.mbx, a.ID); !errors.Is(err, want) {
			t.Fatalf("%s: %v", name, err)
		}
		list, _ := c.List(f.mbx, store.ID{})
		if len(list) != 0 || !warned(f.env, a.ID.String()) {
			t.Fatalf("%s: listed or not warned", name)
		}
	}
	put(v1)
	expect("older version", client.ErrReplay)
	put(v2)
	if _, _, err := c.Read(f.mbx, a.ID); err != nil {
		t.Fatal(err)
	}
	f.forgeVersion(t, bob, a.Meta, 1, 3, nil)
	expect("non-member", client.ErrSigner)
	f.forgeVersion(t, f.u, a.Meta, 1, 3, func(m *store.MailMeta) { m.Received += 1000 })
	expect("created changed", client.ErrMetaChanged)
	f.forgeVersion(t, f.u, a.Meta, 1, 3, func(m *store.MailMeta) { m.MailHash[0] ^= 1 })
	expect("mail hash changed", client.ErrMetaChanged)
	f.forgeVersion(t, f.u, a.Meta, 1, 1, nil)
	expect("user signature on version 1", client.ErrSigner)
	f.forgeVersion(t, nil, a.Meta, 1, 3, nil)
	expect("ingest signature on version 3", client.ErrSigner)
	// The same version 3 signed by alice is accepted.
	f.forgeVersion(t, f.u, a.Meta, 1, 3, func(m *store.MailMeta) { m.Flags = 4 })
	if m, _, err := c.Read(f.mbx, a.ID); err != nil || m.Meta.Version != 3 {
		t.Fatalf("valid version 3: %v", err)
	}
	// After a restart the memory holds: version 2 is older.
	c = f.env.Reopen(f.u)
	put(v2)
	if _, _, err := c.Read(f.mbx, a.ID); !errors.Is(err, client.ErrReplay) {
		t.Fatalf("after a restart: %v", err)
	}
}

// TestSeenVersionsSavedOnce: List saves the versions it saw once at the
// end; if that fails, it returns no mails, and the versions stay seen in
// memory and are saved by the next List (task 09, addendum).
func TestSeenVersionsSavedOnce(t *testing.T) {
	f := newFixture(t)
	if _, err := f.u.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	forgeMails(t, f.env, f.mbx, 5)
	statePath := filepath.Join(f.u.Dir, "state.json")
	saved, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	// state.json cannot be replaced while a directory stands in its place.
	os.Remove(statePath)
	if err := os.MkdirAll(filepath.Join(statePath, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err == nil || list != nil {
		t.Fatalf("list without a saved state: %d mails, %v", len(list), err)
	}
	// The versions stay noted: the next operation tries to save them
	// before it returns anything.
	if _, err := f.u.Client.Search(f.mbx, "to:a@example.org", client.SearchOptions{}); err == nil {
		t.Fatal("search without a saved state")
	}
	os.RemoveAll(statePath)
	if err := os.WriteFile(statePath, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	list, err = f.u.Client.List(f.mbx, store.ID{})
	if err != nil || len(list) != 5 {
		t.Fatalf("list: %d: %v", len(list), err)
	}
	var st struct {
		Mailboxes map[string]struct {
			Versions map[string]uint32 `json:"versions"`
			Mails    map[string]any    `json:"mails"`
		} `json:"mailboxes"`
	}
	data, _ := os.ReadFile(statePath)
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if ms := st.Mailboxes[f.mbx.String()]; len(ms.Versions) != 5 || len(ms.Mails) != 5 {
		t.Fatalf("state holds %d versions", len(ms.Versions))
	}
	// A second List has nothing new to save.
	before, _ := os.Stat(statePath)
	time.Sleep(10 * time.Millisecond)
	if _, err := f.u.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(statePath); !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("state.json written without a new version")
	}
}

// TestMetaTermsMatchServer: the terms a client derives from the metadata
// of an unprocessed mail equal the terms of the server's term list for
// the same mail (5.4, 6.2 step 2), for mails without References or
// In-Reply-To.
func TestMetaTermsMatchServer(t *testing.T) {
	f := newFixture(t)
	msgs := []string{
		"From: \"Müller, Hans\" <Hans.Mueller@Example.DE>\r\nTo: A <a@example.org>, b@other.example\r\nCc: c@other.example\r\nSubject: s1\r\nMessage-ID: <S1@x.example>\r\n\r\nbody\r\n",
		"From: =?utf-8?q?M=C3=BCller=2C_Hans?= <h@x.de>\r\nTo: a@example.org\r\nSubject: s2\r\nContent-Type: multipart/mixed; boundary=x\r\nMessage-ID: <s2@x>\r\n\r\n--x--\r\n",
		"From: no address here\r\nTo: a@example.org\r\nSubject: s3\r\n\r\nbody\r\n",
		"From: ÄRGER@Bücher.example\r\nTo: =?utf-8?q?J=C3=B6rg?= <joerg@x.example>\r\nSubject: s4\r\n\r\nbody\r\n",
		"From: s@x.example\r\nTo: undisclosed-recipients:;\r\nSubject: s5\r\n\r\nbody\r\n",
	}
	for _, m := range msgs {
		f.send(t, "Envelope@Sender.example", m)
	}
	f.flush(t)
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err != nil || len(list) != len(msgs) {
		t.Fatal(err)
	}
	ids, _ := f.env.Store.ListPending(f.mbx, 1)
	if len(ids) != 1 {
		t.Fatal("one term list expected")
	}
	p, err := f.u.Client.OpenPending(f.mbx, 1, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	server := map[store.ID][]string{}
	for _, e := range p.Entries {
		server[e.MailID] = e.Terms
	}
	for _, m := range list {
		got := client.MetaTerms(m.Meta)
		if !reflect.DeepEqual(got, server[m.ID]) {
			t.Fatalf("%s: client %q, server %q", m.Meta.Subject, got, server[m.ID])
		}
	}
	// Without an evaluated header only the envelope counts.
	got := client.MetaTerms(&store.MailMeta{Received: testenv.Start.UnixMilli(), EnvelopeFrom: "X@Y.example", Recipients: []string{"a@example.org"}, From: "z@z.example"})
	if strings.Join(got, " ") != "from:x@y.example fromdomain:y.example day:2026-10-26 month:2026-10 to:a@example.org" {
		t.Fatalf("envelope terms %q", got)
	}
}
