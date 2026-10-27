package client_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
)

func folderVersion(t *testing.T, f *fixture, n uint32) uint32 {
	t.Helper()
	data, err := f.env.Store.ReadFolders(f.mbx, n)
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, data).Header.Version
}

func TestSetFoldersAndRename(t *testing.T) {
	p := newPastFixture(t) // epochs 1 to 3 have begun, it is December
	f := p.fixture
	if err := f.u.Client.Sync(); err != nil { // epochs 5 and 6
		t.Fatal(err)
	}
	inbox := f.inbox(t)
	archive, _ := store.NewID(nil)
	folders := []store.Folder{{ID: inbox, Name: client.InboxName}, {ID: archive, Name: " Archiv "}}
	for name, bad := range map[string][]store.Folder{
		"empty":           nil,
		"no inbox":        {{ID: archive, Name: "Archiv"}},
		"inbox renamed":   {{ID: inbox, Name: "Eingang"}},
		"second INBOX":    {{ID: inbox, Name: client.InboxName}, {ID: archive, Name: client.InboxName}},
		"duplicate":       {{ID: inbox, Name: client.InboxName}, {ID: inbox, Name: client.InboxName}},
		"zero id":         {{ID: inbox, Name: client.InboxName}, {Name: "x"}},
		"empty name":      {{ID: inbox, Name: client.InboxName}, {ID: archive, Name: "  "}},
		"too many (1025)": make([]store.Folder, store.MaxFolders+1),
	} {
		if err := f.u.Client.SetFolders(f.mbx, bad); !errors.Is(err, client.ErrArgument) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := f.u.Client.SetFolders(f.mbx, folders); err != nil {
		t.Fatal(err)
	}
	// The current epoch (3) and the future ones (4 to 6) changed, the
	// past ones (1, 2) not.
	for n := uint32(1); n <= 6; n++ {
		l, err := f.u.Client.FoldersOfEpoch(f.mbx, n)
		if err != nil {
			t.Fatal(err)
		}
		changed := n >= 3
		if (len(l.Folders) == 2) != changed || changed && (l.Folders[1].Name != "Archiv" || folderVersion(t, f, n) != 2) || !changed && folderVersion(t, f, n) != 1 {
			t.Fatalf("folders of epoch %d: %+v", n, l.Folders)
		}
	}
	if err := f.u.Client.Rename(f.mbx, "  "); !errors.Is(err, client.ErrArgument) {
		t.Fatal(err)
	}
	if err := f.u.Client.Rename(f.mbx, "Neu"); err != nil {
		t.Fatal(err)
	}
	if name, err := f.u.Client.MailboxName(f.mbx); err != nil || name != "Neu" {
		t.Fatal(name, err)
	}
	if l, _ := f.u.Client.FoldersOfEpoch(f.mbx, 2); l.Name != "A" {
		t.Fatal("past epoch renamed")
	}
	if l, _ := f.u.Client.FoldersOfEpoch(f.mbx, 3); l.Name != "Neu" || len(l.Folders) != 2 || folderVersion(t, f, 3) != 3 {
		t.Fatal("rename lost the folders")
	}
	// Mails in the inbox stay listed.
	if list, err := f.u.Client.List(f.mbx, store.ID{}); err != nil || len(list) != 3 {
		t.Fatalf("%d mails: %v", len(list), err)
	}

	// A new epoch takes the current list; a delegate cannot change it.
	bob := f.env.NewUser("bob")
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{Delegate: true})
	h := chainOf(t, f.env, f.mbx)
	for _, e := range h[6:] {
		if l, err := f.u.Client.FoldersOfEpoch(f.mbx, e.Number); err != nil || l.Name != "Neu" || len(l.Folders) != 2 {
			t.Fatalf("folders of the new epoch %d: %v", e.Number, err)
		}
	}
	if name, err := bob.Client.MailboxName(f.mbx); err != nil || name != "Neu" {
		t.Fatal(name, err)
	}
	if err := bob.Client.SetFolders(f.mbx, folders[:1]); !errors.Is(err, client.ErrNotMember) {
		t.Fatalf("folders by a delegate: %v", err)
	}
	if err := bob.Client.Rename(f.mbx, "Bob"); !errors.Is(err, client.ErrNotMember) {
		t.Fatalf("rename by a delegate: %v", err)
	}
	// A reader of a past period sees the folders of its period.
	carol := f.env.NewUser("carol")
	f.env.Share(f.u, f.mbx, carol, client.ShareOptions{From: 1, To: 2})
	if name, err := carol.Client.MailboxName(f.mbx); err != nil || name != "A" {
		t.Fatal(name, err)
	}
	if err := carol.Client.Rename(f.mbx, "Carol"); !errors.Is(err, client.ErrNotMember) {
		t.Fatalf("rename by a reader of a past period: %v", err)
	}
}

// folders.gml carries a version per epoch; a list that the server puts
// back after a change is older than the one seen and is not used.
func TestFoldersReplay(t *testing.T) {
	f := newFixture(t)
	head := chainOf(t, f.env, f.mbx)[3].Number
	oldData, _ := f.env.Store.ReadFolders(f.mbx, head)
	if err := f.u.Client.Rename(f.mbx, "B"); err != nil {
		t.Fatal(err)
	}
	if v := folderVersion(t, f, head); v != 2 {
		t.Fatalf("version %d", v)
	}
	newData, _ := f.env.Store.ReadFolders(f.mbx, head)
	f.env.Store.WriteFolders(f.mbx, head, oldData)
	f.env.Warnings.Take()
	if _, err := f.u.Client.MailboxName(f.mbx); !errors.Is(err, client.ErrReplay) {
		t.Fatalf("older folders.gml: %v", err)
	}
	if !warned(f.env, "älter als bereits gesehen") {
		t.Fatal("no warning")
	}
	// The memory survives a restart.
	c := f.env.Reopen(f.u)
	if _, err := c.MailboxName(f.mbx); !errors.Is(err, client.ErrReplay) {
		t.Fatalf("after restart: %v", err)
	}
	var st struct {
		Mailboxes map[string]struct {
			Folders map[string]uint32 `json:"folders"`
		} `json:"mailboxes"`
	}
	json.Unmarshal(mustRead(t, filepath.Join(f.u.Dir, "state.json")), &st)
	if st.Mailboxes[f.mbx.String()].Folders["4"] != 2 {
		t.Fatalf("state %+v", st)
	}
	// A change is not based on a list that was put back (fail closed);
	// with the newer list back, the next change goes above it.
	if err := c.Rename(f.mbx, "C"); !errors.Is(err, client.ErrReplay) {
		t.Fatal(err)
	}
	f.env.Store.WriteFolders(f.mbx, head, newData)
	if err := c.Rename(f.mbx, "C"); err != nil {
		t.Fatal(err)
	}
	if v := folderVersion(t, f, head); v != 3 {
		t.Fatalf("version %d", v)
	}
	if name, err := c.MailboxName(f.mbx); err != nil || name != "C" {
		t.Fatal(name, err)
	}
}

// A crash while rewriting folders.gml leaves some epochs with the new
// list; running the change again completes it.
func TestFoldersCrash(t *testing.T) {
	f := newFixture(t)
	n := 0
	client.SetCrashHook(t, func(p string) bool { n++; return p == "folders" && n == 2 })
	if err := f.u.Client.Rename(f.mbx, "B"); !errors.Is(err, client.ErrCrashed) {
		t.Fatal(err)
	}
	client.SetCrashHook(t, nil)
	c := f.env.Reopen(f.u)
	if err := c.Rename(f.mbx, "B"); err != nil {
		t.Fatal(err)
	}
	for e := uint32(1); e <= 4; e++ {
		if l, err := c.FoldersOfEpoch(f.mbx, e); err != nil || l.Name != "B" {
			t.Fatalf("epoch %d: %v", e, err)
		}
	}
}

// The head of the chain is mailbox.rec for client and server. After a
// crash between writing an epoch and mailbox.rec, readers use the chain
// up to mailbox.rec and do not remember the epochs after it; Sync adopts
// them under the lock and writes mailbox.rec. A real reset of mailbox.rec
// below the remembered head stays a rollback.
func TestHeadIsMailboxRec(t *testing.T) {
	f := newFixture(t)
	f.env.Clock.Set(time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC))
	client.SetCrashHook(t, func(p string) bool { return p == "epoch-written" })
	if err := f.u.Client.Sync(); !errors.Is(err, client.ErrCrashed) {
		t.Fatal(err)
	}
	client.SetCrashHook(t, nil)
	if m, _ := f.env.Store.ReadMailbox(f.mbx); m.Epoch != 4 {
		t.Fatal("mailbox.rec moved")
	}
	if _, _, err := f.env.Store.ReadEpoch(f.mbx, 5); err != nil {
		t.Fatal("epoch 5 not written")
	}
	c := f.env.Reopen(f.u)
	for i := 0; i < 2; i++ {
		if _, err := c.List(f.mbx, store.ID{}); err != nil {
			t.Fatalf("List %d after the crash: %v", i+1, err)
		}
	}
	var st struct {
		Mailboxes map[string]struct {
			Epoch  uint32                     `json:"epoch"`
			Epochs map[string]json.RawMessage `json:"epochs"`
		} `json:"mailboxes"`
	}
	json.Unmarshal(mustRead(t, filepath.Join(f.u.Dir, "state.json")), &st)
	if ms := st.Mailboxes[f.mbx.String()]; ms.Epoch != 4 || ms.Epochs["5"] != nil {
		t.Fatalf("epoch after mailbox.rec remembered: %d", ms.Epoch)
	}
	if err := c.Sync(); err != nil {
		t.Fatalf("Sync repairs: %v", err)
	}
	if _, err := c.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	m, _ := f.env.Store.ReadMailbox(f.mbx)
	if m.Epoch != 6 {
		t.Fatalf("head %d, want 6", m.Epoch)
	}
	// A reset below the remembered head is a rollback, and Sync does not
	// repair it.
	reset := *m
	reset.Epoch = 4
	f.env.Store.WriteMailbox(&reset)
	if _, err := c.List(f.mbx, store.ID{}); !errors.Is(err, client.ErrRollback) {
		t.Fatalf("reset mailbox.rec: %v", err)
	}
	if err := c.Sync(); !errors.Is(err, client.ErrRollback) {
		t.Fatalf("Sync on a reset mailbox.rec: %v", err)
	}
	// A non-member repairs mailbox.rec as well, without creating epochs.
	f.env.Store.WriteMailbox(m)
	client.SetCrashHook(t, func(p string) bool { return p == "mailbox" })
	f.env.Clock.Set(time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC))
	if err := c.Sync(); !errors.Is(err, client.ErrCrashed) {
		t.Fatal(err)
	}
	client.SetCrashHook(t, nil)
	f.env.Store.WriteMailbox(m) // as if mailbox.rec had not been written
	bob := f.env.NewUser("bob")
	if _, err := bob.Client.MailboxName(f.mbx); !errors.Is(err, client.ErrWrap) {
		t.Fatal(err)
	}
	if err := bob.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	if m2, _ := f.env.Store.ReadMailbox(f.mbx); m2.Epoch != 7 {
		t.Fatalf("head %d after the repair by a non-member", m2.Epoch)
	}
}
