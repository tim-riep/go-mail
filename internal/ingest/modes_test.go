//go:build unix

package ingest

import (
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

const modeBits = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

// checkModes reports every file not FilePerm and every directory not
// DirPerm below root (9.1).
func checkModes(t *testing.T, root string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		want := store.FilePerm
		if d.IsDir() {
			want = store.DirPerm
		}
		if fi.Mode()&modeBits != want {
			t.Errorf("%s: mode %v, want %v", p, fi.Mode()&modeBits, want)
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// After a delivery everything below mailboxes/<id>/ has 0660 or 2770,
// even under umask 077; the spool files on the way too.
func TestModesAfterDelivery(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	in := newIngest(t, env)
	spooled := false
	crashHook = func(p string) bool {
		if p == "spooled" {
			spooled = true
			if checkModes(t, env.Store.SpoolDir()) < 5 {
				t.Error("spool not walked")
			}
		}
		return false
	}
	t.Cleanup(func() { crashHook = nil })
	if err := deliver(t, in, "s@x", []string{"info@example.org"}, message("modes", "x")); err != nil {
		t.Fatal(err)
	}
	crashHook = nil
	// The fallback note and a term list as well.
	env.Clock.Set(time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC))
	if err := deliver(t, in, "s@x", []string{"info@example.org"}, message("late", "x")); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if !spooled {
		t.Fatal("spool not checked")
	}
	if n, _ := env.Store.ReadNote(mbx); n == nil {
		t.Fatal("no note")
	}
	if checkModes(t, env.Store.MailboxDir(mbx)) < 20 {
		t.Fatal("mailbox not walked")
	}
	mails, err := env.Store.ListMails(mbx, mustMailbox(t, env, mbx).Inbox)
	if err != nil || len(mails) != 2 {
		t.Fatalf("%d mails: %v", len(mails), err)
	}
}

func mustMailbox(t *testing.T, env *testenv.Env, id store.ID) *store.Mailbox {
	t.Helper()
	m, err := env.Store.ReadMailbox(id)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
