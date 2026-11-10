//go:build unix

package client

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

// TestFIFOClientReadDir (task 24 package F, R41): a FIFO in place of a
// directory that the client lists with store.ReadDir is an error at once
// (syscall.ENOTDIR) instead of an open that waits for a writer: users/
// and mailboxes/ of the data directory (findUser and userMailboxes of
// restore), members/ of an epoch (wrapRecipients of device lost) and
// new-mailboxes/ of the client directory (resumeMailboxes).
func TestFIFOClientReadDir(t *testing.T) {
	mbx := store.ID{5}
	e := &store.Epoch{MailboxID: mbx, Number: 1}
	for _, c := range []struct {
		name string
		path func(st *store.Store, dir string) string
		f    func(st *store.Store, dir string) error
	}{
		{"findUser", func(st *store.Store, _ string) string { return st.Path("users") },
			func(st *store.Store, _ string) error { _, _, err := findUser(st, store.ID{}, nil); return err }},
		{"userMailboxes", func(st *store.Store, _ string) string { return st.Path("mailboxes") },
			func(st *store.Store, _ string) error { _, err := userMailboxes(st, store.ID{1}); return err }},
		{"wrapRecipients", func(st *store.Store, _ string) string {
			return filepath.Join(st.EpochDir(mbx, 1), "members")
		}, func(st *store.Store, _ string) error {
			_, err := (&Client{st: st, me: store.ID{1}}).wrapRecipients(e)
			return err
		}},
		{"resumeMailboxes", func(_ *store.Store, dir string) string { return filepath.Join(dir, newMailboxesDir) },
			func(st *store.Store, dir string) error {
				return (&Client{cfg: Config{Store: st, Dir: dir}, st: st}).resumeMailboxes()
			}},
	} {
		tmp := t.TempDir()
		st, err := store.Init(filepath.Join(tmp, "data"))
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(tmp, "client")
		p := c.path(st, dir)
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Skip(err)
		}
		done := make(chan error, 1)
		go func() { done <- c.f(st, dir) }()
		select {
		case err := <-done:
			if !errors.Is(err, syscall.ENOTDIR) {
				t.Fatalf("%s: %v, want %v", c.name, err, syscall.ENOTDIR)
			}
		case <-time.After(10 * time.Second):
			if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
			t.Fatalf("%s: hangs at the FIFO", c.name)
		}
	}
}
