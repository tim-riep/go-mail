//go:build unix

package store

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestFIFOReadDir (task 24 package F, R41): a FIFO in place of a
// directory that the store lists (ReadDir, RemoveTemp, ListEpochs,
// ListPendingEpochs, ListMails, ListPending, ListFolders,
// ListCheckpoints) is an error at once (syscall.ENOTDIR) instead of an
// open that waits for a writer. ClearInvalidEpoch lists epochs/<n>/ only
// after reading epoch.rec in it, so a FIFO there fails before the list.
func TestFIFOReadDir(t *testing.T) {
	mbx, folder := ID{7}, ID{8}
	for _, c := range []struct {
		name string
		path func(s *Store, tmp string) string
		f    func(s *Store, p string) error
	}{
		{"ReadDir", func(_ *Store, tmp string) string { return filepath.Join(tmp, "fifo") },
			func(_ *Store, p string) error { _, err := ReadDir(p); return err }},
		{"RemoveTemp", func(_ *Store, tmp string) string { return filepath.Join(tmp, "fifo") },
			func(_ *Store, p string) error { return RemoveTemp(p) }},
		{"ListEpochs", func(s *Store, _ string) string { return filepath.Join(s.MailboxDir(mbx), "epochs") },
			func(s *Store, _ string) error { _, err := s.ListEpochs(mbx); return err }},
		{"ListPendingEpochs", func(s *Store, _ string) string { return filepath.Join(s.MailboxDir(mbx), "pending") },
			func(s *Store, _ string) error { _, err := s.ListPendingEpochs(mbx); return err }},
		{"ListMails", func(s *Store, _ string) string { return s.MailDir(mbx, folder) },
			func(s *Store, _ string) error { _, err := s.ListMails(mbx, folder); return err }},
		{"ListPending", func(s *Store, _ string) string { return s.PendingDir(mbx, 1) },
			func(s *Store, _ string) error { _, err := s.ListPending(mbx, 1); return err }},
		{"ListFolders", func(s *Store, _ string) string { return filepath.Join(s.MailboxDir(mbx), "mail") },
			func(s *Store, _ string) error { _, err := s.ListFolders(mbx); return err }},
		{"ListCheckpoints", func(s *Store, _ string) string { return s.CheckpointDir(mbx) },
			func(s *Store, _ string) error { _, err := s.ListCheckpoints(mbx); return err }},
	} {
		tmp := t.TempDir()
		s, err := Init(filepath.Join(tmp, "data"))
		if err != nil {
			t.Fatal(err)
		}
		p := c.path(s, tmp)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Skip(err)
		}
		done := make(chan error, 1)
		go func() { done <- c.f(s, p) }()
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
