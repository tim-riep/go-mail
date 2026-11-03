//go:build unix

package client_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// TestKeystoreNotRegular (task 20l point 2, F3 of the attack review of
// task 20i, R41): Open and DeviceLost read the key store with
// store.ReadFileLimited. A FIFO in its place is refused at once as not
// regular (keys.ErrKeystore and store.ErrNotRegular) instead of blocking
// the open until a writer comes, as keys.ReadKeystoreFile does; a file
// above keys.MaxKeystoreSize is keys.ErrKeystore and store.ErrTooLarge;
// a missing one fs.ErrNotExist.
func TestKeystoreNotRegular(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	u.Client.Close()
	ks := filepath.Join(u.Dir, "keystore")
	saved, err := os.ReadFile(ks)
	if err != nil {
		t.Fatal(err)
	}
	runs := map[string]func() error{
		"open": func() error {
			c, err := client.Open(env.ClientConfig(u.Dir), testenv.Passphrase)
			if err == nil {
				c.Close()
			}
			return err
		},
		"devicelost": func() error {
			_, err := client.DeviceLost(env.ClientConfig(u.Dir), testenv.Passphrase, u.Words)
			return err
		},
	}
	// within runs f and fails the test if it does not return in time.
	within := func(name string, f func() error) error {
		done := make(chan error, 1)
		go func() { done <- f() }()
		select {
		case err := <-done:
			return err
		case <-time.After(30 * time.Second):
			// Release the open with a writer, then fail.
			if w, err := os.OpenFile(ks, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
			t.Fatalf("%s blocks on a FIFO as key store", name)
			return nil
		}
	}
	for name, run := range runs {
		if err := os.Remove(ks); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(ks, 0o600); err != nil {
			t.Skip("mkfifo:", err)
		}
		if err := within(name, run); !errors.Is(err, keys.ErrKeystore) || !errors.Is(err, store.ErrNotRegular) {
			t.Fatalf("%s with a FIFO as key store: %v", name, err)
		}
		if err := os.Remove(ks); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ks, make([]byte, keys.MaxKeystoreSize+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run(); !errors.Is(err, keys.ErrKeystore) || !errors.Is(err, store.ErrTooLarge) {
			t.Fatalf("%s with a key store too large: %v", name, err)
		}
		if err := os.Remove(ks); err != nil {
			t.Fatal(err)
		}
		if err := run(); !errors.Is(err, fs.ErrNotExist) || !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s without key store: %v", name, err)
		}
	}
	if err := os.WriteFile(ks, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := client.Open(env.ClientConfig(u.Dir), testenv.Passphrase)
	if err != nil {
		t.Fatalf("open with the key store back: %v", err)
	}
	c.Close()
}
