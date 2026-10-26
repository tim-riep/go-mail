package client_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

var errLog = errors.New("log says no")

// failLog refuses the operation named fail and accepts everything else.
type failLog struct {
	translog.Log
	fail string
}

func (l *failLog) err(op string) error {
	if l.fail == op {
		return errLog
	}
	return nil
}
func (l *failLog) AppendUser(store.ID, []byte) error          { return l.err("AppendUser") }
func (l *failLog) AppendEpoch(store.ID, uint32, []byte) error { return l.err("AppendEpoch") }
func (l *failLog) CheckUser(store.ID, []byte) error           { return l.err("CheckUser") }
func (l *failLog) CheckGeneration(store.ID, uint32) error     { return l.err("CheckGeneration") }
func (l *failLog) CheckRevokedSignature(store.ID, uint32, []byte) error {
	return l.err("CheckRevokedSignature")
}
func (l *failLog) CheckEpoch(store.ID, uint32, []byte) error  { return l.err("CheckEpoch") }
func (l *failLog) CheckAddress(string, store.ID, int64) error { return l.err("CheckAddress") }
func (l *failLog) CheckPlatform(string, []byte) error         { return l.err("CheckPlatform") }
func (l *failLog) CheckFresh(time.Time) error                 { return l.err("CheckFresh") }

// TestLogRefusalsStopEverything checks that every log check is binding:
// when the log refuses, the operation fails (phase 3 plugs in the real
// log behind the same calls).
func TestLogRefusalsStopEverything(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	open := func(fail string) (*client.Client, error) {
		cfg := f.env.ClientConfig(f.u.Dir)
		cfg.Log = &failLog{Log: f.env.Log, fail: fail}
		return client.Open(cfg, testenv.Passphrase)
	}
	f.u.Client.Close()
	for _, op := range []string{"CheckFresh", "CheckUser"} {
		if _, err := open(op); !errors.Is(err, errLog) {
			t.Fatalf("%s at start: %v", op, err)
		}
	}
	for _, op := range []string{"CheckGeneration", "CheckEpoch", "CheckAddress", "CheckPlatform"} {
		c, err := open(op)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = c.Read(f.mbx, a.ID)
		// A refusal while verifying the chain ends the chain: the mail's
		// epoch is then outside the verified chain.
		if !errors.Is(err, errLog) && !errors.Is(err, client.ErrEpoch) {
			t.Fatalf("%s: read must fail, got %v", op, err)
		}
		c.Close()
	}
	c, _ := open("AppendEpoch")
	if _, err := c.CreateMailbox("x"); !errors.Is(err, errLog) {
		t.Fatal("AppendEpoch")
	}
	c.Close()
	// Registration fails when the log refuses the user.
	dir := filepath.Join(f.env.Base, "reg")
	cfg := f.env.ClientConfig(dir)
	cfg.Log = &failLog{Log: f.env.Log, fail: "AppendUser"}
	client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
	code, _ := f.env.Store.CreateInvite(0)
	if _, err := client.Register(cfg, code); !errors.Is(err, errLog) {
		t.Fatal("AppendUser")
	}
}

// TestSeenEpochReplacedWithValidSignature: even a correctly signed and
// linked replacement of the highest seen epoch is detected by its hash
// (the attacker here holds the user's key, which is stronger than the
// threat model needs).
func TestSeenEpochReplacedWithValidSignature(t *testing.T) {
	f := newFixture(t)
	f.deliver(t, "a", "x")
	data := mustRead(t, f.env.Store.EpochFile(f.mbx, 4))
	e4, _ := store.DecodeEpoch(data)
	e4.Begin++
	ks, _ := keys.OpenKeystore(mustRead(t, filepath.Join(f.u.Dir, "keystore")), testenv.Passphrase)
	e4.Sign(ks.Identity)
	ks.Zero()
	enc, _ := e4.Encode()
	os.WriteFile(f.env.Store.EpochFile(f.mbx, 4), enc, 0o600)
	f.env.Warnings.Take()
	if _, err := f.u.Client.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("replaced epoch: %v", err)
	}
	if !warned(f.env, "wurde ersetzt") {
		t.Fatal("no warning")
	}
}

// TestRegisterTakenID: a user ID that exists already is refused.
func TestRegisterTakenID(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	dir := filepath.Join(env.Base, "copy")
	cfg := env.ClientConfig(dir)
	client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
	// Make the new client's pending user.rec carry alice's record.
	os.WriteFile(filepath.Join(dir, "user.rec"), mustRead(t, env.Store.UserFile(u.ID)), 0o600)
	code, _ := env.Store.CreateInvite(0)
	if _, err := client.Register(cfg, code); !errors.Is(err, store.ErrExists) {
		t.Fatalf("taken id: %v", err)
	}
	// A damaged pending user.rec.
	os.WriteFile(filepath.Join(dir, "user.rec"), []byte("x"), 0o600)
	if _, err := client.Register(cfg, code); err == nil {
		t.Fatal("damaged user.rec")
	}
	os.Remove(filepath.Join(dir, "user.rec"))
	if _, err := client.Register(cfg, code); !errors.Is(err, client.ErrNotRegistered) {
		t.Fatal("missing user.rec")
	}
	// Open with a missing or foreign local user.rec or key store.
	os.Remove(filepath.Join(u.Dir, "keystore"))
	u.Client.Close()
	if _, err := client.Open(env.ClientConfig(u.Dir), testenv.Passphrase); err == nil {
		t.Fatal("missing key store")
	}
	os.Remove(filepath.Join(u.Dir, "user.rec"))
	if _, err := client.Open(env.ClientConfig(u.Dir), testenv.Passphrase); !errors.Is(err, client.ErrNotRegistered) {
		t.Fatal("missing user.rec")
	}
}
