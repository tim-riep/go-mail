package client_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
func (l *failLog) Append(kind translog.Kind, content []byte) (int64, error) {
	op := map[translog.Kind]string{translog.KindUser: "AppendUser", translog.KindEpoch: "AppendEpoch"}[kind]
	if err := l.err(op); err != nil {
		return -1, err
	}
	return l.Log.Append(kind, content)
}
func (l *failLog) CheckUser(u store.ID, d []byte) error {
	if err := l.err("CheckUser"); err != nil {
		return err
	}
	return l.Log.CheckUser(u, d)
}
func (l *failLog) CheckGeneration(u store.ID, g uint32) error {
	if err := l.err("CheckGeneration"); err != nil {
		return err
	}
	return l.Log.CheckGeneration(u, g)
}
func (l *failLog) CheckRevokedSignature(u store.ID, g uint32, d []byte) error {
	if err := l.err("CheckRevokedSignature"); err != nil {
		return err
	}
	return l.Log.CheckRevokedSignature(u, g, d)
}
func (l *failLog) CheckEpoch(m store.ID, n uint32, d []byte) error {
	if err := l.err("CheckEpoch"); err != nil {
		return err
	}
	return l.Log.CheckEpoch(m, n, d)
}
func (l *failLog) CheckAddress(a string, m store.ID, at int64) error {
	if err := l.err("CheckAddress"); err != nil {
		return err
	}
	return l.Log.CheckAddress(a, m, at)
}
func (l *failLog) CheckPlatform(n string, d []byte) error {
	if err := l.err("CheckPlatform"); err != nil {
		return err
	}
	return l.Log.CheckPlatform(n, d)
}
func (l *failLog) CheckFresh(now time.Time) error {
	if err := l.err("CheckFresh"); err != nil {
		return err
	}
	return l.Log.CheckFresh(now)
}

// failing makes every client log opened afterwards refuse op.
func failing(t *testing.T, op string) {
	client.SetLogHook(t, func(l translog.Log) translog.Log { return &failLog{Log: l, fail: op} })
}

// TestLogRefusalsStopEverything checks that every log check is binding:
// when the log refuses, the operation fails (phase 3 plugs in the real
// log behind the same calls).
func TestLogRefusalsStopEverything(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	open := func(fail string) (*client.Client, error) {
		failing(t, fail)
		return client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
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
	failing(t, "AppendUser")
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
	// Since task 14 the log holds the original epoch 4: the replacement
	// contradicts it (CheckEpoch, ErrMismatch), the chain ends there.
	if w := strings.Join(f.env.Warnings.Take(), "\n"); !strings.Contains(w, "wurde ersetzt") && !strings.Contains(w, "bricht bei Epoche 4 ab") {
		t.Fatalf("no warning: %s", w)
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
