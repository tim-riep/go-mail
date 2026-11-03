package client_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 20b point 3: the client log while the chain is loaded.

// countEpochAppends counts the appends of one epoch.rec.
type countEpochAppends struct {
	translog.Log
	data []byte
	n    *int
}

func (l *countEpochAppends) Append(kind translog.Kind, content []byte) (int64, error) {
	if kind == translog.KindEpoch && bytes.Equal(content, l.data) {
		*l.n++
	}
	return l.Log.Append(kind, content)
}

// TestLogUnloggableHeadAppendedOnce: a reader that loads a chain whose
// head (named by mailbox.rec) can never be logged asks the log once: the
// epoch.rec is appended once per load (ErrOrder), not a second time for
// the decision that the head is unloggable. Both ways are covered: the
// log check of the chain fails (a wrong signature, which only the log
// checks before the signature check), or a local check before it fails
// (a revoked generation, checkSignerGen) and only the decision asks the
// log.
func TestLogUnloggableHeadAppendedOnce(t *testing.T) {
	t.Run("log-check", func(t *testing.T) {
		f := newFixture(t)
		f.env.Clock.Advance(time.Minute)
		_, wrong, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		unloggableHeadOnce(t, f, beyondEpoch(t, f, nil, wrong))
	})
	t.Run("local-check", func(t *testing.T) {
		f := newFixture(t)
		f.env.Clock.Advance(time.Minute)
		if gen := f.env.DeviceLost(f.u); gen != 2 {
			t.Fatal(gen)
		}
		f.env.Clock.Advance(time.Minute)
		id1 := identityOf(t, f.u.Words, 1)
		defer keys.Wipe(id1)
		unloggableHeadOnce(t, f, beyondEpoch(t, f, asGen1(f.u.ID), id1))
	})
}

// unloggableHeadOnce plants epoch.rec planted as the head of mailbox.rec
// and checks that one List appends it once.
func unloggableHeadOnce(t *testing.T, f *fixture, planted []byte) {
	t.Helper()
	if _, err := f.env.LogOperator().Append(translog.KindEpoch, planted); !errors.Is(err, translog.ErrOrder) {
		t.Fatalf("planted epoch: %v", err)
	}
	n := headOf(t, f.env, f.mbx) + 1
	if err := store.MkdirAll(f.env.Store.EpochDir(f.mbx, n)); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(f.env.Store.EpochFile(f.mbx, n), planted); err != nil {
		t.Fatal(err)
	}
	mrec, err := f.env.Store.ReadMailbox(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	mrec.Epoch = n
	if err := f.env.Store.WriteMailbox(mrec); err != nil {
		t.Fatal(err)
	}
	appends := 0
	client.SetLogHook(t, func(l translog.Log) translog.Log { return &countEpochAppends{Log: l, data: planted, n: &appends} })
	c := f.env.Reopen(f.u)
	f.env.Warnings.Take()
	appends = 0
	if _, err := c.List(f.mbx, store.ID{}); !errors.Is(err, store.ErrChain) {
		t.Fatalf("reader with the unloggable head: %v", err)
	}
	if appends != 1 {
		t.Fatalf("the unloggable head was appended %d times in one load of the chain, want 1", appends)
	}
	warningWith(t, f.env.Warnings.Take(), fmt.Sprintf("Epoche %d von %s ist nicht loggbar", n, f.mbx))
}

// TestLogContradictsAtHead: an epoch.rec at the head of the chain (here
// the newest logged epoch, above mailbox.rec) that contradicts the
// logged epoch with its number breaks the chain with the usual warning
// and is then named with the fixed cause and the operator's remedy for
// the head; it is never replaced. Beyond the head the remedy stays the
// removal of the file (TestLogDuplicateNeverReplaced).
func TestLogContradictsAtHead(t *testing.T) {
	f := newFixture(t)
	f.env.Clock.Advance(time.Minute)
	ks := f.env.Keystore(f.u)
	defer ks.Zero()
	m, err := f.env.Store.ReadMailbox(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	logged := f.env.ForgeEpoch(f.u, f.mbx, f.env.Clock.Now(), store.ReasonMemberAdded, nil, "A")
	if err := f.env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	other := beyondEpoch(t, f, func(e *store.Epoch) { e.Begin++ }, ks.Identity)
	if err := store.WriteFileAtomic(f.env.Store.EpochFile(f.mbx, logged.Number), other); err != nil {
		t.Fatal(err)
	}
	cause := fmt.Sprintf("Epoche %d von %s widerspricht dem Transparenzlog", logged.Number, f.mbx)
	// A new start sees the log with the forged epoch.
	c := f.env.Reopen(f.u)
	for _, op := range []struct {
		name string
		run  func() error
	}{
		{"reader", func() error { _, err := c.List(f.mbx, store.ID{}); return err }},
		{"sync", c.Sync},
	} {
		f.env.Warnings.Take()
		if err := op.run(); err == nil {
			t.Fatalf("%s over an epoch at the head that contradicts the log", op.name)
		}
		w := f.env.Warnings.Take()
		warningWith(t, w, fmt.Sprintf("Epochenkette von %s bricht bei Epoche %d ab", f.mbx, logged.Number))
		warningWith(t, w, cause, "nie ersetzt", "Abhilfe (Betreiber)", "durch den Inhalt des Logeintrags ersetzen")
		noWarningWith(t, w, cause, "die Datei entfernen")
		if !bytes.Equal(mustRead(t, f.env.Store.EpochFile(f.mbx, logged.Number)), other) {
			t.Fatalf("%s replaced an epoch that contradicts the log", op.name)
		}
	}
}
