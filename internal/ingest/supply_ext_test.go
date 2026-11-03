package ingest_test

// Tests of package ingest that need package client. They live in the
// external test package, so that the tests of package ingest itself do
// not import client (task 09b point 1).

import (
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// startIngest starts an ingest backend on the data directory of env and
// recovers it.
func startIngest(t *testing.T, env *testenv.Env) *ingest.Ingest {
	t.Helper()
	in, err := ingest.New(ingest.Config{Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1, Now: env.Clock.Now,
		DiskSpace: func(string) (uint64, uint64, error) { return 50, 100, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	if err := in.Recover(); err != nil {
		t.Fatal(err)
	}
	return in
}

// deliverTo delivers msg from to rcpts through in, like an SMTP session.
func deliverTo(t *testing.T, in *ingest.Ingest, from string, rcpts []string, msg string) error {
	t.Helper()
	d, err := in.Begin(smtpd.Session{ID: "test", Helo: "client.test", RemoteIP: "127.0.0.1"}, from, rcpts)
	if err != nil {
		return err
	}
	for _, line := range strings.SplitAfter("Received: from test\r\n"+msg, "\r\n") {
		if line == "" {
			continue
		}
		if _, err := d.Write([]byte(line)); err != nil {
			d.Abort()
			return err
		}
	}
	return d.Commit()
}

// mailText returns a small mail with subject and body.
func mailText(subject, body string) string {
	return "From: Sender <sender@example.net>\r\nTo: Info <info@example.org>\r\nSubject: " + subject +
		"\r\nMessage-ID: <m1@example.net>\r\nDate: Mon, 26 Oct 2026 10:00:00 +0000\r\n\r\n" + body + "\r\n"
}

func TestSupplyEmptyFallback(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "info@example.org")
	in := startIngest(t, env)
	// Five months later nobody logged in: the supply (epoch 4, January)
	// ran out; the server keeps using epoch 4 and notes it.
	env.Clock.Set(time.Date(2027, 3, 15, 12, 0, 0, 0, time.UTC))
	if err := deliverTo(t, in, "s@x", []string{"info@example.org"}, mailText("late", "1")); err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(time.Minute)
	deliverTo(t, in, "s@x", []string{"info@example.org"}, mailText("late2", "2"))
	note, err := env.Store.ReadNote(mbx)
	if err != nil || note == nil || note.Epoch != 4 || note.Count != 2 {
		t.Fatalf("note %+v %v", note, err)
	}
	list, _ := u.Client.List(mbx, store.ID{})
	if len(list) != 2 || list[0].Epoch != 4 {
		t.Fatalf("fallback mails must be valid: %d %v", len(list), env.Warnings.Take())
	}
	// The next client creates an epoch with immediate begin and the supply.
	c := env.Reopen(u)
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if n, _ := env.Store.ReadNote(mbx); n != nil {
		t.Fatal("note must be removed after the new epoch")
	}
	e5, _, err := env.Store.ReadEpoch(mbx, 5)
	if err != nil || e5.Reason != store.ReasonRegular || e5.Begin != env.Clock.Now().Add(client.ImmediateDelay).UnixMilli() {
		t.Fatalf("immediate epoch %+v %v", e5, err)
	}
	m, _ := env.Store.ReadMailbox(mbx)
	if m.Epoch != 8 {
		t.Fatalf("head %d, want 8", m.Epoch)
	}
	// Within the delay the server still uses epoch 4; afterwards 5.
	deliverTo(t, in, "s@x", []string{"info@example.org"}, mailText("before", "3"))
	env.Clock.Advance(client.ImmediateDelay)
	deliverTo(t, in, "s@x", []string{"info@example.org"}, mailText("after", "4"))
	list, err = c.List(mbx, store.ID{})
	if err != nil || len(list) != 4 {
		t.Fatalf("%d mails %v %v", len(list), err, env.Warnings.Take())
	}
	if list[2].Epoch != 4 || list[3].Epoch != 5 {
		t.Fatalf("epochs %d %d", list[2].Epoch, list[3].Epoch)
	}
	// A second Sync in the same month changes nothing.
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if m, _ := env.Store.ReadMailbox(mbx); m.Epoch != 8 {
		t.Fatal("second sync must not add epochs")
	}
}
