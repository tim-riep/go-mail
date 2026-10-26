package ingest

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

func newIngest(t *testing.T, env *testenv.Env, mod ...func(*Config)) *Ingest {
	t.Helper()
	cfg := Config{Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1, Now: env.Clock.Now,
		DiskSpace: func(string) (uint64, uint64, error) { return 50, 100, nil }}
	for _, m := range mod {
		m(&cfg)
	}
	in, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Recover(); err != nil {
		t.Fatal(err)
	}
	return in
}

// deliver runs one delivery through the backend interface.
func deliver(t *testing.T, in *Ingest, from string, rcpts []string, msg string) error {
	t.Helper()
	d, err := in.Begin(smtpd.Session{ID: "test", Helo: "client.test", RemoteIP: "127.0.0.1"}, from, rcpts)
	if err != nil {
		return err
	}
	if _, err := d.Write([]byte("Received: from test\r\n")); err != nil {
		d.Abort()
		return err
	}
	for _, line := range strings.SplitAfter(msg, "\r\n") {
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

func message(subject, body string) string {
	return "From: Sender <sender@example.net>\r\nTo: Info <info@example.org>\r\nSubject: " + subject +
		"\r\nMessage-ID: <m1@example.net>\r\nDate: Mon, 26 Oct 2026 10:00:00 +0000\r\n\r\n" + body + "\r\n"
}

func received(m string) []byte { return []byte("Received: from test\r\n" + m) }

var _ = bytes.Equal
var _ = time.Second
var _ store.ID
