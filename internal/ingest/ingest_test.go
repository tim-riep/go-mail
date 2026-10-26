package ingest

import (
	"bytes"
	"testing"

	"github.com/tim-riep/go-mail/internal/testenv"
)

func TestDeliverAndRead(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "Büro", "info@example.org")
	in := newIngest(t, env)
	msg := message("Grüße", "Hallo Welt")
	if err := deliver(t, in, "sender@example.net", []string{"info@example.org"}, msg); err != nil {
		t.Fatal(err)
	}
	mails, err := u.Client.List(mbx, [16]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(mails) != 1 {
		t.Fatalf("%d mails, warnings %v", len(mails), env.Warnings.Take())
	}
	m, content, err := u.Client.Read(mbx, mails[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, received(msg)) {
		t.Fatalf("content %q", content)
	}
	if m.Meta.Subject != "Grüße" || m.Meta.From != "Sender <sender@example.net>" {
		t.Fatalf("meta %+v", m.Meta)
	}
	if name, err := u.Client.MailboxName(mbx); err != nil || name != "Büro" {
		t.Fatal(name, err)
	}
}
