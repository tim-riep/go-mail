package ingest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Review finding B1: the server must not encrypt for an epoch that a
// registered non-member signed and appended to someone else's mailbox.
func TestServerRejectsForeignEpoch(t *testing.T) {
	env := testenv.New(t)
	alice := env.NewUser("alice")
	bob := env.NewUser("bob")
	mbx := env.Mailbox(alice, "A", "a@example.org")
	in := newIngest(t, env)
	e4, d4, _ := env.Store.ReadEpoch(mbx, 4)
	ks, _ := keys.OpenKeystore(mustRead(t, filepath.Join(bob.Dir, "keystore")), testenv.Passphrase)
	e5 := *e4
	e5.Number, e5.PrevHash, e5.Begin = 5, store.EpochHash(d4), e4.Begin+1
	e5.Members = []store.Member{{Kind: store.MemberUser, ID: bob.ID, Gen: 1}}
	e5.SignerID, e5.SignerGen = bob.ID, 1
	e5.ContentPub = ks.Unwrap.PublicKey()
	if err := e5.Sign(ks.Identity); err != nil {
		t.Fatal(err)
	}
	ks.Zero()
	if _, err := env.Store.WriteEpoch(&e5); err != nil {
		t.Fatal(err)
	}
	m, _ := env.Store.ReadMailbox(mbx)
	m.Epoch = 5
	env.Store.WriteMailbox(m)
	env.Clock.Set(time.UnixMilli(e5.Begin).Add(time.Hour))
	if _, err := in.Begin(smtpd.Session{}, "s", []string{"a@example.org"}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatalf("forged epoch used: %v", err)
	}
	// Epoch 2 of the chain replaced by a foreign one: also refused.
	m.Epoch = 4
	env.Store.WriteMailbox(m)
	os.WriteFile(env.Store.EpochFile(mbx, 2), mustRead(t, env.Store.EpochFile(mbx, 3)), 0o600)
	if _, err := in.Begin(smtpd.Session{}, "s", []string{"a@example.org"}); !errors.Is(err, smtpd.ErrTemporary) {
		t.Fatal("broken chain used")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Review finding B3: without a locked ephemeral key nothing is spilled.
func TestNoSpillWithoutMlock(t *testing.T) {
	old := mlockFn
	mlockFn = func([]byte) error { return errors.New("no mlock") }
	defer func() { mlockFn = old }()
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	in := newIngest(t, env, func(c *Config) { c.QueueMemory = 1 })
	deliver(t, in, "s", []string{"a@example.org"}, message("x", "y"))
	if f := files(t, env.Store.WorkDir()); len(f) != 0 {
		t.Fatalf("spilled without mlock: %v", f)
	}
	in.Flush()
	ids, _ := env.Store.ListPending(mbx, 1)
	list, _ := u.Client.List(mbx, store.ID{})
	if len(ids) != 1 || ids[0] != list[0].ID {
		t.Fatal("the mail must keep its marker")
	}
}

// Review remark C3: the envelope recipient gives a to: term (Bcc), and
// the envelope sender stands in for an unparsable From.
func TestEnvelopeTerms(t *testing.T) {
	terms, ok := Terms([]byte("From: undisclosed\r\nTo: other@x.example\r\n\r\n"), testenv.Start, "Sender@S.example", []string{"a@example.org"})
	got := strings.Join(terms, " ")
	if !ok || !strings.Contains(got, "to:a@example.org") || !strings.Contains(got, "from:sender@s.example") || !strings.Contains(got, "to:other@x.example") {
		t.Fatalf("terms %q", got)
	}
}

// Review remark C4: temporary files anywhere in the data directory are
// removed at start.
func TestRecoverRemovesTemporaryFiles(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	tmp := filepath.Join(env.Store.MailboxDir(mbx), ".tmp-0123")
	os.WriteFile(tmp, []byte("x"), 0o600)
	newIngest(t, env)
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("temporary file kept")
	}
}

// Review remark C12: open term lists count against the memory bound.
func TestBatchesCountAgainstMemory(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	mbx := env.Mailbox(u, "A", "a@example.org")
	in := newIngest(t, env, func(c *Config) { c.QueueMemory = 50; c.BatchAge = time.Hour; c.WorkLimit = 1 << 20 })
	deliver(t, in, "s", []string{"a@example.org"}, message("x", "y"))
	in.queue.processJobs()
	ids, _ := env.Store.ListPending(mbx, 1)
	list, _ := u.Client.List(mbx, store.ID{})
	if len(ids) != 1 || ids[0] == list[0].ID {
		t.Fatal("the term list must be written once memory is exceeded")
	}
}
