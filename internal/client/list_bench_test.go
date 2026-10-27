package client_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// forgeMails writes n valid mails with ingest-signed metadata into the
// inbox of mbx (epoch 1) directly, for measurements.
func forgeMails(tb testing.TB, env *testenv.Env, mbx store.ID, n int) {
	tb.Helper()
	e, _, err := env.Store.ReadEpoch(mbx, 1)
	if err != nil {
		tb.Fatal(err)
	}
	m, err := env.Store.ReadMailbox(mbx)
	if err != nil {
		tb.Fatal(err)
	}
	inbox := m.Inbox
	if err := store.MkdirAll(env.Store.MailDir(mbx, inbox)); err != nil {
		tb.Fatal(err)
	}
	for i := 0; i < n; i++ {
		id, _ := store.NewID(nil)
		ms := testenv.Start.Add(time.Duration(i) * time.Millisecond).UnixMilli()
		mail, err := envelope.Seal(envelope.Header{Kind: envelope.KindMail, MailboxID: mbx, Epoch: 1, FileID: id, Created: ms},
			[]envelope.Recipient{{Type: envelope.RecipientEpochContent, ID: mbx, Gen: 1, PublicKey: e.ContentPub}}, []byte("x"), nil)
		if err != nil {
			tb.Fatal(err)
		}
		meta := &store.MailMeta{Version: 1, MailID: id, Received: ms, MailHash: sha256.Sum256(mail), Size: 1, Folder: inbox,
			Recipients: []string{"a@example.org"}, From: "s@x.example", HeadersParsed: true}
		plain, _ := meta.Encode()
		extra, _ := meta.SignedExtra(mbx, 1)
		sealed, err := envelope.Seal(envelope.Header{Kind: envelope.KindMeta, MailboxID: mbx, Epoch: 1, FileID: id, Created: ms, Version: 1},
			[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: mbx, Gen: 1, PublicKey: e.MetaPub}}, plain,
			&envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerIngest, Gen: 1, Key: env.IngestKey, Extra: extra}})
		if err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(env.Store.MetaFile(mbx, inbox, id), sealed, 0o640); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(env.Store.MailFile(mbx, inbox, id), mail, 0o640); err != nil {
			tb.Fatal(err)
		}
	}
}

// BenchmarkListFirst measures the first List of a mailbox with n mails
// never seen before (task 09, addendum): every mail is a new version for
// the local state. The metric ms/mail is the time of one List divided by
// the number of mails.
func BenchmarkListFirst(b *testing.B) {
	for _, n := range []int{500, 2000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			env := testenv.New(b)
			u := env.NewUser("alice")
			mbx := env.Mailbox(u, "A", "a@example.org")
			forgeMails(b, env, mbx, n)
			statePath := filepath.Join(u.Dir, "state.json")
			clean, err := os.ReadFile(statePath)
			if err != nil {
				b.Fatal(err)
			}
			var total time.Duration
			for i := 0; i < b.N; i++ {
				u.Client.Close()
				if err := os.WriteFile(statePath, clean, 0o600); err != nil {
					b.Fatal(err)
				}
				c := env.Reopen(u)
				start := time.Now()
				list, err := c.List(mbx, store.ID{})
				total += time.Since(start)
				if err != nil || len(list) != n {
					b.Fatalf("listed %d: %v", len(list), err)
				}
			}
			b.ReportMetric(float64(total.Nanoseconds())/float64(b.N)/float64(n)/1e6, "ms/mail")
		})
	}
}
