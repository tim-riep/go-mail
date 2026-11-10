package client_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Review of task 27 package C: values cut before a run of invalid UTF-8
// shrank, mails with a mismatching envelope header, and how often Search
// opens a mail.

// serverTerms returns the term list the server wrote for mail id.
func serverTerms(t *testing.T, f *fixture, id store.ID) []string {
	t.Helper()
	files, err := f.env.Store.ListPending(f.mbx, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		p, err := f.u.Client.OpenPending(f.mbx, 1, file)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range p.Entries {
			if e.MailID == id && !e.Unprocessed {
				return e.Terms
			}
		}
	}
	t.Fatal("no term list of the server")
	return nil
}

// TestUnprocessedInvalidRunCut: a To value that store.CleanText cuts at
// 4*store.MaxTextLen+16 raw bytes, before the addresses, and then shrinks
// to one U+FFFD (encoded words of invalid UTF-8): the metadata keep a
// value of 3 bytes, metaCut takes it as cut, and the client takes from:
// and to: from the mail, the server's terms, in Search over the marker
// as well.
func TestUnprocessedInvalidRunCut(t *testing.T) {
	word := "=?utf-8?b?" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\xff", 45))) + "?="
	to := strings.Repeat(word+"\r\n ", 400) + "<j@x.example>, k@y.example"
	msg := "From: s@x.example\r\nTo: " + to + "\r\nSubject: invalid\r\nMessage-ID: <invalid@x.example>\r\n\r\nbody\r\n"
	f := newFixture(t)
	f.send(t, envFrom, msg)
	c := f.u.Client
	m := mailBySubject(t, f, "invalid")
	if m.Meta.To != "�" || !client.MetaCut(m.Meta) {
		t.Fatalf("metadata To %q, cut %v", m.Meta.To, client.MetaCut(m.Meta))
	}
	for _, q := range []string{"to:j@x.example", "to:k@y.example"} {
		if got := search(t, c, f.mbx, q, ""); got != "invalid" {
			t.Fatalf("%s over the marker: %q", q, got)
		}
	}
	f.flush(t)
	srv := serverTerms(t, f, m.ID)
	if !slices.Contains(srv, "to:k@y.example") {
		t.Fatalf("server %q: the case tests nothing", srv)
	}
	got, err := c.UnprocessedTerms(f.mbx, m.ID)
	if err != nil || !reflect.DeepEqual(got, srv) {
		t.Fatalf("client %q, server %q, %v", got, srv, err)
	}
	if meta := client.MetaTerms(m.Meta); slices.Contains(meta, "to:k@y.example") {
		t.Fatalf("metadata %q: the case tests nothing", meta)
	}
	if w := f.env.Warnings.Take(); len(w) != 0 {
		t.Fatalf("warnings %q", w)
	}
}

// checkFailsVerdict forges a mail marked unprocessed, its envelope changed
// by change and its bytes by raw (each if not nil), whose signed metadata
// carry its hash, and checks that a failed check on its bytes is a
// verdict: Search takes the terms of the metadata, Index indexes the
// entry with them and deletes the marker, each with one warning with the
// fixed cause.
func checkFailsVerdict(t *testing.T, change func(h *envelope.Header, r *envelope.Recipient), raw func([]byte) []byte, cause string) {
	t.Helper()
	f := newFixture(t)
	content := "From: s@x.example\r\nTo: " + longList(140) + "\r\n\r\nbody\r\n"
	id := f.forgeParsedRaw(t, content, longList(140), change, raw)
	c := f.u.Client
	want := "WARNUNG: Suchbegriffe der Mail " + id.String() + " nur aus ihren Metadaten: " + cause + "."
	if got := search(t, c, f.mbx, "to:addr139@recipients.example", ""); got != "" {
		t.Fatalf("term from a mail that fails a check: %q", got)
	}
	if w := f.env.Warnings.Take(); len(w) != 1 || w[0] != want {
		t.Fatalf("search: warnings %q", w)
	}
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if w := f.env.Warnings.Take(); len(w) != 1 || w[0] != want {
		t.Fatalf("index: warnings %q", w)
	}
	if pendingCount(t, f.env, f.mbx, 1) != 0 {
		t.Fatal("marker left")
	}
	if got := search(t, c, f.mbx, "to:addr139@recipients.example", ""); got != "" {
		t.Fatalf("term from a mail that fails a check, after index: %q", got)
	}
	if got := search(t, c, f.mbx, "to:addr000@recipients.example", ""); got != "forged" {
		t.Fatalf("metadata term: %q", got)
	}
}

// TestUnprocessedMailHeaderMismatch: a mail whose envelope header names
// another file ID or mailbox than its metadata is not used for terms,
// although the signed metadata carry its hash (only a holder of the
// ingest key can make one): the terms of the metadata, with a warning,
// before and after Index.
func TestUnprocessedMailHeaderMismatch(t *testing.T) {
	other, _ := store.NewID(nil)
	for name, change := range map[string]func(h *envelope.Header, r *envelope.Recipient){
		"file ID": func(h *envelope.Header, _ *envelope.Recipient) { h.FileID = other },
		"mailbox": func(h *envelope.Header, _ *envelope.Recipient) { h.MailboxID = other },
	} {
		t.Run(name, func(t *testing.T) {
			checkFailsVerdict(t, change, nil, "die Datei passt nicht zu ihrem Ort oder ihren Metadaten")
		})
	}
}

// TestUnprocessedMailNotDecryptable: a mail sealed for another key than
// the content key of its epoch, with the right header and the hash in its
// signed metadata, fails decryption: a verdict, as a failed hash or
// header check.
func TestUnprocessedMailNotDecryptable(t *testing.T) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checkFailsVerdict(t, func(_ *envelope.Header, r *envelope.Recipient) { r.PublicKey = k.PublicKey() }, nil, "Entschlüsselung fehlgeschlagen")
}

// TestUnprocessedMailEnvelopeBroken: garbage in place of the envelope of
// a mail, with its hash in the signed metadata (only a holder of the
// ingest key can make one), fails envelope.Parse: a verdict on bytes the
// signed hash fixes, as a failed hash or header check.
func TestUnprocessedMailEnvelopeBroken(t *testing.T) {
	garbage := func([]byte) []byte { return bytes.Repeat([]byte("garbage!"), 512) }
	checkFailsVerdict(t, nil, garbage, "Format ungültig")
}

// TestUnprocessedMailTooLarge: a regular mail file larger than
// store.MaxMailFile (sparse) is never a valid envelope (the limit is
// envelope.MaxFileSize), so it is a verdict, as a file with another hash:
// Search takes the terms of the metadata, the first Index indexes the
// entry with them and deletes the marker, each with one warning; a second
// Index warns no more. Read refuses the file with store.ErrTooLarge and no
// warning, as before task 27.
func TestUnprocessedMailTooLarge(t *testing.T) {
	f := newFixture(t)
	f.send(t, envFrom, msgLongTo)
	c := f.u.Client
	m := mailBySubject(t, f, "longto")
	if err := os.Truncate(f.env.Store.MailFile(f.mbx, f.inbox(t), m.ID), store.MaxMailFile+1); err != nil {
		t.Fatal(err)
	}
	want := "WARNUNG: Suchbegriffe der Mail " + m.ID.String() + " nur aus ihren Metadaten: Format ungültig."
	warnings := func(stage string, n int) {
		t.Helper()
		if w := f.env.Warnings.Take(); len(w) != n || n == 1 && w[0] != want {
			t.Fatalf("%s: warnings %q", stage, w)
		}
	}
	if got := search(t, c, f.mbx, "to:addr139@recipients.example", ""); got != "" {
		t.Fatalf("search: %q", got)
	}
	warnings("search", 1)
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	warnings("index", 1)
	if pendingCount(t, f.env, f.mbx, 1) != 0 {
		t.Fatal("marker left")
	}
	if n, err := c.Index(f.mbx); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	warnings("second index", 0)
	for _, tc := range []struct{ q, want string }{
		{"to:addr000@recipients.example", "longto"},
		{"to:addr139@recipients.example", ""},
	} {
		if got := search(t, c, f.mbx, tc.q, ""); got != tc.want {
			t.Fatalf("%s after index: %q, want %q", tc.q, got, tc.want)
		}
	}
	warnings("search after index", 0)
	if _, _, err := c.Read(f.mbx, m.ID); !errors.Is(err, store.ErrTooLarge) {
		t.Fatalf("read: %v", err)
	}
	warnings("read", 0)
}

// TestUnprocessedSearchOpens: Search opens a mail marked unprocessed whose
// metadata may be cut only for a from:, fromdomain: or to: term, once per
// call however many entries name it, and again in the next call; for any
// other term the metadata give the terms of the server and no mail is
// opened. A mail without a value that may be cut is never opened.
func TestUnprocessedSearchOpens(t *testing.T) {
	f := newFixture(t)
	f.send(t, envFrom, msgLongTo)
	f.send(t, envFrom, header("rechnung@lieferant.de", "short"))
	c := f.u.Client
	m := mailBySubject(t, f, "longto")
	e, _, err := f.env.Store.ReadEpoch(f.mbx, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		f.forgePendingFor(t, e, m.ID, testenv.Start.Add(time.Duration(i+2)*time.Second))
	}
	if pendingCount(t, f.env, f.mbx, 1) != 4 {
		t.Fatal("three markers for the mail and one for the short one expected")
	}
	opens := 0
	client.SetUnprocessedOpenHook(t, func(id store.ID) {
		if id != m.ID {
			t.Errorf("mail %s opened", id)
		}
		opens++
	})
	day := time.UnixMilli(m.Meta.Received).UTC()
	for _, tc := range []struct {
		q, want string
		opens   int
	}{
		{"day:" + day.Format("2006-01-02"), "longto,short", 0},
		{"month:" + day.Format("2006-01"), "longto,short", 0},
		{"thread:<longto@x.example>", "longto", 0},
		{"has:attachment", "", 0},
		{"from:s@x.example", "longto", 1},
		{"fromdomain:x.example", "longto", 1},
		{"from:rechnung@lieferant.de", "short", 1},
		{"to:addr139@recipients.example", "longto", 1},
		{"to:addr139@recipients.example", "longto", 1},
		{"to:nobody@nowhere.example", "", 1},
	} {
		opens = 0
		if got := search(t, c, f.mbx, tc.q, ""); got != tc.want {
			t.Fatalf("%s: %q, want %q", tc.q, got, tc.want)
		}
		if opens != tc.opens {
			t.Fatalf("%s: mail opened %d times, want %d", tc.q, opens, tc.opens)
		}
	}
	if w := f.env.Warnings.Take(); len(w) != 0 {
		t.Fatalf("warnings %q", w)
	}
}
