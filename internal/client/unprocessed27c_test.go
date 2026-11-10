package client_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Task 27 (Nr. 47, AUDIT R27 (b)): for a mail marked unprocessed whose
// metadata may hold a cut From, To or Cc value, the client reads from:
// and to: from the header of the mail itself.

// longList returns n addresses addrNNN@recipients.example with display
// names, folded as a mail client folds a long address list.
func longList(n int) string {
	var l []string
	for i := 0; i < n; i++ {
		l = append(l, fmt.Sprintf("Name %03d <addr%03d@recipients.example>", i, i))
	}
	return strings.Join(l, ",\r\n ")
}

// longName returns a quoted, folded display name of more than
// store.MaxTextLen bytes.
func longName() string {
	var lines []string
	for i := 0; i < 75; i++ {
		var w []string
		for j := 0; j < 8; j++ {
			w = append(w, fmt.Sprintf("Word%04d", i*8+j))
		}
		lines = append(lines, strings.Join(w, " "))
	}
	return `"` + strings.Join(lines, "\r\n ") + `"`
}

var (
	msgLongFrom = "From: " + longName() + " <Real.Sender@Long.example>\r\nTo: a@example.org\r\nSubject: longfrom\r\nMessage-ID: <longfrom@x.example>\r\n\r\nbody\r\n"
	msgLongTo   = "From: s@x.example\r\nTo: " + longList(140) + "\r\nSubject: longto\r\nMessage-ID: <longto@x.example>\r\n\r\nbody\r\n"
	msgLongCc   = "From: s@x.example\r\nTo: a@example.org\r\nCc: " + longList(140) + "\r\nSubject: longcc\r\nMessage-ID: <longcc@x.example>\r\n\r\nbody\r\n"
	msgReply    = "From: " + longName() + " <Real.Sender@Long.example>\r\nTo: a@example.org\r\nSubject: reply\r\nMessage-ID: <reply@x.example>\r\n" +
		"References: <root@x.example> <parent@x.example>\r\nIn-Reply-To: <parent@x.example>\r\n\r\nbody\r\n"
	msgBareTo = "From: s@x.example\r\nTo: " + bareList(150) + "\r\nSubject: bareto\r\nMessage-ID: <bareto@x.example>\r\n\r\nbody\r\n"
)

// bareList returns n addresses someoneNNN@domain-number-NNN.example
// without display names or angle brackets, folded. The metadata cut the
// value within address 107 to "someone107@domain-number-107.e", which
// parses as an address of its own.
func bareList(n int) string {
	var l []string
	for i := 0; i < n; i++ {
		l = append(l, fmt.Sprintf("someone%03d@domain-number-%03d.example", i, i))
	}
	return strings.Join(l, ",\r\n ")
}

const envFrom = "Envelope@Sender.example"

// mailBySubject returns the mail with subject of the inbox.
func mailBySubject(t *testing.T, f *fixture, subject string) *client.Mail {
	t.Helper()
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range list {
		if m.Meta.Subject == subject {
			return m
		}
	}
	t.Fatalf("mail %q not listed", subject)
	return nil
}

// TestUnprocessedTermsMatchServer: the terms the client derives for a
// mail marked unprocessed are the server's term list, also for a header
// whose From, To or Cc value the metadata cut, where the terms of the
// metadata alone differ: addresses beyond the cut are missing, and a bare
// address list cut within an address gives a to: term the server does
// not have. The thread root stays the own Message-ID (TODO(Q12)).
func TestUnprocessedTermsMatchServer(t *testing.T) {
	f := newFixture(t)
	msgs := []string{msgLongFrom, msgLongTo, msgLongCc, msgReply, msgBareTo, header("Rechnung@Lieferant.DE", "short")}
	for _, m := range msgs {
		f.send(t, envFrom, m)
	}
	f.flush(t)
	c := f.u.Client
	list, err := c.List(f.mbx, store.ID{})
	if err != nil || len(list) != len(msgs) {
		t.Fatal(len(list), err)
	}
	ids, _ := f.env.Store.ListPending(f.mbx, 1)
	if len(ids) != 1 {
		t.Fatal("one term list expected")
	}
	p, err := c.OpenPending(f.mbx, 1, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	server := map[store.ID][]string{}
	for _, e := range p.Entries {
		server[e.MailID] = e.Terms
	}
	for _, m := range list {
		subject := m.Meta.Subject
		srv := server[m.ID]
		got, err := c.UnprocessedTerms(f.mbx, m.ID)
		if err != nil {
			t.Fatalf("%s: %v", subject, err)
		}
		meta := client.MetaTerms(m.Meta)
		if subject == "short" {
			if client.MetaCut(m.Meta) || !reflect.DeepEqual(got, srv) || !reflect.DeepEqual(meta, srv) {
				t.Fatalf("short: client %q, metadata %q, server %q", got, meta, srv)
			}
			continue
		}
		if !client.MetaCut(m.Meta) {
			t.Fatalf("%s: metadata not taken as cut", subject)
		}
		if reflect.DeepEqual(meta, srv) {
			t.Fatalf("%s: the terms of the metadata are the server's already; the case tests nothing", subject)
		}
		// The term beyond the cut, independent of the server's rules.
		want := map[string]string{"longfrom": "from:real.sender@long.example", "reply": "from:real.sender@long.example",
			"longto": "to:addr139@recipients.example", "longcc": "to:addr139@recipients.example",
			"bareto": "to:someone149@domain-number-149.example"}[subject]
		if !slices.Contains(got, want) || slices.Contains(meta, want) {
			t.Fatalf("%s: %q beyond the cut: client %q, metadata %q", subject, want, got, meta)
		}
		if subject == "bareto" {
			// The address cut by the metadata is a term of their own,
			// not the server's nor the client's.
			const cut = "to:someone107@domain-number-107.e"
			if !slices.Contains(meta, cut) || slices.Contains(srv, cut) || slices.Contains(got, cut) {
				t.Fatalf("bareto: %q: client %q, metadata %q, server %q", cut, got, meta, srv)
			}
		}
		if subject == "reply" {
			// The server takes the root from References, the client the
			// own Message-ID (S23, Q12 open); everything else is equal.
			i := slices.Index(srv, "thread:<root@x.example>")
			if i < 0 || !slices.Contains(got, "thread:<reply@x.example>") {
				t.Fatalf("reply: client %q, server %q", got, srv)
			}
			srv = slices.Clone(srv)
			srv[i] = "thread:<reply@x.example>"
		}
		if !reflect.DeepEqual(got, srv) {
			t.Fatalf("%s: client %q, server %q", subject, got, srv)
		}
	}
	if w := f.env.Warnings.Take(); len(w) != 0 {
		t.Fatalf("warnings %q", w)
	}
}

// TestUnprocessedLongHeaderSearch: Search over pending/ and Index find a
// mail marked unprocessed under the from: and to: terms of the server,
// beyond the cut of the metadata, and the envelope sender does not stand
// in for a From whose address the metadata cut.
func TestUnprocessedLongHeaderSearch(t *testing.T) {
	f := newFixture(t)
	f.send(t, envFrom, msgLongFrom)
	f.send(t, envFrom, msgLongTo)
	if pendingCount(t, f.env, f.mbx, 1) != 2 {
		t.Fatal("two markers expected")
	}
	c := f.u.Client
	check := func(stage string) {
		t.Helper()
		for _, tc := range []struct{ q, want string }{
			{"from:real.sender@long.example", "longfrom"},
			{"fromdomain:long.example", "longfrom"},
			{"from:envelope@sender.example", ""},
			{"to:addr000@recipients.example", "longto"},
			{"to:addr139@recipients.example", "longto"},
		} {
			if got := search(t, c, f.mbx, tc.q, ""); got != tc.want {
				t.Fatalf("%s: %s: %q, want %q", stage, tc.q, got, tc.want)
			}
		}
	}
	check("pending")
	n, err := c.Index(f.mbx)
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if pendingCount(t, f.env, f.mbx, 1) != 0 || segmentCount(t, f.env, f.mbx, 1) != 1 {
		t.Fatal("index state")
	}
	check("index")
	if w := f.env.Warnings.Take(); len(w) != 0 {
		t.Fatalf("warnings %q", w)
	}
}

// vanishLog renames the mail file at path away on the first address
// check after armed is set: between the listing of the mail files and
// the reading of the mail, as when the mail file is not there yet. With
// then, it calls then(path) after the rename, to put something else in
// its place.
type vanishLog struct {
	translog.Log
	path  string
	armed *bool
	then  func(path string)
}

func (l *vanishLog) CheckAddress(address string, mailbox store.ID, at int64) error {
	if *l.armed {
		*l.armed = false
		os.Rename(l.path, l.path+".away")
		if l.then != nil {
			l.then(l.path)
		}
	}
	return l.Log.CheckAddress(address, mailbox, at)
}

// TestUnprocessedMailNotThereYet: a mail file that is not there (the
// server moves it into the mailbox after the metadata) leaves the marker
// for a later Index, also if it goes between the listing and the reading
// of the mail; Search takes the terms of the metadata meanwhile.
func TestUnprocessedMailNotThereYet(t *testing.T) {
	f := newFixture(t)
	f.send(t, envFrom, msgLongTo)
	m := mailBySubject(t, f, "longto")
	path := f.env.Store.MailFile(f.mbx, f.inbox(t), m.ID)
	f.u.Client.Close()
	armed := false
	client.SetLogHook(t, func(l translog.Log) translog.Log { return &vanishLog{Log: l, path: path, armed: &armed} })
	c, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	restore := func() {
		t.Helper()
		if err := os.Rename(path+".away", path); err != nil {
			t.Fatal(err)
		}
	}
	// Not there before the run: the mail is not listed, the marker stays
	// (as before).
	if err := os.Rename(path, path+".away"); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Index(f.mbx); err != nil || n != 0 || pendingCount(t, f.env, f.mbx, 1) != 1 {
		t.Fatal("before the run", n, err)
	}
	restore()
	// Gone between listing and reading: Search takes the terms of the
	// metadata, Index leaves the marker, nothing is warned.
	armed = true
	if got := search(t, c, f.mbx, "to:addr000@recipients.example", ""); got != "longto" || armed {
		t.Fatalf("metadata term: %q (hook fired: %v)", got, !armed)
	}
	restore()
	armed = true
	if got := search(t, c, f.mbx, "to:addr139@recipients.example", ""); got != "" || armed {
		t.Fatalf("term beyond the cut without the mail: %q", got)
	}
	restore()
	armed = true
	n, err := c.Index(f.mbx)
	if err != nil || n != 0 || armed {
		t.Fatal(n, err, armed)
	}
	if pendingCount(t, f.env, f.mbx, 1) != 1 || segmentCount(t, f.env, f.mbx, 1) != 0 {
		t.Fatal("the marker must stay until the mail is there")
	}
	if w := f.env.Warnings.Take(); len(w) != 0 {
		t.Fatalf("warnings %q", w)
	}
	restore()
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if pendingCount(t, f.env, f.mbx, 1) != 0 {
		t.Fatal("marker left")
	}
	if got := search(t, c, f.mbx, "to:addr139@recipients.example", ""); got != "longto" {
		t.Fatalf("after the mail arrived: %q", got)
	}
}

// TestUnprocessedMailSwapped: a mail file replaced by content anyone can
// encrypt for the content key of the epoch, with the right mail header,
// fails the hash of the signed metadata. Its header is not used; the mail
// is indexed with the terms of the metadata, with a warning.
func TestUnprocessedMailSwapped(t *testing.T) {
	f := newFixture(t)
	f.send(t, envFrom, msgLongTo)
	m := mailBySubject(t, f, "longto")
	e, _, err := f.env.Store.ReadEpoch(f.mbx, 1)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := envelope.Seal(envelope.Header{Kind: envelope.KindMail, MailboxID: f.mbx, Epoch: 1, FileID: m.ID, Created: m.Meta.Received},
		[]envelope.Recipient{{Type: envelope.RecipientEpochContent, ID: f.mbx, Gen: 1, PublicKey: e.ContentPub}},
		[]byte("From: evil@evil.example\r\nTo: x@evil.example\r\n\r\nbody\r\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, f.inbox(t), m.ID), forged); err != nil {
		t.Fatal(err)
	}
	c := f.u.Client
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	// One warning, with the mail ID and a fixed cause.
	if w := f.env.Warnings.Take(); len(w) != 1 || w[0] != "WARNUNG: Suchbegriffe der Mail "+m.ID.String()+" nur aus ihren Metadaten: die Mail passt nicht zu ihren Metadaten." {
		t.Fatalf("warnings %q", w)
	}
	for _, tc := range []struct{ q, want string }{
		{"from:evil@evil.example", ""},
		{"to:x@evil.example", ""},
		{"to:addr139@recipients.example", ""},
		{"from:s@x.example", "longto"},
		{"to:addr000@recipients.example", "longto"},
	} {
		if got := search(t, c, f.mbx, tc.q, ""); got != tc.want {
			t.Fatalf("%s: %q, want %q", tc.q, got, tc.want)
		}
	}
}

// forgeParsed writes a mail with content and metadata that say its header
// was evaluated with To to, signed by the ingest key, and a marker for
// it.
func (f *fixture) forgeParsed(t *testing.T, content, to string) store.ID {
	t.Helper()
	return f.forgeParsedHeader(t, content, to, nil)
}

// forgeParsedHeader is forgeParsed with the envelope header and the
// recipient of the mail changed by change, if not nil, before it is
// sealed; the signed metadata carry the hash of exactly that file (only a
// holder of the ingest key can do this).
func (f *fixture) forgeParsedHeader(t *testing.T, content, to string, change func(h *envelope.Header, r *envelope.Recipient)) store.ID {
	t.Helper()
	return f.forgeParsedRaw(t, content, to, change, nil)
}

// forgeParsedRaw is forgeParsedHeader with the bytes of the sealed mail
// changed by raw, if not nil; the signed metadata carry the hash of the
// changed bytes.
func (f *fixture) forgeParsedRaw(t *testing.T, content, to string, change func(h *envelope.Header, r *envelope.Recipient), raw func([]byte) []byte) store.ID {
	t.Helper()
	e, _, err := f.env.Store.ReadEpoch(f.mbx, 1)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := store.NewID(nil)
	inbox := f.inbox(t)
	received := testenv.Start.Add(time.Minute)
	ms := received.UnixMilli()
	h := envelope.Header{Kind: envelope.KindMail, MailboxID: f.mbx, Epoch: 1, FileID: id, Created: ms}
	r := envelope.Recipient{Type: envelope.RecipientEpochContent, ID: f.mbx, Gen: 1, PublicKey: e.ContentPub}
	if change != nil {
		change(&h, &r)
	}
	mail, err := envelope.Seal(h, []envelope.Recipient{r}, []byte(content), nil)
	if err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		mail = raw(mail)
	}
	m := &store.MailMeta{Version: 1, MailID: id, Received: ms, MailHash: sha256.Sum256(mail), Size: uint32(len(content)), Folder: inbox,
		EnvelopeFrom: "s@x.example", Recipients: []string{"a@example.org"}, HeadersParsed: true, From: "s@x.example",
		To: store.CleanText(to, store.MaxTextLen), Subject: "forged"}
	plain, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	extra, _ := m.SignedExtra(f.mbx, 1)
	meta, err := envelope.Seal(envelope.Header{Kind: envelope.KindMeta, MailboxID: f.mbx, Epoch: 1, FileID: id, Created: ms, Version: 1},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: f.mbx, Gen: 1, PublicKey: e.MetaPub}}, plain,
		&envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerIngest, Gen: 1, Key: f.env.IngestKey, Extra: extra}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MkdirAll(f.env.Store.MailDir(f.mbx, inbox)); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(f.env.Store.MetaFile(f.mbx, inbox, id), meta); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(f.env.Store.MailFile(f.mbx, inbox, id), mail); err != nil {
		t.Fatal(err)
	}
	f.forgePendingFor(t, e, id, received)
	return id
}

// TestUnprocessedHeaderNotEvaluable: metadata that say the header was
// evaluated, for a mail whose header the client cannot evaluate (no end
// of the header, or more than 500 fields): the terms of the metadata,
// with a warning.
func TestUnprocessedHeaderNotEvaluable(t *testing.T) {
	for name, content := range map[string]string{
		"no end":     "To: " + longList(140) + "\r\nX-Broken: no end of header\r\n",
		"501 fields": "To: " + longList(140) + "\r\n" + strings.Repeat("X-A: b\r\n", 500) + "\r\nbody\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.forgeParsed(t, content, longList(140))
			c := f.u.Client
			if n, err := c.Index(f.mbx); err != nil || n != 1 {
				t.Fatal(n, err)
			}
			if !warned(f.env, "nur aus ihren Metadaten: Kopf der Mail nicht auswertbar") {
				t.Fatal("no warning about the header")
			}
			if got := search(t, c, f.mbx, "to:addr000@recipients.example", ""); got != "forged" {
				t.Fatalf("metadata term: %q", got)
			}
			if got := search(t, c, f.mbx, "to:addr139@recipients.example", ""); got != "" {
				t.Fatalf("term from a header not evaluated: %q", got)
			}
		})
	}
}

// TestUnprocessedShortHeaderNotOpened: without a value that may be cut,
// the mail itself is not opened: a broken mail file changes nothing and
// warns nothing.
func TestUnprocessedShortHeaderNotOpened(t *testing.T) {
	f := newFixture(t)
	f.send(t, envFrom, header("rechnung@lieferant.de", "short"))
	m := mailBySubject(t, f, "short")
	path := f.env.Store.MailFile(f.mbx, f.inbox(t), m.ID)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := store.WriteFileAtomic(path, data); err != nil {
		t.Fatal(err)
	}
	c := f.u.Client
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if got := search(t, c, f.mbx, "from:rechnung@lieferant.de", ""); got != "short" {
		t.Fatalf("search: %q", got)
	}
	if w := f.env.Warnings.Take(); len(w) != 0 {
		t.Fatalf("warnings %q", w)
	}
}

// TestMetaCutBoundary: a value store.CleanText cuts at the end counts as
// cut, whatever the width of its characters, and so does one it cut
// first at 4*store.MaxTextLen+16 raw bytes and then shrank, a run of
// invalid UTF-8 becoming one U+FFFD; a value of store.MaxTextLen -
// utf8.UTFMax bytes without U+FFFD does not; nor does any value of a
// header the server did not evaluate, or the envelope sender.
func TestMetaCutBoundary(t *testing.T) {
	set := []func(m *store.MailMeta, v string){
		func(m *store.MailMeta, v string) { m.From = v },
		func(m *store.MailMeta, v string) { m.To = v },
		func(m *store.MailMeta, v string) { m.Cc = v },
	}
	for _, r := range []string{"a", "ä", "€", "𝄞", "é"} {
		v := store.CleanText(strings.Repeat(r, store.MaxTextLen), store.MaxTextLen)
		if len(v) > store.MaxTextLen || !utf8.ValidString(v) {
			t.Fatalf("%q: cut value of %d bytes", r, len(v))
		}
		for i, s := range set {
			m := &store.MailMeta{HeadersParsed: true}
			s(m, v)
			if !client.MetaCut(m) {
				t.Fatalf("%q field %d: %d bytes not taken as cut", r, i, len(v))
			}
			m.HeadersParsed = false
			if client.MetaCut(m) {
				t.Fatalf("%q field %d: cut without an evaluated header", r, i)
			}
		}
	}
	for i, s := range set {
		m := &store.MailMeta{HeadersParsed: true}
		s(m, strings.Repeat("a", store.MaxTextLen-utf8.UTFMax))
		if client.MetaCut(m) {
			t.Fatalf("field %d: short value taken as cut", i)
		}
		s(m, strings.Repeat("a", store.MaxTextLen-utf8.UTFMax+1))
		if !client.MetaCut(m) {
			t.Fatalf("field %d: value at the boundary not taken as cut", i)
		}
		// Cut first, then shrunk: the addresses after the invalid run
		// are gone, the value is short.
		v := store.CleanText(strings.Repeat("\xff", 4*store.MaxTextLen+16)+" <j@x.example>", store.MaxTextLen)
		if v != "�" {
			t.Fatalf("CleanText gave %q", v)
		}
		s(m, v)
		if !client.MetaCut(m) {
			t.Fatalf("field %d: value cut before the invalid run shrank not taken as cut", i)
		}
		s(m, "a�b <j@x.example>")
		if !client.MetaCut(m) {
			t.Fatalf("field %d: short value with U+FFFD not taken as cut", i)
		}
	}
	if client.MetaCut(&store.MailMeta{HeadersParsed: true, EnvelopeFrom: strings.Repeat("a", store.MaxAddressLen)}) {
		t.Fatal("envelope sender taken as cut")
	}
}
