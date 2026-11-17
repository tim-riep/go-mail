package client_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Task 28, package 28C (Nr. 103, 106 of the list after M1).

// swapLog puts a directory in place of each file of *paths since the
// listing of the mail files: on the first address check after armed is
// set it renames each file away and makes a directory under its name
// (store.ErrNotRegular when the mail is read).
type swapLog struct {
	translog.Log
	paths *[]string
	armed *bool
	fail  func(error)
}

func (l *swapLog) CheckAddress(address string, mailbox store.ID, at int64) error {
	if *l.armed {
		*l.armed = false
		for _, p := range *l.paths {
			if err := os.Rename(p, p+".away"); err != nil {
				l.fail(err)
			}
			if err := os.Mkdir(p, 0o700); err != nil {
				l.fail(err)
			}
		}
	}
	return l.Log.CheckAddress(address, mailbox, at)
}

// TestUnprocessedUnreadableTogether: one call of Search or Index warns
// about each mail marked unprocessed that it cannot read, once per mail,
// up to unreadableTogether-1 (9) mails; from 10 on it warns once, with
// their number, the fixed cause and the first five mail IDs, and with
// nothing else (task 28, Nr. 103). A verdict on the bytes of a mail is
// warned about per mail all the same. Two markers of one mail count it
// once. The markers of the mails that cannot be read stay; once they can
// be read, Index takes their terms without a warning.
func TestUnprocessedUnreadableTogether(t *testing.T) {
	f := newFixture(t)
	msg := func(subject string) string {
		return "From: s@x.example\r\nTo: " + longList(140) + "\r\nSubject: " + subject + "\r\nMessage-ID: <" + subject + "@x.example>\r\n\r\nbody\r\n"
	}
	const n = 10
	for i := 0; i < n; i++ {
		f.send(t, envFrom, msg(fmt.Sprintf("u%02d", i)))
	}
	f.send(t, envFrom, msg("verdict"))
	inbox := f.inbox(t)
	var ids []store.ID
	var paths []string
	var verdict store.ID
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err != nil || len(list) != n+1 {
		t.Fatal(len(list), err)
	}
	for _, m := range list {
		if !client.MetaCut(m.Meta) {
			t.Fatal("not cut")
		}
		if m.Meta.Subject == "verdict" {
			verdict = m.ID
			continue
		}
		ids = append(ids, m.ID)
		paths = append(paths, f.env.Store.MailFile(f.mbx, inbox, m.ID))
	}
	// The mail "verdict" fails its hash: a verdict, warned about per mail.
	vpath := f.env.Store.MailFile(f.mbx, inbox, verdict)
	b, err := os.ReadFile(vpath)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err := store.WriteFileAtomic(vpath, b); err != nil {
		t.Fatal(err)
	}
	verdictWarning := "WARNUNG: Suchbegriffe der Mail " + verdict.String() + " nur aus ihren Metadaten: die Mail passt nicht zu ihren Metadaten."
	// A second marker for the first mail: counted once.
	e, _, err := f.env.Store.ReadEpoch(f.mbx, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.forgePendingFor(t, e, ids[0], testenv.Start.Add(2*time.Second))
	f.u.Client.Close()
	armed := false
	var swapped []string
	client.SetLogHook(t, func(l translog.Log) translog.Log {
		return &swapLog{Log: l, paths: &swapped, armed: &armed, fail: func(err error) { t.Error(err) }}
	})
	c, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	restore := func() {
		t.Helper()
		if armed {
			t.Fatal("the mail files were not replaced since the listing")
		}
		for _, p := range swapped {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(p+".away", p); err != nil {
				t.Fatal(err)
			}
		}
	}
	single := func(id store.ID) string {
		return "WARNUNG: Mail " + id.String() + " lässt sich nicht lesen: Datei nicht lesbar. " +
			"Ihr Eintrag in pending/ bleibt für einen späteren Index-Lauf liegen; bis dahin gelten die Suchbegriffe ihrer Metadaten."
	}
	together := regexp.MustCompile(`^WARNUNG: (\d+) Mails lassen sich nicht lesen \(Datei nicht lesbar\); die ersten: ([a-z2-7, ]+)\. ` +
		`Ihre Einträge in pending/ bleiben für einen späteren Index-Lauf liegen; bis dahin gelten die Suchbegriffe ihrer Metadaten\.$`)
	// checkTogether checks that w is the one warning for count mails
	// that cannot be read, naming five distinct of unread.
	checkTogether := func(stage, w string, count int, unread []store.ID) {
		t.Helper()
		m := together.FindStringSubmatch(w)
		if m == nil || m[1] != fmt.Sprint(count) {
			t.Fatalf("%s: warning %q, want one for %d mails", stage, w, count)
		}
		named := strings.Split(m[2], ", ")
		seen := map[string]bool{}
		for _, s := range named {
			if seen[s] || !slices.ContainsFunc(unread, func(id store.ID) bool { return id.String() == s }) {
				t.Fatalf("%s: %q named", stage, s)
			}
			seen[s] = true
		}
		if len(named) != 5 {
			t.Fatalf("%s: %d IDs named, want 5", stage, len(named))
		}
	}
	// Nine mails that cannot be read: a warning for each, and the verdict.
	swapped, armed = paths[:n-1], true
	if got := search(t, c, f.mbx, "to:addr000@recipients.example", ""); strings.Count(got, ",") != n {
		t.Fatalf("search, nine: %q", got)
	}
	restore()
	want := []string{verdictWarning}
	for _, id := range ids[:n-1] {
		want = append(want, single(id))
	}
	w := f.env.Warnings.Take()
	slices.Sort(w)
	slices.Sort(want)
	if !slices.Equal(w, want) {
		t.Fatalf("search, nine: warnings %q, want %q", w, want)
	}
	// Ten: one warning for all of them, and the verdict.
	swapped, armed = paths, true
	if got := search(t, c, f.mbx, "to:addr000@recipients.example", ""); strings.Count(got, ",") != n {
		t.Fatalf("search, ten: %q", got)
	}
	restore()
	w = f.env.Warnings.Take()
	if len(w) != 2 || w[0] != verdictWarning {
		t.Fatalf("search, ten: warnings %q", w)
	}
	checkTogether("search, ten", w[1], n, ids)
	// Index: the verdict is indexed, the ten markers (eleven files) stay.
	armed = true
	if got, err := c.Index(f.mbx); err != nil || got != 1 {
		t.Fatal(got, err)
	}
	restore()
	w = f.env.Warnings.Take()
	if len(w) != 2 || w[0] != verdictWarning {
		t.Fatalf("index: warnings %q", w)
	}
	checkTogether("index", w[1], n, ids)
	if pendingCount(t, f.env, f.mbx, 1) != n+1 {
		t.Fatal("markers of mails that cannot be read must stay")
	}
	// A second run: the one warning only.
	armed = true
	if got, err := c.Index(f.mbx); err != nil || got != 0 {
		t.Fatal(got, err)
	}
	restore()
	w = f.env.Warnings.Take()
	if len(w) != 1 {
		t.Fatalf("index 2: warnings %q", w)
	}
	checkTogether("index 2", w[0], n, ids)
	// Readable again: every entry indexed with the terms of its mail.
	if got, err := c.Index(f.mbx); err != nil || got != n+1 {
		t.Fatal(got, err)
	}
	if pendingCount(t, f.env, f.mbx, 1) != 0 {
		t.Fatal("markers left")
	}
	if got := search(t, c, f.mbx, "to:addr139@recipients.example", ""); strings.Count(got, ",") != n-1 || strings.Contains(got, "verdict") {
		t.Fatalf("after the mails could be read: %q", got)
	}
	if w := f.env.Warnings.Take(); len(w) != 0 {
		t.Fatalf("end: warnings %q", w)
	}
}

// trailerElement returns a signature trailer element, taken from an
// envelope sealed and signed for that purpose: appended to a sealed mail
// it is a valid trailer after the last block, which envelope.Parse
// accepts on a file of any kind.
func trailerElement(t *testing.T) []byte {
	t.Helper()
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := store.NewID(nil)
	h := envelope.Header{Kind: envelope.KindMail, MailboxID: id, Epoch: 1, FileID: id, Created: 1}
	r := []envelope.Recipient{{Type: envelope.RecipientEpochContent, ID: id, Gen: 1, PublicKey: k.PublicKey()}}
	plain, err := envelope.Seal(h, r, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := envelope.Seal(h, r, []byte("x"), &envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerIngest, Gen: 1, Key: sk}})
	if err != nil {
		t.Fatal(err)
	}
	return signed[len(plain):]
}

// TestMailWithTrailer: a mail file with a signature trailer, whose hash
// the signed metadata carry (only a holder of the ingest key can make
// one), is not a mail (a mail is unsigned, openMail checks f.Trailer):
// envelope.Parse accepts it, so the check in openMail is the only one.
// Read refuses it with ErrMismatch and the warning of a header that does
// not match (as in TestMailHeaderChecks, "signed mail"); for an entry
// marked unprocessed it is a verdict (task 28, Nr. 106).
func TestMailWithTrailer(t *testing.T) {
	f := newFixture(t)
	content := "From: s@x.example\r\nTo: " + longList(140) + "\r\n\r\nbody\r\n"
	tr := trailerElement(t)
	withTrailer := func(b []byte) []byte { return append(slices.Clip(b), tr...) }
	id := f.forgeParsedRaw(t, content, longList(140), nil, withTrailer)
	data, err := os.ReadFile(f.env.Store.MailFile(f.mbx, f.inbox(t), id))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := envelope.Parse(data); err != nil || p.Trailer == nil {
		t.Fatalf("the mail file must parse with a trailer: %v", err)
	}
	f.env.Warnings.Take()
	if _, content, err := f.u.Client.Read(f.mbx, id); !errors.Is(err, client.ErrMismatch) || content != nil {
		t.Fatalf("read: %v, %d bytes", err, len(content))
	}
	if w := f.env.Warnings.Take(); len(w) != 1 || w[0] != "WARNUNG: Kopf der Mail "+id.String()+" passt nicht zu den Metadaten." {
		t.Fatalf("read: warnings %q", w)
	}
	checkFailsVerdict(t, nil, withTrailer, "die Datei passt nicht zu ihrem Ort oder ihren Metadaten")
}

// TestUnprocessedUnreadableMany: with more than ten mails that cannot be
// read, the one warning of a call of Search or Index gives their number,
// not that of the IDs it keeps, and names the first five in the order
// the call met them (review 28C, F6: mutants MH and MB). Search warns
// also when it returns early with an error after it met them (mutant
// MA): here the pending directory of the next epoch cannot be listed.
func TestUnprocessedUnreadableMany(t *testing.T) {
	f := newFixture(t)
	const n = 12
	for i := 0; i < n; i++ {
		f.send(t, envFrom, "From: s@x.example\r\nTo: "+longList(140)+"\r\nSubject: "+fmt.Sprintf("u%02d", i)+"\r\n\r\nbody\r\n")
	}
	inbox := f.inbox(t)
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err != nil || len(list) != n {
		t.Fatal(len(list), err)
	}
	var paths []string
	for _, m := range list {
		if !client.MetaCut(m.Meta) {
			t.Fatal("not cut")
		}
		paths = append(paths, f.env.Store.MailFile(f.mbx, inbox, m.ID))
	}
	if _, _, err := f.env.Store.ReadEpoch(f.mbx, 2); err != nil {
		t.Fatalf("a second epoch is needed: %v", err)
	}
	f.u.Client.Close()
	armed := false
	client.SetLogHook(t, func(l translog.Log) translog.Log {
		return &swapLog{Log: l, paths: &paths, armed: &armed, fail: func(err error) { t.Error(err) }}
	})
	var met []store.ID
	client.SetUnprocessedOpenHook(t, func(id store.ID) { met = append(met, id) })
	c, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	restore := func() {
		t.Helper()
		if armed {
			t.Fatal("the mail files were not replaced since the listing")
		}
		for _, p := range paths {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(p+".away", p); err != nil {
				t.Fatal(err)
			}
		}
	}
	// check checks that the warnings are the one for the n mails met,
	// naming the first five met, in that order.
	check := func(stage string) {
		t.Helper()
		if len(met) != n {
			t.Fatalf("%s: %d mails opened, want %d", stage, len(met), n)
		}
		var first []string
		for _, id := range met[:5] {
			first = append(first, id.String())
		}
		want := fmt.Sprintf("WARNUNG: %d Mails lassen sich nicht lesen (Datei nicht lesbar); die ersten: %s. "+
			"Ihre Einträge in pending/ bleiben für einen späteren Index-Lauf liegen; bis dahin gelten die Suchbegriffe ihrer Metadaten.",
			n, strings.Join(first, ", "))
		if w := f.env.Warnings.Take(); len(w) != 1 || w[0] != want {
			t.Fatalf("%s: warnings %q, want %q", stage, w, want)
		}
		met = nil
	}
	f.env.Warnings.Take()
	armed = true
	if got := search(t, c, f.mbx, "to:addr000@recipients.example", ""); strings.Count(got, ",") != n-1 {
		t.Fatalf("search: %q", got)
	}
	restore()
	check("search")
	armed = true
	if got, err := c.Index(f.mbx); err != nil || got != 0 {
		t.Fatal(got, err)
	}
	restore()
	check("index")
	// Search returns early: pending/ of epoch 2, listed after the
	// entries of epoch 1, is a file.
	p2 := f.env.Store.PendingDir(f.mbx, 2)
	if err := os.MkdirAll(filepath.Dir(p2), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	armed = true
	if got, err := c.Search(f.mbx, "to:addr000@recipients.example", client.SearchOptions{}); err == nil || got != nil {
		t.Fatalf("search with pending/ of epoch 2 a file: %d mails, %v", len(got), err)
	}
	restore()
	check("search, early return")
	if err := os.Remove(p2); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Index(f.mbx); err != nil || got != n {
		t.Fatal(got, err)
	}
	if w := f.env.Warnings.Take(); len(w) != 0 {
		t.Fatalf("end: warnings %q", w)
	}
}
