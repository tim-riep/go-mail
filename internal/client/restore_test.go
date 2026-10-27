package client_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/shamir"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 06b C: keygen --shares, Restore and the input of words
// (S11).

// noShares is a Prompter that cannot show shares.
type noShares struct{ e testenv.Echo }

func (p *noShares) ShowWords(w []string) error      { return p.e.ShowWords(w) }
func (p *noShares) AskWord(pos int) (string, error) { return p.e.AskWord(pos) }

// sloppy answers like a person typing carelessly: upper case, full-width
// letters (NFKD maps them to ASCII) and white space around the word.
type sloppy struct{ testenv.Echo }

func (p *sloppy) AskWord(pos int) (string, error) {
	w, _ := p.Echo.AskWord(pos)
	if pos%2 == 0 {
		return " \t" + strings.ToUpper(w) + " \n", nil
	}
	return strings.Map(func(r rune) rune { return r - 'a' + 'Ａ' }, w) + " ", nil
}

// twoWords answers with two words.
type twoWords struct{ testenv.Echo }

func (p *twoWords) AskWord(pos int) (string, error) {
	w, _ := p.Echo.AskWord(pos)
	return w + " " + w, nil
}

// mess writes words as one line in upper case with irregular white space.
func mess(words []string) []string {
	return []string{"\n  " + strings.ToUpper(strings.Join(words, " \t ")) + "  "}
}

// noFiles fails if dir exists.
func noFiles(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("%s was created", dir)
	}
}

// TestWordInput: the confirmation of keygen and the words of device lost
// and Restore are normalized (NFKD, lower case, any white space), but a
// typo or a second word is never accepted (2.2 "Eingabe von Wörtern").
func TestWordInput(t *testing.T) {
	env := testenv.New(t)
	p := &sloppy{}
	if _, err := client.Keygen(env.ClientConfig(filepath.Join(env.Base, "s")), testenv.Passphrase, p); err != nil {
		t.Fatalf("sloppy but correct answers: %v", err)
	}
	if strings.ContainsFunc(strings.Join(p.Words(), ""), unicode.IsUpper) {
		t.Fatal("the shown words are not the list words")
	}
	dir := filepath.Join(env.Base, "two")
	if _, err := client.Keygen(env.ClientConfig(dir), testenv.Passphrase, &twoWords{}); !errors.Is(err, client.ErrConfirm) {
		t.Fatalf("two words: %v", err)
	}
	noFiles(t, filepath.Join(dir, "keystore"))
	alice := env.NewUser("alice")
	alice.Client.Close()
	gen, err := client.DeviceLost(env.ClientConfig(alice.Dir), testenv.Passphrase, mess(alice.Words))
	if err != nil || gen != 2 {
		t.Fatalf("device lost with sloppy words: %d, %v", gen, err)
	}
}

// TestKeygenSharesAndRestore: keygen --shares 2-of-3 shows three shares
// of 30 words and writes none of them; every combination of two shares
// restores the user in a new client directory (typed sloppily), which
// warns on every start that it has no confirmed state yet and reads the
// mailbox; the seed words restore it as well. Wrong shares, a share of
// another split or the shares of another seed fail without creating any
// file. A device lost works right after a restore.
func TestKeygenSharesAndRestore(t *testing.T) {
	env := testenv.New(t)
	dir := filepath.Join(env.Base, "clients", "alice")
	cfg := env.ClientConfig(dir)
	echo := &testenv.Echo{}
	opts := client.KeygenOptions{Shares: client.Shares{Threshold: 2, Count: 3}}
	for name, bad := range map[string]client.KeygenOptions{
		"1-of-3":   {Shares: client.Shares{Threshold: 1, Count: 3}},
		"3-of-2":   {Shares: client.Shares{Threshold: 3, Count: 2}},
		"2-of-256": {Shares: client.Shares{Threshold: 2, Count: 256}},
	} {
		if _, err := client.KeygenWithOptions(cfg, testenv.Passphrase, echo, bad); !errors.Is(err, client.ErrArgument) || !errors.Is(err, shamir.ErrParams) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := client.KeygenWithOptions(cfg, testenv.Passphrase, &noShares{}, opts); !errors.Is(err, client.ErrArgument) {
		t.Fatalf("prompter without shares: %v", err)
	}
	noFiles(t, dir)
	id, err := client.KeygenWithOptions(cfg, testenv.Passphrase, echo, opts)
	if err != nil {
		t.Fatal(err)
	}
	shares := echo.Shares()
	if len(shares) != 3 {
		t.Fatalf("%d shares", len(shares))
	}
	for i, s := range shares {
		if len(s) != shamir.ShareWords {
			t.Fatalf("share %d has %d words", i+1, len(s))
		}
	}
	// Neither the seed nor a share is in a file.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		data := string(mustRead(t, filepath.Join(dir, ent.Name())))
		for _, w := range append(shares, echo.Words()) {
			if strings.Contains(data, strings.Join(w[:4], " ")) || strings.Contains(data, strings.Join(w[:4], "")) {
				t.Fatalf("%s holds secret words", ent.Name())
			}
		}
	}
	code, err := env.Store.CreateInvite(env.Clock.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(cfg, code); err != nil {
		t.Fatal(err)
	}
	c, err := client.Open(cfg, testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	mbx, err := c.CreateMailbox("A")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	restore := func(name string, o client.RestoreOptions) *client.Client {
		t.Helper()
		rcfg := env.ClientConfig(filepath.Join(env.Base, "restore", name))
		env.Warnings.Take()
		rid, err := client.Restore(rcfg, o, testenv.Passphrase)
		if err != nil || rid != id {
			t.Fatalf("%s: restored %s, %v", name, rid, err)
		}
		if w := strings.Join(env.Warnings.Take(), "\n"); !strings.Contains(w, "Noch kein bestätigter Zustand") {
			t.Fatalf("%s: warnings: %s", name, w)
		}
		rc, err := client.Open(rcfg, testenv.Passphrase)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if w := strings.Join(env.Warnings.Take(), "\n"); !strings.Contains(w, "Noch kein bestätigter Zustand") {
			t.Fatalf("%s: no warning on start: %s", name, w)
		}
		if n, err := rc.MailboxName(mbx); err != nil || n != "A" {
			t.Fatalf("%s: mailbox: %q, %v", name, n, err)
		}
		return rc
	}
	for _, pair := range [][2]int{{0, 1}, {0, 2}, {1, 2}, {2, 0}} {
		name := string(rune('a'+pair[0])) + string(rune('a'+pair[1]))
		restore(name, client.RestoreOptions{Shares: [][]string{shares[pair[0]], mess(shares[pair[1]])}}).Close()
	}
	restore("all", client.RestoreOptions{Shares: shares}).Close()
	restore("words", client.RestoreOptions{Words: mess(echo.Words()), UserID: id}).Close()

	// Wrong input: an error and no file.
	other := &testenv.Echo{}
	if _, err := client.KeygenWithOptions(env.ClientConfig(filepath.Join(env.Base, "other")), testenv.Passphrase, other, opts); err != nil {
		t.Fatal(err)
	}
	foreign := other.Shares()
	typo := append([]string(nil), shares[1]...)
	typo[7] = typo[8]
	nobody, _ := store.NewID(nil)
	for name, c := range map[string]struct {
		opts client.RestoreOptions
		want error
	}{
		"one share":           {client.RestoreOptions{Shares: shares[:1]}, shamir.ErrInsufficient},
		"the same share":      {client.RestoreOptions{Shares: [][]string{shares[0], shares[0]}}, shamir.ErrDuplicate},
		"a typo":              {client.RestoreOptions{Shares: [][]string{shares[0], typo}}, shamir.ErrChecksum},
		"29 words":            {client.RestoreOptions{Shares: [][]string{shares[0], shares[1][1:]}}, shamir.ErrWordCount},
		"another seed":        {client.RestoreOptions{Shares: foreign[:2]}, client.ErrSeed},
		"another seed, words": {client.RestoreOptions{Words: other.Words()}, client.ErrSeed},
		"another user":        {client.RestoreOptions{Words: echo.Words(), UserID: nobody}, client.ErrSeed},
		"words and shares":    {client.RestoreOptions{Words: echo.Words(), Shares: shares}, client.ErrArgument},
		"nothing":             {client.RestoreOptions{}, client.ErrArgument},
	} {
		rdir := filepath.Join(env.Base, "wrong", strings.ReplaceAll(name, " ", "-"))
		if _, err := client.Restore(env.ClientConfig(rdir), c.opts, testenv.Passphrase); !errors.Is(err, c.want) {
			t.Fatalf("%s: %v", name, err)
		}
		noFiles(t, rdir)
	}
	// Shares of two splits: they do not combine, or (one split ID in 65536)
	// combine to a seed of nobody.
	mixed := filepath.Join(env.Base, "wrong", "mixed")
	if _, err := client.Restore(env.ClientConfig(mixed), client.RestoreOptions{Shares: [][]string{shares[0], foreign[1]}}, testenv.Passphrase); !errors.Is(err, shamir.ErrMismatch) && !errors.Is(err, client.ErrSeed) {
		t.Fatalf("mixed splits: %v", err)
	}
	noFiles(t, mixed)
	if _, err := client.Restore(cfg, client.RestoreOptions{Shares: shares}, testenv.Passphrase); !errors.Is(err, client.ErrRegistered) {
		t.Fatalf("restore into a used client directory: %v", err)
	}
	if _, err := client.Restore(env.ClientConfig(mixed), client.RestoreOptions{Shares: shares}, nil); err == nil {
		t.Fatal("empty passphrase")
	}

	// Device lost after a restore; the old device can no longer open.
	rcfg := env.ClientConfig(filepath.Join(env.Base, "restore", "ab"))
	gen, err := client.DeviceLost(rcfg, testenv.Passphrase, mess(echo.Words()))
	if err != nil || gen != 2 {
		t.Fatalf("device lost after restore: %d, %v", gen, err)
	}
	rc, err := client.Open(rcfg, testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if n, err := rc.MailboxName(mbx); err != nil || n != "A" {
		t.Fatalf("after device lost: %q, %v", n, err)
	}
	if _, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrDeviceLostPending) {
		t.Fatalf("the old device: %v", err)
	}
	ks, err := keys.ReadKeystoreFile(filepath.Join(env.Base, "restore", "ab", "keystore"))
	if err != nil {
		t.Fatal(err)
	}
	if k, err := keys.OpenKeystore(ks, testenv.Passphrase); err != nil || k.Generation != 2 {
		t.Fatalf("key store after device lost: %v", err)
	}
}

// TestRestorePastPeriodReader: a user who only has wraps of a past
// period (never a member) finds the mailbox again after Restore.
func TestRestorePastPeriodReader(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "october")
	bob := f.env.NewUser("bob")
	f.env.Clock.Set(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC))
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	if wrapped := f.env.Share(f.u, f.mbx, bob, client.ShareOptions{From: 1, To: 1}); len(wrapped) != 1 {
		t.Fatalf("wrapped %v", wrapped)
	}
	bob.Client.Close()
	cfg := f.env.ClientConfig(filepath.Join(f.env.Base, "bob-restored"))
	if _, err := client.Restore(cfg, client.RestoreOptions{Words: bob.Words}, testenv.Passphrase); err != nil {
		t.Fatal(err)
	}
	c, err := client.Open(cfg, testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.Mailboxes(); len(got) != 1 || got[0] != f.mbx {
		t.Fatalf("mailboxes %v", got)
	}
	readBody(t, f.env, c, f.mbx, old.ID, "october")
}
