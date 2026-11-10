//go:build unix

package client_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// TestUnprocessedMailUnreadable: a mail file that cannot be read when
// unprocessedTerms opens it (a directory or a FIFO in its place since the
// listing, store.ErrNotRegular, or a symbolic link to itself, an error of
// the system that names the path) is no verdict on the mail: Index leaves
// the marker, with a warning that names the mail ID and the fixed cause
// "Datei nicht lesbar", and Search takes the terms of the metadata
// meanwhile, with the same warning. Once the mail can be read, Index
// takes from: and to: from it. In its place before the listing, the mail
// is not listed at all: Index leaves the marker without a warning and
// Search does not find the mail (as before task 27).
func TestUnprocessedMailUnreadable(t *testing.T) {
	for name, put := range map[string]func(path string) error{
		"directory": func(path string) error { return os.Mkdir(path, 0o700) },
		"fifo":      func(path string) error { return syscall.Mkfifo(path, 0o600) },
		"loop":      func(path string) error { return os.Symlink(filepath.Base(path), path) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.send(t, envFrom, msgLongTo)
			m := mailBySubject(t, f, "longto")
			path := f.env.Store.MailFile(f.mbx, f.inbox(t), m.ID)
			f.u.Client.Close()
			armed := false
			client.SetLogHook(t, func(l translog.Log) translog.Log {
				return &vanishLog{Log: l, path: path, armed: &armed, then: func(path string) {
					if err := put(path); err != nil {
						t.Error(err)
					}
				}}
			})
			c, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			restore := func() {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path+".away", path); err != nil {
					t.Fatal(err)
				}
			}
			noWarnings := func(stage string) {
				t.Helper()
				if w := f.env.Warnings.Take(); len(w) != 0 {
					t.Fatalf("%s: warnings %q", stage, w)
				}
			}
			// In place before the run: not listed, the marker stays.
			if err := os.Rename(path, path+".away"); err != nil {
				t.Fatal(err)
			}
			if err := put(path); err != nil {
				t.Fatal(err)
			}
			if n, err := c.Index(f.mbx); err != nil || n != 0 || pendingCount(t, f.env, f.mbx, 1) != 1 {
				t.Fatal("before the run", n, err)
			}
			if got := search(t, c, f.mbx, "to:addr000@recipients.example", ""); got != "" {
				t.Fatalf("mail not listed found: %q", got)
			}
			noWarnings("before the run")
			restore()
			// In place since the listing: one warning per call, the
			// terms of the metadata, the marker stays.
			want := "WARNUNG: Mail " + m.ID.String() + " lässt sich nicht lesen: Datei nicht lesbar. " +
				"Ihr Eintrag in pending/ bleibt für einen späteren Index-Lauf liegen; bis dahin gelten die Suchbegriffe ihrer Metadaten."
			warning := func(stage string) {
				t.Helper()
				if w := f.env.Warnings.Take(); len(w) != 1 || w[0] != want {
					t.Fatalf("%s: warnings %q", stage, w)
				}
			}
			for _, tc := range []struct{ q, want string }{
				{"to:addr000@recipients.example", "longto"},
				{"to:addr139@recipients.example", ""},
			} {
				armed = true
				if got := search(t, c, f.mbx, tc.q, ""); got != tc.want || armed {
					t.Fatalf("%s: %q, want %q (hook fired: %v)", tc.q, got, tc.want, !armed)
				}
				warning(tc.q)
				restore()
			}
			armed = true
			if n, err := c.Index(f.mbx); err != nil || n != 0 || armed {
				t.Fatal(n, err, armed)
			}
			warning("index")
			if pendingCount(t, f.env, f.mbx, 1) != 1 || segmentCount(t, f.env, f.mbx, 1) != 0 {
				t.Fatal("the marker must stay while the mail cannot be read")
			}
			restore()
			if n, err := c.Index(f.mbx); err != nil || n != 1 {
				t.Fatal(n, err)
			}
			if pendingCount(t, f.env, f.mbx, 1) != 0 {
				t.Fatal("marker left")
			}
			if got := search(t, c, f.mbx, "to:addr139@recipients.example", ""); got != "longto" {
				t.Fatalf("after the mail could be read: %q", got)
			}
			noWarnings("end")
		})
	}
}

// npMarker is in every header value, address and the body of the mail of
// TestNoPlaintextUnprocessedCutHeader.
const npMarker = "zqvmark27c"

// npLongTo returns To with 140 addresses, the marker in display names and
// in addresses before and after the cut of the metadata.
func npLongTo() string {
	var l []string
	for i := 0; i < 140; i++ {
		l = append(l, fmt.Sprintf("%s Name%03d <%s%03d@recipients.example>", strings.ToUpper(npMarker), i, npMarker, i))
	}
	return strings.Join(l, ",\r\n ")
}

// npWalk fails if a regular file under dirs holds the marker, in any
// case.
func npWalk(t *testing.T, stage string, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		filepath.Walk(d, func(p string, fi os.FileInfo, err error) error {
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			b, _ := os.ReadFile(p)
			if bytes.Contains(bytes.ToLower(b), []byte(npMarker)) {
				t.Fatalf("%s: marker in %s", stage, p)
			}
			return nil
		})
	}
}

// npCheck fails if a warning or err holds the marker.
func npCheck(t *testing.T, f *fixture, stage string, err error) {
	t.Helper()
	for _, x := range f.env.Warnings.Take() {
		if strings.Contains(strings.ToLower(x), npMarker) {
			t.Fatalf("%s: marker in warning %q", stage, x)
		}
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), npMarker) {
		t.Fatalf("%s: marker in error %v", stage, err)
	}
}

// TestNoPlaintextUnprocessedCutHeader: the path of a mail marked
// unprocessed whose To the metadata cut (the mail opened for from: and
// to:) and its other outcomes leave no plaintext on disk, in TMPDIR, in
// warnings or in errors, through Search, Index (two runs) and Read. The
// outcomes: hash mismatch; a FIFO, a directory or nothing in place of the
// mail file before the listing (not listed) or since the listing (the
// read fails), and a file grown beyond store.MaxMailFile since the
// listing; a mail file larger than store.MaxMailFile (sparse); an
// envelope cut short whose hash the signed metadata carry (the envelope
// format fails); a header that cannot be evaluated.
func TestNoPlaintextUnprocessedCutHeader(t *testing.T) {
	msg := "From: " + strings.ToUpper(npMarker) + " <" + npMarker + "from@sender.example>\r\nTo: " + npLongTo() +
		"\r\nSubject: " + npMarker + "subject\r\nMessage-ID: <" + npMarker + "@x.example>\r\n\r\n" + npMarker + "body\r\n"
	// put replaces the mail file at path since the listing, for the modes
	// that end in "-since-listing".
	put := map[string]func(path string) error{
		"dir-since-listing":     func(path string) error { return os.Mkdir(path, 0o700) },
		"fifo-since-listing":    func(path string) error { return syscall.Mkfifo(path, 0o600) },
		"missing-since-listing": func(string) error { return nil },
		"grown-since-listing": func(path string) error {
			b, err := os.ReadFile(path + ".away")
			if err == nil {
				err = os.WriteFile(path, b, 0o600)
			}
			if err == nil {
				err = os.Truncate(path, store.MaxMailFile+1)
			}
			return err
		},
	}
	for _, mode := range []string{"ok", "hash", "fifo", "dir", "missing", "toolarge", "envelope", "noeval",
		"dir-since-listing", "fifo-since-listing", "missing-since-listing", "grown-since-listing"} {
		t.Run(mode, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			f := newFixture(t)
			c := f.u.Client
			var id store.ID
			switch mode {
			case "noeval":
				id = f.forgeParsed(t, "To: "+npLongTo()+"\r\nX: "+npMarker+"\r\n"+strings.Repeat("X-A: b\r\n", 500)+"\r\n"+npMarker+"\r\n", npLongTo())
			case "envelope":
				id = f.forgeParsedRaw(t, msg, npLongTo(), nil, func(b []byte) []byte { return b[:len(b)-7] })
			default:
				f.send(t, envFrom, msg)
				list, err := c.List(f.mbx, store.ID{})
				if err != nil || len(list) != 1 {
					t.Fatal(len(list), err)
				}
				id = list[0].ID
				if !client.MetaCut(list[0].Meta) {
					t.Fatal("not cut")
				}
			}
			path := f.env.Store.MailFile(f.mbx, f.inbox(t), id)
			armed, restore := false, func() {}
			if then := put[mode]; then != nil {
				f.u.Client.Close()
				client.SetLogHook(t, func(l translog.Log) translog.Log {
					return &vanishLog{Log: l, path: path, armed: &armed, then: func(path string) {
						if err := then(path); err != nil {
							t.Error(err)
						}
					}}
				})
				var err error
				if c, err = client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase); err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				restore = func() {
					t.Helper()
					if armed {
						t.Fatal("the mail file was not replaced since the listing")
					}
					if err := os.RemoveAll(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(path+".away", path); err != nil {
						t.Fatal(err)
					}
				}
			}
			var err error
			switch mode {
			case "hash":
				var b []byte
				if b, err = os.ReadFile(path); err == nil {
					b[len(b)-1] ^= 1
					err = store.WriteFileAtomic(path, b)
				}
			case "fifo":
				if err = os.Remove(path); err == nil {
					err = syscall.Mkfifo(path, 0o600)
				}
			case "dir":
				if err = os.Remove(path); err == nil {
					err = os.Mkdir(path, 0o700)
				}
			case "missing":
				err = os.Remove(path)
			case "toolarge":
				err = os.Truncate(path, store.MaxMailFile+1)
			}
			if err != nil {
				t.Fatal(err)
			}
			since := put[mode] != nil
			for _, q := range []string{"to:" + npMarker + "139@recipients.example", "to:" + npMarker + "000@recipients.example", "from:" + npMarker + "from@sender.example"} {
				armed = since
				done := make(chan error, 1)
				go func() { _, err := c.Search(f.mbx, q, client.SearchOptions{}); done <- err }()
				select {
				case err := <-done:
					npCheck(t, f, "search", err)
				case <-time.After(30 * time.Second):
					t.Fatal("search hangs")
				}
				restore()
			}
			npWalk(t, "after search", f.env.Base, tmp)
			for _, run := range []string{"index", "index 2"} {
				armed = since && pendingCount(t, f.env, f.mbx, 1) != 0
				replaced := armed
				_, err = c.Index(f.mbx)
				if replaced {
					restore()
				}
				npCheck(t, f, run, err)
				npWalk(t, "after "+run, f.env.Base, tmp)
			}
			for _, q := range []string{"to:" + npMarker + "139@recipients.example", "subject:x"} {
				_, err := c.Search(f.mbx, q, client.SearchOptions{})
				npCheck(t, f, "search after index", err)
			}
			_, _, err = c.Read(f.mbx, id)
			npCheck(t, f, "read", err)
			npWalk(t, "end", f.env.Base, tmp)
		})
	}
}
