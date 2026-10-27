package bench

import (
	"bytes"
	"go/parser"
	"go/token"
	"io/fs"
	"net/mail"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/testenv"
)

func TestMailSizes(t *testing.T) {
	for _, sz := range Sizes {
		m, err := Mail(sz, 7)
		if err != nil {
			t.Fatal(err)
		}
		if len(m) != sz.Bytes {
			t.Fatalf("%s: %d bytes", sz.Name, len(m))
		}
		again, _ := Mail(sz, 7)
		if !bytes.Equal(m, again) {
			t.Fatalf("%s: not reproducible", sz.Name)
		}
		other, _ := Mail(sz, 8)
		if bytes.Equal(m[len(m)-100:], other[len(other)-100:]) {
			t.Fatalf("%s: the seed does not change the body", sz.Name)
		}
		if !bytes.HasPrefix(m, []byte(MailHeader(sz.Name, 7))) || !bytes.HasSuffix(m, []byte("\r\n")) {
			t.Fatalf("%s: header or end", sz.Name)
		}
		for i, l := range bytes.Split(m[:len(m)-2], []byte("\r\n")) {
			if len(l)+2 > 1000 || bytes.ContainsAny(l, "\r\n") {
				t.Fatalf("%s: line %d", sz.Name, i)
			}
		}
		body := m[len(MailHeader(sz.Name, 7)):]
		if bytes.IndexByte(body, '.') >= 0 {
			t.Fatalf("%s: dot in the body", sz.Name)
		}
		msg, err := mail.ReadMessage(bytes.NewReader(m))
		if err != nil || msg.Header.Get("To") != "<"+BenchTo+">" {
			t.Fatalf("%s: header %v", sz.Name, err)
		}
	}
	// Every rest of a line works, including one and two bytes.
	h := len(MailHeader("x", 1))
	for n := h + 3; n < h+3*78; n++ {
		m, err := Mail(Size{"x", n}, 1)
		if err != nil || len(m) != n {
			t.Fatalf("size %d: %d %v", n, len(m), err)
		}
		for _, l := range bytes.Split(m[h:len(m)-2], []byte("\r\n")) {
			if len(l) == 0 {
				t.Fatalf("size %d: empty body line", n)
			}
		}
	}
	if _, err := Mail(Size{"x", h + 2}, 1); err != ErrSize {
		t.Fatalf("too small: %v", err)
	}
}

// TestCorpus checks the term distribution of the corpus with the terms
// of ingest and logs the number of distinct terms per 1,000 mails (the
// basis of point 3).
func TestCorpus(t *testing.T) {
	const n = 1000
	c := Corpus(1, n, testenv.Start)
	again := Corpus(1, n, testenv.Start)
	senders, rcpts, days, threads, terms := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]int{}
	att, replies, total := 0, 0, 0
	for i, m := range c {
		if !bytes.Equal(m.Data, again[i].Data) || !m.Received.Equal(again[i].Received) {
			t.Fatalf("mail %d not reproducible", i)
		}
		if i > 0 && m.Received.Before(c[i-1].Received) {
			t.Fatalf("mail %d out of order", i)
		}
		first := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC) // the midnight after testenv.Start
		if m.Received.Before(first) || !m.Received.Before(first.AddDate(0, 0, CorpusDays)) {
			t.Fatalf("mail %d outside the days", i)
		}
		senders[m.EnvelopeFrom] = true
		rcpts[m.Rcpts[0]] = true
		days[m.Received.Format(time.DateOnly)] = true
		threads[m.Thread] = true
		if m.Attachment {
			att++
		}
		msg, err := mail.ReadMessage(bytes.NewReader(m.Data))
		if err != nil {
			t.Fatalf("mail %d: %v", i, err)
		}
		if msg.Header.Get("References") != "" {
			replies++
		}
		hdr := m.Data[:bytes.Index(m.Data, []byte("\r\n\r\n"))+4]
		list, ok := ingest.Terms(hdr, m.Received, m.EnvelopeFrom, m.Rcpts)
		if !ok {
			t.Fatalf("mail %d: no terms", i)
		}
		has := strings.Join(list, " ")
		if !strings.Contains(has, "from:"+m.EnvelopeFrom) || !strings.Contains(has, "thread:"+m.Thread) ||
			strings.Contains(has, "has:attachment") != m.Attachment {
			t.Fatalf("mail %d: terms %q", i, list)
		}
		for _, x := range list {
			terms[x]++
		}
		total += len(list)
	}
	if len(senders) != CorpusSenders || len(rcpts) != len(CorpusRecipients) || len(days) != CorpusDays {
		t.Fatalf("senders %d, recipients %d, days %d", len(senders), len(rcpts), len(days))
	}
	if att < n*15/100 || att > n*25/100 || replies < n*35/100 || replies > n*45/100 {
		t.Fatalf("attachments %d, replies %d of %d", att, replies, n)
	}
	t.Logf("per %d mails: %d distinct terms, %d terms in total, %d threads", n, len(terms), total, len(threads))
}

func TestHardware(t *testing.T) {
	dir := t.TempDir()
	h := CollectHardware(dir)
	if h.NumCPU <= 0 || h.GOARCH != runtime.GOARCH || h.Dir == "" {
		t.Fatalf("%+v", h)
	}
	if runtime.GOOS == "linux" {
		if h.FS == "unknown" || h.Kernel == "unknown" || ReadVmRSS() == 0 {
			t.Fatalf("%+v", h)
		}
	}
	for _, l := range h.Lines() {
		if k, _, ok := strings.Cut(l, ": "); !ok || strings.ContainsAny(k, " \t") {
			t.Fatalf("not a configuration line: %q", l)
		}
	}
	mounts := []byte("rootfs / rootfs rw 0 0\n/dev/a / ext4 rw 0 0\n/dev/b /data\\040x xfs rw 0 0\ntmpfs /data tmpfs rw 0 0\n")
	for _, c := range []struct{ path, fs, mnt string }{
		{"/data x/y", "xfs", "/data x"},
		{"/data/y", "tmpfs", "/data"},
		{"/datax", "ext4", "/"},
		{"/", "ext4", "/"},
	} {
		if _, mnt, fs := mountOf(mounts, c.path); fs != c.fs || mnt != c.mnt {
			t.Fatalf("%s: %s on %s", c.path, fs, mnt)
		}
	}
	if s := unescapeMount(`a\040b\\x\04`); s != `a b\\x\04` {
		t.Fatalf("unescape %q", s)
	}
	if procField([]byte("model name\t: X\nVmRSS:\t 12 kB\n"), "VmRSS") != "12 kB" {
		t.Fatal("procField")
	}
}

func TestConfigLines(t *testing.T) {
	lines := configLines()
	if !strings.HasPrefix(lines[0], "command: go test ") || !strings.HasSuffix(lines[0], " ./internal/bench") {
		t.Fatalf("%q", lines[0])
	}
	if shellQuote("^$") != `'^$'` || shellQuote("a'b") != `'a'\''b'` || shellQuote("-v") != "-v" {
		t.Fatal("shellQuote")
	}
}

// TestNotLinked checks that no package outside internal/bench imports
// it, so nothing of it is linked into the programs.
func TestNotLinked(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			abs, _ := filepath.Abs(p)
			if abs == self || (strings.HasPrefix(d.Name(), ".") && p != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == "github.com/tim-riep/go-mail/internal/bench" {
				t.Errorf("%s imports internal/bench", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
