package bench

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"
)

// Size is a size class of the throughput benchmarks.
type Size struct {
	Name  string
	Bytes int
}

// Sizes are the size classes of docs/tasks/12 point 1.
var Sizes = []Size{
	{"4KiB", 4 << 10},
	{"64KiB", 64 << 10},
	{"1MiB", 1 << 20},
	{"10MiB", 10 << 20},
}

// SizeByName returns the size class with the given name.
func SizeByName(name string) (Size, bool) {
	for _, s := range Sizes {
		if s.Name == name {
			return s, true
		}
	}
	return Size{}, false
}

// Addresses of the generated mails.
const (
	BenchFrom = "sender@bench.example"
	BenchTo   = "info@bench.example"
)

// lineLen is the number of text characters per body line; with CRLF a
// line has 78 bytes, well below the 1,000 octets of RFC 5321.
const lineLen = 76

// alphabet holds the characters of the body text: no dot, so the SMTP
// client never needs to stuff a line.
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// ErrSize reports a size class too small for the fixed header.
var ErrSize = errors.New("bench: size too small for the fixed header")

// newRand returns the deterministic generator of the benchmark data. It
// produces test data only: nothing of it is a key, nonce or ID (those
// come from crypto/rand inside the code under test).
func newRand(seed uint64) *rand.Rand {
	var s [32]byte
	for i := range 8 {
		s[i] = byte(seed >> (8 * i))
	}
	copy(s[8:], "go-mail benchmark data")
	return rand.New(rand.NewChaCha8(s))
}

// fill writes len(p) text characters from r into p.
func fill(r *rand.Rand, p []byte) {
	for i := 0; i < len(p); {
		v := r.Uint64()
		for k := 0; k < 10 && i < len(p); k++ {
			p[i] = alphabet[v&63]
			v >>= 6
			i++
		}
	}
}

// MailHeader returns the fixed header of a generated mail of size class
// name, including the empty line that ends it.
func MailHeader(name string, seed uint64) string {
	return "From: Bench Sender <" + BenchFrom + ">\r\n" +
		"To: <" + BenchTo + ">\r\n" +
		"Subject: Benchmark " + name + "\r\n" +
		"Date: Mon, 26 Oct 2026 10:00:00 +0000\r\n" +
		fmt.Sprintf("Message-ID: <bench-%s-%d@bench.example>\r\n", strings.ToLower(name), seed) +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=us-ascii\r\n" +
		"Content-Transfer-Encoding: 7bit\r\n" +
		"\r\n"
}

// Mail returns a mail of exactly s.Bytes bytes: the fixed header of
// MailHeader and a body of text lines generated from seed. The same
// size class and seed always give the same bytes. Lines end in CRLF and
// are at most 78 bytes long; the body never contains a dot.
func Mail(s Size, seed uint64) ([]byte, error) {
	h := MailHeader(s.Name, seed)
	rem := s.Bytes - len(h)
	if rem < 3 {
		return nil, ErrSize
	}
	out := make([]byte, 0, s.Bytes)
	out = append(out, h...)
	r := newRand(seed)
	line := make([]byte, lineLen)
	for rem > 0 {
		n := min(lineLen, rem-2)
		// A rest of one or two bytes cannot form a line (one character
		// and CRLF): leave three for the last line.
		if left := rem - n - 2; left > 0 && left < 3 {
			n -= 3 - left
		}
		fill(r, line[:n])
		out = append(out, line[:n]...)
		out = append(out, '\r', '\n')
		rem -= n + 2
	}
	return out, nil
}

// Corpus parameters: the typical term distribution of docs/tasks/12
// point 3.
const (
	CorpusSenders     = 10
	CorpusDays        = 30
	CorpusAttachments = 0.20 // share of mails with an attachment
	CorpusReplies     = 0.40 // share of mails that answer an earlier mail
)

// CorpusRecipients are the three addresses of the corpus mailbox.
var CorpusRecipients = []string{"info@bench.example", "alice@bench.example", "billing@bench.example"}

var corpusDomains = []string{"lieferant.example", "bank.example", "kunde.example", "verein.example", "shop.example"}

// CorpusSender returns sender i (0 <= i < CorpusSenders).
func CorpusSender(i int) string {
	return fmt.Sprintf("absender%d@%s", i, corpusDomains[i%len(corpusDomains)])
}

// CorpusMail is one mail of the corpus.
type CorpusMail struct {
	Received     time.Time
	EnvelopeFrom string
	Rcpts        []string
	Attachment   bool
	Thread       string // Message-ID of the thread root
	Data         []byte
}

// Corpus returns n mails received in the CorpusDays calendar days (UTC)
// beginning with the first midnight at or after start, sorted by
// receipt: CorpusSenders senders, the three
// CorpusRecipients, a share CorpusAttachments with an attachment
// (multipart/mixed) and a share CorpusReplies answering an earlier mail
// (References and In-Reply-To, so the thread term is that of the root).
// Mails have about 0.5 to 6 KiB. The same seed always gives the same mails.
func Corpus(seed uint64, n int, start time.Time) []CorpusMail {
	r := newRand(seed)
	start = start.UTC()
	if day := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC); day.Equal(start) {
		start = day
	} else {
		start = day.AddDate(0, 0, 1)
	}
	times := make([]time.Time, n)
	for i := range times {
		day := r.IntN(CorpusDays)
		sec := r.IntN(24 * 3600)
		times[i] = start.Add(time.Duration(day)*24*time.Hour + time.Duration(sec)*time.Second)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	out := make([]CorpusMail, n)
	ids := make([]string, n)
	roots := make([]string, n)
	text := make([]byte, 64)
	for i := range out {
		from := CorpusSender(r.IntN(CorpusSenders))
		to := CorpusRecipients[r.IntN(len(CorpusRecipients))]
		ids[i] = fmt.Sprintf("<c%d-%d@%s>", seed, i, from[strings.IndexByte(from, '@')+1:])
		roots[i] = ids[i]
		var b strings.Builder
		fmt.Fprintf(&b, "From: Absender <%s>\r\nTo: <%s>\r\n", from, to)
		fmt.Fprintf(&b, "Date: %s\r\nMessage-ID: %s\r\n", times[i].UTC().Format(time.RFC1123Z), ids[i])
		if i > 0 && r.Float64() < CorpusReplies {
			p := r.IntN(i)
			roots[i] = roots[p]
			fmt.Fprintf(&b, "In-Reply-To: %s\r\nReferences: %s %s\r\nSubject: Re: Vorgang %d\r\n", ids[p], roots[p], ids[p], p)
		} else {
			fmt.Fprintf(&b, "Subject: Vorgang %d\r\n", i)
		}
		att := r.Float64() < CorpusAttachments
		lines := 8 + r.IntN(24)
		if att {
			bd := fmt.Sprintf("b%d-%d", seed, i)
			fmt.Fprintf(&b, "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n", bd)
			fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n", bd)
			writeLines(&b, r, text, lines)
			fmt.Fprintf(&b, "--%s\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"anhang%d.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n", bd, i)
			writeLines(&b, r, text, 16+r.IntN(48))
			fmt.Fprintf(&b, "--%s--\r\n", bd)
		} else {
			b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n")
			writeLines(&b, r, text, lines)
		}
		out[i] = CorpusMail{Received: times[i], EnvelopeFrom: from, Rcpts: []string{to}, Attachment: att, Thread: roots[i], Data: []byte(b.String())}
	}
	return out
}

func writeLines(b *strings.Builder, r *rand.Rand, buf []byte, n int) {
	for range n {
		fill(r, buf)
		b.Write(buf)
		b.WriteString("\r\n")
	}
}
