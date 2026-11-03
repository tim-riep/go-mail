// Package terms holds the term rules of 5.4 (DECISIONS D55) in one place:
// the server (package ingest) applies them to a received header, the
// client (package client) to the metadata of a mail marked unprocessed
// (6.2 step 2) and to a search term (6.3). Neither side keeps a copy.
//
// The rules:
//
//   - from: and fromdomain: from the address in From; if From has no
//     readable address, from the envelope sender,
//   - day: and month: from the receipt time in UTC (the Date header is
//     chosen freely by the sender, the receipt time is signed),
//   - has:attachment if the content type of the top level is
//     multipart/mixed (HasAttachment),
//   - thread: from the first entry of References, else In-Reply-To, else
//     Message-ID, each with angle brackets (ThreadRoot),
//   - to: from the envelope recipients of the mailbox (so that a Bcc copy
//     is found under its address), then To and Cc, last, so that a mail
//     to many addresses does not push out the other terms,
//
// every term lower case, cleaned (valid UTF-8 without control
// characters), Unicode NFC and at most MaxTermLen bytes, no term twice,
// at most MaxTerms terms.
//
// Inputs that differ between server and client: the server reads the
// header as received, the client only the values the metadata keep. They
// are cut to store.MaxTextLen bytes (4096) each, the envelope sender to
// store.MaxAddressLen bytes (320), and the metadata keep neither
// References nor In-Reply-To. For a header with an overlong From, To or
// Cc value, or an overlong envelope sender, the from: and to: terms a
// client derives can therefore differ from those of the server (the
// addresses after the cut are missing, or an address is cut), and the
// thread: term of a reply is its own Message-ID (SPEC-ISSUES S23,
// TODO(Q12)). TestMetaTermsMatchServer in package client pins both.
package terms

import (
	"mime"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

// Limits of a term list (5.4); they are the limits of the pending record
// (store.PendingSchema).
const (
	MaxTerms   = store.MaxTerms   // terms of one mail
	MaxTermLen = store.MaxTermLen // bytes of one term
)

// The kinds of terms of 5.4.
const (
	From       = "from:"
	FromDomain = "fromdomain:"
	To         = "to:"
	Day        = "day:"
	Month      = "month:"
	Thread     = "thread:"
	Attachment = "has:attachment"
)

// prefixes are the kinds of terms that take a value.
var prefixes = []string{From, FromDomain, To, Day, Month, Thread}

// Normalize normalizes one term (5.4): lower case, valid UTF-8 without
// control characters, Unicode NFC, at most MaxTermLen bytes.
func Normalize(t string) string {
	return store.CleanText(strings.ToLower(t), MaxTermLen)
}

// Query normalizes a search term exactly like the terms of a term list
// (Normalize, after trimming surrounding white space) and reports whether
// it is one of the terms of 5.4: from:, fromdomain:, to:, day:, month:,
// thread: with a value that is not blank, or has:attachment.
func Query(q string) (string, bool) {
	t := Normalize(strings.TrimSpace(q))
	if t == Attachment {
		return t, true
	}
	for _, p := range prefixes {
		if v, ok := strings.CutPrefix(t, p); ok && strings.TrimSpace(v) != "" {
			return t, true
		}
	}
	return "", false
}

// FirstMsgID returns the first "<...>" token of a header value, empty if
// there is none.
func FirstMsgID(v string) string {
	i := strings.IndexByte(v, '<')
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(v[i:], '>')
	if j < 0 {
		return ""
	}
	return v[i : i+j+1]
}

// ThreadRoot returns the root of the thread of a mail (thread:): the
// first "<...>" token of the header value References, else of
// In-Reply-To, else of Message-ID; empty if none has one. A side that
// does not know a value passes "" for it (the metadata of a mail keep
// neither References nor In-Reply-To, TODO(Q12)).
func ThreadRoot(references, inReplyTo, messageID string) string {
	for _, v := range []string{references, inReplyTo, messageID} {
		if id := FirstMsgID(v); id != "" {
			return id
		}
	}
	return ""
}

// HasAttachment reports whether contentType, the value of the header
// Content-Type of the top level, is multipart/mixed (has:attachment):
// media type parsed by mime.ParseMediaType, so case and parameters do not
// matter; a value that does not parse is no attachment.
func HasAttachment(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "multipart/mixed"
}

// Mail is what the term list of one mail is made of.
type Mail struct {
	// FromAddr is the address in From, empty if From has none that can
	// be read.
	FromAddr string
	// EnvelopeFrom is the envelope sender; it stands in for FromAddr.
	EnvelopeFrom string
	// EnvelopeTo are the envelope recipients of the mailbox.
	EnvelopeTo []string
	// HeaderTo are the addresses in To and Cc.
	HeaderTo []string
	// Received is the receipt time.
	Received time.Time
	// Attachment is set if the top level is multipart/mixed
	// (HasAttachment).
	Attachment bool
	// Thread is the root of the thread ("<...>", ThreadRoot), empty if
	// none.
	Thread string
}

// List returns the term list of m (5.4, see the package comment).
func List(m *Mail) []string {
	var out []string
	seen := map[string]bool{}
	add := func(t string) {
		if t == "" || seen[t] || len(out) >= MaxTerms {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	from := m.FromAddr
	if from == "" {
		from = m.EnvelopeFrom
	}
	if from != "" {
		add(Normalize(From + from))
		if at := strings.LastIndexByte(from, '@'); at >= 0 && at < len(from)-1 {
			add(Normalize(FromDomain + from[at+1:]))
		}
	}
	u := m.Received.UTC()
	add(Normalize(Day + u.Format("2006-01-02")))
	add(Normalize(Month + u.Format("2006-01")))
	if m.Attachment {
		add(Attachment)
	}
	if m.Thread != "" {
		add(Normalize(Thread + m.Thread))
	}
	// Recipients last: a mail to many addresses must not push out the
	// other terms when the list reaches MaxTerms.
	for _, a := range m.EnvelopeTo {
		add(Normalize(To + a))
	}
	for _, a := range m.HeaderTo {
		add(Normalize(To + a))
	}
	return out
}
