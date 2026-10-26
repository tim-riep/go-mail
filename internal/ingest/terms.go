package ingest

import (
	"bytes"
	"mime"
	"net/mail"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

// headerFields are the header values a client lists, cleaned for storage
// (3.6 rule 3), and the inputs of the term list.
type headerFields struct {
	from, to, cc, subject, date, messageID string
	attachment                             bool
	fromAddr                               string
	rcptAddrs                              []string
	thread                                 string
}

var wordDecoder = mime.WordDecoder{}

// decodeText decodes RFC 2047 encoded words where the charset is known
// and cleans the result; on any decoding error the raw value is used.
func decodeText(v string) string {
	if d, err := wordDecoder.DecodeHeader(v); err == nil {
		v = d
	}
	return store.CleanText(v, store.MaxTextLen)
}

// firstMsgID returns the first "<...>" token of a header value.
func firstMsgID(v string) string {
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

// parseHeader parses a captured header (5.3: net/mail, at most 1 MB and
// 500 fields). It reports false if the header cannot be evaluated; the
// mail then stays marked unprocessed.
func parseHeader(h []byte) (headerFields, bool) {
	var f headerFields
	if len(h) == 0 || len(h) > MaxHeaderBytes {
		return f, false
	}
	// Count fields before parsing: lines that do not start with
	// whitespace.
	fields := 0
	for _, line := range bytes.Split(h, []byte("\r\n")) {
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			fields++
		}
	}
	if fields > MaxHeaderFields {
		return f, false
	}
	msg, err := mail.ReadMessage(bytes.NewReader(h))
	if err != nil {
		return f, false
	}
	hd := msg.Header
	f.from = decodeText(hd.Get("From"))
	f.to = decodeText(hd.Get("To"))
	f.cc = decodeText(hd.Get("Cc"))
	f.subject = decodeText(hd.Get("Subject"))
	f.date = decodeText(hd.Get("Date"))
	f.messageID = decodeText(hd.Get("Message-Id"))
	if mt, _, err := mime.ParseMediaType(hd.Get("Content-Type")); err == nil && mt == "multipart/mixed" {
		f.attachment = true
	}
	if a, err := mail.ParseAddress(hd.Get("From")); err == nil {
		f.fromAddr = a.Address
	}
	for _, name := range []string{"To", "Cc"} {
		if v := hd.Get(name); v != "" {
			if list, err := mail.ParseAddressList(v); err == nil {
				for _, a := range list {
					f.rcptAddrs = append(f.rcptAddrs, a.Address)
				}
			}
		}
	}
	// The thread root: the first References entry, else In-Reply-To, else
	// the message's own ID.
	for _, name := range []string{"References", "In-Reply-To", "Message-Id"} {
		if id := firstMsgID(hd.Get(name)); id != "" {
			f.thread = id
			break
		}
	}
	return f, true
}

// term normalizes one term: lower case, Unicode NFC, valid UTF-8 without
// control characters, at most store.MaxTermLen bytes (5.4).
func term(prefix, value string) string {
	return store.CleanText(strings.ToLower(prefix+value), store.MaxTermLen)
}

// Terms returns the term list of a mail (5.4) received at t: from and
// fromdomain from the header From (the envelope sender if From has no
// parsable address), to from To, Cc and the envelope recipients of this
// mailbox (so that a Bcc copy is found by its address), day, month,
// has:attachment and thread. It reports false if the header cannot be
// evaluated.
func Terms(header []byte, received time.Time, envelopeFrom string, rcpts []string) ([]string, bool) {
	f, ok := parseHeader(header)
	if !ok {
		return nil, false
	}
	if f.fromAddr == "" && envelopeFrom != "" {
		f.fromAddr = envelopeFrom
	}
	f.rcptAddrs = append(append([]string(nil), rcpts...), f.rcptAddrs...)
	return termsOf(&f, received), true
}

func termsOf(f *headerFields, received time.Time) []string {
	var out []string
	seen := map[string]bool{}
	add := func(t string) {
		if t == "" || seen[t] || len(out) >= store.MaxTerms {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	if f.fromAddr != "" {
		add(term("from:", f.fromAddr))
		if at := strings.LastIndexByte(f.fromAddr, '@'); at >= 0 && at < len(f.fromAddr)-1 {
			add(term("fromdomain:", f.fromAddr[at+1:]))
		}
	}
	u := received.UTC()
	add(term("day:", u.Format("2006-01-02")))
	add(term("month:", u.Format("2006-01")))
	if f.attachment {
		add("has:attachment")
	}
	if f.thread != "" {
		add(term("thread:", f.thread))
	}
	// Recipients last: a mail to many addresses must not push out the
	// other terms when the list reaches store.MaxTerms.
	for _, a := range f.rcptAddrs {
		add(term("to:", a))
	}
	return out
}
