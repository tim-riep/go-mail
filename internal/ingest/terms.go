package ingest

import (
	"bytes"
	"mime"
	"net/mail"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/terms"
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
	f.attachment = terms.HasAttachment(hd.Get("Content-Type"))
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
	f.thread = terms.ThreadRoot(hd.Get("References"), hd.Get("In-Reply-To"), hd.Get("Message-Id"))
	return f, true
}

// Terms returns the term list of a mail (5.4) received at t, by the rules
// of package terms: from and fromdomain from the header From (the
// envelope sender if From has no parsable address), to from the envelope
// recipients of this mailbox (so that a Bcc copy is found by its
// address), To and Cc, day, month, has:attachment and thread. It reports
// false if the header cannot be evaluated.
func Terms(header []byte, received time.Time, envelopeFrom string, rcpts []string) ([]string, bool) {
	f, ok := parseHeader(header)
	if !ok {
		return nil, false
	}
	return terms.List(&terms.Mail{
		FromAddr:     f.fromAddr,
		EnvelopeFrom: envelopeFrom,
		EnvelopeTo:   rcpts,
		HeaderTo:     f.rcptAddrs,
		Received:     received,
		Attachment:   f.attachment,
		Thread:       f.thread,
	}), true
}
