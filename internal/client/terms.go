package client

import (
	"net/mail"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/terms"
)

// metaTerms returns the term list of a mail from its checked metadata
// (6.2 step 2): for an entry marked unprocessed the client derives the
// terms itself with the rules of package terms, which the server applies
// in ingest.Terms (5.4, DECISIONS D55), from the header values the
// metadata keep: From (decoded; else the envelope sender), the envelope
// recipients of this mailbox, To and Cc, the receipt, the attachment
// flag and, as the thread root, the Message-ID (the metadata keep
// neither References nor In-Reply-To, so the root of a reply is its own
// Message-ID here, not the root the server would have found; SPEC-ISSUES
// S23, TODO(Q12)). If the server did not evaluate the header
// (HeadersParsed false), only the envelope counts. Values the metadata
// cut (package terms) can make the from: and to: terms differ from the
// server's; TestMetaTermsMatchServer checks both against each other.
func metaTerms(m *store.MailMeta) []string {
	in := terms.Mail{
		EnvelopeFrom: m.EnvelopeFrom,
		EnvelopeTo:   m.Recipients,
		Received:     time.UnixMilli(m.Received),
	}
	if m.HeadersParsed {
		in.FromAddr = addressOf(m.From)
		for _, v := range []string{m.To, m.Cc} {
			in.HeaderTo = append(in.HeaderTo, addressesOf(v)...)
		}
		in.Attachment = m.Attachment
		in.Thread = terms.ThreadRoot("", "", m.MessageID)
	}
	return terms.List(&in)
}

// addressOf returns the address of a decoded header value (the metadata
// hold From after RFC 2047 decoding): net/mail first, else the last
// "<...@...>" token.
func addressOf(v string) string {
	if v == "" {
		return ""
	}
	if a, err := mail.ParseAddress(v); err == nil {
		return a.Address
	}
	if l := bracketed(v); len(l) > 0 {
		return l[len(l)-1]
	}
	return ""
}

// addressesOf returns the addresses of a decoded address list.
func addressesOf(v string) []string {
	if v == "" {
		return nil
	}
	if list, err := mail.ParseAddressList(v); err == nil {
		out := make([]string, 0, len(list))
		for _, a := range list {
			out = append(out, a.Address)
		}
		return out
	}
	return bracketed(v)
}

// bracketed returns the "<...@...>" tokens of v without the brackets.
func bracketed(v string) []string {
	var out []string
	for {
		i := strings.IndexByte(v, '<')
		if i < 0 {
			return out
		}
		j := strings.IndexByte(v[i:], '>')
		if j < 0 {
			return out
		}
		if a := v[i+1 : i+j]; strings.Contains(a, "@") && !strings.ContainsAny(a, " <") {
			out = append(out, a)
		}
		v = v[i+j+1:]
	}
}
