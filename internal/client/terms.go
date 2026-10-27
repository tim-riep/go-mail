package client

import (
	"net/mail"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

// metaTerms returns the term list of a mail from its checked metadata
// (6.2 step 2): for an entry marked unprocessed the client derives the
// terms itself, with the rules the server applies in ingest.Terms (5.4,
// DECISIONS D55) to the header values the metadata keep:
//
//   - from: and fromdomain: from the address in From, else from the
//     envelope sender,
//   - day: and month: from the receipt in UTC,
//   - has:attachment if the metadata say so,
//   - thread: from the Message-ID (the metadata keep neither References
//     nor In-Reply-To, so the root of a reply is its own Message-ID here,
//     not the root the server would have found; SPEC-ISSUES S23),
//   - to: from the envelope recipients of this mailbox, To and Cc, last,
//
// all lower case, cleaned, NFC, at most store.MaxTerms terms. If the
// server did not evaluate the header (HeadersParsed false), only the
// envelope counts.
//
// The code is a copy of the rules of ingest.Terms, not a call: package
// ingest imports client in its own tests, so client cannot import ingest.
// TestMetaTermsMatchServer checks both against each other.
func metaTerms(m *store.MailMeta) []string {
	var fromAddr, thread string
	rcpts := append([]string(nil), m.Recipients...)
	attachment := false
	if m.HeadersParsed {
		fromAddr = addressOf(m.From)
		for _, v := range []string{m.To, m.Cc} {
			rcpts = append(rcpts, addressesOf(v)...)
		}
		attachment = m.Attachment
		thread = firstMsgID(m.MessageID)
	}
	if fromAddr == "" {
		fromAddr = m.EnvelopeFrom
	}
	var out []string
	seen := map[string]bool{}
	add := func(t string) {
		if t == "" || seen[t] || len(out) >= store.MaxTerms {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	if fromAddr != "" {
		add(termOf("from:", fromAddr))
		if at := strings.LastIndexByte(fromAddr, '@'); at >= 0 && at < len(fromAddr)-1 {
			add(termOf("fromdomain:", fromAddr[at+1:]))
		}
	}
	u := time.UnixMilli(m.Received).UTC()
	add(termOf("day:", u.Format("2006-01-02")))
	add(termOf("month:", u.Format("2006-01")))
	if attachment {
		add("has:attachment")
	}
	if thread != "" {
		add(termOf("thread:", thread))
	}
	for _, a := range rcpts {
		add(termOf("to:", a))
	}
	return out
}

// termOf normalizes one term like the server (5.4): lower case, Unicode
// NFC, valid UTF-8 without control characters, at most store.MaxTermLen
// bytes.
func termOf(prefix, value string) string {
	return store.CleanText(strings.ToLower(prefix+value), store.MaxTermLen)
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
