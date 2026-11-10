package client

import (
	"errors"
	"io/fs"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tim-riep/go-mail/internal/keys"
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
// Index, and Search for a from:, fromdomain: or to: term, take the terms
// of such a mail from unprocessedTerms, which reads from: and to: from
// the mail itself when a value may be cut.
func metaTerms(m *store.MailMeta) []string {
	in := metaInput(m)
	return terms.List(&in)
}

// metaInput returns the inputs of the term list of a mail from its
// checked metadata (see metaTerms).
func metaInput(m *store.MailMeta) terms.Mail {
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
	return in
}

// metaCut reports whether the metadata of a mail whose header the server
// evaluated may hold a cut From, To or Cc value. The server stores them
// with store.CleanText, which cuts in two places:
//
//   - at the end, at a character boundary at most store.MaxTextLen bytes
//     long, so a value cut there is longer than store.MaxTextLen -
//     utf8.UTFMax bytes;
//   - first, the raw value at 4*store.MaxTextLen+16 bytes, before every
//     run of invalid UTF-8 becomes one U+FFFD (utf8.RuneError), so a
//     value cut there can be of any length; it holds U+FFFD, though.
//     Without invalid UTF-8 the steps after that cut shrink a value at
//     most to a third (a C1 control or bidirectional character becomes a
//     space, NFC composes a Hangul syllable of three jamo), so it stays
//     longer than store.MaxTextLen and is cut at the end as well.
//
// A value that holds U+FFFD without being cut only makes the mail be
// opened without need. The envelope sender is not looked at: smtpd takes
// at most 254 bytes (parsePath), below its limit in the metadata
// (store.MaxAddressLen), and the mail does not hold it.
func metaCut(m *store.MailMeta) bool {
	cut := func(v string) bool {
		return len(v) > store.MaxTextLen-utf8.UTFMax || strings.ContainsRune(v, utf8.RuneError)
	}
	return m.HeadersParsed && (cut(m.From) || cut(m.To) || cut(m.Cc))
}

// unprocessedTerms returns the terms of mail m in folder for an entry
// marked unprocessed (6.2 step 2, 6.3 step 4): those of metaTerms, and if
// a header value of the metadata may be cut (metaCut, AUDIT R27 (b)),
// with from: and to: read from the header of the mail itself, so that
// they are the server's (task 27, Nr. 47). The mail is opened with the
// checks of Read (openMail: SHA-256 against the signed metadata, mail
// header, decryption), its header captured and parsed like the server
// does (terms.HeaderOf, terms.ParseHeader) and its addresses taken with
// terms.Addresses; everything else, the thread root included (TODO(Q12)),
// stays as the metadata give it. Only the terms leave this function. The
// buffer content is wiped after use; the copies net/mail makes of the
// header values (the strings of mail.Header, the buffer of its reader)
// stay in memory until the garbage collector frees them (AUDIT R32).
//
// If a check of openMail fails on the bytes of the mail file (hash,
// format and header of the envelope, decryption; a file larger than
// store.MaxMailFile, which is never a valid envelope) or the header
// cannot be evaluated (errHeader), the result is the terms of the
// metadata, as before, with one warning that names the mail ID and a
// fixed cause only (warnCause): those bytes stay as they are, so Index
// indexes the entry with these terms and deletes the marker. Any other
// failure (the file is not there, is not a regular file or cannot be
// read, the keys of the epoch are not available) gives the terms of the
// metadata and the error: Index leaves the marker for a later run, Search
// takes the terms of the metadata meanwhile. Index and Search only get
// here for a mail whose file they listed (mailFolders, pendingMeta), so a
// file that is not there went between the listing and the reading, a
// race; it is not warned about. Every other such failure is, with the
// mail ID and a fixed cause: "Datei nicht lesbar" if the file cannot be
// read (fileUnreadable), else that of warnCause.
func (c *Client) unprocessedTerms(ch *chain, folder store.ID, m *Mail) ([]string, error) {
	out := metaTerms(m.Meta)
	if !metaCut(m.Meta) {
		return out, nil
	}
	if unprocessedOpenHook != nil {
		unprocessedOpenHook(m.ID)
	}
	content, checked, err := c.openMail(ch, folder, m, false)
	if err == nil {
		defer keys.Wipe(content)
		var hd mail.Header
		h, ok := terms.HeaderOf(content)
		if ok {
			hd, ok = terms.ParseHeader(h)
		}
		if ok {
			in := metaInput(m.Meta)
			in.FromAddr, in.HeaderTo = terms.Addresses(hd)
			return terms.List(&in), nil
		}
		err, checked = errHeader, true
	}
	if !checked {
		if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, fs.ErrNotExist) {
			cause := warnCause(err)
			if fileUnreadable(err) {
				cause = "Datei nicht lesbar"
			}
			c.warn("WARNUNG: Mail %s lässt sich nicht lesen: %s. Ihr Eintrag in pending/ bleibt für einen späteren Index-Lauf liegen; bis dahin gelten die Suchbegriffe ihrer Metadaten.", m.ID, cause)
		}
		return out, err
	}
	c.warn("WARNUNG: Suchbegriffe der Mail %s nur aus ihren Metadaten: %s.", m.ID, warnCause(err))
	return out, nil
}

// fileUnreadable reports whether err of openMail is one of reading the
// mail file that is no verdict on its bytes: a file that is not a regular
// one (store.ErrNotRegular) or an error of the system on its open, stat
// or read (*fs.PathError: EACCES, EIO, ELOOP, ...), whose text names the
// path. warnCause knows neither and gives "Prüfung fehlgeschlagen".
// openMail returns no *fs.PathError for the epoch or its keys: keysFor
// wraps the error of reading the wrap with %v (ErrWrap).
func fileUnreadable(err error) bool {
	var pe *fs.PathError
	return errors.Is(err, store.ErrNotRegular) || errors.As(err, &pe)
}

// unprocessedOpenHook is called by tests each time unprocessedTerms opens
// a mail, with its ID.
var unprocessedOpenHook func(id store.ID)

// errHeader: the header of a mail whose metadata say it was evaluated
// cannot be evaluated by the rules of the server (unprocessedTerms).
var errHeader = errors.New("client: header of the mail cannot be evaluated")

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
