package terms

import (
	"bytes"
	"net/mail"
)

// Limits of the header the server evaluates (5.2, 5.3): at most 1 MB and
// 500 fields; a larger header is not evaluated and the mail stays marked
// unprocessed.
const (
	MaxHeaderBytes  = 1_000_000
	MaxHeaderFields = 500
)

// HeaderOf returns the header at the start of msg as the server captures
// it from the received stream (package ingest): the bytes up to and
// including the first empty line, if that ends within the first
// MaxHeaderBytes bytes. It reports false otherwise. The client applies
// it to the content of a mail, which is the stream as received, with
// the Received field of the server first (5.2 step 2).
func HeaderOf(msg []byte) ([]byte, bool) {
	if len(msg) > MaxHeaderBytes {
		msg = msg[:MaxHeaderBytes]
	}
	i := bytes.Index(msg, []byte("\r\n\r\n"))
	if i < 0 {
		return nil, false
	}
	return msg[:i+4], true
}

// ParseHeader parses a captured header (5.3: net/mail, at most
// MaxHeaderBytes bytes and MaxHeaderFields fields). It reports false if
// the header cannot be evaluated.
func ParseHeader(h []byte) (mail.Header, bool) {
	if len(h) == 0 || len(h) > MaxHeaderBytes {
		return nil, false
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
		return nil, false
	}
	msg, err := mail.ReadMessage(bytes.NewReader(h))
	if err != nil {
		return nil, false
	}
	return msg.Header, true
}

// Addresses returns the inputs of the from: and to: terms (Mail.FromAddr
// and Mail.HeaderTo) from a parsed header, read from the values as
// received: the address of From (empty if From does not parse as one
// address; the envelope sender then stands in) and the addresses of To
// and Cc (a value that does not parse as an address list adds none).
func Addresses(hd mail.Header) (string, []string) {
	var from string
	if a, err := mail.ParseAddress(hd.Get("From")); err == nil {
		from = a.Address
	}
	var to []string
	for _, name := range []string{"To", "Cc"} {
		if v := hd.Get(name); v != "" {
			if list, err := mail.ParseAddressList(v); err == nil {
				for _, a := range list {
					to = append(to, a.Address)
				}
			}
		}
	}
	return from, to
}
