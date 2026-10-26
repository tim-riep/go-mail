package rec

import (
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// The specification (3.6, rule 3) requires every string to be UTF-8 in
// Unicode Normalization Form C, and the decoder must reject anything
// else. Version 1.1 of the specification allows golang.org/x/text for
// this check; the version is pinned in go.mod. The package never
// normalizes on behalf of a caller: strings that are not NFC are
// rejected, so that encoding and decoding stay byte-identical.
//
// norm.NFC treats bytes that are not valid UTF-8 as opaque and reports
// them as normalized, so UTF-8 validity is checked first and separately
// (validUTF8). utf8.ValidString rejects surrogates and overlong forms.

// isNFC reports whether s is valid UTF-8 in NFC.
func isNFC(s string) bool {
	return validUTF8(s) && norm.NFC.IsNormalString(s)
}

func validUTF8(s string) bool { return utf8.ValidString(s) }
