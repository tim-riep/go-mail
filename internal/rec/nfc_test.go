package rec

import (
	"testing"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// rs builds a string from code points. Test strings are written this way
// so that combining marks and jamo are visible as numbers in the source.
func rs(r ...rune) string { return string(r) }

// TestUnicodeVersion records which Unicode version the normalization
// tables of golang.org/x/text implement. A mismatch with the toolchain's
// unicode package is not an error (the decoder uses only x/text), but it
// is worth knowing when the dependency is updated.
func TestUnicodeVersion(t *testing.T) {
	if norm.Version != unicode.Version {
		t.Logf("x/text normalizes by Unicode %s, the toolchain's unicode package is %s", norm.Version, unicode.Version)
	}
}

// TestIsNFC keeps the cases of the phase 0 implementation. The "yes"
// cases include strings that pass the NFC quick check only as "maybe"
// and strings that need a full normalization to confirm; the "no" cases
// include singletons, out-of-order marks, composable pairs and jamo
// sequences, and invalid UTF-8.
func TestIsNFC(t *testing.T) {
	yes := []string{
		"",
		"abc",
		rs('G', 'r', 0x00fc, 0x00df, 'e'), // precomposed ü and ß
		rs(0x00e9),                        // é precomposed
		rs('q', 0x0301),                   // q + acute: no composite exists
		rs('q', 0x0323, 0x0301),           // q + dot below (220) + acute (230): ordered, no composites
		rs(0xac00),                        // Hangul syllable
		rs(0x1100),                        // lone L jamo
		rs(0x1161),                        // lone V jamo (quick check Maybe, nothing to compose with)
		rs(0x1100, ' ', 0x1161),           // L, space, V: the space blocks composition
		rs(0xac01),                        // LVT syllable
		rs(0x0e01, 0x0e34),                // Thai consonant + vowel sign, no composite
		rs(0x0b47, ' ', 0x0b3e),           // Oriya pair separated by a starter
		rs(0x1e0d, 0x0307),                // ḍ + dot above: NFC of d + dot below + dot above
		rs(0x1ea0, 0x030a),                // Ạ + ring: NFC of Å + dot below
		rs(0x1e69, 0x0316),                // ṩ + 0316 (220): NFC although 220 < 230 (recomposition yields the same)
		rs(0x05d1, 0x05bc, 0x05bf),        // Hebrew bet + dagesh (21) + rafe (23): FB31 is excluded
		rs(0x1f600),                       // emoji
		rs(0x03a9),                        // Omega
		rs(0xfb01),                        // fi ligature: compatibility decomposition only
		rs(0x0f71, 0x0f72),                // Tibetan: 0F73 is excluded, so the pair stays
		rs(0x0f71, 0x0f72, 0x0f74),        // 0F75 is excluded too
	}
	no := []string{
		rs('e', 0x0301),            // composes to é
		rs(0x212b),                 // ANGSTROM SIGN, singleton
		rs(0x2126),                 // OHM SIGN, singleton
		rs(0x0344),                 // COMBINING GREEK DIALYTIKA TONOS, non-starter decomposition
		rs(0x1100, 0x1161),         // L+V jamo compose to a syllable
		rs(0xac00, 0x11a8),         // LV + T compose
		rs(0x1100, 0x1161, 0x11a8), // L+V+T
		rs(0x0b47, 0x0b3e),         // Oriya vowel signs compose to 0B4B
		rs('q', 0x0301, 0x0323),    // marks out of canonical order (230 before 220)
		rs('s', 0x0323, 0x0307),    // s + dot below composes to ṣ
		rs(0x1e63, 0x0307),         // ṣ + dot above composes to ṩ
		rs('A', 0x030a, 0x0323),    // A + ring composes to Å
		rs(0x1e0b, 0x0323),         // ḋ + dot below: NFC is ḍ + dot above
		rs(0x00fc, 0x0323),         // ü + dot below: NFC is ụ + diaeresis
		rs(0x00c5, 0x0323),         // Å + dot below: NFC is Ạ + ring
		rs('A', 0x0334, 0x0301),    // A + overlay (1) + acute: acute is not blocked, composes to Á
		rs('A', 0x0300, 0x0301),    // A + grave composes to À
		rs(0x0391, 0x0301),         // Greek Alpha + acute composes
		rs(0x0415, 0x0308),         // Cyrillic Е + diaeresis composes to Ё
		rs(0x1e0d, 0x0307, 0x0323), // 0307 (230) then 0323 (220): out of order
		rs(0x0f73),                 // Tibetan vowel sign, excluded composite (quick check No)
		"\xff",                     // invalid UTF-8
		"\xed\xa0\x80",             // surrogate
		"\xc0\x80",                 // overlong NUL
		"a\xffb",                   // invalid byte inside otherwise normalized text
	}
	for _, s := range yes {
		if !isNFC(s) {
			t.Errorf("isNFC(%+q) = false, want true", s)
		}
	}
	for _, s := range no {
		if isNFC(s) {
			t.Errorf("isNFC(%+q) = true, want false", s)
		}
	}
}

// TestInvalidUTF8NotNormalizedByXText documents why validUTF8 is checked
// separately: x/text reports invalid bytes as normalized.
func TestInvalidUTF8NotNormalizedByXText(t *testing.T) {
	for _, s := range []string{"\xff", "\xed\xa0\x80", "\xc0\x80"} {
		if !norm.NFC.IsNormalString(s) {
			t.Logf("x/text now rejects %+q itself; the separate check stays", s)
		}
		if validUTF8(s) {
			t.Errorf("validUTF8(%+q) = true", s)
		}
	}
}

// TestNormalizeNFCSamples keeps the phase 0 normalization samples as a
// check on the dependency: the expected NFC form of each input.
func TestNormalizeNFCSamples(t *testing.T) {
	cases := []struct{ in, want string }{
		{rs('e', 0x0301), rs(0x00e9)},
		{rs(0x1e0b, 0x0323), rs(0x1e0d, 0x0307)},
		{rs(0x00fc, 0x0323), rs(0x1ee5, 0x0308)},
		{rs(0x00c5, 0x0323), rs(0x1ea0, 0x030a)},
		{rs(0x1100, 0x1161, 0x11a8), rs(0xac01)},
		{rs(0xac00, 0x11a8), rs(0xac01)},
		{rs(0x212b), rs(0x00c5)},
		{rs(0x0344), rs(0x0308, 0x0301)},
		{rs('s', 0x0307, 0x0323), rs(0x1e69)},
		{rs(0x1e69, 0x0316), rs(0x1e69, 0x0316)},
		{rs(0x0f73), rs(0x0f71, 0x0f72)},
		{rs('A', 0x0334, 0x0301), rs(0x00c1, 0x0334)},
		{rs(0xac01), rs(0xac01)},
	}
	for _, c := range cases {
		got := norm.NFC.String(c.in)
		if got != c.want {
			t.Errorf("nfc(%+q) = %+q, want %+q", c.in, got, c.want)
		}
		if isNFC(c.want) != true {
			t.Errorf("isNFC(%+q) = false for an NFC string", c.want)
		}
		if (c.in == c.want) != isNFC(c.in) {
			t.Errorf("isNFC(%+q) disagrees with normalization", c.in)
		}
	}
}
