package words

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/shamir"
)

func TestNormalize(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{" \t\r\n ", nil},
		{"abandon", []string{"abandon"}},
		{"ABANDON Ability", []string{"abandon", "ability"}},
		{"  abandon\tability\r\nable  ", []string{"abandon", "ability", "able"}},
		// Unicode white space: no-break space, NEL, em space, ideographic
		// space, line separator.
		{"abandon ability\u0085able about　above absent", []string{"abandon", "ability", "able", "about", "above", "absent"}},
		// Compatibility forms: ligature fi, fullwidth letters, Kelvin sign.
		{"ﬁle", []string{"file"}},
		{"ＡＢＬＥ", []string{"able"}},
		{"Kite", []string{"kite"}},
		// Mixed: upper case ligature word after a tab.
		{"\tFINK ﬁnal", []string{"fink", "final"}},
	} {
		if got := Normalize(c.in); len(got) != len(c.want) || (len(got) > 0 && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Composed and decomposed umlauts normalize alike (NFKD), upper and
	// lower case alike.
	a, b, c := Normalize("Äpfel"), Normalize("Äpfel"), Normalize("äpfel")
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a, c) || a[0] != "äpfel" {
		t.Fatalf("umlauts: %q %q %q", a, b, c)
	}
	// Invalid UTF-8 never matches a word.
	if got := Normalize("ab\xffle"); len(got) != 1 || Check(got) == nil {
		t.Fatalf("invalid UTF-8: %q", got)
	}
}

func TestOne(t *testing.T) {
	if w, err := One("  Zoo\n"); err != nil || w != "zoo" {
		t.Fatal(w, err)
	}
	for _, in := range []string{"", "  ", "zoo zoo", "a b"} {
		if _, err := One(in); !errors.Is(err, ErrNotOneWord) {
			t.Fatalf("One(%q): %v", in, err)
		}
	}
}

func TestCheck(t *testing.T) {
	if err := Check(Normalize("Abandon ABILITY able")); err != nil {
		t.Fatal(err)
	}
	if err := Check(nil); err != nil {
		t.Fatal(err)
	}
	// Abbreviations to four letters are not accepted, and the error names
	// the position, never the word.
	err := Check(Normalize("abandon abil able"))
	if !errors.Is(err, ErrUnknownWord) || !strings.Contains(err.Error(), "word 2") || strings.Contains(err.Error(), "abil") {
		t.Fatalf("abbreviation: %v", err)
	}
	if err := Check([]string{"Zoo"}); !errors.Is(err, ErrUnknownWord) {
		t.Fatal("Check must be exact")
	}
}

// TestSeedAndShareInput types a seed and a share sloppily and checks that
// the strict decoders of keys and shamir accept the normalized words.
func TestSeedAndShareInput(t *testing.T) {
	seed, err := keys.NewSeed(nil)
	if err != nil {
		t.Fatal(err)
	}
	ws, _ := seed.Words()
	typed := "  " + strings.ToUpper(strings.Join(ws[:12], "\t")) + "\r\n" + strings.Join(ws[12:], "  ") + "\n"
	got, err := keys.SeedFromWords(Normalize(typed))
	if err != nil || *got != *seed {
		t.Fatalf("seed: %v", err)
	}
	shares, err := shamir.Split(seed[:], 2, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	sw := shares[1].Words()
	// Fullwidth forms of the first word, upper case for the rest.
	first := strings.Map(func(r rune) rune { return r - 'a' + 'ａ' }, sw[0])
	typed = first + "  " + strings.ToUpper(strings.Join(sw[1:], " \n"))
	s, err := shamir.ShareFromWords(Normalize(typed))
	if err != nil || s.Index != shares[1].Index || s.Y != shares[1].Y {
		t.Fatalf("share: %v", err)
	}
}

func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"", "abandon ability", "ﬁle ＡBLE", "Ä\tÄ", "\xff\xfe", "KΩİ"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		ws := Normalize(in)
		for _, w := range ws {
			if w == "" || strings.IndexFunc(w, unicode.IsSpace) >= 0 {
				t.Fatalf("word with white space: %q", w)
			}
			if strings.ToLower(w) != w {
				t.Fatalf("word not in lower case: %q", w)
			}
		}
		if len(ws) > 0 {
			// Every word of the list stays itself.
			for _, w := range ws {
				if _, ok := keys.LookupWord(w); ok && !norm.NFKD.IsNormalString(w) {
					t.Fatalf("list word not in NFKD: %q", w)
				}
			}
		}
		if _, err := One(in); (err == nil) != (len(ws) == 1) {
			t.Fatalf("One disagrees with Normalize on %q", in)
		}
		if err := Check(ws); err != nil && !errors.Is(err, ErrUnknownWord) {
			t.Fatal(err)
		}
	})
}
