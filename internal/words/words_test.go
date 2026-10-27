package words

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
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
		if got, err := Normalize(c.in); err != nil || len(got) != len(c.want) || (len(got) > 0 && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Composed and decomposed umlauts normalize alike (NFKD), upper and
	// lower case alike.
	a, b, c := nn(t, "Äpfel"), nn(t, "Äpfel"), nn(t, "äpfel")
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a, c) || a[0] != "äpfel" {
		t.Fatalf("umlauts: %q %q %q", a, b, c)
	}
	// Invalid UTF-8 never matches a word.
	if got := nn(t, "ab\xffle"); len(got) != 1 || Check(got) == nil {
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
	if err := Check(nn(t, "Abandon ABILITY able")); err != nil {
		t.Fatal(err)
	}
	if err := Check(nil); err != nil {
		t.Fatal(err)
	}
	// Abbreviations to four letters are not accepted, and the error names
	// the position, never the word.
	err := Check(nn(t, "abandon abil able"))
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
	got, err := keys.SeedFromWords(nn(t, typed))
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
	s, err := shamir.ShareFromWords(nn(t, typed))
	if err != nil || s.Index != shares[1].Index || s.Y != shares[1].Y {
		t.Fatalf("share: %v", err)
	}
}

func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"", "abandon ability", "ﬁle ＡBLE", "Ä\tÄ", "\xff\xfe", "KΩİ"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		ws, err := Normalize(in)
		if err != nil {
			if !errors.Is(err, ErrTooLong) || strings.Contains(err.Error(), in) && in != "" {
				t.Fatal(err)
			}
			if _, err := One(in); !errors.Is(err, ErrTooLong) {
				t.Fatalf("One accepts what Normalize refuses: %v", err)
			}
			return
		}
		if len(ws) > MaxTokens {
			t.Fatalf("%d words", len(ws))
		}
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

// nn normalizes s and fails the test on an error.
func nn(t testing.TB, s string) []string {
	t.Helper()
	ws, err := Normalize(s)
	if err != nil {
		t.Fatal(err)
	}
	return ws
}

// TestLimits: input with more than MaxTokens words or MaxInput bytes is
// refused before it is normalized, and so is input that NFKD splits into
// more than MaxTokens words (U+00A8 DIAERESIS decomposes into a space and
// a combining mark); the errors never name the input (task 15b point 5).
func TestLimits(t *testing.T) {
	ok := strings.TrimSpace(strings.Repeat("zoo ", MaxTokens))
	if ws := nn(t, ok); len(ws) != MaxTokens {
		t.Fatalf("%d words", len(ws))
	}
	for name, in := range map[string]string{
		"words":      ok + " zoo",
		"bytes":      strings.Repeat("z", MaxInput+1),
		"after NFKD": strings.Repeat("a¨", MaxTokens+1),
	} {
		_, err := Normalize(in)
		if !errors.Is(err, ErrTooLong) || strings.Contains(err.Error(), "zoo") || strings.Contains(err.Error(), "zz") {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := One(in); !errors.Is(err, ErrTooLong) {
			t.Fatalf("%s: One: %v", name, err)
		}
	}
	if got := countFields(strings.Repeat("a ", 10*MaxTokens), MaxTokens); got != MaxTokens+1 {
		t.Fatalf("countFields stops at %d", got)
	}
	// List: the elements may hold several words; the bounds hold for the
	// elements and for their total.
	if ws, err := List([]string{" Abandon  ability", "ABLE"}); err != nil || strings.Join(ws, " ") != "abandon ability able" {
		t.Fatal(ws, err)
	}
	many := make([]string, MaxTokens+1)
	for i := range many {
		many[i] = "zoo"
	}
	if _, err := List(many); !errors.Is(err, ErrTooLong) {
		t.Fatal(err)
	}
	if _, err := List([]string{strings.Repeat("z", MaxInput/2), strings.Repeat("z", MaxInput/2)}); !errors.Is(err, ErrTooLong) {
		t.Fatal(err)
	}
}

// TestShamirVectors: the share words of the vectors of package shamir,
// typed sloppily (upper case, extra and other white space, line breaks),
// normalize to exactly the words of the vector, and shamir decodes them
// to exactly the bytes of the vector (task 15b point 5: the input of the
// command line and the ceremony yields the same word list and encoding as
// shamir itself).
func TestShamirVectors(t *testing.T) {
	raw, err := os.ReadFile("../shamir/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Splits []struct {
			Name   string
			Shares []struct {
				Index uint8
				Bytes string
				Words string
			}
		}
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, sp := range v.Splits {
		for _, sh := range sp.Shares {
			want := strings.Fields(sh.Words)
			typed := "  " + strings.ToUpper(strings.Join(want[:10], "\t")) + "\r\n" + strings.Join(want[10:], " 　 ") + "\n"
			got := nn(t, typed)
			if strings.Join(got, " ") != sh.Words {
				t.Fatalf("%s share %d: words differ", sp.Name, sh.Index)
			}
			lst, err := List([]string{strings.Join(want[:15], " "), strings.ToUpper(strings.Join(want[15:], "  "))})
			if err != nil || strings.Join(lst, " ") != sh.Words {
				t.Fatalf("%s share %d: list: %v", sp.Name, sh.Index, err)
			}
			s, err := shamir.ShareFromWords(got)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(s.Bytes()) != sh.Bytes || s.Index != sh.Index {
				t.Fatalf("%s share %d: bytes differ", sp.Name, sh.Index)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("no vectors")
	}
}
