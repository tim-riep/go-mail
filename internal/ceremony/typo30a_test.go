package ceremony

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/shamir"
)

// swapWords returns a copy of the words of a share with word i swapped
// with the first later word for which shamir.ShareFromWords reports
// shamir.ErrChecksum. Two equal words, swapped, give the same share
// (task 30A).
func swapWords(t testing.TB, words []string, i int) []string {
	t.Helper()
	for j := i + 1; j < len(words); j++ {
		ws := append([]string(nil), words...)
		ws[i], ws[j] = ws[j], ws[i]
		if _, err := shamir.ShareFromWords(ws); errors.Is(err, shamir.ErrChecksum) {
			return ws
		}
	}
	t.Fatalf("no swap with word %d breaks the checksum", i+1)
	return nil
}

// TestSwapWords: swapWords breaks the checksum of shares whose word i+1
// equals a later word j+1, where swapping the two changes nothing, for
// i = 0 (TestInitProbeFails, cmd/gomail-ceremony) and i = 3
// (cmd/gomailctl) and every later j up to the last word, so that a helper
// swapping with any fixed later word unchecked fails here (task 33C;
// before, only words 1 and 2); and of random shares.
func TestSwapWords(t *testing.T) {
	for _, i := range []int{0, 3} {
		for j := i + 1; j < shamir.ShareWords; j++ {
			checkSwap(t, fmt.Sprintf("words %d and %d equal", i+1, j+1), equalWordsShare(t, i, j), i)
		}
	}
	secret := sha256.Sum256([]byte("task 30A share"))
	shares, err := shamir.Split(secret[:], 2, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	for n, s := range shares {
		for _, i := range []int{0, 3} {
			checkSwap(t, fmt.Sprintf("random share %d", n+1), s.Words(), i)
		}
	}
}

// checkSwap fails unless swapWords(t, words, i) swaps word i+1 with one
// later word and shamir.ShareFromWords reports shamir.ErrChecksum for the
// result; what names the share.
func checkSwap(t *testing.T, what string, words []string, i int) {
	t.Helper()
	got := swapWords(t, words, i)
	if _, err := shamir.ShareFromWords(got); !errors.Is(err, shamir.ErrChecksum) {
		t.Fatalf("%s, swap with word %d: %v", what, i+1, err)
	}
	if len(got) != len(words) {
		t.Fatalf("%s: %d words, want %d", what, len(got), len(words))
	}
	var changed []int
	for j := range words {
		if got[j] != words[j] {
			changed = append(changed, j)
		}
	}
	if len(changed) != 2 || changed[0] != i || got[i] != words[changed[1]] || got[changed[1]] != words[i] {
		t.Fatalf("%s, swap with word %d: words %v (from 0) changed", what, i+1, changed)
	}
}

// equalWordsShare returns the words of a share whose words i+1 and j+1
// are equal (i < j; word i+1 ends before bit 160). The binary form of a
// share (version 1, identifier, threshold, index, y) has 296 bits; the
// checksum, the first 4 bytes of SHA-256("gomail/v1/share" || 0x00 ||
// binary form), and two zero bits follow. Word i+1 is copied to the bits
// of word j+1 in the binary form, and its bits facing the two zero bits
// are cleared; where word j+1 lies in the checksum, bytes 20 to 23 (in y,
// apart from both words) count up until it matches. The words are those
// of Share.Words.
func equalWordsShare(t *testing.T, i, j int) []string {
	t.Helper()
	const payload = shamir.ShareSize * 8
	if i >= j || i*11+11 > 160 || j >= shamir.ShareWords {
		t.Fatalf("words %d and %d", i+1, j+1)
	}
	bit := func(b []byte, n int) byte {
		if n/8 >= len(b) {
			return 0
		}
		return b[n/8] >> (7 - n%8) & 1
	}
	set := func(b []byte, n int, x byte) {
		b[n/8] = b[n/8]&^(1<<(7-n%8)) | x<<(7-n%8)
	}
	word := func(b []byte, k int) int {
		v := 0
		for n := k * 11; n < k*11+11; n++ {
			v = v<<1 | int(bit(b, n))
		}
		return v
	}
	// Threshold 2 and index 0x81: word 1 copied to word 3 makes the
	// threshold at least 4, to word 4 clears all bits of the index but
	// the first.
	p := make([]byte, shamir.ShareSize)
	p[0], p[1], p[2], p[3], p[4] = 1, 0x5a, 0x3c, 2, 0x81
	y := sha256.Sum256([]byte("task 33C share"))
	copy(p[5:], y[:])
	for k := 0; k < 11; k++ {
		from, to := i*11+k, j*11+k
		switch {
		case to < payload:
			set(p, to, bit(p, from))
		case to >= payload+32:
			set(p, from, 0)
		}
	}
	for n := uint32(1); ; n++ {
		h := sha256.New()
		h.Write([]byte("gomail/v1/share\x00"))
		h.Write(p)
		b := h.Sum(append([]byte(nil), p...))[:shamir.ShareSize+4]
		if word(b, i) == word(b, j) {
			break
		}
		if j*11+11 <= payload || n == 1<<20 {
			t.Fatalf("words %d and %d: no match", i+1, j+1)
		}
		binary.BigEndian.PutUint32(p[20:24], n)
	}
	s, err := shamir.ShareFromBytes(p)
	if err != nil {
		t.Fatalf("words %d and %d: %v", i+1, j+1, err)
	}
	words := s.Words()
	if words[i] != words[j] {
		t.Fatalf("words %d and %d differ: %q %q", i+1, j+1, words[i], words[j])
	}
	if _, err := shamir.ShareFromWords(words); err != nil {
		t.Fatalf("words %d and %d: %v", i+1, j+1, err)
	}
	return words
}

// TestSwapWordsCopies: the copies of swapWords in cmd/gomail-ceremony and
// cmd/gomailctl (the test packages share no helper) are, comments aside,
// the function above that TestSwapWords tests, with the same imports for
// errors and shamir (task 33C).
func TestSwapWordsCopies(t *testing.T) {
	imports := map[string]string{
		"errors": "errors",
		"shamir": "github.com/tim-riep/go-mail/internal/shamir",
	}
	var want string
	for _, name := range []string{
		"typo30a_test.go",
		"../../cmd/gomail-ceremony/typo30a_test.go",
		"../../cmd/gomailctl/typo30a_test.go",
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.FromSlash(name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			as := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				as = imp.Name.Name
			}
			if w, ok := imports[as]; ok && w != path {
				t.Errorf("%s: %s is %q, want %q", name, as, path, w)
			}
		}
		var got []string
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "swapWords" {
				var b bytes.Buffer
				if err := format.Node(&b, fset, fd); err != nil {
					t.Fatal(err)
				}
				got = append(got, b.String())
			}
		}
		switch {
		case len(got) != 1:
			t.Errorf("%s: %d functions swapWords, want 1", name, len(got))
		case want == "":
			want = got[0]
		case got[0] != want:
			t.Errorf("%s: swapWords\n%s\nwant (internal/ceremony)\n%s", name, got[0], want)
		}
	}
	if want == "" {
		t.Fatal("no swapWords in internal/ceremony")
	}
}
