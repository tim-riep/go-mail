package client

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
)

// TestWarnUnreadable: the warnings of one call about the mails it cannot
// read (unreadable, warnUnreadable). Below unreadableTogether mails one
// per mail, with its own cause, in the order met; from there on one
// warning with the number of mails (each counted once, also those beyond
// the IDs kept), every distinct cause in the order met (also one met
// only after the IDs kept) and the first unreadableNamed IDs in the
// order met (review 28C, F6: mutants MH, MB and MC).
func TestWarnUnreadable(t *testing.T) {
	const other = "Epochenschlüssel nicht verfügbar"
	ids := make([]store.ID, 14)
	for i := range ids {
		var err error
		if ids[i], err = store.NewID(nil); err != nil {
			t.Fatal(err)
		}
	}
	single := func(id store.ID, cause string) string {
		return "WARNUNG: Mail " + id.String() + " lässt sich nicht lesen: " + cause +
			". Ihr Eintrag in pending/ bleibt für einen späteren Index-Lauf liegen; bis dahin gelten die Suchbegriffe ihrer Metadaten."
	}
	together := func(n int, causes string, first []store.ID) string {
		var named []string
		for _, id := range first {
			named = append(named, id.String())
		}
		return fmt.Sprintf("WARNUNG: %d Mails lassen sich nicht lesen (%s); die ersten: %s. "+
			"Ihre Einträge in pending/ bleiben für einen späteren Index-Lauf liegen; bis dahin gelten die Suchbegriffe ihrer Metadaten.",
			n, causes, strings.Join(named, ", "))
	}
	for _, tc := range []struct {
		name   string
		mails  []int // indexes into ids, in the order met
		causes func(i int) string
		want   []string
	}{
		{"none", nil, nil, nil},
		{"nine, two causes", []int{3, 1, 4, 1, 5, 0, 2, 6, 8, 7}, func(i int) string {
			if i%2 == 1 {
				return other
			}
			return causeUnreadable
		}, []string{
			single(ids[3], other), single(ids[1], other), single(ids[4], causeUnreadable), single(ids[5], other),
			single(ids[0], causeUnreadable), single(ids[2], causeUnreadable), single(ids[6], causeUnreadable),
			single(ids[8], causeUnreadable), single(ids[7], other),
		}},
		{"ten", []int{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}, func(int) string { return causeUnreadable },
			[]string{together(10, causeUnreadable, []store.ID{ids[9], ids[8], ids[7], ids[6], ids[5]})}},
		{"fourteen, twice each, the second cause after the tenth mail",
			[]int{13, 0, 12, 1, 11, 2, 10, 3, 9, 4, 5, 6, 7, 8, 13, 0, 12, 1, 11, 2, 10, 3, 9, 4, 5, 6, 7, 8},
			func(i int) string {
				if i == 6 || i == 8 {
					return other
				}
				return causeUnreadable
			},
			[]string{together(14, causeUnreadable+"; "+other, []store.ID{ids[13], ids[0], ids[12], ids[1], ids[11]})}},
		{"twelve, two causes from the first",
			[]int{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
			func(i int) string {
				if i == 2 {
					return other
				}
				return causeUnreadable
			},
			[]string{together(12, other+"; "+causeUnreadable, []store.ID{ids[2], ids[3], ids[4], ids[5], ids[6]})}},
	} {
		var got []string
		c := &Client{cfg: Config{Warn: func(s string) { got = append(got, s) }}}
		var u unreadable
		for _, i := range tc.mails {
			u.add(ids[i], tc.causes(i))
		}
		c.warnUnreadable(&u)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: warnings\n%q\nwant\n%q", tc.name, got, tc.want)
		}
	}
}
