package main

import (
	"testing"

	"github.com/tim-riep/go-mail/internal/witness"
)

// TestReplacingText (backlog 85): the line publish --replace-witnesses
// prints right before platform/witnesses.rec is replaced, for a regular
// working copy (old and new quorum), for a symbolic and a hard link (no
// old quorum) and without a working copy to name; each says to look at
// the file when the line after the rename does not follow.
func TestReplacingText(t *testing.T) {
	w := &witness.Witnesses{List: []witness.Key{{Name: "w1"}, {Name: "w2"}}, Min: 2}
	const look = "; fehlt die nächste Zeile, platform/witnesses.rec selbst ansehen.\n"
	for _, c := range []struct {
		got, want string
	}{
		{replacingText(&witness.Witnesses{List: w.List[:1], Min: 1}, "", w),
			"platform/witnesses.rec wird jetzt ersetzt: bisher Quorum 1 von 1 (w1), künftig Quorum 2 von 2 (w1, w2) wie im Pin" + look},
		{replacingText(nil, "a symbolic link", w),
			"platform/witnesses.rec ist ein symbolischer Link und wird jetzt durch die Zeugen des Pins ersetzt: künftig Quorum 2 von 2 (w1, w2) wie im Pin" + look},
		{replacingText(nil, "a hard link", nil),
			"platform/witnesses.rec ist ein harter Link und wird jetzt durch die Zeugen des Pins ersetzt: künftig Zeugen und Quorum wie im Pin" + look},
		{replacingText(nil, "", w), "platform/witnesses.rec wird jetzt ersetzt: künftig Quorum 2 von 2 (w1, w2) wie im Pin" + look},
	} {
		if c.got != c.want {
			t.Fatalf("%q, want %q", c.got, c.want)
		}
	}
}
