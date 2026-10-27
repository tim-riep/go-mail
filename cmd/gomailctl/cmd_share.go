package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tim-riep/go-mail/internal/client"
)

// gomailctl mailbox share <mailbox-id> <user-id> [--from <epoch>] [--to <epoch>]
// gomailctl mailbox revoke <mailbox-id> <user-id>
//
// (9.2, 2.5). share without --to makes the user a member from a new
// epoch on (member-added) and with --from also wraps the existing epochs
// from that one; with --to it wraps only the epochs of a past period
// (no member). revoke deletes the user's wraps and begins a new epoch
// without it. "Zugriff entziehen" and "Daten löschen" are never combined
// (2.5): revoke deletes no mails.

func runShare(e *env, o *options, _ client.Config, c *client.Client) int {
	mbx, user := o.ids[0], o.ids[1]
	wrapped, err := c.Share(mbx, user, client.ShareOptions{From: o.from, To: o.to})
	if len(wrapped) > 0 {
		fmt.Fprintf(e.stdout, "Verpackt für %s: Epochen %s.\n", user, epochList(wrapped))
	}
	if err != nil {
		return e.fail(err)
	}
	if o.to != 0 {
		fmt.Fprintf(e.stdout, "%s liest %s für den Zeitraum der Epochen %d bis %d (kein Mitglied).\n", user, mbx, max(o.from, 1), o.to)
	} else {
		fmt.Fprintf(e.stdout, "%s ist Mitglied von %s ab der neuen Epoche.\n", user, mbx)
	}
	return 0
}

func runRevoke(e *env, o *options, _ client.Config, c *client.Client) int {
	mbx, user := o.ids[0], o.ids[1]
	if err := c.Revoke(mbx, user); err != nil {
		return e.fail(err)
	}
	fmt.Fprintf(e.stdout, "Zugriff von %s auf %s entzogen: eine neue Epoche ohne dieses Mitglied hat begonnen.\n", user, mbx)
	fmt.Fprintln(e.stdout, "Bereits gelesene oder gespeicherte Mails können bei ihm bleiben; gelöscht wurde nichts.")
	return 0
}

// epochList joins epoch numbers with commas.
func epochList(ns []uint32) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(s, ", ")
}
