package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
)

// gomailctl search <mailbox-id> <term> [--since YYYY-MM] (9.2, 6.3): the
// mails that carry the term (from:, fromdomain:, to:, day:, month:,
// thread:, has:attachment; 5.4), one line each with mail ID, time of
// receipt (UTC), folder and subject. The subject comes from the
// decrypted metadata only and is written to standard output, never to a
// file; the term appears in no message.
//
// gomailctl flag <mailbox-id> <mail-id> [--set a,b] [--clear c] (7, K4):
// sets and clears flags of a mail. TODO(ask): 9.2 names no command for
// flags; the name flag and the flags --set and --clear follow task 13.

func runSearch(e *env, o *options, _ client.Config, c *client.Client) int {
	mbx := o.ids[0]
	mails, err := c.Search(mbx, o.query, client.SearchOptions{Since: o.since})
	names := map[store.ID]string{}
	if len(mails) > 0 {
		folders, ferr := c.Folders(mbx)
		if ferr != nil {
			return e.fail(ferr)
		}
		for _, f := range folders {
			names[f.ID] = f.Name
		}
	}
	for _, m := range mails {
		t := time.UnixMilli(m.Meta.Received).UTC().Format("2006-01-02 15:04")
		folder, ok := names[m.Meta.Folder]
		if !ok {
			folder = m.Meta.Folder.String()
		}
		fmt.Fprintf(e.stdout, "%s  %s  %s  %s\n", m.ID, t, folder, m.Meta.Subject)
	}
	if err != nil {
		return e.fail(err)
	}
	return 0
}

func runFlag(e *env, o *options, _ client.Config, c *client.Client) int {
	m, err := c.SetFlags(o.ids[0], o.ids[1], o.set, o.clr)
	if err != nil {
		return e.fail(err)
	}
	flags := strings.Join(client.FlagNames(m.Meta.Flags), ", ")
	if flags == "" {
		flags = "keine"
	}
	fmt.Fprintf(e.stdout, "Flags von %s: %s (Version %d)\n", m.ID, flags, m.Meta.Version)
	return 0
}
