package client

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

// SearchOptions configure Search.
type SearchOptions struct {
	// Since limits the search to the epochs of the period from the first
	// day of this month (UTC, "YYYY-MM") on and to mails received since
	// then. Empty searches every epoch.
	Since string
}

// termPrefixes are the kinds of terms of 5.4 that take a value.
var termPrefixes = []string{"from:", "fromdomain:", "to:", "day:", "month:", "thread:"}

// normalizeTerm normalizes a search term exactly like the server
// normalizes the terms of a term list (5.4, ingest): lower case, cleaned,
// Unicode NFC, at most store.MaxTermLen bytes. It accepts only the terms
// of 5.4: from:, fromdomain:, to:, day:, month:, thread: with a value,
// and has:attachment. The error never contains the term.
func normalizeTerm(q string) (string, error) {
	t := termOf("", strings.TrimSpace(q))
	if t == "has:attachment" {
		return t, nil
	}
	for _, p := range termPrefixes {
		if v, ok := strings.CutPrefix(t, p); ok && strings.TrimSpace(v) != "" {
			return t, nil
		}
	}
	return "", ErrQuery
}

// parseSince returns the first millisecond of the month "YYYY-MM" in UTC,
// 0 for an empty string.
func parseSince(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	t, err := time.Parse("2006-01", s)
	if err != nil {
		return 0, fmt.Errorf("%w: --since expects YYYY-MM", ErrArgument)
	}
	return t.UTC().UnixMilli(), nil
}

// inPeriod reports whether epoch i of ch may hold mails received at or
// after since: its period ends with the begin of the next epoch that is
// not discarded.
func (ch *chain) inPeriod(i int, since int64) bool {
	if since == 0 {
		return true
	}
	for _, next := range ch.epochs[i+1:] {
		if !ch.discarded[next.Number] {
			return next.Begin > since
		}
	}
	return true
}

// Search finds the mails of mailbox mbx that carry the term query (6.3):
// the term is normalized like 5.4; for every epoch of the period
// (opts.Since) that is not discarded and this client has access to, the
// mark of the term is computed with the index key of the epoch, the hits
// of every accepted segment are united and duplicate mail IDs dropped,
// and the entries of pending/ not indexed yet are searched directly
// (their term lists, or the terms derived from the checked metadata of an
// entry marked unprocessed). Every hit is then checked like in List; only
// mails that pass every check, belong to the epoch whose index named them
// and lie in a folder of folders.gml are returned, sorted like List.
//
// Neither the term nor anything derived from it appears in a warning or
// an error.
func (c *Client) Search(mbx store.ID, query string, opts SearchOptions) ([]*Mail, error) {
	term, err := normalizeTerm(query)
	if err != nil {
		return nil, err
	}
	since, err := parseSince(opts.Since)
	if err != nil {
		return nil, err
	}
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, err
	}
	_, known, err := c.inbox(ch)
	if err != nil {
		return nil, err
	}
	all, err := c.mailFolders(mbx)
	if err != nil {
		return nil, err
	}
	// Only mails in folders that folders.gml names are shown, as in List.
	where := map[store.ID]store.ID{}
	for id, f := range all {
		if slices.ContainsFunc(known, func(x store.Folder) bool { return x.ID == f }) {
			where[id] = f
		}
	}
	hits := map[store.ID]map[uint32]bool{}
	hit := func(id store.ID, n uint32) {
		if hits[id] == nil {
			hits[id] = map[uint32]bool{}
		}
		hits[id][n] = true
	}
	checked := map[store.ID]*Mail{}
	var first error
	for i, e := range ch.epochs {
		if ch.discarded[e.Number] || !ch.inPeriod(i, since) {
			continue
		}
		if !c.listed(e) && !c.ownWrapExists(mbx, e.Number) {
			continue
		}
		k, err := c.keysFor(ch, e)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		mk := mark(k, term)
		segs, err := c.readSegments(ch, e)
		if err != nil {
			return nil, err
		}
		for _, s := range segs {
			for _, id := range lookup(s.seg, mk) {
				hit(id, e.Number)
			}
		}
		files, err := c.st.ListPending(mbx, e.Number)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			p, err := c.openPending(ch, e, file)
			if err != nil {
				continue // warned
			}
			for _, en := range p.Entries {
				terms := en.Terms
				if en.Unprocessed {
					m, err := c.pendingMeta(ch, e, en.MailID, where)
					if err != nil {
						continue
					}
					checked[m.ID] = m
					terms = metaTerms(m.Meta)
				}
				if slices.Contains(terms, term) {
					hit(en.MailID, e.Number)
				}
			}
		}
	}
	var out []*Mail
	for id, epochs := range hits {
		folder, ok := where[id]
		if !ok {
			continue // no such mail in a folder of folders.gml
		}
		m := checked[id]
		if m == nil {
			if m, err = c.checkMeta(ch, folder, id); err != nil {
				c.warnRejected(id, "wird nicht angezeigt", err)
				continue
			}
		}
		if !epochs[m.Epoch] {
			c.warn("WARNUNG: Mail %s wurde im Index einer anderen Epoche gefunden und wird nicht angezeigt.", id)
			continue
		}
		if m.Meta.Received < since {
			continue
		}
		out = append(out, m)
	}
	if err := c.saveSeen(); err != nil {
		return nil, err
	}
	sortMails(out)
	if first == nil {
		first = ch.err
	}
	return out, first
}
