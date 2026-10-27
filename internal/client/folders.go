package client

import (
	"fmt"
	"strings"

	"github.com/tim-riep/go-mail/internal/store"
)

// SetFolders replaces the folder list of the mailbox (section 4 "Ändert
// ein Mitglied die Ordner, schreibt sein Client die Liste neu für die
// aktuelle und alle bereits angelegten künftigen Epochen"). The inbox
// must stay in the list under its ID and the name INBOX, and no other
// folder may be called INBOX. Folder names are cleaned like the mailbox
// name. Only a user member of every epoch concerned writes folders.gml
// (a delegate never does, QUESTIONS Q6); past epochs keep their list.
func (c *Client) SetFolders(mbx store.ID, folders []store.Folder) error {
	if err := c.writable(); err != nil {
		return err
	}
	return c.mutate(mbx, func(ch *chain) error {
		base, inbox, err := c.folderList(ch)
		if err != nil {
			return err
		}
		list, err := checkFolders(folders, inbox)
		if err != nil {
			return err
		}
		return c.rewriteFolders(ch, base.Name, inbox, list)
	})
}

// Rename changes the name of the mailbox in folders.gml of the current
// and every future epoch (section 4, S20), like SetFolders.
func (c *Client) Rename(mbx store.ID, name string) error {
	if err := c.writable(); err != nil {
		return err
	}
	name = strings.TrimSpace(store.CleanText(name, store.MaxMailboxName))
	if name == "" {
		return fmt.Errorf("%w: empty mailbox name", ErrArgument)
	}
	return c.mutate(mbx, func(ch *chain) error {
		base, inbox, err := c.folderList(ch)
		if err != nil {
			return err
		}
		return c.rewriteFolders(ch, name, inbox, base.Folders)
	})
}

// checkFolders cleans and checks a folder list for inbox.
func checkFolders(in []store.Folder, inbox store.ID) ([]store.Folder, error) {
	if len(in) == 0 || len(in) > store.MaxFolders {
		return nil, fmt.Errorf("%w: %d folders", ErrArgument, len(in))
	}
	out := make([]store.Folder, 0, len(in))
	seen := make(map[store.ID]bool, len(in))
	hasInbox := false
	for _, f := range in {
		name := strings.TrimSpace(store.CleanText(f.Name, store.MaxFolderNameLen))
		switch {
		case f.ID.IsZero() || name == "":
			return nil, fmt.Errorf("%w: folder without ID or name", ErrArgument)
		case seen[f.ID]:
			return nil, fmt.Errorf("%w: duplicate folder", ErrArgument)
		case name == InboxName && f.ID != inbox, f.ID == inbox && name != InboxName:
			return nil, fmt.Errorf("%w: the inbox keeps its ID and the name %s", ErrArgument, InboxName)
		}
		seen[f.ID] = true
		hasInbox = hasInbox || f.ID == inbox
		out = append(out, store.Folder{ID: f.ID, Name: name})
	}
	if !hasInbox {
		return nil, fmt.Errorf("%w: the inbox must stay", ErrArgument)
	}
	return out, nil
}

// rewriteFolders writes folders.gml with name and folders for the epoch
// in force and every later epoch of ch that is not discarded, signed by
// this user, who must be a user member of each of them (the reader
// accepts folders.gml only from a user member of its epoch). Nothing is
// written if one of them fails that check.
func (c *Client) rewriteFolders(ch *chain, name string, inbox store.ID, folders []store.Folder) error {
	mbx := ch.mailbox.ID
	cur := ch.current(c.cfg.Now().UnixMilli())
	if cur == nil {
		return fmt.Errorf("%w: no epoch of %s has begun", ErrEpoch, mbx)
	}
	var targets []*store.Epoch
	for _, e := range ch.epochs[cur.Number-1:] {
		if ch.discarded[e.Number] {
			continue
		}
		if !c.isUserMember(e) {
			return fmt.Errorf("%w: not a user member of epoch %d of %s", ErrNotMember, e.Number, mbx)
		}
		targets = append(targets, e)
	}
	ms := c.mailboxState(mbx)
	for _, e := range targets {
		// One above the version read, and above every version seen.
		_, _, v, err := c.foldersAt(ch, e.Number)
		if err != nil {
			c.warn("WARNUNG: folders.gml der Epoche %d von %s wird ersetzt: %s.", e.Number, mbx, warnCause(err))
		}
		k := fmt.Sprint(e.Number)
		v = max(v, ms.Folders[k])
		if v == ^uint32(0) {
			return fmt.Errorf("%w: version of folders.gml exhausted", ErrArgument)
		}
		v++
		plain, err := (&store.FolderList{MailboxID: mbx, Epoch: e.Number, Name: name, Folders: folders}).Encode()
		if err != nil {
			return err
		}
		sealed, err := c.sealMeta(e, inbox, plain, v)
		if err != nil {
			return err
		}
		if err := c.st.WriteFolders(mbx, e.Number, sealed); err != nil {
			return err
		}
		ms.Folders[k] = v
		if err := c.save(); err != nil {
			return err
		}
		if crash("folders") {
			return errCrashed
		}
	}
	return nil
}
