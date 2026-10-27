package store

import (
	"fmt"
	"strings"

	"github.com/tim-riep/go-mail/internal/rec"
)

// MailboxSchema is mailboxes/<id>/mailbox.rec (section 4): mailbox ID,
// the highest epoch number (head of the epoch chain) and the ID of the
// inbox folder the server delivers to. The record is not signed (3.7 has
// no short name for it); a client detects a reset head with its local
// state (2.4). The name of the mailbox is in folders.gml of every epoch
// (S20).
var MailboxSchema = rec.MustSchema("gomail/v1/rec/mailbox",
	id16(1, "mailbox_id", true),
	rec.Field{Num: 2, Name: "epoch", Kind: rec.U32, Required: true},
	id16(3, "inbox", true),
)

// Mailbox is a decoded mailbox.rec.
type Mailbox struct {
	ID    ID
	Epoch uint32 // head of the epoch chain
	Inbox ID
}

func (m *Mailbox) check() error {
	if m.ID.IsZero() || m.Inbox.IsZero() || m.Epoch == 0 {
		return fmt.Errorf("%w: incomplete mailbox", ErrRecord)
	}
	return nil
}

// Encode returns the canonical encoding.
func (m *Mailbox) Encode() ([]byte, error) {
	if err := m.check(); err != nil {
		return nil, err
	}
	return rec.New(MailboxSchema).SetBytes(1, m.ID[:]).SetU32(2, m.Epoch).SetBytes(3, m.Inbox[:]).Encode()
}

// DecodeMailbox decodes mailbox.rec.
func DecodeMailbox(data []byte) (*Mailbox, error) {
	r, err := rec.Decode(MailboxSchema, data)
	if err != nil {
		return nil, err
	}
	m := &Mailbox{ID: idFromBytes(r.Bytes(1)), Epoch: r.U32(2), Inbox: idFromBytes(r.Bytes(3))}
	if err := m.check(); err != nil {
		return nil, err
	}
	return m, nil
}

// Limits of folders.gml.
const (
	MaxFolders       = 1024 // folders of one mailbox
	MaxMailboxName   = 256  // bytes of the mailbox name
	MaxFolderNameLen = 256  // bytes of one folder name
)

// FolderSchema is one entry of folders.gml.
var FolderSchema = rec.MustSchema("gomail/v1/rec/folder",
	id16(1, "id", true),
	rec.Field{Num: 2, Name: "name", Kind: rec.String, MaxLen: MaxFolderNameLen, Required: true},
)

// FoldersSchema is the plaintext of epochs/<n>/folders.gml (section 4,
// S20): the name of the mailbox and its folder list, sealed for the meta
// key of exactly this epoch. Mailbox and epoch are part of the plaintext,
// so a list cannot be moved to another mailbox or epoch.
var FoldersSchema = rec.MustSchema("gomail/v1/rec/folders",
	id16(1, "mailbox_id", true),
	rec.Field{Num: 2, Name: "epoch", Kind: rec.U32, Required: true},
	rec.Field{Num: 3, Name: "name", Kind: rec.String, MaxLen: MaxMailboxName, Required: true},
	rec.Field{Num: 4, Name: "folders", Kind: rec.List, Elem: FolderSchema, MaxCount: MaxFolders, Required: true},
)

// Folder is one folder.
type Folder struct {
	ID   ID
	Name string
}

// FolderList is the content of folders.gml of one epoch.
type FolderList struct {
	MailboxID ID
	Epoch     uint32
	Name      string // name of the mailbox
	Folders   []Folder
}

func (l *FolderList) check() error {
	if l.MailboxID.IsZero() || l.Epoch == 0 {
		return fmt.Errorf("%w: folder list without mailbox or epoch", ErrRecord)
	}
	if strings.TrimSpace(l.Name) == "" {
		return fmt.Errorf("%w: empty mailbox name", ErrRecord)
	}
	if len(l.Folders) == 0 {
		return fmt.Errorf("%w: no folders", ErrRecord)
	}
	seen := make(map[ID]bool, len(l.Folders))
	for _, f := range l.Folders {
		if f.ID.IsZero() || f.Name == "" || seen[f.ID] {
			return fmt.Errorf("%w: invalid folder", ErrRecord)
		}
		seen[f.ID] = true
	}
	return nil
}

// Encode returns the canonical encoding.
func (l *FolderList) Encode() ([]byte, error) {
	if err := l.check(); err != nil {
		return nil, err
	}
	list := make([]*rec.Record, 0, len(l.Folders))
	for _, f := range l.Folders {
		list = append(list, rec.New(FolderSchema).SetBytes(1, f.ID[:]).SetString(2, f.Name))
	}
	return rec.New(FoldersSchema).SetBytes(1, l.MailboxID[:]).SetU32(2, l.Epoch).SetString(3, l.Name).SetList(4, list).Encode()
}

// DecodeFolders decodes the plaintext of folders.gml and checks that it
// belongs to mailbox mbx and epoch.
func DecodeFolders(mbx ID, epoch uint32, data []byte) (*FolderList, error) {
	r, err := rec.Decode(FoldersSchema, data)
	if err != nil {
		return nil, err
	}
	l := &FolderList{MailboxID: idFromBytes(r.Bytes(1)), Epoch: r.U32(2), Name: r.String(3)}
	for _, e := range r.List(4) {
		l.Folders = append(l.Folders, Folder{ID: idFromBytes(e.Bytes(1)), Name: e.String(2)})
	}
	if err := l.check(); err != nil {
		return nil, err
	}
	if l.MailboxID != mbx || l.Epoch != epoch {
		return nil, fmt.Errorf("%w: folders of another mailbox or epoch", ErrRecord)
	}
	return l, nil
}
