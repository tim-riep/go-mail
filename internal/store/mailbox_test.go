package store

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/rec"
)

func TestFolderList(t *testing.T) {
	l := &FolderList{MailboxID: ID{1}, Epoch: 3, Name: "Büro", Folders: []Folder{{ID{2}, "INBOX"}, {ID{3}, "Archiv"}}}
	fd, err := l.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFolders(ID{1}, 3, fd)
	if err != nil || got.Name != "Büro" || len(got.Folders) != 2 || got.Folders[1] != l.Folders[1] {
		t.Fatalf("folders: %v", err)
	}
	if again, _ := got.Encode(); !bytes.Equal(again, fd) {
		t.Fatal("folders not byte-identical")
	}
	if _, err := DecodeFolders(ID{9}, 3, fd); !errors.Is(err, ErrRecord) {
		t.Fatal("folders of another mailbox")
	}
	if _, err := DecodeFolders(ID{1}, 4, fd); !errors.Is(err, ErrRecord) {
		t.Fatal("folders of another epoch")
	}
	long := strings.Repeat("a", MaxMailboxName)
	if _, err := (&FolderList{MailboxID: ID{1}, Epoch: 1, Name: long, Folders: l.Folders}).Encode(); err != nil {
		t.Fatalf("name of %d bytes: %v", MaxMailboxName, err)
	}
	for name, bad := range map[string]*FolderList{
		"no mailbox":      {Epoch: 1, Name: "a", Folders: l.Folders},
		"epoch 0":         {MailboxID: ID{1}, Name: "a", Folders: l.Folders},
		"empty name":      {MailboxID: ID{1}, Epoch: 1, Folders: l.Folders},
		"blank name":      {MailboxID: ID{1}, Epoch: 1, Name: " \t 　", Folders: l.Folders},
		"long name":       {MailboxID: ID{1}, Epoch: 1, Name: long + "a", Folders: l.Folders},
		"no folders":      {MailboxID: ID{1}, Epoch: 1, Name: "a"},
		"zero folder":     {MailboxID: ID{1}, Epoch: 1, Name: "a", Folders: []Folder{{ID{}, "x"}}},
		"empty folder":    {MailboxID: ID{1}, Epoch: 1, Name: "a", Folders: []Folder{{ID{2}, ""}}},
		"duplicate":       {MailboxID: ID{1}, Epoch: 1, Name: "a", Folders: []Folder{{ID{2}, "a"}, {ID{2}, "b"}}},
		"name not in NFC": {MailboxID: ID{1}, Epoch: 1, Name: "é", Folders: l.Folders},
	} {
		if _, err := bad.Encode(); err == nil {
			t.Fatalf("%s encoded", name)
		}
	}
	// The decoder applies the same rules.
	folder := func(id ID, n string) *rec.Record { return rec.New(FolderSchema).SetBytes(1, id[:]).SetString(2, n) }
	for name, r := range map[string]*rec.Record{
		"blank name": rec.New(FoldersSchema).SetBytes(1, (&ID{1})[:]).SetU32(2, 1).SetString(3, "  ").SetList(4, []*rec.Record{folder(ID{2}, "a")}),
		"no folders": rec.New(FoldersSchema).SetBytes(1, (&ID{1})[:]).SetU32(2, 1).SetString(3, "a").SetList(4, nil),
		"duplicate":  rec.New(FoldersSchema).SetBytes(1, (&ID{1})[:]).SetU32(2, 1).SetString(3, "a").SetList(4, []*rec.Record{folder(ID{2}, "a"), folder(ID{2}, "b")}),
		"epoch 0":    rec.New(FoldersSchema).SetBytes(1, (&ID{1})[:]).SetU32(2, 0).SetString(3, "a").SetList(4, []*rec.Record{folder(ID{2}, "a")}),
	} {
		if _, err := DecodeFolders(ID{1}, 1, mustEncode(t, r)); !errors.Is(err, ErrRecord) {
			t.Fatalf("%s decoded: %v", name, err)
		}
	}
	if _, err := DecodeFolders(ID{1}, 1, nil); err == nil {
		t.Fatal("nil")
	}

	// folders.gml lives in the directory of its epoch and is replaced.
	s, _ := Init(t.TempDir())
	if err := s.WriteFolders(ID{1}, 3, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteFolders(ID{1}, 3, fd); err != nil {
		t.Fatal(err)
	}
	if b, err := s.ReadFolders(ID{1}, 3); err != nil || !bytes.Equal(b, fd) {
		t.Fatal("folders file")
	}
	if s.FoldersFile(ID{1}, 3) != filepath.Join(s.MailboxDir(ID{1}), "epochs", "3", "folders.gml") {
		t.Fatal("path of folders.gml")
	}
	if _, err := s.ReadFolders(ID{1}, 4); !errors.Is(err, ErrNotFound) {
		t.Fatal("folders of a missing epoch")
	}
	MkdirAll(s.MailDir(ID{1}, ID{2}))
	MkdirAll(filepath.Join(s.MailboxDir(ID{1}), "mail", "junk"))
	if f, _ := s.ListFolders(ID{1}); len(f) != 1 || f[0] != (ID{2}) {
		t.Fatal("list folders")
	}
	if f, _ := s.ListFolders(ID{5}); f != nil {
		t.Fatal("folders of missing mailbox")
	}
}
