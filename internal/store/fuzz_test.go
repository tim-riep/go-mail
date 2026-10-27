package store

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// roundTrip decodes with one decoder of store and encodes the result
// again.
type roundTrip func(in []byte) ([]byte, error)

func encodeAfter[T any](decode func([]byte) (T, error), encode func(T) ([]byte, error)) roundTrip {
	return func(in []byte) ([]byte, error) {
		v, err := decode(in)
		if err != nil {
			return nil, err
		}
		return encode(v)
	}
}

// FuzzDecodeRecords feeds every record decoder of store. The first byte
// selects the decoder. Nothing may panic, and every accepted input must
// encode back to exactly the same bytes (3.6 rule 6).
func FuzzDecodeRecords(f *testing.F) {
	tu := newTestUser(f, 1, 2)
	idPub := tu.identity.Public().(ed25519.PublicKey)
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	decoders := []roundTrip{
		encodeAfter(DecodeUser, (*User).Encode),
		encodeAfter(DecodeMailbox, (*Mailbox).Encode),
		encodeAfter(DecodeEpoch, func(e *Epoch) ([]byte, error) {
			e.VerifySignature(idPub)
			out, err := e.Encode()
			NewChain().Add(e, out)
			return out, err
		}),
		encodeAfter(DecodeEpochKeys, (*EpochKeys).Encode),
		encodeAfter(DecodeMailMeta, func(m *MailMeta) ([]byte, error) {
			m.SignedExtra(ID{1}, 1)
			return m.Encode()
		}),
		encodeAfter(DecodePending, (*Pending).Encode),
		encodeAfter(DecodeEpochNote, (*EpochNote).Encode),
		encodeAfter(DecodeJournal, EncodeJournal),
		func(in []byte) ([]byte, error) {
			role, gen, priv, err := DecodePlatformKey(in)
			if err != nil {
				return nil, err
			}
			return EncodePlatformKey(role, gen, priv)
		},
		encodeAfter(DecodePlatformPin, (*PlatformPin).Encode),
		encodeAfter(DecodeAddressAssignment, (*AddressAssignment).Encode),
		encodeAfter(func(b []byte) (*FolderList, error) { return DecodeFolders(ID{1}, 1, b) }, (*FolderList).Encode),
		encodeAfter(DecodeWrapAccept, func(a *WrapAccept) ([]byte, error) {
			a.Verify(idPub)
			return a.Encode()
		}),
		encodeAfter(DecodeCheckpoint, func(c *Checkpoint) ([]byte, error) {
			c.Verify(idPub)
			return c.Encode()
		}),
		encodeAfter(func(b []byte) (*IndexSegment, error) { return DecodeIndexSegment(ID{1}, 2, b) }, EncodeIndexSegment),
	}

	// Seed corpus: one valid record per decoder, and variants.
	seeds := make([][][]byte, len(decoders))
	add := func(i int, data []byte) { seeds[i] = append(seeds[i], data) }
	must := func(data []byte, err error) []byte {
		if err != nil {
			f.Fatal(err)
		}
		return data
	}
	add(0, must(tu.user.Encode()))
	add(1, must((&Mailbox{ID: ID{1}, Epoch: 2, Inbox: ID{2}}).Encode()))
	_, ed := newTestEpoch(f, tu, ID{9}, 1, 5, nil)
	_, ed2 := newTestEpoch(f, tu, ID{9}, 2, 6, ed)
	e3 := unsignedEpoch(f, tu, ID{9}, 3, 5, ReasonMemberRemoved, ed2)
	e3.Discards = []uint32{2}
	e3.Members = append(e3.Members, Member{MemberRecovery, ID{7}, 1}, Member{MemberDelegate, ID{8}, 1})
	_, ed3 := signEpoch(f, tu, e3)
	add(2, ed)
	add(2, ed2)
	add(2, ed3)
	add(3, must((&EpochKeys{MailboxID: ID{9}, Epoch: 1, Content: x25519(f, 1), Meta: x25519(f, 2), Index: [32]byte{3}}).Encode()))
	add(4, must(testMeta().Encode()))
	add(5, must((&Pending{MailboxID: ID{1}, Epoch: 2, Entries: []PendingEntry{{MailID: ID{3}, Unprocessed: true}, {MailID: ID{4}, Terms: []string{"a", "b"}}}}).Encode()))
	add(6, must((&EpochNote{MailboxID: ID{1}, Epoch: 1, Count: 1}).Encode()))
	add(7, must(EncodeJournal([]Move{{"spool/a", "mailboxes/b"}})))
	add(8, must(EncodePlatformKey(KeyRoleAdmin, 1, k)))
	add(9, must((&PlatformPin{Gen: 1, Pub: k.Public().(ed25519.PublicKey), Dev: true}).Encode()))
	a := &AddressAssignment{Address: "a@b.c", MailboxID: ID{1}, ValidFrom: 1, AdminGen: 1}
	a.Sign(k)
	add(10, must(a.Encode()))
	add(11, must((&FolderList{MailboxID: ID{1}, Epoch: 1, Name: "Büro", Folders: []Folder{{ID{2}, "INBOX"}, {ID{3}, "Archiv"}}}).Encode()))
	add(12, must(testAccept(f, tu).Encode()))
	add(13, must(testCheckpoint(f, tu, ID{5}).Encode()))
	add(14, must(EncodeIndexSegment(&IndexSegment{MailboxID: ID{1}, Epoch: 2, Postings: []Posting{
		{Mark: mark(0), MailIDs: mailIDs(3, 0)}, {Mark: mark(1), MailIDs: mailIDs(1, 9)}}})))
	for i, list := range seeds {
		for _, s := range list {
			f.Add(append([]byte{byte(i)}, s...))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		sel := int(data[0]) % len(decoders)
		in := data[1:]
		out, err := decoders[sel](in)
		if err != nil {
			return
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("decoder %d accepted input that does not re-encode identically", sel)
		}
	})
}
