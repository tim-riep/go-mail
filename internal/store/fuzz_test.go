package store

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// FuzzDecodeRecords feeds every record decoder of store. The first byte
// selects the decoder. Nothing may panic, and every accepted input must
// encode back to exactly the same bytes (3.6 rule 6).
func FuzzDecodeRecords(f *testing.F) {
	tu := newTestUser(f, 1, 2)
	ud, _ := tu.user.Encode()
	_, ed := newTestEpoch(f, tu, ID{9}, 1, 5, nil)
	_, ed2 := newTestEpoch(f, tu, ID{9}, 2, 6, ed)
	md, _ := (&Mailbox{ID: ID{1}, Epoch: 2, Inbox: ID{2}, Name: []byte("n")}).Encode()
	kd, _ := (&EpochKeys{MailboxID: ID{9}, Epoch: 1, Content: x25519(f, 1), Meta: x25519(f, 2), Index: [32]byte{3}}).Encode()
	meta, _ := testMeta().Encode()
	pd, _ := (&Pending{MailboxID: ID{1}, Epoch: 2, Entries: []PendingEntry{{MailID: ID{3}, Unprocessed: true}, {MailID: ID{4}, Terms: []string{"a", "b"}}}}).Encode()
	nd, _ := (&EpochNote{MailboxID: ID{1}, Epoch: 1, Count: 1}).Encode()
	jd, _ := EncodeJournal([]Move{{"spool/a", "mailboxes/b"}})
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	kfd, _ := EncodePlatformKey(KeyRoleAdmin, 1, k)
	pin, _ := (&PlatformPin{Gen: 1, Pub: k.Public().(ed25519.PublicKey), Dev: true}).Encode()
	a := &AddressAssignment{Address: "a@b.c", MailboxID: ID{1}, ValidFrom: 1, AdminGen: 1}
	a.Sign(k)
	ad, _ := a.Encode()
	for i, s := range [][]byte{ud, md, ed, kd, meta, pd, nd, jd, kfd, pin, ad, ed2} {
		f.Add(append([]byte{byte(i)}, s...))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		in := data[1:]
		var out []byte
		var err error
		switch data[0] % 12 {
		case 0:
			var u *User
			if u, err = DecodeUser(in); err == nil {
				out, err = u.Encode()
			}
		case 1:
			var m *Mailbox
			if m, err = DecodeMailbox(in); err == nil {
				out, err = m.Encode()
			}
		case 2, 11:
			var e *Epoch
			if e, err = DecodeEpoch(in); err == nil {
				out, err = e.Encode()
				e.VerifySignature(tu.identity.Public().(ed25519.PublicKey))
			}
		case 3:
			var k *EpochKeys
			if k, err = DecodeEpochKeys(in); err == nil {
				out, err = k.Encode()
			}
		case 4:
			var m *MailMeta
			if m, err = DecodeMailMeta(in); err == nil {
				out, err = m.Encode()
				m.SignedExtra(ID{1}, 1)
			}
		case 5:
			var p *Pending
			if p, err = DecodePending(in); err == nil {
				out, err = p.Encode()
			}
		case 6:
			var n *EpochNote
			if n, err = DecodeEpochNote(in); err == nil {
				out, err = n.Encode()
			}
		case 7:
			var m []Move
			if m, err = DecodeJournal(in); err == nil {
				out, err = EncodeJournal(m)
			}
		case 8:
			var role uint8
			var gen uint32
			var priv ed25519.PrivateKey
			if role, gen, priv, err = DecodePlatformKey(in); err == nil {
				out, err = EncodePlatformKey(role, gen, priv)
			}
		case 9:
			var p *PlatformPin
			if p, err = DecodePlatformPin(in); err == nil {
				out, err = p.Encode()
			}
		case 10:
			var a *AddressAssignment
			if a, err = DecodeAddressAssignment(in); err == nil {
				out, err = a.Encode()
			}
		}
		if err != nil {
			return
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("decoder %d accepted input that does not re-encode identically", data[0]%12)
		}
	})
}
