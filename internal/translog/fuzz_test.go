package translog

import (
	"bytes"
	"os"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// FuzzParseHeadText: no panic, and every accepted text formats back to
// the identical bytes (one text per head).
func FuzzParseHeadText(f *testing.F) {
	text, _ := testHead().Text()
	f.Add(text)
	f.Add([]byte("o\n1\nAAAA\ntime 0\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseHeadText(b)
		if err != nil {
			return
		}
		again, err := h.Text()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted %q, formats as %q (%v)", b, again, err)
		}
	})
}

// FuzzDecodeEntry: no panic, and every accepted entry encodes back to
// the identical bytes.
func FuzzDecodeEntry(f *testing.F) {
	f.Add([]byte("gomail/v1/rec/log-entry\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := DecodeEntry(b, 0)
		if err != nil {
			return
		}
		again, err := e.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("not canonical: %v", err)
		}
	})
}

// FuzzOpenHead: no panic on any signed head; an accepted head has a
// text that formats back to the signed text and at most MaxSignatures
// signature lines.
func FuzzOpenHead(f *testing.F) {
	e := newEnv(f, 1, 1)
	h := e.headOf(t0)
	f.Add(sign(f, h, e.all()...))
	f.Add(sign(f, h, e.ws[0].signer))
	f.Add([]byte("gomail-test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\ntime 1\n\n— gomail-log AAAA\n"))
	known := e.known()
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := OpenHead(b, known)
		if err != nil {
			return
		}
		text, err := h.Text()
		if err != nil || !bytes.HasPrefix(b, text) || len(h.Sigs) > MaxSignatures || len(h.Sigs) == 0 {
			t.Fatalf("accepted head: %v", err)
		}
	})
}

// FuzzProofs: CheckRecordProof and CheckTreeProof never panic or hang,
// whatever the sizes and proof hashes, and accept exactly the true
// proofs of a small tree.
func FuzzProofs(f *testing.F) {
	m := &memTree{}
	var leaves []tlog.Hash
	for i := 0; i < 7; i++ {
		leaves = append(leaves, m.add(f, []byte{byte(i)}))
	}
	root, err := tlog.TreeHash(7, m)
	if err != nil {
		f.Fatal(err)
	}
	rp, _ := tlog.ProveRecord(7, 3, m)
	tp, _ := tlog.ProveTree(7, 3, m)
	flat := func(p []tlog.Hash) []byte {
		var b []byte
		for _, h := range p {
			b = append(b, h[:]...)
		}
		return b
	}
	f.Add(int64(7), int64(3), flat(rp))
	f.Add(int64(7), int64(3), flat(tp))
	f.Add(MaxTreeSize+1, int64(1), []byte{})
	f.Add(int64(1)<<62, int64(1)<<61, make([]byte, 64))
	f.Fuzz(func(t *testing.T, n, i int64, b []byte) {
		if len(b) > 100*tlog.HashSize {
			return
		}
		proof := make([]tlog.Hash, len(b)/tlog.HashSize)
		for k := range proof {
			copy(proof[k][:], b[k*tlog.HashSize:])
		}
		var h tlog.Hash
		copy(h[:], b)
		_ = CheckRecordProof(proof, n, h, i, h)
		_ = CheckTreeProof(proof, n, h, i, h)
		// Soundness on the small tree.
		if i >= 0 && i < 7 {
			if CheckRecordProof(proof, 7, root, i, leaves[i]) == nil {
				want, _ := tlog.ProveRecord(7, i, m)
				if !bytes.Equal(flat(proof), flat(want)) {
					t.Fatal("false inclusion proof accepted")
				}
			}
		}
		if i >= 1 && i <= 7 {
			old, _ := tlog.TreeHash(i, m)
			if CheckTreeProof(proof, 7, root, i, old) == nil {
				want, _ := tlog.ProveTree(7, i, m)
				if !bytes.Equal(flat(proof), flat(want)) {
					t.Fatal("false consistency proof accepted")
				}
			}
		}
	})
}

// FuzzAuditIndex: an audit index from the client directory never makes
// the log panic: it is decoded, checked, cloned, encoded again and every
// kind of entry is admitted against it.
func FuzzAuditIndex(f *testing.F) {
	e, c, _ := fullEnv(f)
	data, err := os.ReadFile(c.opts.IndexFile)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"version":1,"size":0,"root":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	r := makeRecords(f)
	ids := e.p.ids(f, 1)
	fs := &files{root: e.st.Root}
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := unmarshalState(b, fs, ids)
		if err != nil {
			return
		}
		again, err := s.clone().marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unmarshalState(again, fs, ids); err != nil {
			t.Fatalf("re-encoded index refused: %v", err)
		}
		for _, x := range []struct {
			kind    Kind
			content []byte
		}{{KindUser, r.user}, {KindUser, r.user2}, {KindEpoch, r.epoch}, {KindAddress, r.address}, {KindPlatform, r.cert}, {KindPlatform, r.succ}} {
			e, obj, enc, err := prepare(x.kind, x.content)
			if err != nil {
				t.Fatal(err)
			}
			if ch, err := s.admit(e, obj, LeafHash(enc)); err == nil {
				ch.commit(s.Size)
			}
		}
	})
}
