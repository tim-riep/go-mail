package witness

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/translog"
)

// FuzzParseProof: no panic, and every accepted body formats back to the
// identical bytes.
func FuzzParseProof(f *testing.F) {
	f.Add([]byte("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseProof(b)
		if err != nil {
			return
		}
		if again := FormatProof(p); !bytes.Equal(again, b) {
			t.Fatalf("accepted %q, formats as %q", b, again)
		}
	})
}

// FuzzDecodeWitnesses: no panic, and every accepted list encodes back
// to the identical bytes.
func FuzzDecodeWitnesses(f *testing.F) {
	f.Add([]byte("gomail/v1/rec/witnesses\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		w, err := DecodeWitnesses(b)
		if err != nil {
			return
		}
		again, err := w.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("not canonical: %v", err)
		}
	})
}

// fuzzWitness returns a witness whose stored head has size 3 and whose
// state writes go nowhere, and a function that resets it to that state.
func fuzzWitness(f *testing.F) (*fixture, func()) {
	fx := newFixture(f)
	fx.log.add(f, 3)
	if _, err := fx.w.Cosign(fx.log.head(f, 3, fx.clk.ms()), nil); err != nil {
		f.Fatal(err)
	}
	fx.w.write = func(string, []byte) error { return nil }
	base, stored := fx.w.state, fx.w.stored
	return fx, func() {
		fx.w.mu.Lock()
		fx.w.state, fx.w.stored = base, stored
		fx.w.mu.Unlock()
	}
}

// checkCosigned checks the invariants of a cosign body against the
// stored head of size 3 of fuzzWitness.
func checkCosigned(t *testing.T, fx *fixture, out []byte) {
	n, err := note.Open(out, note.VerifierList(mustVerifier(t, fx.log.vkey), mustVerifier(t, fx.vkey)))
	if err != nil || len(n.Sigs) != 2 || len(n.UnverifiedSigs) != 0 {
		t.Fatalf("cosign body does not verify: %v", err)
	}
	if lines := sigLines(t, out); len(lines) != 2 {
		t.Fatalf("cosign body has %d signature lines", len(lines))
	}
	h, err := translog.ParseHeadText([]byte(n.Text))
	if err != nil || h.Origin != testOrigin || h.Size < 3 || (h.Size == 3 && h.Hash != fx.log.root(t, 3)) {
		t.Fatalf("cosigned a head that breaks the rules: %v", err)
	}
	if h.Size > 3 && (h.Size > fx.log.size || h.Hash != fx.log.root(t, h.Size)) {
		t.Fatal("cosigned a head that is not an extension of the stored one")
	}
	if h.Time > fx.clk.ms()+translog.MaxClockSkew.Milliseconds() {
		t.Fatal("cosigned a head from the future")
	}
}

// fuzzSeeds adds signed heads and proofs to the corpus: the stored head,
// a larger one with its proof and with a wrong proof, a fork, a head in
// the future and garbage.
func fuzzSeeds(f *testing.F, fx *fixture) {
	ms := fx.clk.ms()
	fx.log.add(f, 2)
	f.Add(fx.log.head(f, 3, ms), []byte{})
	f.Add(fx.log.head(f, 5, ms+1), FormatProof(fx.log.proof(f, 3, 5)))
	f.Add(fx.log.head(f, 5, ms+1), FormatProof(fx.log.proof(f, 2, 5)))
	other := newTestLogKey(f, "b", fx.log.priv)
	other.add(f, 3)
	f.Add(other.head(f, 3, ms), []byte{})
	f.Add(fx.log.head(f, 4, ms+1<<40), FormatProof(fx.log.proof(f, 3, 4)))
	f.Add([]byte("go-mail.test/log\n3\nAAAA\ntime 1\n\n— gomail-log AAAA\n"), []byte("AAAA\n"))
}

// FuzzCosign: the bodies a server delivers (head, proof) never panic
// the witness, and every cosignature it gives obeys the rules.
func FuzzCosign(f *testing.F) {
	fx, reset := fuzzWitness(f)
	fuzzSeeds(f, fx)
	f.Fuzz(func(t *testing.T, head, proofBody []byte) {
		reset()
		proof, err := ParseProof(proofBody)
		if err != nil {
			proof = nil
		}
		out, err := fx.w.Cosign(head, proof)
		if err != nil {
			return
		}
		checkCosigned(t, fx, out)
	})
}

// roundTrip serves the protocol from fixed bodies without a network.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// FuzzPoll: Poll against a server that answers GET /head and GET
// /consistency with arbitrary bodies.
func FuzzPoll(f *testing.F) {
	fx, reset := fuzzWitness(f)
	fuzzSeeds(f, fx)
	var head, proof, posted []byte
	fx.w.client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		body := []byte("stored\n")
		switch r.URL.Path {
		case PathHead:
			body = head
		case PathConsistency:
			body = proof
		case PathCosign:
			posted, _ = io.ReadAll(r.Body)
		}
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": {ContentType}},
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: -1,
			Request:       r,
		}, nil
	})}
	f.Fuzz(func(t *testing.T, h, p []byte) {
		reset()
		head, proof, posted = h, p, nil
		if err := fx.w.Poll(context.Background()); err != nil {
			if posted != nil {
				t.Fatal("posted although the round failed")
			}
			return
		}
		if posted != nil {
			checkCosigned(t, fx, posted)
		}
	})
}
