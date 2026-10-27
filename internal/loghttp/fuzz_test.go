package loghttp

import (
	"bytes"
	"net/http"
	"os"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// FuzzServer feeds arbitrary requests to the handlers of the server:
// never a panic, only the statuses of the protocol, text/plain answers,
// error bodies of one ASCII line, and heads/ never holds a line the
// server did not verify (every stored head opens with the log key and
// all witnesses).
func FuzzServer(f *testing.F) {
	e := newEnv(f, 3, 2)
	e.grow(3)
	e.srv.Tick()
	c := e.srv.Candidate()
	text, _ := c.Text()
	signers := []note.Signer{e.signer}
	for _, w := range e.ws {
		data, err := os.ReadFile(w.keyFile)
		if err != nil {
			f.Fatal(err)
		}
		s, err := note.NewSigner(strings.TrimSpace(string(data)))
		if err != nil {
			f.Fatal(err)
		}
		signers = append(signers, s)
	}
	sign := func(ss ...note.Signer) []byte {
		b, err := note.Sign(&note.Note{Text: string(text)}, ss...)
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	f.Add(uint8(1), uint8(2), "", sign(signers[0], signers[1]), true)
	f.Add(uint8(1), uint8(2), "", sign(signers[0], signers[1], signers[2]), true)
	f.Add(uint8(1), uint8(2), "", append(sign(signers[0], signers[3]), "— witness-a AAAA\n"...), true)
	f.Add(uint8(1), uint8(2), "", c.Note, true)
	f.Add(uint8(0), uint8(1), "from=1&to=5", []byte(nil), false)
	f.Add(uint8(0), uint8(1), "from=2&to=2", []byte(nil), false)
	f.Add(uint8(0), uint8(0), "", []byte(nil), false)
	f.Add(uint8(2), uint8(3), "x=1", []byte("x"), true)
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut}
	paths := []string{witness.PathHead, witness.PathConsistency, witness.PathCosign, "/gomail/log/other"}
	allowed := map[int]bool{200: true, 400: true, 403: true, 404: true, 405: true, 409: true, 413: true, 500: true}
	f.Fuzz(func(t *testing.T, m, p uint8, query string, body []byte, ctype bool) {
		target := paths[int(p)%len(paths)]
		if query != "" {
			if strings.ContainsAny(query, " #\r\n\x00") {
				return
			}
			target += "?" + query
		}
		ct := ""
		if ctype {
			ct = witness.ContentType
		}
		var r *http.Request
		func() {
			defer func() {
				if recover() != nil {
					r = nil // httptest.NewRequest panics on a target it cannot parse
				}
			}()
			r = newRequest(methods[int(m)%len(methods)], target, ct, body)
		}()
		if r == nil {
			return
		}
		w := newRecorder()
		e.srv.ServeHTTP(w, r)
		if !allowed[w.Code] || w.Header().Get("Content-Type") != witness.ContentType {
			t.Fatalf("status %d, type %q", w.Code, w.Header().Get("Content-Type"))
		}
		if w.Code != http.StatusOK {
			b := w.Body.Bytes()
			if len(b) == 0 || len(b) > 64 || bytes.IndexByte(b, '\n') != len(b)-1 {
				t.Fatalf("error body %q", b)
			}
			for _, ch := range b[:len(b)-1] {
				if ch < 0x20 || ch > 0x7e {
					t.Fatalf("error body %q", b)
				}
			}
		}
		if msg := e.headFile(c.Size); msg != nil {
			if _, err := e.openHead(msg); err != nil {
				t.Fatalf("stored head does not open: %v", err)
			}
		}
		if len(body) > translog.MaxHeadNote && w.Code != http.StatusRequestEntityTooLarge && r.Method == http.MethodPost && target == witness.PathCosign {
			t.Fatalf("large body: %d", w.Code)
		}
	})
}
