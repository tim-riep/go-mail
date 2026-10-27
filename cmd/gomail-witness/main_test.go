package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

const origin = "go-mail.test/log"

// logServer serves one signed head of size 1 and accepts every
// cosignature (the real server side is task 11).
func logServer(t *testing.T) (url, vkey string, posts func() int) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := translog.NewLogSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	vkey, _ = note.NewEd25519VerifierKey(translog.LogSignerName, pub)
	h := &translog.Head{Origin: origin, Size: 1, Hash: tlog.RecordHash([]byte("entry")), Time: time.Now().UnixMilli()}
	text, err := h.Text()
	if err != nil {
		t.Fatal(err)
	}
	head, err := note.Sign(&note.Note{Text: string(text)}, signer)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", witness.ContentType)
		switch r.URL.Path {
		case witness.PathHead:
			w.Write(head)
		case witness.PathCosign:
			io.Copy(io.Discard, r.Body)
			mu.Lock()
			n++
			mu.Unlock()
			io.WriteString(w, "stored\n")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL, vkey, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

func TestUsage(t *testing.T) {
	ctx := context.Background()
	for _, args := range [][]string{
		nil, {"x"}, {"keygen"}, {"keygen", "--name", "w"}, {"keygen", "--key", "k"},
		{"keygen", "--name", "w", "--key", "k", "extra"}, {"keygen", "--bogus"},
		{"serve"}, {"serve", "--log", "http://x", "--origin", "o", "--key", "k", "--state", "s"},
		{"serve", "--log", "http://x", "--log-key", "v", "--origin", "o", "--key", "k", "--state", "s", "--interval", "10ms"},
		{"serve", "--log", "http://x", "--log-key", "v", "--origin", "o", "--key", "k", "--state", "s", "extra"},
	} {
		var out, errb bytes.Buffer
		if code := run(ctx, args, &out, &errb); code != exitUsage {
			t.Fatalf("%v: exit %d", args, code)
		}
		if errb.Len() == 0 {
			t.Fatalf("%v: no message", args)
		}
	}
}

func TestKeygenAndServe(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "witness.key")
	var out, errb bytes.Buffer
	ctx := context.Background()
	if code := run(ctx, []string{"keygen", "--name", "witness.test", "--key", key}, &out, &errb); code != exitOK {
		t.Fatalf("keygen: %d %s", code, errb.String())
	}
	vkey := strings.TrimSuffix(out.String(), "\n")
	if _, err := note.NewVerifier(vkey); err != nil || !strings.HasPrefix(vkey, "witness.test+") {
		t.Fatalf("printed %q", out.String())
	}
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("key file mode")
	}
	if code := run(ctx, []string{"keygen", "--name", "witness.test", "--key", key}, &out, &errb); code != exitError {
		t.Fatal("key file replaced")
	}

	url, logKey, posts := logServer(t)
	state := filepath.Join(dir, "state")
	args := []string{"serve", "--log", url, "--log-key", logKey, "--origin", origin, "--key", key, "--state", state, "--interval", "1s"}

	// serve cosigns, posts and stops when the context ends.
	sctx, cancel := context.WithCancel(ctx)
	var logb syncBuffer
	done := make(chan int, 1)
	go func() { done <- run(sctx, args, io.Discard, &logb) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logb.String(), "cosigned") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != exitOK {
		t.Fatalf("serve: exit %d: %s", code, logb.String())
	}
	if posts() == 0 {
		t.Fatal("no cosignature posted")
	}
	logs := logb.String()
	if !strings.Contains(logs, "cosigned") || !strings.Contains(logs, "size=1") || strings.Contains(logs, origin) {
		t.Fatalf("log lines: %s", logs)
	}

	// A bad configuration: exit 1.
	bad := append([]string(nil), args...)
	bad[4] = "not-a-key"
	if code := run(ctx, bad, io.Discard, &errb); code != exitError {
		t.Fatalf("bad log key: exit %d", code)
	}

	// A forked state: exit 3 at once.
	sum := sha256.Sum256([]byte(origin))
	if err := os.WriteFile(filepath.Join(state, hex.EncodeToString(sum[:])+".fork"), []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := run(ctx, args, io.Discard, &errb); code != exitFork {
		t.Fatalf("fork: exit %d", code)
	}
}

// syncBuffer is a bytes.Buffer safe for the logger's goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
