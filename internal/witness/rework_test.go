package witness

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/translog"
)

// TestForkOlderTime: a head of the stored size with another hash is a
// fork even when its time line is older than the stored one; rule 6
// compares the hash before the time (task 08b).
func TestForkOlderTime(t *testing.T) {
	f := newFixture(t)
	f.log.add(t, 3)
	if _, err := f.w.Cosign(f.log.head(t, 3, f.clk.ms()), nil); err != nil {
		t.Fatal(err)
	}
	other := newTestLogKey(t, "b", f.log.priv)
	other.add(t, 3)
	older := other.head(t, 3, f.clk.ms()-time.Hour.Milliseconds())
	_, err := f.w.Cosign(older, nil)
	if !errors.Is(err, ErrFork) || errors.Is(err, ErrTime) {
		t.Fatalf("older head of another hash: %v", err)
	}
	if !f.st().Fork {
		t.Fatal("fork not recorded")
	}
	if ev := readFile(t, f.w.path(forkExt)); !bytes.Equal(ev, older) {
		t.Fatal("fork evidence is not the refused head")
	}
	f.restart()
	if !f.st().Fork {
		t.Fatal("fork forgotten after restart")
	}
}

// TestServeForkEvidenceNotWritten: when the evidence of a fork cannot be
// written, Serve ends at once with ErrFork and ErrState (task 08b).
func TestServeForkEvidenceNotWritten(t *testing.T) {
	f := newFixture(t)
	f.publish(2)
	if err := f.w.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	other := newTestLogKey(t, "b", f.log.priv)
	other.add(t, 2)
	f.clk.add(time.Minute)
	f.srv.setCandidate(other.head(t, 2, f.clk.ms()))
	writes := 0
	f.w.write = func(string, []byte) error { writes++; return errors.New("disk full") }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := f.w.serve(ctx)
	if !errors.Is(err, ErrFork) || !errors.Is(err, ErrState) {
		t.Fatalf("serve: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("serve ran until the context ended")
	}
	if writes != 1 || !f.st().Fork || f.srv.postCount() != 1 {
		t.Fatalf("writes %d, fork %v, posts %d", writes, f.st().Fork, f.srv.postCount())
	}
	if _, err := os.Lstat(f.w.path(forkExt)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fork file written by the failing hook")
	}
}

// countingTransport counts the body bytes the witness reads from
// responses to requests for path.
type countingTransport struct {
	rt   http.RoundTripper
	path string
	read atomic.Int64
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.rt.RoundTrip(r)
	if err == nil && r.URL.Path == c.path {
		resp.Body = &countingBody{ReadCloser: resp.Body, n: &c.read}
	}
	return resp, err
}

type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

// newTransport is a transport without proxy and connection reuse.
func newTransport() *http.Transport {
	return &http.Transport{DisableKeepAlives: true}
}

// endless writes a never-ending text body until the client goes away.
// It counts the bytes written and closes done when it returns.
func endless(w http.ResponseWriter, r *http.Request, written *atomic.Int64, done chan<- struct{}) {
	defer close(done)
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	chunk := bytes.Repeat([]byte("A"), 1024)
	for r.Context().Err() == nil {
		n, err := w.Write(chunk)
		written.Add(int64(n))
		if err != nil {
			return
		}
		w.(http.Flusher).Flush()
	}
}

// TestBodyLimit: get stops reading a body that does not end at the
// limit of the path plus one byte and drops the connection (task 08b).
func TestBodyLimit(t *testing.T) {
	for _, path := range []string{PathHead, PathConsistency} {
		t.Run(path[len("/gomail/log/"):], func(t *testing.T) {
			f := newFixture(t)
			var stream atomic.Bool
			var written atomic.Int64
			done := make(chan struct{})
			mux := http.NewServeMux()
			mux.Handle("/", f.srv.Config.Handler)
			mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
				if !stream.Load() {
					f.srv.Config.Handler.ServeHTTP(w, r)
					return
				}
				endless(w, r, &written, done)
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			ct := &countingTransport{rt: newTransport(), path: path}
			cfg := f.config()
			cfg.Log, cfg.HTTP = srv.URL, &http.Client{Transport: ct}
			f.w.Close()
			w, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			limit := int64(translog.MaxHeadNote)
			f.publish(2)
			if path == PathConsistency {
				limit = MaxProofBody
				if err := w.Poll(context.Background()); err != nil {
					t.Fatal(err)
				}
				f.clk.add(time.Minute)
				f.publish(2)
			}
			ct.read.Store(0)
			stream.Store(true)
			start := time.Now()
			if err := w.Poll(context.Background()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("endless body: %v", err)
			}
			d := time.Since(start)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the server still writes: the connection was not dropped")
			}
			read := ct.read.Load()
			t.Logf("read %d bytes, server wrote %d bytes, %v", read, written.Load(), d)
			if read > limit+1 || read >= 64<<10 {
				t.Fatalf("read %d bytes, limit %d", read, limit)
			}
			if d > RequestTimeout/4 {
				t.Fatalf("took %v", d)
			}
		})
	}
}

// TestTimeout: Config.Timeout ends a request that gets no answer, a
// body that stalls and a POST without answer (task 08b).
func TestTimeout(t *testing.T) {
	const timeout = 200 * time.Millisecond
	for name, stall := range map[string]string{"no answer": PathHead, "stalled body": PathHead, "post": PathCosign} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			stop := make(chan struct{})
			mux := http.NewServeMux()
			mux.Handle("/", f.srv.Config.Handler)
			mux.HandleFunc(stall, func(w http.ResponseWriter, r *http.Request) {
				if name == "stalled body" {
					w.Header().Set("Content-Type", ContentType)
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("gomail"))
					w.(http.Flusher).Flush()
				}
				select {
				case <-r.Context().Done():
				case <-stop:
				}
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			t.Cleanup(func() { close(stop) }) // runs before srv.Close
			cfg := f.config()
			cfg.Log, cfg.Timeout = srv.URL, timeout
			f.w.Close()
			w, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			f.publish(1)
			start := time.Now()
			err = w.Poll(context.Background())
			d := time.Since(start)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("got %v", err)
			}
			if d < timeout || d > timeout+3*time.Second {
				t.Fatalf("took %v, timeout %v", d, timeout)
			}
		})
	}
}

// TestRedirectOwnClient: a client from Config.HTTP never follows a
// redirect, whatever its own CheckRedirect says, and stays unchanged
// (task 08b).
func TestRedirectOwnClient(t *testing.T) {
	follow := func(*http.Request, []*http.Request) error { return nil }
	for name, own := range map[string]*http.Client{
		"default policy": {Transport: newTransport()},
		"follows":        {Transport: newTransport(), CheckRedirect: follow},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.publish(1)
			var followed atomic.Int32
			mux := http.NewServeMux()
			mux.Handle("/", f.srv.Config.Handler)
			mux.HandleFunc(PathHead, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/moved"+PathHead, http.StatusFound)
			})
			mux.HandleFunc("/moved"+PathHead, func(w http.ResponseWriter, r *http.Request) {
				followed.Add(1)
				f.srv.Config.Handler.ServeHTTP(w, r)
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			before := own.CheckRedirect
			cfg := f.config()
			cfg.Log, cfg.HTTP = srv.URL, own
			f.w.Close()
			w, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if err := w.Poll(context.Background()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("redirect: %v", err)
			}
			if followed.Load() != 0 || f.srv.postCount() != 0 {
				t.Fatal("redirect followed")
			}
			if w.client == own || w.client.Transport != own.Transport || (own.CheckRedirect == nil) != (before == nil) {
				t.Fatal("the given client was changed or not used")
			}
		})
	}
}
