package witness

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/translog"
)

// Poll runs one round: fetch the head, fetch the proof, Cosign, post.
//
// A 404 on the head (the server has not signed one yet) ends the round
// without error. The proof is fetched only for a head larger than the
// stored one. When the candidate already carries the witness's own
// cosignature line for the same text, nothing is posted.
func (w *Witness) Poll(ctx context.Context) error {
	st, err := w.State()
	if err != nil {
		return w.fail("state", err)
	}
	if st.Fork {
		return w.fail("state", ErrFork)
	}
	body, status, err := w.get(ctx, w.url(PathHead, ""), translog.MaxHeadNote)
	if err != nil {
		return w.fail("fetch head", err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		w.log.Info("no head yet", "status", status)
		return nil
	default:
		return w.fail("fetch head", fmt.Errorf("%w: head status %d", ErrProtocol, status))
	}
	h, err := w.openHead(body)
	if err != nil {
		return w.fail("open head", err)
	}
	var proof tlog.TreeProof
	if st.Head != nil && h.Size > st.Head.Size && h.Size <= translog.MaxTreeSize {
		q := "from=" + strconv.FormatInt(st.Head.Size, 10) + "&to=" + strconv.FormatInt(h.Size, 10)
		pb, status, err := w.get(ctx, w.url(PathConsistency, q), MaxProofBody)
		if err != nil {
			return w.fail("fetch proof", err)
		}
		if status != http.StatusOK {
			return w.fail("fetch proof", fmt.Errorf("%w: consistency status %d", ErrProtocol, status))
		}
		if proof, err = ParseProof(pb); err != nil {
			return w.fail("parse proof", err)
		}
	}
	out, err := w.Cosign(body, proof)
	if err != nil {
		return w.fail("refused", err)
	}
	attrs := []any{"size", h.Size, "hash", hashPrefix(h.Hash)}
	if hasLine(body, lastLine(out)) {
		w.log.Info("head already cosigned", attrs...)
		return nil
	}
	status, err = w.post(ctx, out)
	if err != nil {
		return w.fail("post cosignature", err)
	}
	attrs = append(attrs, "status", status)
	switch status {
	case http.StatusOK:
		w.log.Info("cosigned", attrs...)
		return nil
	case http.StatusConflict:
		// The candidate changed meanwhile; the next round fetches again.
		w.log.Info("candidate changed", attrs...)
		return nil
	default:
		w.log.Warn("cosignature refused by the server", attrs...)
		return fmt.Errorf("%w: cosign status %d", ErrProtocol, status)
	}
}

// fail logs a failed step of Poll and returns err.
func (w *Witness) fail(step string, err error) error {
	if errors.Is(err, ErrFork) {
		w.log.Error("fork: the log showed two heads of one size; cosigning stopped", "step", step, "reason", reason(err))
	} else {
		w.log.Warn(step, "reason", reason(err))
	}
	return err
}

// Serve runs Poll every cfg.Interval until ctx ends (gomail-witness
// serve). A fork stops it with ErrFork; when the evidence of the fork
// could not be written, the error wraps ErrState as well (the process
// ends rather than runs on without durable evidence). Other failures of
// a round are logged and the next round runs as planned; Serve returns
// nil when ctx ends.
func Serve(ctx context.Context, cfg Config) error {
	w, err := New(cfg)
	if err != nil {
		return err
	}
	defer w.Close()
	return w.serve(ctx)
}

func (w *Witness) serve(ctx context.Context) error {
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		if err := w.Poll(ctx); errors.Is(err, ErrFork) {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// url returns the URL of a protocol path below the configured base.
func (w *Witness) url(path, query string) string {
	u := *w.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawPath = ""
	u.RawQuery = query
	return u.String()
}

// get fetches a text body of at most max bytes. The body is read only
// for status 200; it must be text/plain with charset utf-8.
func (w *Witness) get(ctx context.Context, url string, max int64) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, w.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, MaxErrorBody))
		return nil, resp.StatusCode, nil
	}
	if !textPlain(resp.Header.Get("Content-Type")) {
		return nil, 0, fmt.Errorf("%w: content type", ErrProtocol)
	}
	if resp.ContentLength > max {
		return nil, 0, fmt.Errorf("%w: response of %d bytes, at most %d", ErrProtocol, resp.ContentLength, max)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if int64(len(body)) > max {
		return nil, 0, fmt.Errorf("%w: response longer than %d bytes", ErrProtocol, max)
	}
	return body, resp.StatusCode, nil
}

// post sends the cosigned head and returns the status. The response
// body is at most read up to MaxErrorBody and discarded.
func (w *Witness) post(ctx context.Context, body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, w.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url(PathCosign, ""), bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	req.Header.Set("Content-Type", ContentType)
	resp, err := w.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, MaxErrorBody))
	resp.Body.Close()
	return resp.StatusCode, nil
}

// textPlain reports whether a Content-Type header is text/plain with
// charset utf-8 (the protocol's ContentType, case-insensitive).
func textPlain(v string) bool {
	mt, params, err := mime.ParseMediaType(v)
	return err == nil && mt == "text/plain" && len(params) == 1 && strings.EqualFold(params["charset"], "utf-8")
}

// lastLine returns the last line of a note, with its newline.
func lastLine(n []byte) []byte {
	t := bytes.TrimSuffix(n, []byte("\n"))
	return n[bytes.LastIndexByte(t, '\n')+1:]
}

// hasLine reports whether the signature block of the signed note msg
// contains line (with its newline) as a whole line.
func hasLine(msg, line []byte) bool {
	i := bytes.LastIndex(msg, []byte("\n\n"))
	if i < 0 || len(line) == 0 {
		return false
	}
	sigs := msg[i+1:] // starts with "\n", so every line follows a "\n"
	return bytes.Contains(sigs, append([]byte("\n"), line...))
}

// hashPrefix is the first four bytes of a root hash in hex, for logs.
func hashPrefix(h tlog.Hash) string { return hex.EncodeToString(h[:4]) }
