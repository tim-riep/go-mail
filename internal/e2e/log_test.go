package e2e

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/loghttp"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// logSide is the log side of the server (package loghttp) on the
// operator log of env, served over HTTP, and the pinned witness of env
// polling it, both on the clock of env. Tick and Poll run only when the
// test calls cosign.
type logSide struct {
	env  *testenv.Env
	side *loghttp.Server
	w    *witness.Witness
}

func startLogSide(t *testing.T, env *testenv.Env) *logSide {
	t.Helper()
	signer, err := translog.NewLogSigner(env.IngestKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := env.IngestKey.Public().(ed25519.PublicKey)
	lk, err := translog.NewLogVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	wv, err := translog.NewWitnessVerifier(env.Witness.Name, env.Witness.Pub)
	if err != nil {
		t.Fatal(err)
	}
	side, err := loghttp.New(loghttp.Config{Log: env.Operator, Signer: signer, LogKey: lk, Witnesses: []note.Verifier{wv},
		Now: env.Clock.Now, MinGap: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(side)
	t.Cleanup(hs.Close)
	vkey, err := note.NewEd25519VerifierKey(translog.LogSignerName, pub)
	if err != nil {
		t.Fatal(err)
	}
	w, err := witness.New(witness.Config{Log: hs.URL, LogKeys: []string{vkey}, Origin: env.Pin.Origin, KeyFile: env.WitnessKeyFile,
		StateDir: filepath.Join(t.TempDir(), "witness-state"), Now: env.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return &logSide{env: env, side: side, w: w}
}

// size is the committed size of the log.
func size(t *testing.T, op translog.Operator) int64 {
	t.Helper()
	n := int64(0)
	for ; ; n++ {
		if _, err := op.Entry(n); err != nil {
			if !errors.Is(err, translog.ErrNotInLog) && !errors.Is(err, translog.ErrPending) {
				t.Fatal(err)
			}
			return n
		}
	}
}

// cosign lets the server sign the committed tree and the witness cosign
// it until a head of the committed size is published in heads/.
func (l *logSide) cosign(t *testing.T) *translog.Head {
	t.Helper()
	want := size(t, l.env.Operator)
	for i := 0; i < 20; i++ {
		l.env.Clock.Advance(2 * time.Second)
		l.side.Tick()
		if err := l.w.Poll(context.Background()); err != nil {
			t.Fatalf("witness: %v", err)
		}
		l.side.Tick()
		if h, err := l.env.Operator.Head(); err == nil && h.Size == want {
			return h
		}
	}
	t.Fatalf("no head of size %d published", want)
	return nil
}

// TestLogEndToEnd: server, witness and two clients on the transparency
// log of the data directory (task 15). Every user, epoch and address
// assignment is logged, the server encrypts for the logged epoch, the
// witness cosigns the heads, an address without a log entry is refused,
// and a rollback of epoch.rec and mailbox.rec by the server is caught
// after a restart.
func TestLogEndToEnd(t *testing.T) {
	env := testenv.NewLogged(t)
	ls := startLogSide(t, env)
	alice := env.NewUser("alice")
	bob := env.NewUser("bob")
	mbx := env.Mailbox(alice, "Büro", "info@brownbear.example")
	env.Share(alice, mbx, bob, client.ShareOptions{})
	s := startServer(t, env)
	h := ls.cosign(t)
	if h.Size < 8 {
		t.Fatalf("head of size %d", h.Size)
	}
	if _, err := os.Stat(env.Store.Path("log", "heads", strconv.FormatInt(h.Size, 10)+".sig")); err != nil {
		t.Fatal(err)
	}

	// The mail is encrypted for the newest logged epoch; both members
	// read it.
	if err := send(s, "s@x.example", []string{"info@brownbear.example"}, "Subject: logged\r\n\r\nx\r\n"); err != nil {
		t.Fatal(err)
	}
	m, err := env.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	es, err := env.Log.Lookup(translog.KindEpoch, mbx[:])
	if err != nil || len(es) == 0 || es[len(es)-1].Seq != int64(m.Epoch) {
		t.Fatalf("epochs in the log: %v %d", err, len(es))
	}
	for _, u := range []*testenv.User{alice, bob} {
		list, err := u.Client.List(mbx, store.ID{})
		if err != nil || len(list) != 1 {
			t.Fatalf("list: %v %v", err, env.Warnings.Take())
		}
		_, data, err := env.Store.ReadEpoch(mbx, list[0].Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if err := env.Log.CheckEpoch(mbx, list[0].Epoch, data); err != nil {
			t.Fatalf("mail of an epoch not in the log: %v", err)
		}
		if _, _, err := u.Client.Read(mbx, list[0].ID); err != nil {
			t.Fatal(err)
		}
	}

	// An address only in addresses.json: 550.
	if _, err := env.Store.AddAddress("unlogged@brownbear.example", mbx); err != nil {
		t.Fatal(err)
	}
	if err := send(s, "s@x.example", []string{"unlogged@brownbear.example"}, "Subject: x\r\n\r\ny\r\n"); smtpCode(err) != 550 {
		t.Fatalf("address without a log entry: %v", err)
	}

	// A member is removed: an immediate epoch, logged. The server resets
	// mailbox.rec and epoch.rec to the epoch before and restarts.
	env.Clock.Advance(time.Minute)
	if err := alice.Client.Revoke(mbx, bob.ID); err != nil {
		t.Fatal(err)
	}
	head, err := env.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	if head.Epoch <= m.Epoch {
		t.Fatalf("no new epoch: %d", head.Epoch)
	}
	ls.cosign(t)
	s.srv.Close()
	s.in.Close()
	for n := head.Epoch; n > m.Epoch; n-- {
		if err := os.RemoveAll(env.Store.EpochDir(mbx, n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
	s2 := startServer(t, env, func(c *ingest.Config) { c.Log = env.OpenOperator() })
	if err := send(s2, "s@x.example", []string{"info@brownbear.example"}, "Subject: after\r\n\r\nz\r\n"); smtpCode(err) != 451 {
		t.Fatalf("after the rollback: %v", err)
	}
	if l := string(s2.logs.Bytes()); !strings.Contains(l, "rollback") || strings.Contains(l, "brownbear") {
		t.Fatalf("server log: %s", l)
	}
}
