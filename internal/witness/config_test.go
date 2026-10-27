package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

func TestKeygen(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "w.key")
	vkey, err := Keygen("witness.example/a", p, nil)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	data := readFile(t, p)
	if !bytes.HasPrefix(data, []byte("PRIVATE+KEY+witness.example/a+")) || bytes.Count(data, []byte("\n")) != 1 || data[len(data)-1] != '\n' {
		t.Fatalf("key file %q", data)
	}
	if !strings.HasPrefix(vkey, "witness.example/a+") || strings.Contains(vkey, "PRIVATE") {
		t.Fatalf("vkey %q", vkey)
	}
	signer, own, err := loadKey(p)
	if err != nil {
		t.Fatal(err)
	}
	v := mustVerifier(t, vkey)
	if own.KeyHash() != v.KeyHash() || signer.KeyHash() != v.KeyHash() || own.Name() != v.Name() {
		t.Fatal("loaded key differs from the printed verifier key")
	}
	msg, _ := note.Sign(&note.Note{Text: "x\n"}, signer)
	if _, err := note.Open(msg, note.VerifierList(v)); err != nil {
		t.Fatal(err)
	}

	// Never replaced.
	if _, err := Keygen("other", p, nil); !errors.Is(err, ErrKey) || !errors.Is(err, store.ErrExists) {
		t.Fatalf("replaced: %v", err)
	}
	if !bytes.Equal(readFile(t, p), data) {
		t.Fatal("key file changed")
	}
	for _, name := range []string{"", "a b", "a+b", translog.LogSignerName, strings.Repeat("n", MaxName+1)} {
		if _, err := Keygen(name, filepath.Join(dir, "n.key"), nil); !errors.Is(err, ErrKey) {
			t.Fatalf("name %q: %v", name, err)
		}
	}
	if _, err := Keygen("a", "", nil); !errors.Is(err, ErrKey) {
		t.Fatal("empty file name")
	}
	if _, err := Keygen("a", filepath.Join(dir, "r.key"), io.LimitReader(rand.Reader, 3)); !errors.Is(err, ErrKey) {
		t.Fatal("short randomness")
	}
	if _, err := Keygen("a", filepath.Join(dir, "missing", "r.key"), nil); !errors.Is(err, ErrKey) {
		t.Fatal("missing directory")
	}
	// Deterministic with a given reader.
	a, _ := Keygen("d", filepath.Join(dir, "d1.key"), bytes.NewReader(make([]byte, 64)))
	b, _ := Keygen("d", filepath.Join(dir, "d2.key"), bytes.NewReader(make([]byte, 64)))
	if a != b || a == "" {
		t.Fatal("reader not used")
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.key")
	if _, err := Keygen("w", good, nil); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSuffix(string(readFile(t, good)), "\n")
	logSkey, _, _ := note.GenerateKey(rand.Reader, translog.LogSignerName)
	_, vk, _ := note.GenerateKey(rand.Reader, "w")
	// A signer key whose key data is not algorithm 1 with a seed is
	// refused by note already; one with a wrong hash as well.
	parts := strings.SplitN(line, "+", 5)
	wrongHash := strings.Join([]string{parts[0], parts[1], parts[2], "00000000", parts[4]}, "+")
	for name, content := range map[string]string{
		"no newline":   line,
		"two newlines": line + "\n\n",
		"crlf":         line + "\r\n",
		"verifier key": vk + "\n",
		"log name":     logSkey + "\n",
		"wrong hash":   wrongHash + "\n",
		"garbage":      "PRIVATE+KEY+w+x\n",
		"too long":     strings.Repeat("x", MaxKeyFile+1),
		"empty":        "",
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_"))
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadKey(p); !errors.Is(err, ErrKey) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if err := os.Chmod(good, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadKey(good); !errors.Is(err, ErrKey) {
		t.Fatal("group-readable key accepted")
	}
	if _, _, err := loadKey(filepath.Join(dir, "missing")); !errors.Is(err, ErrKey) {
		t.Fatal("missing key")
	}
	if _, _, err := loadKey(dir); !errors.Is(err, ErrKey) {
		t.Fatal("directory as key")
	}
}

func TestNewConfig(t *testing.T) {
	f := newFixture(t)
	f.w.Close()
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	second := newTestLogKey(t, "a", priv2)
	_, otherV, _ := note.GenerateKey(rand.Reader, "not-the-log")
	for name, c := range map[string]struct {
		mod func(*Config)
		err error
	}{
		"origin empty":     {func(c *Config) { c.Origin = "" }, ErrConfig},
		"origin space":     {func(c *Config) { c.Origin = "a b" }, ErrOrigin},
		"negative":         {func(c *Config) { c.Interval = -1 }, ErrConfig},
		"negative timeout": {func(c *Config) { c.Timeout = -1 }, ErrConfig},
		"url empty":        {func(c *Config) { c.Log = "" }, ErrConfig},
		"url ftp":          {func(c *Config) { c.Log = "ftp://x" }, ErrConfig},
		"url no host":      {func(c *Config) { c.Log = "http:///x" }, ErrConfig},
		"url user":         {func(c *Config) { c.Log = "http://u:p@x" }, ErrConfig},
		"url query":        {func(c *Config) { c.Log = "http://x/?a=b" }, ErrConfig},
		"url empty query":  {func(c *Config) { c.Log = "http://x/?" }, ErrConfig},
		"url fragment":     {func(c *Config) { c.Log = "http://x/#f" }, ErrConfig},
		"url opaque":       {func(c *Config) { c.Log = "http:x" }, ErrConfig},
		"url malformed":    {func(c *Config) { c.Log = "http://[::1" }, ErrConfig},
		"no log key":       {func(c *Config) { c.LogKeys = nil }, ErrKey},
		"log key garbage":  {func(c *Config) { c.LogKeys = []string{"x"} }, ErrKey},
		"log key name":     {func(c *Config) { c.LogKeys = []string{otherV} }, ErrKey},
		"log key twice":    {func(c *Config) { c.LogKeys = []string{second.vkey, f.log.vkey, second.vkey} }, ErrKey},
		"no state":         {func(c *Config) { c.StateDir = "" }, ErrConfig},
		"no key":           {func(c *Config) { c.KeyFile = "" }, ErrConfig},
		"missing key":      {func(c *Config) { c.KeyFile = filepath.Join(f.dir, "nokey") }, ErrKey},
		"state in nowhere": {func(c *Config) { c.StateDir = filepath.Join(f.dir, "a", "b") }, ErrState},
		"state is file":    {func(c *Config) { c.StateDir = f.key }, ErrState},
	} {
		cfg := f.config()
		c.mod(&cfg)
		w, err := New(cfg)
		if !errors.Is(err, c.err) {
			t.Errorf("%s: got %v, want %v", name, err, c.err)
		}
		if w != nil {
			w.Close()
		}
	}

	// Defaults: interval, clock, client, logger.
	cfg := f.config()
	cfg.Interval, cfg.Now, cfg.HTTP, cfg.Logger = 0, nil, nil, nil
	w, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if w.cfg.Interval != DefaultInterval || w.now == nil || w.client == nil || w.log == nil || w.client.CheckRedirect == nil ||
		w.cfg.Timeout != RequestTimeout || w.client.Timeout != RequestTimeout {
		t.Fatal("defaults")
	}
	// One witness per state directory.
	if _, err := New(f.config()); !errors.Is(err, ErrState) || !errors.Is(err, store.ErrLocked) {
		t.Fatalf("second witness on a locked state: %v", err)
	}
	w.Close()
}

func TestStateDir(t *testing.T) {
	f := newFixture(t)
	f.w.Close()

	// Rights of the state directory.
	if err := os.Chmod(f.state, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f.config()); !errors.Is(err, ErrState) {
		t.Fatalf("group-readable state directory: %v", err)
	}
	if err := os.Chmod(f.state, 0o700); err != nil {
		t.Fatal(err)
	}

	// A key file inside the state directory, also through a symlink.
	inKey := filepath.Join(f.state, "w.key")
	if _, err := Keygen("w", inKey, nil); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.dir, "link")
	if err := os.Symlink(f.state, link); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{inKey, filepath.Join(link, "w.key"), filepath.Join(f.state, "sub", "..", "w.key")} {
		cfg := f.config()
		cfg.KeyFile = k
		if _, err := New(cfg); !errors.Is(err, ErrKey) {
			t.Fatalf("key %s in the state directory: %v", k, err)
		}
	}
	cfg := f.config()
	cfg.StateDir = link
	cfg.KeyFile = filepath.Join(f.state, "w.key")
	if _, err := New(cfg); !errors.Is(err, ErrKey) {
		t.Fatal("key in the state directory through a linked state")
	}
	os.Remove(inKey)
	if inside(filepath.Join(f.dir, "statex", "k"), f.state) || inside(f.dir, f.state) || !inside(f.state, f.state) {
		t.Fatal("inside")
	}

	// A new state directory is created with 0700; temporary files are
	// removed at the start.
	fresh := filepath.Join(f.dir, "fresh")
	cfg = f.config()
	cfg.StateDir = fresh
	w, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if fi, err := os.Stat(fresh); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatal("mode of a new state directory")
	}
	tmp := filepath.Join(fresh, ".tmp-0011223344556677")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary file left")
	}
}

// TestStoredHead: the stored head is used only with a valid own
// cosignature and the configured origin.
func TestStoredHead(t *testing.T) {
	f := newFixture(t)
	f.publish(3)
	body, err := f.w.Cosign(f.srv.getCandidate(), nil)
	if err != nil {
		t.Fatal(err)
	}
	headPath := f.w.path(headExt)
	f.w.Close()

	// The log key may be rotated away: the stored head stays usable.
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	rotated := newTestLogKey(t, "a", priv2)
	cfg := f.config()
	cfg.LogKeys = []string{rotated.vkey}
	w, err := New(cfg)
	if err != nil {
		t.Fatalf("state after a log key rotation: %v", err)
	}
	if st, _ := w.State(); st.Head == nil || st.Head.Size != 3 {
		t.Fatal("state lost")
	}
	w.Close()

	write := func(b []byte) {
		t.Helper()
		if err := store.WritePrivateFileAtomic(headPath, b); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(f.dir, "other.key")
	if _, err := Keygen("witness.test", other, nil); err != nil {
		t.Fatal(err)
	}
	otherSigner, _, err := loadKey(other)
	if err != nil {
		t.Fatal(err)
	}
	ownSigner, _, _ := loadKey(f.key)
	flipped := append([]byte(nil), body...)
	flipped[len(flipped)-20] ^= 1 // inside the signature, not in the unused bits
	h := &translog.Head{Origin: "other.test/log", Size: 1, Hash: f.log.root(t, 1), Time: 1}
	otherText, _ := h.Text()
	for name, b := range map[string][]byte{
		"only the log signature": f.log.head(t, 3, 1),
		"another witness key":    f.log.sign(t, f.log.text(t, 3, 1), otherSigner),
		"broken own signature":   flipped,
		"other origin":           f.log.sign(t, string(otherText), ownSigner),
		"garbage":                []byte("garbage"),
		"too long":               bytes.Repeat([]byte("x"), translog.MaxHeadNote+1),
	} {
		write(b)
		if w, err := New(f.config()); !errors.Is(err, ErrState) {
			if w != nil {
				w.Close()
			}
			t.Errorf("%s: got %v", name, err)
		}
	}
	write(body)
	// A .fork file sets Fork whatever it holds; an unreadable entry
	// (a directory) as well.
	fork := strings.TrimSuffix(headPath, headExt) + forkExt
	if err := os.Mkdir(fork, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err = New(f.config())
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := w.State(); !st.Fork || st.Head == nil {
		t.Fatal("fork not read")
	}
	w.Close()
	// The head file as a directory is unusable.
	os.Remove(fork)
	os.Remove(headPath)
	if err := os.Mkdir(headPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f.config()); !errors.Is(err, ErrState) {
		t.Fatalf("head file is a directory: %v", err)
	}
}
