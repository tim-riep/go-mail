package bench

import (
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// platformEnv names the directory TestBuildPlatform writes into.
const platformEnv = "GOMAIL_BENCH_PLATFORM"

// copyTree copies the regular files and directories below src to dst,
// keeping their permissions.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(to, fi.Mode().Perm())
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fi.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}

// TestBuildPlatform is the child process of newPlatformRig, not a test
// of its own: it builds a development platform with one user and a
// mailbox for BenchTo and copies the data directory and the key
// directory into $GOMAIL_BENCH_PLATFORM. It is skipped without it.
func TestBuildPlatform(t *testing.T) {
	dir := os.Getenv(platformEnv)
	if dir == "" {
		t.Skip("child process of newPlatformRig")
	}
	r := newEnvRig(t, BenchTo)
	if err := copyTree(filepath.Join(r.env.Base, "data"), filepath.Join(dir, "data")); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(r.env.KeyDir, filepath.Join(dir, "keys")); err != nil {
		t.Fatal(err)
	}
}

// newPlatformRig is newIngestRig without the platform's setup in this
// process: a child process builds the data directory, so the key
// derivation of the key store (Argon2id, 64 MiB) and the clients never
// show up in this process's memory. The clock stands at testenv.Start.
func newPlatformRig(tb testing.TB) *rig {
	tb.Helper()
	dir := tb.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestBuildPlatform$", "-test.count=1")
	cmd.Env = append(os.Environ(), platformEnv+"="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		tb.Fatalf("building the platform: %v\n%s", err, out)
	}
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		tb.Fatal(err)
	}
	log, err := translog.NewUnverified(true)
	if err != nil {
		tb.Fatal(err)
	}
	key, _, err := ceremony.ReadKey(filepath.Join(dir, "keys", ceremony.IngestKeyFile), store.KeyRoleIngest)
	if err != nil {
		tb.Fatal(err)
	}
	r := &rig{st: st, log: log, ingestKey: key, now: func() time.Time { return testenv.Start }}
	r.startIngest(tb)
	r.serve(tb, r.in)
	return r
}
