package bench

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
)

// envNames are the environment variables that change a measurement; the
// ones that are set are printed with every benchmark run.
var envNames = []string{
	"GOTOOLCHAIN", "GOMAXPROCS", "GOGC", "GOMEMLIMIT", "GODEBUG", "GOAMD64", "GOARM64",
	"TMPDIR", "GOMAIL_BENCH_SYNC_MAILS", "GOMAIL_BENCH_MEM_MAILS", "GOMAIL_BENCH_MEM_CONNS",
}

// shellQuote quotes s for a POSIX shell where needed.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`*?[]^|&;<>(){}!#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// command reconstructs the go test command line of this run from the
// flags of the test binary.
func command() string {
	parts := []string{"go", "test"}
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "-test.") {
			a = "-" + strings.TrimPrefix(a, "-test.")
		}
		// Output paths of go test itself are left out.
		if strings.HasPrefix(a, "-paniconexit0") || strings.HasPrefix(a, "-testlogfile") || strings.HasPrefix(a, "-gocoverdir") || strings.HasPrefix(a, "-timeout") {
			continue
		}
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(append(parts, "./internal/bench"), " ")
}

// configLines describes the run: command, environment and hardware, in
// the "key: value" format of Go benchmark output.
func configLines() []string {
	lines := []string{"command: " + command()}
	var env []string
	for _, n := range envNames {
		if v, ok := os.LookupEnv(n); ok {
			env = append(env, n+"="+shellQuote(v))
		}
	}
	lines = append(lines, "env: "+strings.Join(env, " "))
	return append(lines, CollectHardware(os.TempDir()).Lines()...)
}

func TestMain(m *testing.M) {
	flag.Parse()
	if f := flag.Lookup("test.bench"); f != nil && f.Value.String() != "" {
		for _, l := range configLines() {
			fmt.Println(l)
		}
	}
	os.Exit(m.Run())
}
