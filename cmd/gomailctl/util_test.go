package main

import (
	"os"
	"testing"
)

// runMainEnv makes the test binary run main instead of the tests: the
// tests on a pseudo terminal (pty_linux_test.go) start it as gomailctl.
const runMainEnv = "GOMAILCTL_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
	}
	os.Exit(m.Run())
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// exists reports whether path exists.
func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
