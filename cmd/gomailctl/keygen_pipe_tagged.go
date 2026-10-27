//go:build gomail_test

package main

import (
	"errors"
	"os"
)

// testEnvKeygenPipe is read only by a test build (go build -tags
// gomail_test, internal/e2e and scripts/two-host-test.sh): set to 1,
// keygen without --shares runs on files and pipes as in phase 1 (seed
// words on standard output, the three words from standard input, no
// screen handling), so that a script can answer the word questions. A
// production build has neither this file nor the variable.
//
// TODO(ask): the scripted tests have no terminal; the strict rule of
// task 13b finding 1 holds in every production build only.
const testEnvKeygenPipe = "GOMAILCTL_TEST_KEYGEN_PIPE"

// testKeygenPipe reports whether GOMAILCTL_TEST_KEYGEN_PIPE is 1; any
// other value refuses keygen (fail closed).
func testKeygenPipe() (bool, error) {
	v, ok := os.LookupEnv(testEnvKeygenPipe)
	switch {
	case !ok:
		return false, nil
	case v == "1":
		return true, nil
	}
	return false, errors.New(testEnvKeygenPipe + ": nur 1 ist erlaubt")
}
