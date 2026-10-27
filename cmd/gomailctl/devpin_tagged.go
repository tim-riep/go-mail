//go:build gomail_test

package main

import (
	"errors"
	"os"

	"github.com/tim-riep/go-mail/internal/client"
)

// testEnvDevIdentity is read only by a test build (go build -tags
// gomail_test, internal/e2e, scripts/two-host-test.sh): with the value 1
// the client accepts the pin of a development ceremony
// (client.Config.AllowDevIdentity, task 14). A production build has
// neither this file nor the variable.
const testEnvDevIdentity = "GOMAIL_TEST_DEV_IDENTITY"

// devIdentity applies GOMAIL_TEST_DEV_IDENTITY; any value but 1 stops
// the command (fail closed).
func devIdentity(c *client.Config) error {
	v, ok := os.LookupEnv(testEnvDevIdentity)
	if !ok {
		return nil
	}
	if v != "1" {
		return errors.New(testEnvDevIdentity + ": only the value 1 is allowed")
	}
	c.AllowDevIdentity = true
	return nil
}
