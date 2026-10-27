//go:build !gomail_test

package main

import "github.com/tim-riep/go-mail/internal/ingest"

// testConfig changes nothing in a production build: the free space check
// of 5.1 has no switch (task 15c finding 7). The end-to-end tests build
// the programs with the tag gomail_test (testconfig_tagged.go).
func testConfig(*ingest.Config) error { return nil }
