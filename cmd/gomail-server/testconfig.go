//go:build !gomail_test

package main

import (
	"time"

	"github.com/tim-riep/go-mail/internal/ingest"
)

// testConfig changes nothing in a production build: the free space check
// of 5.1 has no switch (task 15c finding 7). The end-to-end tests build
// the programs with the tag gomail_test (testconfig_tagged.go).
func testConfig(*ingest.Config) error { return nil }

// testMinGap is 0 in a production build: loghttp.DefaultMinGap, at most
// one new head a minute while the log grows (translog doc.go "Heads").
func testMinGap() time.Duration { return 0 }
