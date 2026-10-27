//go:build !gomail_test

package main

import "github.com/tim-riep/go-mail/internal/client"

// devIdentity changes nothing in a production build: a pin of a
// development ceremony is refused (client.ErrDevIdentity, task 14; no
// command line flag accepts it). The end-to-end tests build the programs
// with the tag gomail_test (devpin_tagged.go).
func devIdentity(*client.Config) error { return nil }
