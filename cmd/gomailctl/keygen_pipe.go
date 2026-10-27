//go:build !gomail_test

package main

// testKeygenPipe reports false in a production build: keygen shows the
// seed only on a terminal and reads its words only from one (task 13b
// finding 1); there is no switch around it. The end-to-end tests build
// the programs with the tag gomail_test (keygen_pipe_tagged.go).
func testKeygenPipe() (bool, error) { return false, nil }
