//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package ingest

import "errors"

func mlock([]byte) error   { return errors.New("mlock not supported") }
func munlock([]byte) error { return nil }
