//go:build !unix

package main

import "io/fs"

// fileGroup is unknown on this platform; the PoC runs on Unix.
func fileGroup(fs.FileInfo) (int, bool) { return 0, false }

func inGroup(int) bool { return true }
