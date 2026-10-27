//go:build !unix

package main

import "io/fs"

// fileGroup is unknown on this platform; the PoC runs on Unix.
func fileGroup(fs.FileInfo) (int, bool) { return 0, false }

func inGroup(int) bool { return true }

// fileOwner is unknown on this platform: init, which needs the owner of
// the directory it created, fails closed (task 15k finding 2).
func fileOwner(fs.FileInfo) (int, bool) { return 0, false }
