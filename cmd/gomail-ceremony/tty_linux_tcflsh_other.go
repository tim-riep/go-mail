//go:build linux && !(386 || amd64 || arm) && !ceremony_notty

package main

import "syscall"

// ioctlFlush is TCFLSH.
const ioctlFlush = syscall.TCFLSH
