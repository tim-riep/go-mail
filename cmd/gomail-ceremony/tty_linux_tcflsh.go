//go:build linux && (386 || amd64 || arm) && !ceremony_notty

package main

// ioctlFlush is TCFLSH (asm-generic/ioctls.h 0x540B); the syscall
// package does not define it on these architectures.
const ioctlFlush = 0x540B
