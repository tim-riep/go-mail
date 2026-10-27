// Package store is the file system layout of go-mail (specification
// section 4): the data directory, atomic writes, per-mailbox file locks,
// the records of users, mailboxes and epochs (2.2, 2.4) with the shared
// chain checker, folder lists, wrap acceptances, client checkpoints,
// index segments, invitations and address assignments.
//
// The data directory never holds a private key (section 4). Every file
// in it is either encrypted (.gml), a public key, a signed record, or one
// of the plain working files the specification names (addresses.json,
// invites/<code>.json). Records are canonical (3.6) and decoded strictly;
// every length is checked against a maximum before anything is read.
//
// Writes are atomic: a temporary file in the target directory is
// written, synced, renamed onto the target and the directory is synced.
// Readers therefore see either the old or the new file, never a part.
// Files in the data directory are 0660 and directories 2770 (9.1); locks
// are POSIX record locks (fcntl), open file description locks on Linux.
package store
