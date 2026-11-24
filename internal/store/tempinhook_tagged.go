//go:build gomail_test

package store

import "os"

// SetTempInHook sets the function that ReplaceFileIn, WriteFileAtomicIn
// and CreateFileAtomicIn call at their points ("written", "rename" or
// "link", "renamed" or "linked"; tempInHook) and returns a function
// that puts back the one before. It exists only in a build with the tag
// gomail_test, for the tests of gomail-ceremony publish, which stand
// for another process that changes the temporary file of witnesses.rec
// (review of task 33 A, H1); a production build has no way to set the
// hook, and it reads no environment. h is not called concurrently by
// one call of those functions; the caller does not change it while one
// runs.
func SetTempInHook(h func(root *os.Root, tmp, point string)) (restore func()) {
	old := tempInHook
	tempInHook = h
	return func() { tempInHook = old }
}
