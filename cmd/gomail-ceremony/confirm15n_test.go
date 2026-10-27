package main

import "time"

// Test hook of task 15n finding 3: confirm waits confirmDelay (1 s in the
// program) after every prompt that calls a holder or asks whether a
// share is noted. The tests shorten it, never to 0 (shortConfirm): in
// this process for the stand-in terminals, and in the program re-executed
// on a pseudo terminal (TestMain), unless confirmEnv asks for the delay
// of the program. TestPTYEarlyEnter runs with the delay of the program.

// testConfirmDelay is confirmDelay in the tests. A test that types Enter
// at a confirmation waits answerPause first (pty.confirm, vt.confirm).
const (
	testConfirmDelay = 10 * time.Millisecond
	answerPause      = 120 * time.Millisecond
)

// confirmEnv set to "real" keeps confirmDelay of the program in the
// program re-executed by a test; otherwise it runs with testConfirmDelay.
const confirmEnv = "GOMAIL_CEREMONY_TEST_CONFIRM"

func init() { shortConfirm(testConfirmDelay) }

// shortConfirm sets confirmDelay to d, which must be longer than 0; it
// reports whether it did.
func shortConfirm(d time.Duration) bool {
	if d <= 0 {
		return false
	}
	confirmDelay = d
	return true
}
