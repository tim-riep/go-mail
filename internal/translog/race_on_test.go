//go:build race

package translog

// raceEnabled reports whether the tests run with the race detector,
// which slows the timing bound of TestNewestHeadSize.
const raceEnabled = true
