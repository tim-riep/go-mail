// Package bench holds the benchmarks of milestone 7 (docs/tasks/12) and
// their helpers: reproducible mail generators with a fixed seed, a
// corpus with a typical term distribution and the capture of the
// hardware a measurement ran on.
//
// Nothing in this package is linked into the programs: no package
// outside internal/bench imports it (TestNotLinked checks this). The
// benchmarks run only in temporary directories; the hardware description
// goes to the benchmark output, never into a data directory.
//
// Run everything with scripts/bench.sh; single numbers with
//
//	go test -run '^$' -bench <name> ./internal/bench
package bench
