//go:build !gomail_dev

package main

import "flag"

// A production build has no development ceremony (task 15b point 4):
// init does not know --dev and --data (a usage error, exit code 2), and
// no path of the program writes a platform root into a file
// (ceremony.InitDev returns ceremony.ErrDev in this build). The test
// build with the tag gomail_dev has them (dev_dev.go).

// devUsage is empty: no init --dev.
const devUsage = ""

// devFlagSet stands for the flags of init --dev, which this build lacks.
type devFlagSet struct{}

// devFlags adds no flag.
func devFlags(*flag.FlagSet) *devFlagSet { return nil }

// run never runs a development ceremony.
func (*devFlagSet) run(*env, string, bool) (int, bool) { return 0, false }
