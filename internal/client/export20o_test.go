package client

// ErrIncompleteDir is the error of Open, Register and DeviceLost on the
// temporary directory of an unfinished keygen or restore
// (errIncompleteDir, task 20o point 1).
var ErrIncompleteDir = errIncompleteDir

// ErrInsideDataDir rejects a client directory inside the data directory
// (errInsideDataDir, task 20o point 3).
var ErrInsideDataDir = errInsideDataDir

// ErrNotDurable is the error of a keygen or restore that renamed a
// complete client directory but could not confirm its durability
// (errNotDurable, task 20o point 4).
var ErrNotDurable = errNotDurable

// AfterRename is afterRename: the error of createClientDir for a failed
// lookup of the client directory right after the rename.
var AfterRename = afterRename
