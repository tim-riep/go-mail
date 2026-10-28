package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// The commands of task 13 (9.2, 2.2, 2.5, 6.3, 7, K4), each in its own
// file: keygen [--shares k-of-n] (cmd_keygen.go), mailbox share and
// mailbox revoke (cmd_share.go), device lost and restore
// (cmd_devicelost.go), search and flag (cmd_search.go).
//
// Exit codes: 0 success, 1 error, 2 usage error (unknown command or
// flag, wrong number of arguments, a malformed ID, epoch, split or
// month), 3 client.ErrPartial (a share, device lost or sync that is not
// complete; what was done is printed, the error names the remedy), 130
// abort by a signal while the seed, a share or typed words may be on the
// screen (screen.go). An error of the client API, client.ErrArgument
// and client.ErrQuery included, is exit code 1: the command line checks
// its arguments itself (exit code 2), so such an error comes from a
// value only the client can judge (a flag name, a search term, a split
// the client refuses).
//
// Not built (task 13):
//   - mailbox rotate (9.2): TODO(Q7), no reason for the epoch yet.
//   - mailbox set --server-search (9.2): TODO(Q3), not part of M1.
//   - mailbox share --delegate: not in 9.2, and no command uses member
//     kind 3 before Q6 is decided (TODO(Q6)).
//   - recovery keygen/set/clear/read: not in 9.2, no command before Q1
//     is decided (TODO(Q1)); the API stays internal.
//   - mailbox folders set, mailbox rename: not in 9.2; API only.
//   - index: not in 9.2; Index runs in sync.

// exitPartial is the exit code of client.ErrPartial.
const exitPartial = 3

// options are the flags and parsed arguments of a command of task 13.
type options struct {
	from, to uint32        // mailbox share
	split    client.Shares // keygen --shares
	shares   int           // restore --shares
	since    string        // search --since
	set, clr []string      // flag --set, --clear
	ids      []store.ID    // positional IDs
	query    string        // search term
}

// command is a command of task 13.
type command struct {
	// args is the number of positional arguments.
	args int
	// flags adds the flags of the command.
	flags func(fs *flag.FlagSet, o *options)
	// check checks the flags and arguments; an error is a usage error.
	check func(o *options, pos []string) error
	// pre runs before the client configuration (the locks of 9.1) is
	// taken; an error ends the command with exit code 1.
	pre func(e *env, o *options) error
	// open: run gets a client opened with the passphrase.
	open bool
	run  func(e *env, o *options, cfg client.Config, c *client.Client) int
}

var commands = map[string]command{
	"keygen":         {flags: keygenFlags, pre: keygenPre, run: runKeygen},
	"mailbox share":  {args: 2, flags: shareFlags, check: checkShare, open: true, run: runShare},
	"mailbox revoke": {args: 2, check: checkIDs, open: true, run: runRevoke},
	"device lost":    {pre: wordsPre, run: runDeviceLost},
	"restore":        {flags: restoreFlags, pre: wordsPre, run: runRestore},
	"search":         {args: 2, flags: searchFlags, check: checkSearch, open: true, run: runSearch},
	"flag":           {args: 2, flags: flagFlags, check: checkFlag, open: true, run: runFlag},
}

// commandName returns the name of a command of task 13 and its
// arguments; ok is false for the commands main.go runs itself.
func commandName(args []string) (name string, rest []string, ok bool) {
	switch args[0] {
	case "keygen", "restore", "search", "flag":
		return args[0], args[1:], true
	case "device":
		if len(args) > 1 {
			return "device " + args[1], args[2:], true
		}
		return "device", nil, true
	case "mailbox":
		if len(args) > 1 && (args[1] == "share" || args[1] == "revoke") {
			return "mailbox " + args[1], args[2:], true
		}
	}
	return "", nil, false
}

// dispatch runs a command of task 13; ok is false for the others.
func (e *env) dispatch(args []string) (code int, ok bool) {
	name, rest, ok := commandName(args)
	if !ok {
		return 0, false
	}
	cmd, known := commands[name]
	if !known {
		fmt.Fprint(e.stderr, usage)
		return 2, true
	}
	var o options
	fs := e.flags(name)
	if cmd.flags != nil {
		cmd.flags(fs, &o)
	}
	pos, err := parse(fs, rest)
	if err != nil {
		// Package flag reported it (search: not, see searchFlags).
		fmt.Fprint(e.stderr, usage)
		return 2, true
	}
	if len(pos) != cmd.args {
		err = errors.New("falsche Zahl von Argumenten")
	}
	if err == nil && cmd.check != nil {
		err = cmd.check(&o, pos)
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "gomailctl %s: %v\n", name, err)
		fmt.Fprint(e.stderr, usage)
		return 2, true
	}
	if cmd.pre != nil {
		if err := cmd.pre(e, &o); err != nil {
			return e.fail(err), true
		}
	}
	cfg, release, err := e.config()
	if err != nil {
		return e.fail(err), true
	}
	defer release()
	if !cmd.open {
		return cmd.run(e, &o, cfg, nil), true
	}
	pass, err := e.passphrase(false)
	if err != nil {
		return e.fail(err), true
	}
	c, err := client.Open(cfg, pass)
	keys.Wipe(pass)
	if err != nil {
		return e.fail(err), true
	}
	defer c.Close()
	return cmd.run(e, &o, cfg, c), true
}

// epochFlag parses an epoch number of at least 1 into *v.
func epochFlag(v *uint32) func(string) error {
	return func(s string) error {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 {
			return errors.New("eine Epoche ist eine Zahl von 1 bis 4294967295")
		}
		*v = uint32(n)
		return nil
	}
}

// checkIDs parses the positional arguments as IDs.
func checkIDs(o *options, pos []string) error {
	for _, p := range pos {
		id, err := store.ParseID(p)
		if err != nil {
			return errors.New("ungültige ID")
		}
		o.ids = append(o.ids, id)
	}
	return nil
}

// ---------------------------------------------------------------- keygen

// splitRe is the form k-of-n of keygen --shares.
var splitRe = regexp.MustCompile(`^([0-9]{1,3})-of-([0-9]{1,3})$`)

func keygenFlags(fs *flag.FlagSet, o *options) {
	fs.Func("shares", "Seed zusätzlich in Anteile aufteilen (k-of-n, etwa 2-of-3)", func(s string) error {
		m := splitRe.FindStringSubmatch(s)
		if m == nil {
			return errors.New("erwartet k-of-n, etwa 2-of-3")
		}
		k, _ := strconv.Atoi(m[1])
		n, _ := strconv.Atoi(m[2])
		if k < 2 || n < k || n > 255 {
			return errors.New("es gilt 2 <= k <= n <= 255")
		}
		o.split = client.Shares{Threshold: k, Count: n}
		return nil
	})
}

// ----------------------------------------------------------------- share

func shareFlags(fs *flag.FlagSet, o *options) {
	fs.Func("from", "erste Epoche, die der Benutzer bekommt", epochFlag(&o.from))
	fs.Func("to", "letzte Epoche eines vergangenen Zeitraums", epochFlag(&o.to))
}

func checkShare(o *options, pos []string) error {
	if o.to != 0 && o.from > o.to {
		return errors.New("--from liegt nach --to")
	}
	return checkIDs(o, pos)
}

// --------------------------------------------------------------- restore

func restoreFlags(fs *flag.FlagSet, o *options) {
	fs.Func("shares", "Seed aus k Anteilen wiederherstellen", func(s string) error {
		k, err := strconv.Atoi(s)
		if err != nil || k < 2 || k > 255 {
			return errors.New("erwartet eine Zahl von 2 bis 255")
		}
		o.shares = k
		return nil
	})
}

// ---------------------------------------------------------------- search

func searchFlags(fs *flag.FlagSet, o *options) {
	// A search term must never appear in an error message (00-vorgaben):
	// the messages of package flag quote what they cannot parse.
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.since, "since", "", "nur ab diesem Monat (JJJJ-MM)")
}

func checkSearch(o *options, pos []string) error {
	if o.since != "" {
		if _, err := time.Parse("2006-01", o.since); err != nil {
			return errors.New("--since erwartet JJJJ-MM")
		}
	}
	if err := checkIDs(o, pos[:1]); err != nil {
		return err
	}
	o.query = pos[1]
	return nil
}

// ------------------------------------------------------------------ flag

// flagList parses a comma-separated list of flag names into *v.
func flagList(v *[]string) func(string) error {
	return func(s string) error {
		for _, n := range strings.Split(s, ",") {
			n = strings.TrimSpace(n)
			if n == "" {
				return errors.New("leerer Flag-Name")
			}
			*v = append(*v, n)
		}
		return nil
	}
}

func flagFlags(fs *flag.FlagSet, o *options) {
	fs.Func("set", "Flags setzen (durch Komma getrennt)", flagList(&o.set))
	fs.Func("clear", "Flags entfernen (durch Komma getrennt)", flagList(&o.clr))
}

func checkFlag(o *options, pos []string) error {
	if len(o.set) == 0 && len(o.clr) == 0 {
		return errors.New("--set oder --clear fehlt")
	}
	return checkIDs(o, pos)
}
