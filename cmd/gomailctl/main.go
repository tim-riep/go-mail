// Command gomailctl is the user's client (9.2):
//
//	gomailctl keygen [--shares k-of-n]
//	gomailctl register --invite <code>
//	gomailctl mailbox create <name>
//	gomailctl mailbox share <mailbox-id> <user-id> [--from <epoch>] [--to <epoch>]
//	gomailctl mailbox revoke <mailbox-id> <user-id>
//	gomailctl sync
//	gomailctl device lost
//	gomailctl restore [--shares <k>]
//	gomailctl list <mailbox-id> [--folder <name>]
//	gomailctl read <mailbox-id> <mail-id>
//	gomailctl search <mailbox-id> <term> [--since YYYY-MM]
//	gomailctl flag <mailbox-id> <mail-id> [--set a,b] [--clear c]
//	gomailctl inspect <file>
//
// The commands of task 13 (keygen --shares, mailbox share and revoke,
// device lost, restore, search, flag) live in the files cmd_*.go; see
// commands.go for the exit codes (0 success, 1 error, 2 usage error, 3
// client.ErrPartial) and for the commands of 9.2 that are not built.
//
// Common flags: --data <dir> (data directory), --dir <dir> (client
// directory, default ~/.config/gomailctl), --platform <file> (trusted
// platform identity, identity-1.pin of the ceremony) and
// --insecure-no-log (required until task 14 builds the client log). The
// passphrase of the key store is read from GOMAILCTL_PASSPHRASE, from
// --passphrase-file or from standard input (one line of at most 4096
// bytes).
//
// The seed and shares appear only on a terminal and are cleared from it
// (screen.go): keygen requires a terminal on standard output and on
// standard input; seed and share words typed on a terminal are read with
// the echo off (task 13b).
//
// Every command but inspect holds the shared client lock locks/client
// and works only while the lock of a running gomail-server is in force
// on the data directory (9.1, "Testsperre"; config).
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog/translogtest"
)

func main() {
	relayBrokenPipe()
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

const usage = `Aufruf:
  gomailctl keygen [--shares k-of-n]       [gemeinsame Optionen]
  gomailctl register --invite <code>       [gemeinsame Optionen]
  gomailctl mailbox create <name>          [gemeinsame Optionen]
  gomailctl mailbox share <postfach-id> <benutzer-id> [--from <epoche>] [--to <epoche>] [gemeinsame Optionen]
  gomailctl mailbox revoke <postfach-id> <benutzer-id> [gemeinsame Optionen]
  gomailctl sync                           [gemeinsame Optionen]
  gomailctl device lost                    [gemeinsame Optionen]
  gomailctl restore [--shares <k>]         [gemeinsame Optionen]
  gomailctl list <postfach-id> [--folder <name>] [gemeinsame Optionen]
  gomailctl read <postfach-id> <mail-id>   [gemeinsame Optionen]
  gomailctl search <postfach-id> <begriff> [--since JJJJ-MM] [gemeinsame Optionen]
  gomailctl flag <postfach-id> <mail-id> [--set a,b] [--clear c] [gemeinsame Optionen]
  gomailctl inspect <datei>

Gemeinsame Optionen:
  --data <dir>             Datenverzeichnis
  --dir <dir>              Client-Verzeichnis (Standard ~/.config/gomailctl)
  --platform <datei>       Plattformidentität (identity-1.pin)
  --insecure-no-log        ohne Transparenzlog (bis zum Client-Log erforderlich)
  --passphrase-file <datei> Passphrase aus Datei (sonst GOMAILCTL_PASSPHRASE oder Eingabe)
`

type env struct {
	stdin  *bufio.Reader
	in     io.Reader // the standard input stdin reads, for the terminal checks
	stdout io.Writer
	stderr io.Writer
	now    func() time.Time

	data, dir, platform, passFile, invite, folder string
	noLog                                         bool
}

func (e *env) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	fs.StringVar(&e.data, "data", "", "Datenverzeichnis")
	fs.StringVar(&e.dir, "dir", "", "Client-Verzeichnis")
	fs.StringVar(&e.platform, "platform", "", "Plattformidentität")
	fs.StringVar(&e.passFile, "passphrase-file", "", "Datei mit der Passphrase")
	fs.BoolVar(&e.noLog, "insecure-no-log", false, "ohne Transparenzlog")
	return fs
}

// parse accepts flags before, between and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{stdin: bufio.NewReader(stdin), in: stdin, stdout: stdout, stderr: stderr, now: time.Now}
	return e.run(args)
}

func (e *env) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(e.stderr, usage)
		return 2
	}
	if code, ok := e.dispatch(args); ok {
		return code
	}
	cmd := args[0]
	fs := e.flags(cmd)
	if cmd == "register" {
		fs.StringVar(&e.invite, "invite", "", "Einladungscode")
	}
	if cmd == "list" {
		fs.StringVar(&e.folder, "folder", "", "Ordnername")
	}
	pos, err := parse(fs, args[1:])
	if err != nil {
		fmt.Fprint(e.stderr, usage)
		return 2
	}
	want := map[string]int{"register": 0, "mailbox": 2, "sync": 0, "list": 1, "read": 2, "inspect": 1}
	n, ok := want[cmd]
	if !ok || len(pos) != n || cmd == "mailbox" && pos[0] != "create" || cmd == "register" && e.invite == "" {
		fmt.Fprint(e.stderr, usage)
		return 2
	}
	if cmd == "inspect" {
		return e.inspect(pos[0])
	}
	cfg, release, err := e.config()
	if err != nil {
		return e.fail(err)
	}
	defer release()
	switch cmd {
	case "register":
		code, err := store.ParseID(strings.TrimSpace(e.invite))
		if err != nil {
			return e.fail(err)
		}
		id, err := client.Register(cfg, code)
		if err != nil {
			return e.fail(err)
		}
		fmt.Fprintf(e.stdout, "Registriert: %s\n", id)
		return 0
	}
	pass, err := e.passphrase(false)
	if err != nil {
		return e.fail(err)
	}
	c, err := client.Open(cfg, pass)
	keys.Wipe(pass)
	if err != nil {
		return e.fail(err)
	}
	defer c.Close()
	switch cmd {
	case "mailbox":
		id, err := c.CreateMailbox(pos[1])
		if err != nil {
			return e.fail(err)
		}
		fmt.Fprintf(e.stdout, "%s\n", id)
		return 0
	case "sync":
		if err := c.Sync(); err != nil {
			return e.fail(err)
		}
		fmt.Fprintln(e.stdout, "Epochenvorrat aktuell.")
		return 0
	case "list":
		return e.list(c, pos[0])
	}
	return e.read(c, pos[0], pos[1])
}

func (e *env) fail(err error) int {
	fmt.Fprintln(e.stderr, "gomailctl:", err)
	if errors.Is(err, client.ErrPartial) {
		return exitPartial
	}
	return 1
}

// config builds the client configuration and takes the client's side of
// the start check of 9.1 (D70, "Testsperre"): the shared client lock
// locks/client, held until release is called at the end of the command,
// and the check that the server's exclusive lock on locks/server is in
// force here (store.CheckPeerLock). Without a running gomail-server whose
// lock this machine sees (no server, or locks that the file system does
// not enforce across machines, such as SSHFS) the client refuses to work
// on the data directory. The server holds its lock for its whole run;
// the client cannot tell a stopped server from an ineffective lock, so
// both are refused (fail closed).
func (e *env) config() (client.Config, func(), error) {
	if e.data == "" || e.platform == "" {
		return client.Config{}, nil, errors.New("--data und --platform sind erforderlich")
	}
	// TODO(task-14): the client log (translog.Open with a Verifier,
	// Refresh, state.json) replaces the placeholder and --insecure-no-log.
	log, err := translogtest.NewUnverified(e.noLog)
	if err != nil {
		return client.Config{}, nil, err
	}
	st, err := store.Open(e.data)
	if err != nil {
		return client.Config{}, nil, err
	}
	pin, err := ceremony.ReadPin(e.platform)
	if err != nil {
		return client.Config{}, nil, err
	}
	dir := e.dir
	if dir == "" {
		cfgDir, err := os.UserConfigDir()
		if err != nil {
			return client.Config{}, nil, err
		}
		dir = filepath.Join(cfgDir, "gomailctl")
	}
	release, err := st.HoldRoleLock(store.RoleClient)
	if err != nil {
		return client.Config{}, nil, fmt.Errorf("Client-Sperre locks/client (9.1): %w", err)
	}
	if err := st.CheckPeerLock(store.RoleServer); err != nil {
		release()
		return client.Config{}, nil, fmt.Errorf("Testsperre (9.1): keine wirksame Sperre eines laufenden gomail-server auf locks/server; "+
			"der Client arbeitet nur neben einem Server, dessen Sperre hier wirkt: %w", err)
	}
	return client.Config{Store: st, Dir: dir, Pin: pin, Log: log, Now: e.now,
		Warn: func(s string) { fmt.Fprintln(e.stderr, s) }}, release, nil
}

// passphrase reads the passphrase: GOMAILCTL_PASSPHRASE, the file, or a
// line of at most 4096 bytes from standard input (readSecret; a longer
// line is refused, task 13b finding 5). Input on a terminal is echoed;
// keygen clears the screen with its scroll-back buffer before it shows
// the seed. Use the file or the variable for real secrets.
// TODO(ask): whether the passphrase too is read with the echo off.
func (e *env) passphrase(twice bool) ([]byte, error) {
	if v := os.Getenv("GOMAILCTL_PASSPHRASE"); v != "" {
		return []byte(v), nil
	}
	if e.passFile != "" {
		b, err := store.ReadFileLimited(e.passFile, 4096)
		if err != nil {
			return nil, err
		}
		return []byte(strings.TrimRight(string(b), "\r\n")), nil
	}
	read := func(prompt string) ([]byte, error) {
		fmt.Fprint(e.stderr, prompt)
		line, err := e.readSecret()
		if errors.Is(err, errLongLine) {
			return nil, fmt.Errorf("Passphrase: %w (höchstens %d Bytes)", err, e.stdin.Size())
		}
		if err != nil {
			return nil, errors.New("keine Passphrase")
		}
		p := bytes.Clone(line)
		clear(line)
		return p, nil
	}
	p, err := read("Passphrase: ")
	if err != nil {
		return nil, err
	}
	if twice {
		q, err := read("Passphrase wiederholen: ")
		if err != nil {
			keys.Wipe(p)
			return nil, err
		}
		same := bytes.Equal(p, q)
		keys.Wipe(q)
		if !same {
			keys.Wipe(p)
			return nil, errors.New("die Passphrasen stimmen nicht überein")
		}
	}
	if len(p) == 0 {
		return nil, errors.New("leere Passphrase")
	}
	return p, nil
}

func (e *env) list(c *client.Client, mbxArg string) int {
	mbx, err := store.ParseID(mbxArg)
	if err != nil {
		return e.fail(err)
	}
	var folder store.ID
	if e.folder != "" {
		folders, err := c.Folders(mbx)
		if err != nil {
			return e.fail(err)
		}
		found := false
		for _, f := range folders {
			if f.Name == e.folder {
				folder, found = f.ID, true
			}
		}
		if !found {
			return e.fail(fmt.Errorf("kein Ordner %q", e.folder))
		}
	}
	mails, err := c.List(mbx, folder)
	// The subject is the only plaintext of the metadata shown (task 13:
	// no plaintext in the output but the subject of list and search).
	// TODO(ask): the sender column of phase 1 is dropped for it.
	for _, m := range mails {
		t := time.UnixMilli(m.Meta.Received).UTC().Format("2006-01-02 15:04")
		fmt.Fprintf(e.stdout, "%s  %s  %7d  %s\n", m.ID, t, m.Meta.Size, m.Meta.Subject)
	}
	if err != nil {
		return e.fail(err)
	}
	return 0
}

func (e *env) read(c *client.Client, mbxArg, mailArg string) int {
	mbx, err := store.ParseID(mbxArg)
	if err != nil {
		return e.fail(err)
	}
	id, err := store.ParseID(mailArg)
	if err != nil {
		return e.fail(err)
	}
	_, content, err := c.Read(mbx, id)
	if err != nil {
		return e.fail(err)
	}
	defer keys.Wipe(content)
	if _, err := e.stdout.Write(content); err != nil {
		return e.fail(err)
	}
	return 0
}

func (e *env) inspect(path string) int {
	data, err := store.ReadFileLimited(path, store.MaxMailFile)
	if err != nil {
		return e.fail(err)
	}
	out, err := client.Inspect(data)
	if err != nil {
		return e.fail(err)
	}
	fmt.Fprintf(e.stdout, "%s\n", out)
	return 0
}
