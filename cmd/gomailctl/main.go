// Command gomailctl is the user's client (9.2). Phase 1:
//
//	gomailctl keygen
//	gomailctl register --invite <code>
//	gomailctl mailbox create <name>
//	gomailctl sync
//	gomailctl list <mailbox-id> [--folder <name>]
//	gomailctl read <mailbox-id> <mail-id>
//	gomailctl inspect <file>
//
// Common flags: --data <dir> (data directory), --dir <dir> (client
// directory, default ~/.config/gomailctl), --platform <file> (trusted
// platform identity, identity-1.pin of the ceremony) and
// --insecure-no-log (required in phase 1). The passphrase of the key
// store is read from GOMAILCTL_PASSPHRASE, from --passphrase-file or from
// standard input.
package main

import (
	"bufio"
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
	"github.com/tim-riep/go-mail/internal/translog"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

const usage = `Aufruf:
  gomailctl keygen                         [gemeinsame Optionen]
  gomailctl register --invite <code>       [gemeinsame Optionen]
  gomailctl mailbox create <name>          [gemeinsame Optionen]
  gomailctl sync                           [gemeinsame Optionen]
  gomailctl list <postfach-id> [--folder <name>] [gemeinsame Optionen]
  gomailctl read <postfach-id> <mail-id>   [gemeinsame Optionen]
  gomailctl inspect <datei>

Gemeinsame Optionen:
  --data <dir>             Datenverzeichnis
  --dir <dir>              Client-Verzeichnis (Standard ~/.config/gomailctl)
  --platform <datei>       Plattformidentität (identity-1.pin)
  --insecure-no-log        ohne Transparenzlog (in Phase 1 erforderlich)
  --passphrase-file <datei> Passphrase aus Datei (sonst GOMAILCTL_PASSPHRASE oder Eingabe)
`

type env struct {
	stdin  *bufio.Reader
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
	e := &env{stdin: bufio.NewReader(stdin), stdout: stdout, stderr: stderr, now: time.Now}
	return e.run(args)
}

func (e *env) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(e.stderr, usage)
		return 2
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
	want := map[string]int{"keygen": 0, "register": 0, "mailbox": 2, "sync": 0, "list": 1, "read": 2, "inspect": 1}
	n, ok := want[cmd]
	if !ok || len(pos) != n || cmd == "mailbox" && pos[0] != "create" || cmd == "register" && e.invite == "" {
		fmt.Fprint(e.stderr, usage)
		return 2
	}
	if cmd == "inspect" {
		return e.inspect(pos[0])
	}
	cfg, err := e.config()
	if err != nil {
		return e.fail(err)
	}
	switch cmd {
	case "keygen":
		return e.keygen(cfg)
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
	return 1
}

func (e *env) config() (client.Config, error) {
	if e.data == "" || e.platform == "" {
		return client.Config{}, errors.New("--data und --platform sind erforderlich")
	}
	log, err := translog.NewUnverified(e.noLog)
	if err != nil {
		return client.Config{}, err
	}
	st, err := store.Open(e.data)
	if err != nil {
		return client.Config{}, err
	}
	pin, err := ceremony.ReadPin(e.platform)
	if err != nil {
		return client.Config{}, err
	}
	dir := e.dir
	if dir == "" {
		cfgDir, err := os.UserConfigDir()
		if err != nil {
			return client.Config{}, err
		}
		dir = filepath.Join(cfgDir, "gomailctl")
	}
	return client.Config{Store: st, Dir: dir, Pin: pin, Log: log, Now: e.now,
		Warn: func(s string) { fmt.Fprintln(e.stderr, s) }}, nil
}

// passphrase reads the passphrase: GOMAILCTL_PASSPHRASE, the file, or a
// line from standard input. Input on a terminal is echoed: phase 1 has no
// terminal control (only the standard library and x/crypto, x/mod,
// x/text); use the file or the variable for real secrets.
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
		line, err := e.stdin.ReadString('\n')
		if err != nil && line == "" {
			return nil, errors.New("keine Passphrase")
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	p, err := read("Passphrase: ")
	if err != nil {
		return nil, err
	}
	if twice {
		q, err := read("Passphrase wiederholen: ")
		if err != nil {
			return nil, err
		}
		if string(p) != string(q) {
			return nil, errors.New("die Passphrasen stimmen nicht überein")
		}
	}
	if len(p) == 0 {
		return nil, errors.New("leere Passphrase")
	}
	return p, nil
}

// prompter shows the words and reads the answers from standard input.
type prompter struct{ e *env }

func (p prompter) ShowWords(words []string) error {
	fmt.Fprintln(p.e.stdout, "Ihr Seed (24 Wörter). Schreiben Sie ihn auf Papier; er wird danach gelöscht:")
	for i, w := range words {
		fmt.Fprintf(p.e.stdout, "%2d. %-10s", i+1, w)
		if i%4 == 3 {
			fmt.Fprintln(p.e.stdout)
		}
	}
	fmt.Fprintln(p.e.stdout)
	return nil
}

func (p prompter) AskWord(pos int) (string, error) {
	fmt.Fprintf(p.e.stderr, "Wort Nr. %d: ", pos)
	line, err := p.e.stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("keine Eingabe")
	}
	// Only the line terminator is removed. TODO(S11): normalization of
	// the input (spaces, case) is not decided yet.
	return strings.TrimRight(line, "\r\n"), nil
}

func (e *env) keygen(cfg client.Config) int {
	pass, err := e.passphrase(true)
	if err != nil {
		return e.fail(err)
	}
	defer keys.Wipe(pass)
	id, err := client.Keygen(cfg, pass, prompter{e})
	if err != nil {
		return e.fail(err)
	}
	fmt.Fprintf(e.stdout, "Benutzer %s angelegt (noch nicht registriert).\n", id)
	return 0
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
	for _, m := range mails {
		t := time.UnixMilli(m.Meta.Received).UTC().Format("2006-01-02 15:04")
		fmt.Fprintf(e.stdout, "%s  %s  %7d  %-30.30s  %s\n", m.ID, t, m.Meta.Size, m.Meta.From, m.Meta.Subject)
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
