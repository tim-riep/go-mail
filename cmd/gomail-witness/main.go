// Command gomail-witness is the witness of 2.7 (package witness):
//
//	gomail-witness keygen --name <name> --key <file>
//	gomail-witness serve --log <url> --log-key <vkey> [--log-key <vkey>] --origin <origin>
//	                     --key <file> --state <dir> [--interval 10s]
//
// keygen writes a new note signer key (rights 0600, never replaced) and
// prints the verifier key line for witnesses.rec and the client pin.
// serve polls the log server, cosigns every head that is consistent with
// the last cosigned one and posts the cosignature back (pull; the
// witness opens no port). It stops for good when the log shows two heads
// of one size (exit code 3). Its log lines carry sizes, hash prefixes
// and status codes only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tim-riep/go-mail/internal/witness"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `Aufruf:
  gomail-witness keygen --name <name> --key <schlüsseldatei>
  gomail-witness serve --log <url> --log-key <verifier-zeile> [--log-key <verifier-zeile>]
                       --origin <origin> --key <schlüsseldatei> --state <verzeichnis>
                       [--interval 10s]
`

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
	exitFork  = 3
)

// keyList collects a repeated flag.
type keyList []string

func (k *keyList) String() string { return strings.Join(*k, " ") }

func (k *keyList) Set(s string) error {
	*k = append(*k, s)
	return nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], stdout, stderr)
	case "serve":
		return serve(ctx, args[1:], stderr)
	}
	fmt.Fprint(stderr, usage)
	return exitUsage
}

func keygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "Name des Zeugen (druckbares ASCII ohne Leerzeichen und '+')")
	key := fs.String("key", "", "neue Schlüsseldatei (0600, wird nie ersetzt)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *name == "" || *key == "" {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	vkey, err := witness.Keygen(*name, *key, nil)
	if err != nil {
		fmt.Fprintln(stderr, "gomail-witness:", err)
		return exitError
	}
	fmt.Fprintln(stdout, vkey)
	fmt.Fprintln(stderr, "Die Zeile oben ist der öffentliche Schlüssel des Zeugen (für witnesses.rec und den Pin der Clients).")
	return exitOK
}

func serve(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var logKeys keyList
	logURL := fs.String("log", "", "Basis-URL des Log-Servers (http oder https)")
	fs.Var(&logKeys, "log-key", "Verifier-Zeile des Log-Schlüssels (gomail-log+<hash>+<schlüssel>), bei einer Ingest-Rotation zweimal")
	origin := fs.String("origin", "", "Origin des Logs")
	key := fs.String("key", "", "Schlüsseldatei des Zeugen (0600, außerhalb des Zustandsverzeichnisses)")
	state := fs.String("state", "", "Zustandsverzeichnis (0700)")
	interval := fs.Duration("interval", witness.DefaultInterval, "Abstand der Abfragen")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *logURL == "" || len(logKeys) == 0 || *origin == "" || *key == "" || *state == "" {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	if *interval < time.Second {
		fmt.Fprintln(stderr, "gomail-witness: --interval muss mindestens 1s sein")
		return exitUsage
	}
	err := witness.Serve(ctx, witness.Config{
		Log:      *logURL,
		LogKeys:  logKeys,
		Origin:   *origin,
		KeyFile:  *key,
		StateDir: *state,
		Interval: *interval,
		Logger:   slog.New(slog.NewTextHandler(stderr, nil)),
	})
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, witness.ErrFork) && errors.Is(err, witness.ErrState):
		fmt.Fprintln(stderr, "gomail-witness: Das Log hat zwei verschiedene Köpfe gleicher Größe gezeigt. Der Zeuge signiert nicht mehr; der Beweis konnte NICHT im Zustandsverzeichnis gespeichert werden.")
		return exitFork
	case errors.Is(err, witness.ErrFork):
		fmt.Fprintln(stderr, "gomail-witness: Das Log hat zwei verschiedene Köpfe gleicher Größe gezeigt. Der Zeuge signiert nicht mehr; der Beweis liegt im Zustandsverzeichnis.")
		return exitFork
	default:
		fmt.Fprintln(stderr, "gomail-witness:", err)
		return exitError
	}
}
