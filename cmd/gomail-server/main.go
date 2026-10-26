// Command gomail-server is the SMTP server of go-mail (9.2):
//
//	gomail-server serve --data <dir> --listen 127.0.0.1:2525 --ingest-key <file> --insecure-no-log
//	gomail-server invite create --data <dir>
//	gomail-server address add <address> --mailbox <id> --data <dir> --admin-key <file> --insecure-no-log
//
// The server listens only on a loopback address unless
// --isolated-test-network is given (5.1). Without --insecure-no-log it
// refuses to start, because the transparency log does not exist yet
// (phase 3). Logs contain IDs, sizes and status codes only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, nil))
}

const usage = `Aufruf:
  gomail-server serve --data <dir> [--listen 127.0.0.1:2525] --ingest-key <datei> --insecure-no-log
                      [--hostname <name>] [--isolated-test-network]
  gomail-server invite create --data <dir>
  gomail-server address add <adresse> --mailbox <postfach-id> --data <dir> --admin-key <datei> --insecure-no-log
`

// parse parses flags that may appear before, between or after the
// positional arguments.
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

// ready receives the listening address (tests).
type ready func(addr string)

func run(ctx context.Context, args []string, stdout, stderr io.Writer, onReady ready) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return serve(ctx, args[1:], stderr, onReady)
	case "invite":
		return invite(args[1:], stdout, stderr)
	case "address":
		return address(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "gomail-server:", err)
	return 1
}

// checkListen enforces 5.1: loopback only, unless the operator states
// that the network is an isolated test network.
func checkListen(addr string, isolated bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if isolated {
		return nil
	}
	ip := net.ParseIP(host)
	if host == "localhost" || ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("--listen muss eine Loopback-Adresse sein (etwa 127.0.0.1:2525); ein anderes Netz nur mit --isolated-test-network (5.1)")
}

func serve(ctx context.Context, args []string, stderr io.Writer, onReady ready) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "Datenverzeichnis")
	listen := fs.String("listen", "127.0.0.1:2525", "Adresse für SMTP")
	keyFile := fs.String("ingest-key", "", "privater Ingest-Schlüssel (nicht im Datenverzeichnis)")
	hostname := fs.String("hostname", "localhost", "Name im SMTP-Gruß")
	isolated := fs.Bool("isolated-test-network", false, "erlaubt eine Adresse außerhalb von Loopback in einem isolierten Testnetz")
	noLog := fs.Bool("insecure-no-log", false, "ohne Transparenzlog (nur Entwicklung)")
	if pos, err := parse(fs, args); err != nil || len(pos) != 0 || *data == "" || *keyFile == "" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	tlog, err := translog.NewUnverified(*noLog)
	if err != nil {
		return fail(stderr, err)
	}
	if err := checkListen(*listen, *isolated); err != nil {
		return fail(stderr, err)
	}
	st, err := store.Open(*data)
	if err != nil {
		return fail(stderr, err)
	}
	if abs, err := absPath(*keyFile); err == nil && isInside(abs, st.Root) {
		return fail(stderr, errors.New("der Ingest-Schlüssel darf nicht im Datenverzeichnis liegen (Abschnitt 4)"))
	}
	key, gen, err := ceremony.ReadKey(*keyFile, store.KeyRoleIngest)
	if err != nil {
		return fail(stderr, err)
	}
	defer keys.Wipe(key)
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	logger.Warn("running without transparency log (--insecure-no-log)")
	in, err := ingest.New(ingest.Config{Store: st, Log: tlog, IngestKey: key, IngestGen: gen, Logger: logger})
	if err != nil {
		return fail(stderr, err)
	}
	if err := in.Recover(); err != nil {
		return fail(stderr, err)
	}
	in.Start()
	defer in.Close()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fail(stderr, err)
	}
	srv := smtpd.NewServer(smtpd.Config{Hostname: *hostname, Logger: logger}, in)
	logger.Info("smtp listening", "addr", ln.Addr().String())
	if onReady != nil {
		onReady(ln.Addr().String())
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		srv.Close()
		<-done
		logger.Info("smtp stopped")
		return 0
	case err := <-done:
		return fail(stderr, err)
	}
}

func invite(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "Datenverzeichnis")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 1 || pos[0] != "create" || *data == "" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	st, err := store.Open(*data)
	if err != nil {
		return fail(stderr, err)
	}
	code, err := st.CreateInvite(time.Now().UnixMilli())
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, code.String())
	return 0
}

func address(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("address", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "Datenverzeichnis")
	mailbox := fs.String("mailbox", "", "Postfach-ID")
	keyFile := fs.String("admin-key", "", "privater Admin-Schlüssel")
	noLog := fs.Bool("insecure-no-log", false, "ohne Transparenzlog (nur Entwicklung)")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 2 || pos[0] != "add" || *data == "" || *mailbox == "" || *keyFile == "" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	tlog, err := translog.NewUnverified(*noLog)
	if err != nil {
		return fail(stderr, err)
	}
	st, err := store.Open(*data)
	if err != nil {
		return fail(stderr, err)
	}
	mbx, err := store.ParseID(*mailbox)
	if err != nil {
		return fail(stderr, err)
	}
	if _, err := st.ReadMailbox(mbx); err != nil {
		return fail(stderr, fmt.Errorf("Postfach %s: %w", mbx, err))
	}
	addr, err := store.NormalizeAddress(pos[1])
	if err != nil {
		return fail(stderr, err)
	}
	admin, gen, err := ceremony.ReadKey(*keyFile, store.KeyRoleAdmin)
	if err != nil {
		return fail(stderr, err)
	}
	defer keys.Wipe(admin)
	cert, err := st.ReadPlatformCert(keys.RoleAdmin, gen)
	if err != nil || !cert.Pub.Equal(admin.Public()) {
		return fail(stderr, errors.New("der Admin-Schlüssel passt nicht zu admin-<gen>.cert"))
	}
	// Signed assignment for the log (2.3); addresses.json is the working copy.
	a := &store.AddressAssignment{Address: addr, MailboxID: mbx, ValidFrom: time.Now().UnixMilli(), AdminGen: gen}
	if err := a.Sign(admin); err != nil {
		return fail(stderr, err)
	}
	enc, err := a.Encode()
	if err != nil {
		return fail(stderr, err)
	}
	// TODO(phase3-translog): signed address assignment into the log (2.3).
	if err := tlog.AppendAddress(enc); err != nil {
		return fail(stderr, err)
	}
	if _, err := st.AddAddress(addr, mbx); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s -> %s\n", addr, mbx)
	return 0
}
