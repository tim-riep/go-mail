// Command gomail-server is the SMTP server of go-mail (9.2) and the
// operator of the transparency log (2.7, task 11):
//
//	gomail-server serve --data <dir> --listen 127.0.0.1:2525 --ingest-key <file>
//	                    --pin <file> --log-listen 127.0.0.1:<port> [--head-interval 1h]
//	                    [--require-client-lock]
//	gomail-server invite create --data <dir>
//	gomail-server address add <address> --mailbox <id> --data <dir> --admin-key <file> --pin <file>
//	gomail-server log repair --data <dir> --pin <file>
//
// serve always runs with the transparency log (task 15: there is no
// switch to run without it; tests use package testenv and
// translogtest). --pin (identity-<gen>.pin, outside the data directory)
// and --log-listen are required. At the start serve checks, in this
// order, and refuses to start when a check fails:
//
//  1. the rights of 9.1 on the data directory and its top-level entries
//     only (checkDataDir: nothing open to others; a directory without
//     setgid, missing group rights and a foreign group are warnings;
//     deeper entries are not walked, they inherit the group through the
//     setgid bit);
//  2. the pin and platform/ (checkPlatformPin, translog.ErrMismatch): no
//     identity generation the pin does not know (operating rule after a
//     succession, Q10 point 5), no contradiction to its identity list;
//  3. platform/witnesses.rec, the working copy of the witnesses (a
//     warning when it differs from the pin), and the operator log of the
//     data directory opened against the pin's identity list and origin
//     (translog.Open checks the tiles against tree.rec and the quorum);
//  4. ingest.New: the server lock locks/server, held exclusively until
//     the end (a second server fails), the ingest key against its
//     certificate, the certificate in the log and not superseded; with
//     --require-client-lock also a client lock locks/client that is in
//     force (ingest.Config.PeerCheck, store.CheckPeerLock(RoleClient));
//  5. the start test of the locks (checkLocks, 9.1 "Testsperre");
//  6. the log head (checkHead: Operator.SignHead without publishing).
//
// --require-client-lock (task 15c finding 3, reading D70 of 9.1 "each
// side checks the lock of the other"): off by default, because a
// long-running server cannot assume a running client at its start; the
// test of two machines (task 16) turns it on to show both directions.
// A server whose platform cannot tell the free space of the data
// directory (NetBSD, Windows) starts, but says that it accepts no mail
// (5.1, ingest.Ingest.DiskSpace). The free space limit of 5.1 has no
// switch in this program; only a test build (go build -tags gomail_test,
// as internal/e2e builds it) reads GOMAIL_TEST_MIN_FREE
// (testconfig_tagged.go, task 15c finding 7).
//
// Then it signs heads with the ingest key (Q4) on the cadence of package
// loghttp, serves the witness protocol on --log-listen and SMTP on
// --listen; ingest checks every delivery against the same operator log.
// "address add" logs the signed assignment with Append(KindAddress)
// before it changes addresses.json, and only when the address is free
// or already assigned to that mailbox (exit status 2 otherwise; no
// message names the address). "log repair" rebuilds tree.rec, the tiles
// and keys/ from the entries and the signed heads (translog.RepairTree)
// while no server runs.
//
// Both listeners accept only a loopback address unless
// --isolated-test-network is given (5.1). Pin, ingest key and admin key
// must lie outside the data directory, compared with symbolic links
// resolved (pin or admin key inside it: exit status 2). Logs contain
// IDs, sizes, hash prefixes and status codes only.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/loghttp"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, nil))
}

const usage = `Aufruf:
  gomail-server serve --data <dir> [--listen 127.0.0.1:2525] --ingest-key <datei>
                      --pin <datei> --log-listen <adresse> [--head-interval 1h]
                      [--hostname <name>] [--isolated-test-network] [--require-client-lock]
  gomail-server invite create --data <dir>
  gomail-server address add <adresse> --mailbox <postfach-id> --data <dir> --admin-key <datei> --pin <datei>
  gomail-server log repair --data <dir> --pin <datei>
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

// ready receives the listening addresses of SMTP and of the log (tests).
type ready func(smtp, log string)

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
	case "log":
		return logCmd(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "gomail-server:", err)
	if errors.As(err, new(usageError)) {
		return 2
	}
	return 1
}

// usageError is a wrong invocation that is only found after the flags
// are parsed (a pin inside the data directory, an address already
// assigned): exit status 2, as for a usage error.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

// resolve returns the absolute path p with every symbolic link resolved;
// p must exist.
func resolve(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// outsideData resolves file and the data directory root with their
// symbolic links (as translog resolves Options.IndexFile, task 07c
// finding 4) and returns the resolved file; inside reports a file inside
// root, also one reached through a link or in a data directory reached
// through one (task 11b finding 6).
func outsideData(file, root, what string) (resolved string, inside bool, err error) {
	rf, err := resolve(file)
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", what, err)
	}
	rr, err := resolve(root)
	if err != nil {
		return "", false, fmt.Errorf("Datenverzeichnis: %w", err)
	}
	return rf, isInside(rf, rr), nil
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
	return errors.New("--listen und --log-listen müssen Loopback-Adressen sein (etwa 127.0.0.1:2525); ein anderes Netz nur mit --isolated-test-network (5.1)")
}

// readPin reads the server's pin (identity-<gen>.pin), which must lie
// outside the data directory (translog Options.Identities: never from
// files in the data directory). Pin and data directory are compared with
// their symbolic links resolved; a pin inside it is a usageError, and
// the pin is read through its resolved path.
func readPin(path, root string) (*store.PlatformPin, []translog.Identity, error) {
	rp, inside, err := outsideData(path, root, "Pin")
	if err != nil {
		return nil, nil, err
	}
	if inside {
		return nil, nil, usageError{"der Pin darf nicht im Datenverzeichnis liegen"}
	}
	pin, err := store.ReadPlatformPin(rp)
	if err != nil {
		return nil, nil, fmt.Errorf("Pin: %w", err)
	}
	ids := make([]translog.Identity, 0, len(pin.Identities))
	for _, id := range pin.Identities {
		ids = append(ids, translog.Identity{Gen: id.Gen, Pub: id.Pub})
	}
	return pin, ids, nil
}

// readWitnesses reads platform/witnesses.rec, the server's working copy
// of the witnesses, and reports whether it differs from the pin.
func readWitnesses(st *store.Store, pin *store.PlatformPin) (*witness.Witnesses, bool, error) {
	data, err := st.ReadPlatformFile("witnesses.rec")
	if err != nil {
		return nil, false, fmt.Errorf("platform/witnesses.rec: %w", err)
	}
	w, err := witness.DecodeWitnesses(data)
	if err != nil {
		return nil, false, err
	}
	same := w.Min == pin.MinWitnesses && len(w.List) == len(pin.Witnesses)
	for _, k := range w.List {
		found := false
		for _, p := range pin.Witnesses {
			found = found || (p.Name == k.Name && p.Pub.Equal(k.Pub))
		}
		same = same && found
	}
	return w, !same, nil
}

func serve(ctx context.Context, args []string, stderr io.Writer, onReady ready) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "Datenverzeichnis")
	listen := fs.String("listen", "127.0.0.1:2525", "Adresse für SMTP")
	keyFile := fs.String("ingest-key", "", "privater Ingest-Schlüssel (nicht im Datenverzeichnis)")
	hostname := fs.String("hostname", "localhost", "Name im SMTP-Gruß")
	isolated := fs.Bool("isolated-test-network", false, "erlaubt eine Adresse außerhalb von Loopback in einem isolierten Testnetz")
	pinFile := fs.String("pin", "", "Pin der Plattform (identity-<gen>.pin, nicht im Datenverzeichnis)")
	logListen := fs.String("log-listen", "", "Adresse für das Zeugenprotokoll (HTTP)")
	headInterval := fs.Duration("head-interval", translog.HeadInterval, "längster Abstand zweier signierter Köpfe")
	requireClient := fs.Bool("require-client-lock", false, "beim Start eine wirksame Client-Sperre locks/client verlangen (9.1, Testsperre)")
	if pos, err := parse(fs, args); err != nil || len(pos) != 0 || *data == "" || *keyFile == "" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if *pinFile == "" || *logListen == "" {
		fmt.Fprintln(stderr, "gomail-server: --pin und --log-listen sind erforderlich (der Server läuft nur mit Transparenzlog, 2.7)")
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err := checkListen(*listen, *isolated); err != nil {
		return fail(stderr, err)
	}
	if err := checkListen(*logListen, *isolated); err != nil {
		return fail(stderr, err)
	}
	st, err := store.Open(*data)
	if err != nil {
		return fail(stderr, err)
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	if err := checkDataDir(st, logger); err != nil {
		return fail(stderr, err)
	}
	kf, inside, err := outsideData(*keyFile, st.Root, "Ingest-Schlüssel")
	if err != nil {
		return fail(stderr, err)
	}
	if inside {
		return fail(stderr, errors.New("der Ingest-Schlüssel darf nicht im Datenverzeichnis liegen (Abschnitt 4)"))
	}
	key, gen, err := ceremony.ReadKey(kf, store.KeyRoleIngest)
	if err != nil {
		return fail(stderr, err)
	}
	defer keys.Wipe(key)
	op, side, signer, err := openLogSide(st, *pinFile, key, *headInterval, logger)
	if err != nil {
		return fail(stderr, err)
	}
	// ingest.New takes the server lock (9.1, D70) and holds it until
	// Close. PeerCheck only with --require-client-lock (D70: by default a
	// server cannot require a running client; the client refuses without
	// an effective server lock).
	cfg := ingest.Config{Store: st, Log: op, IngestKey: key, IngestGen: gen, Logger: logger, PeerCheck: *requireClient}
	if err := testConfig(&cfg); err != nil {
		return fail(stderr, err)
	}
	in, err := ingest.New(cfg)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrLocked):
			err = fmt.Errorf("ein anderer Server hält die Serversperre locks/server (9.1): %w", err)
		case errors.Is(err, store.ErrPeerLock):
			err = fmt.Errorf("Testsperre: --require-client-lock verlangt eine wirksame Client-Sperre locks/client (9.1): %w", err)
		}
		return fail(stderr, err)
	}
	defer in.Close()
	if err := checkLocks(st, *requireClient, logger); err != nil {
		return fail(stderr, err)
	}
	checkDiskSpace(in.DiskSpace, logger)
	if err := checkHead(op, signer, time.Now(), logger); err != nil {
		return fail(stderr, err)
	}
	if err := in.Recover(); err != nil {
		return fail(stderr, err)
	}
	in.Start()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fail(stderr, err)
	}
	srv := smtpd.NewServer(smtpd.Config{Hostname: *hostname, Logger: logger}, in)
	logger.Info("smtp listening", "addr", ln.Addr().String())
	served := make(chan error, 1)
	lln, err := net.Listen("tcp", *logListen)
	if err != nil {
		ln.Close()
		return fail(stderr, err)
	}
	logAddr := lln.Addr().String()
	logger.Info("log listening", "addr", logAddr)
	hs := loghttp.NewHTTPServer(side)
	go func() { served <- hs.Serve(lln) }()
	logCtx, stopLog := context.WithCancel(ctx)
	ran := make(chan struct{})
	go func() { side.Run(logCtx); close(ran) }()
	// The signer refers to key: the log side stops before the deferred
	// Wipe of key runs.
	defer func() {
		stopLog()
		hs.Close()
		<-ran
	}()
	if onReady != nil {
		onReady(ln.Addr().String(), logAddr)
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
	case err := <-served:
		srv.Close()
		<-done
		return fail(stderr, err)
	}
}

// openLogSide reads the pin, checks platform/ against it
// (checkPlatformPin), opens the operator log of the pin and the log
// side of the server (task 11) and returns the log signer of key.
func openLogSide(st *store.Store, pinFile string, key ed25519.PrivateKey, interval time.Duration, logger *slog.Logger) (translog.Operator, *loghttp.Server, note.Signer, error) {
	pin, ids, err := readPin(pinFile, st.Root)
	if err != nil {
		return nil, nil, nil, err
	}
	if pin.Dev {
		logger.Warn("development pin (gomail-ceremony init --dev)")
	}
	if err := checkPlatformPin(st, pin); err != nil {
		return nil, nil, nil, err
	}
	ws, differs, err := readWitnesses(st, pin)
	if err != nil {
		return nil, nil, nil, err
	}
	if differs {
		logger.Warn("platform/witnesses.rec differs from the pin; heads need the quorum of witnesses.rec, clients that of the pin")
	}
	wvs, err := ws.Verifiers()
	if err != nil {
		return nil, nil, nil, err
	}
	l, err := translog.Open(translog.Options{Store: st, Identities: ids, Origin: pin.Origin, Known: note.VerifierList(wvs...),
		Witnesses: wvs, MinWitnesses: ws.Min})
	if err != nil {
		return nil, nil, nil, err
	}
	op := l.(translog.Operator)
	signer, err := translog.NewLogSigner(key)
	if err != nil {
		return nil, nil, nil, err
	}
	lk, err := translog.NewLogVerifier(key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, nil, nil, err
	}
	side, err := loghttp.New(loghttp.Config{Log: op, Signer: signer, LogKey: lk, Witnesses: wvs, HeadInterval: interval, Logger: logger})
	if err != nil {
		return nil, nil, nil, err
	}
	return op, side, signer, nil
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
	keyFile := fs.String("admin-key", "", "privater Admin-Schlüssel (nicht im Datenverzeichnis)")
	pinFile := fs.String("pin", "", "Pin der Plattform (identity-<gen>.pin, nicht im Datenverzeichnis)")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 2 || pos[0] != "add" || *data == "" || *mailbox == "" || *keyFile == "" || *pinFile == "" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	st, err := store.Open(*data)
	if err != nil {
		return fail(stderr, err)
	}
	pin, ids, err := readPin(*pinFile, st.Root)
	if err != nil {
		return fail(stderr, err)
	}
	tl, err := translog.Open(translog.Options{Store: st, Identities: ids, Origin: pin.Origin})
	if err != nil {
		return fail(stderr, err)
	}
	// The admin key lies outside the data directory like pin and ingest
	// key (section 4, 9.1), compared with symbolic links resolved and read
	// through its resolved path (task 11b finding 6).
	akf, inside, err := outsideData(*keyFile, st.Root, "Admin-Schlüssel")
	if err != nil {
		return fail(stderr, err)
	}
	if inside {
		return fail(stderr, usageError{"der Admin-Schlüssel darf nicht im Datenverzeichnis liegen (Abschnitt 4)"})
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
		return failAddr(stderr, err, pos[1], "")
	}
	admin, gen, err := ceremony.ReadKey(akf, store.KeyRoleAdmin)
	if err != nil {
		return failAddr(stderr, err, pos[1], addr)
	}
	defer keys.Wipe(admin)
	cert, err := st.ReadPlatformCert(keys.RoleAdmin, gen)
	if err != nil || !cert.Pub.Equal(admin.Public()) {
		return fail(stderr, errors.New("der Admin-Schlüssel passt nicht zu admin-<gen>.cert"))
	}
	// Signed assignment for the log (2.3); addresses.json is the working copy.
	a := &store.AddressAssignment{Address: addr, MailboxID: mbx, ValidFrom: time.Now().UnixMilli(), AdminGen: gen}
	if err := a.Sign(admin); err != nil {
		return failAddr(stderr, err, pos[1], addr)
	}
	enc, err := a.Encode()
	if err != nil {
		return failAddr(stderr, err, pos[1], addr)
	}
	// The signed assignment goes into the log before the working copy
	// addresses.json changes (2.3, translog doc.go "Who writes"). Under
	// addresses.lock (lock order addresses.lock, log/lock: Append takes
	// log/lock inside) the address must be free or already assigned to
	// this mailbox, in addresses.json and in the log, before anything is
	// logged (task 11b finding 2): otherwise the log would name this
	// mailbox from valid_from on while addresses.json, which AddAddress
	// never changes for an assigned address, keeps the other one.
	// TODO(ask): no reassignment of an address to another mailbox in
	// the PoC (strictest reading; proposal for SPEC-ISSUES in the report
	// of task 11b: how a reassignment is logged and applied).
	//
	// Reading (task 15, instead of a store function that writes
	// addresses.json under the same hold of addresses.lock): the lock is
	// released after Append, because AddAddress takes it itself. That
	// is safe because the log entry decides: from the Append on, every
	// concurrent "address add" for another mailbox finds it under
	// addresses.lock in checkAddressFree and refuses, and ingest accepts
	// mail only for an assignment the log holds (Log.CheckAddress); a
	// crash before AddAddress leaves the address unassigned in
	// addresses.json, and "address add" for the same mailbox repeats.
	// TestAddressAddParallel pins it.
	unlock, err := store.LockPath(st.Path("addresses.lock"))
	if err != nil {
		return failAddr(stderr, err, pos[1], addr)
	}
	if err := checkAddressFree(st, tl, addr, mbx); err != nil {
		unlock()
		return failAddr(stderr, err, pos[1], addr)
	}
	if addressHook != nil {
		addressHook()
	}
	_, err = tl.Append(translog.KindAddress, enc)
	unlock()
	if err != nil {
		return failAddr(stderr, err, pos[1], addr)
	}
	if _, err := st.AddAddress(addr, mbx); err != nil {
		if errors.Is(err, store.ErrExists) {
			err = fmt.Errorf("Postfach %s: Adresse inzwischen anders zugeordnet; der Logeintrag ist geschrieben, addresses.json unverändert", mbx)
		}
		return failAddr(stderr, err, pos[1], addr)
	}
	fmt.Fprintf(stdout, "%s -> %s\n", addr, mbx)
	return 0
}

// addressHook is the injection point of "address add" between the check
// under addresses.lock and the Append (task 11b finding 2); nil in
// production, set only by tests of this package.
var addressHook func()

// checkAddressFree reports a usageError unless addr is unassigned or
// assigned to mbx in addresses.json and in every valid entry of the log
// for it. The message names the mailbox only, never the address.
func checkAddressFree(st *store.Store, tl translog.Log, addr string, mbx store.ID) error {
	assigned := usageError{fmt.Sprintf("Postfach %s: Adresse bereits zugeordnet", mbx)}
	cur, err := st.LoadAddresses()
	if err != nil {
		return err
	}
	if old, ok := cur[addr]; ok && old != mbx {
		return assigned
	}
	es, err := tl.Lookup(translog.KindAddress, []byte(addr))
	if err != nil {
		return err
	}
	for _, e := range es {
		a, err := store.DecodeAddressAssignment(e.Content)
		if err != nil {
			return fmt.Errorf("Logeintrag %d: %w", e.Index, err)
		}
		if a.MailboxID != mbx {
			return assigned
		}
	}
	return nil
}

// failAddr is fail for "address add": the address, as given (raw) or
// normalized, never appears in the message (task 11b finding 2).
func failAddr(stderr io.Writer, err error, raw, addr string) int {
	msg := err.Error()
	for _, a := range []string{raw, addr} {
		if a != "" {
			msg = regexp.MustCompile("(?i)"+regexp.QuoteMeta(a)).ReplaceAllString(msg, "<Adresse>")
		}
	}
	fmt.Fprintln(stderr, "gomail-server:", msg)
	if errors.As(err, new(usageError)) {
		return 2
	}
	return 1
}

func logCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "Datenverzeichnis")
	pinFile := fs.String("pin", "", "Pin der Plattform (identity-<gen>.pin, nicht im Datenverzeichnis)")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 1 || pos[0] != "repair" || *data == "" || *pinFile == "" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	st, err := store.Open(*data)
	if err != nil {
		return fail(stderr, err)
	}
	pin, ids, err := readPin(*pinFile, st.Root)
	if err != nil {
		return fail(stderr, err)
	}
	// No server may run meanwhile (9.1: the server lock).
	release, err := st.HoldRoleLock(store.RoleServer)
	if err != nil {
		return fail(stderr, fmt.Errorf("Server-Sperre: %w", err))
	}
	defer release()
	if err := translog.RepairTree(translog.Options{Store: st, Identities: ids, Origin: pin.Origin}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "log/tree.rec, Kacheln und keys/ aus den Einträgen und Köpfen neu gebaut")
	return 0
}
