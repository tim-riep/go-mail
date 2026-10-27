// Command gomail-ceremony is the offline tool for the platform root
// (2.3). Phase 1 implements only the development ceremony:
//
//	gomail-ceremony init --dev --data <datadir> --keys <keydir> --insecure-no-log
//
// It creates a platform root without Shamir, derives identity, admin and
// ingest keys of generation 1, writes the certificates and public keys
// into the data directory and the private keys and the (insecure) root
// into the key directory, which must be separate from the data directory.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/translog/translogtest"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usage = `Aufruf:
  gomail-ceremony init --dev --data <datenverzeichnis> --keys <schlüsselverzeichnis> --insecure-no-log

Phase 1 kennt nur die Entwicklungszeremonie (--dev): Plattform-Root ohne
Shamir-Aufteilung, nur für die Entwicklung. Die echte Zeremonie folgt.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dev := fs.Bool("dev", false, "Entwicklungszeremonie ohne Shamir (einzige Möglichkeit in Phase 1)")
	data := fs.String("data", "", "Datenverzeichnis")
	keyDir := fs.String("keys", "", "Verzeichnis für private Schlüssel, getrennt vom Datenverzeichnis")
	noLog := fs.Bool("insecure-no-log", false, "ohne Transparenzlog (nur Entwicklung)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if !*dev {
		fmt.Fprintln(stderr, "gomail-ceremony: nur 'init --dev' ist in Phase 1 umgesetzt (keine Shamir-Zeremonie)")
		return 2
	}
	if *data == "" || *keyDir == "" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	log, err := translogtest.NewUnverified(*noLog)
	if err != nil {
		fmt.Fprintln(stderr, "gomail-ceremony:", err)
		return 1
	}
	res, err := ceremony.InitDev(*data, *keyDir, time.Now(), log, nil, 0)
	if err != nil {
		fmt.Fprintln(stderr, "gomail-ceremony:", err)
		return 1
	}
	fmt.Fprintf(stderr, "WARNUNG: Entwicklungszeremonie. Der Plattform-Root liegt ungeteilt in %s/%s.\n", res.KeyDir, ceremony.RootFile)
	fmt.Fprintf(stdout, "Datenverzeichnis:      %s\n", *data)
	fmt.Fprintf(stdout, "Schlüsselverzeichnis:  %s\n", res.KeyDir)
	fmt.Fprintf(stdout, "Ingest-Schlüssel:      %s/%s  (für gomail-server serve --ingest-key)\n", res.KeyDir, ceremony.IngestKeyFile)
	fmt.Fprintf(stdout, "Admin-Schlüssel:       %s/%s  (für gomail-server address add --admin-key)\n", res.KeyDir, ceremony.AdminKeyFile)
	fmt.Fprintf(stdout, "Plattformidentität:    %s/%s  (für gomailctl --platform)\n", res.KeyDir, ceremony.PinFile)
	return 0
}
