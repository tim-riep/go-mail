//go:build gomail_dev

package main

import (
	"flag"
	"fmt"

	"github.com/tim-riep/go-mail/internal/ceremony"
)

// The development ceremony "init --dev", only in a build with the tag
// gomail_dev (task 15b point 4): it writes the platform root into a
// file (ceremony.InitDev). The certificates go into the operator log of
// the new data directory; there is no --insecure-no-log any more.

// devUsage is the usage line of init --dev.
const devUsage = `  gomail-ceremony init --dev --data <datenverzeichnis> --keys <schlüssel>
init --dev ist die Entwicklungszeremonie ohne Shamir, nur in einem Testbuild.
`

// devFlagSet holds the flags of init --dev.
type devFlagSet struct {
	on   *bool
	data *string
}

// devFlags adds --dev and --data to the flags of init.
func devFlags(fs *flag.FlagSet) *devFlagSet {
	return &devFlagSet{
		on:   fs.Bool("dev", false, "Entwicklungszeremonie ohne Shamir (nur Tests)"),
		data: fs.String("data", "", "Datenverzeichnis (nur --dev)"),
	}
}

// run runs init --dev if it was asked for (ok); realSet reports flags of
// the real ceremony, which do not go with --dev.
func (d *devFlagSet) run(e *env, keyDir string, realSet bool) (code int, ok bool) {
	if !*d.on {
		if *d.data != "" {
			return e.usage("--data gibt es nur mit --dev"), true
		}
		return 0, false
	}
	if realSet {
		return e.usage("--dev verträgt sich nicht mit den Angaben der echten Zeremonie"), true
	}
	if *d.data == "" || keyDir == "" {
		return e.usage("--data und --keys sind nötig"), true
	}
	res, err := ceremony.InitDev(*d.data, keyDir, now(), nil, 0)
	if err != nil {
		return e.fail(err), true
	}
	fmt.Fprintf(e.stderr, "WARNUNG: Entwicklungszeremonie, nur für Tests. Der Plattform-Root liegt ungeteilt in %s/%s.\n", res.KeyDir, ceremony.RootFile)
	fmt.Fprintf(e.stdout, "Datenverzeichnis:      %s\n", *d.data)
	fmt.Fprintf(e.stdout, "Schlüsselverzeichnis:  %s\n", res.KeyDir)
	fmt.Fprintf(e.stdout, "Ingest-Schlüssel:      %s/%s  (für gomail-server serve --ingest-key)\n", res.KeyDir, ceremony.IngestKeyFile)
	fmt.Fprintf(e.stdout, "Admin-Schlüssel:       %s/%s  (für gomail-server address add --admin-key)\n", res.KeyDir, ceremony.AdminKeyFile)
	fmt.Fprintf(e.stdout, "Plattformidentität:    %s/%s  (für gomailctl --platform und gomail-server --pin)\n", res.KeyDir, ceremony.PinFile)
	return 0, true
}
