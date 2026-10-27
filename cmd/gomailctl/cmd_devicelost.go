package main

import (
	"fmt"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/shamir"
)

// gomailctl device lost (9.2, 2.2 "Generationen"): with the seed words
// and the passphrase of the key store, a new generation that revokes the
// current one; the own files are issued again, the other members wrap
// the mailboxes for it on their next sync.
//
// gomailctl restore [--shares <k>] (2.2 "Wiederherstellung", 2.7 "Neue
// Geräte und Wiederherstellung"): sets up an empty client directory for
// the user of a seed, typed as 24 words or as k shares of 30 words, with
// a new passphrase. TODO(ask): 9.2 names no command for it; the name
// restore and the flag --shares follow task 13.
//
// Words are read from standard input (readWords). From a terminal the
// echo is off while they are typed, standard output must be the same
// terminal (wordsPre, before the passphrase or any word is read), and
// the screen is cleared after the seed and after every share; the abort
// signals clear it too (screen). From a file or a pipe they are read as
// they come (task 13b finding 2).

// wordsPre refuses device lost and restore before anything is read when
// standard input is a terminal and standard output is not the same
// terminal (checkWordInput).
func wordsPre(e *env, _ *options) error { return e.checkWordInput() }

func runDeviceLost(e *env, _ *options, cfg client.Config, _ *client.Client) int {
	pass, err := e.passphrase(false)
	if err != nil {
		return e.fail(err)
	}
	defer keys.Wipe(pass)
	s, err := e.wordScreen()
	if err != nil {
		return e.fail(err)
	}
	ws, err := e.readWords(s, "Seed", keys.SeedWords)
	s.close()
	if err != nil {
		return e.fail(err)
	}
	gen, err := client.DeviceLost(cfg, pass, ws)
	clear(ws)
	if gen != 0 {
		fmt.Fprintf(e.stdout, "Neue Generation %d; die vorherige ist widerrufen. Die anderen Mitglieder verpacken die Postfächer beim nächsten sync neu.\n", gen)
	}
	if err != nil {
		return e.fail(err)
	}
	return 0
}

func runRestore(e *env, o *options, cfg client.Config, _ *client.Client) int {
	pass, err := e.passphrase(true)
	if err != nil {
		return e.fail(err)
	}
	defer keys.Wipe(pass)
	s, err := e.wordScreen()
	if err != nil {
		return e.fail(err)
	}
	var opts client.RestoreOptions
	if o.shares == 0 {
		opts.Words, err = e.readWords(s, "Seed", keys.SeedWords)
	}
	for i := 1; i <= o.shares && err == nil; i++ {
		var ws []string
		ws, err = e.readWords(s, fmt.Sprintf("Anteil %d von %d", i, o.shares), shamir.ShareWords)
		opts.Shares = append(opts.Shares, ws)
		s.wipe()
	}
	s.close()
	if err != nil {
		return e.fail(err)
	}
	id, err := client.Restore(cfg, opts, pass)
	clear(opts.Words)
	for _, ws := range opts.Shares {
		clear(ws)
	}
	if err != nil {
		return e.fail(err)
	}
	fmt.Fprintf(e.stdout, "Benutzer %s auf diesem Gerät wiederhergestellt.\n", id)
	return 0
}
