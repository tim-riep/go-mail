package main

import (
	"fmt"
	"strings"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/words"
)

// gomailctl keygen [--shares k-of-n] (2.2 "Sicherung des Seeds",
// "Wiederherstellung"; task 13b finding 1): standard output and standard
// input must be terminals (keygenPre), before anything is shown, read or
// written. The abort signals are handled from before the seed is shown
// (screen). The screen is cleared, the 24 words are shown until the user
// confirms with Enter typed after they appeared, and the screen is
// cleared again; three of the words are then asked back with the echo
// off. With --shares the seed is split additionally and every share is
// shown once through prompter.ShowShares. The platform gets no share.
// Only after the last display is cleared and the terminal restored does
// the client write the key store: an abort signal before that clears the
// screen and ends the program with exit code 130 and nothing written.
//
// TODO(ask): 2.2 does not say whether the seed stays on the screen while
// its words are asked back; gomailctl clears it first, so that the
// answers come from the paper copy.

// keygenPre refuses keygen before anything is shown, read or written
// when standard input or output is the master side of a pseudo terminal
// (errPtyMaster, task 13d finding 1), standard output is not a terminal
// (errNoTerminal) or standard input is not a terminal (errNoTerminalIn)
// whose echo can be switched off (errNoEchoControl). Only a test build
// accepts files and pipes, without --shares (testKeygenPipe).
func keygenPre(e *env, o *options) error {
	if ptyMasterOf(e.in) || ptyMasterOf(e.stdout) {
		return errPtyMaster
	}
	pipe, err := testKeygenPipe()
	if err != nil {
		return err
	}
	if pipe && o.split == (client.Shares{}) {
		return nil
	}
	if !isTerminal(e.stdout) {
		return errNoTerminal
	}
	ctl := echoControl(e.in)
	if ctl == nil {
		return errNoTerminalIn
	}
	// The echo is switched off once and restored before the passphrase
	// is read: a terminal whose echo stays on is refused here.
	restore, err := ctl.echo()
	if err != nil {
		return fmt.Errorf("%w (%v)", errNoEchoControl, err)
	}
	return restore()
}

func runKeygen(e *env, o *options, cfg client.Config, _ *client.Client) int {
	pass, err := e.passphrase(true)
	if err != nil {
		return e.fail(err)
	}
	defer keys.Wipe(pass)
	p := &prompter{e: e, shares: o.split.Count > 0}
	if pipe, _ := testKeygenPipe(); !pipe || p.shares {
		if p.s, err = e.openScreen(); err != nil {
			return e.fail(err)
		}
		defer p.s.close()
	}
	id, err := client.KeygenWithOptions(cfg, pass, p, client.KeygenOptions{Shares: o.split})
	p.s.close()
	if err != nil {
		return e.fail(err)
	}
	fmt.Fprintf(e.stdout, "Benutzer %s angelegt (noch nicht registriert).\n", id)
	if o.split.Count > 0 {
		fmt.Fprintf(e.stdout, "%d Anteile wurden angezeigt; je %d davon stellen den Seed wieder her (gomailctl restore --shares %d).\n",
			o.split.Count, o.split.Threshold, o.split.Threshold)
	}
	return 0
}

// prompter is the client.SharePrompter of keygen: the seed and the shares
// on the screen s, the prompts on standard error, the answers from
// standard input. s is nil only in the pipe mode of a test build.
type prompter struct {
	e      *env
	s      *screen
	shares bool // ShowShares follows the three words and closes s
	asked  int  // words asked back so far
}

// ShowWords clears the screen, shows the 24 words until the user
// confirms with input typed after they appeared (flushTyped) and clears
// the screen again.
func (p *prompter) ShowWords(ws []string) error {
	e := p.e
	if p.s == nil {
		fmt.Fprint(e.stdout, formatSeed(ws))
		return nil
	}
	p.s.wipe()
	p.s.show(formatSeed(ws))
	if err := e.flushTyped(); err != nil {
		return err
	}
	fmt.Fprint(e.stderr, "Seed notiert? Eingabetaste löscht den Bildschirm: ")
	err := e.confirm()
	p.s.wipe()
	return err
}

// formatSeed is the screen of the seed: its 24 words, numbered, four in
// a row.
func formatSeed(ws []string) string {
	var b strings.Builder
	b.WriteString("Ihr Seed (24 Wörter). Schreiben Sie ihn auf Papier; er wird danach gelöscht:\n")
	for i, w := range ws {
		fmt.Fprintf(&b, "%2d. %-10s", i+1, w)
		if i%4 == 3 {
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")
	return b.String()
}

// AskWord reads one line with the echo off and normalizes it with
// words.One (2.2 "Eingabe von Wörtern", S11); the client checks the
// word. Errors name the position, never the input. After the last of
// the three words, without --shares, the screen is cleared and closed
// (terminal restored, signal handling ended) before the client writes
// the key store.
func (p *prompter) AskWord(pos int) (string, error) {
	e := p.e
	if p.s != nil {
		if err := e.flushTyped(); err != nil {
			return "", err
		}
	}
	if p.s != nil {
		if err := p.s.echoOff(); err != nil {
			return "", err
		}
	}
	fmt.Fprintf(e.stderr, "Wort Nr. %d: ", pos)
	line, err := e.readSecret()
	if p.s != nil {
		p.s.echoOn()
		fmt.Fprintln(e.stderr)
	}
	if err != nil {
		return "", fmt.Errorf("Wort Nr. %d: %w", pos, err)
	}
	w, err := words.One(string(line))
	clear(line)
	if err != nil {
		return "", fmt.Errorf("Wort Nr. %d: %w", pos, err)
	}
	if p.asked++; p.asked == client.ConfirmWords && !p.shares {
		p.s.close()
	}
	return w, nil
}

// ShowShares shows the shares one holder at a time (client.SharePrompter;
// shares[i] are the 30 words of the share with index i+1), only on the
// terminal: the holder of share i is called and confirms with Enter, the
// share is shown, and only Enter typed after it appeared confirms that it
// is noted (task 13b finding 3: input typed ahead is discarded before
// every holder is called and again once the share is on the screen);
// then the screen is cleared. At the end the screen is closed (cleared,
// terminal restored, signal handling ended).
func (p *prompter) ShowShares(shares [][]string) error {
	e, s := p.e, p.s
	if s == nil {
		return errNoTerminal
	}
	defer s.close()
	s.wipe()
	for i, sh := range shares {
		if err := e.flushTyped(); err != nil {
			return err
		}
		fmt.Fprintf(e.stderr, "Inhaber von Anteil %d von %d an den Bildschirm, dann Eingabetaste: ", i+1, len(shares))
		if err := e.confirm(); err != nil {
			return err
		}
		s.show(formatShare(i+1, len(shares), sh))
		if err := e.flushTyped(); err != nil {
			return err
		}
		fmt.Fprint(e.stderr, "Anteil notiert? Eingabetaste löscht den Bildschirm: ")
		err := e.confirm()
		s.wipe()
		if err != nil {
			return err
		}
	}
	return nil
}

// formatShare is the screen of share i of n: its 30 words, numbered, six
// in a row.
func formatShare(i, n int, ws []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Anteil %d von %d (%d Wörter). Schreiben Sie ihn auf Papier; er wird nirgends gespeichert:\n", i, n, len(ws))
	for k, w := range ws {
		fmt.Fprintf(&b, "%2d. %-10s", k+1, w)
		if k%6 == 5 {
			b.WriteString("\n")
		}
	}
	if len(ws)%6 != 0 {
		b.WriteString("\n")
	}
	return b.String()
}
