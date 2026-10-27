//go:build gomail_test

package main

import (
	"bufio"
	"path/filepath"
	"strings"
	"testing"
)

// pipeKeys is a keyboard behind a pipe: no terminal.
type pipeKeys struct{ k *keyboard }

func (p pipeKeys) Read(b []byte) (int, error) { return p.k.Read(b) }

// TestKeygenPipeTestBuild: in a test build GOMAILCTL_TEST_KEYGEN_PIPE=1
// lets keygen without --shares run on pipes as in phase 1 (for the
// scripted end-to-end tests); with --shares, or any other value, keygen
// refuses before it shows anything.
func TestKeygenPipeTestBuild(t *testing.T) {
	c := newCLI(t)
	data := c.env.Store.Path("")
	keygen := func(dir string, args ...string) (int, string, string) {
		out := &syncBuf{}
		kb := &keyboard{err: &syncBuf{}}
		kb.answer = func(prompt string) (string, bool) {
			if m := wordPromptRe.FindStringSubmatch(prompt); m != nil {
				return seedOf(t, out.String())[atoi(m[1])-1], true
			}
			return "", false
		}
		in := pipeKeys{kb}
		e := &env{stdin: bufio.NewReader(in), in: in, stdout: out, stderr: kb.err, now: c.env.Clock.Now, beforeRefresh: c.beforeRefresh()}
		code := e.run(append(append([]string{"keygen"}, args...), "--data", data, "--dir", dir, "--pin", c.pin))
		return code, out.String(), kb.err.String()
	}
	t.Setenv(testEnvKeygenPipeName, "1")
	dir := filepath.Join(c.env.Base, "clients", "pipe")
	if code, out, errOut := keygen(dir); code != 0 || strings.Contains(out, clearScreen) || !strings.Contains(out, "angelegt") {
		t.Fatalf("pipe mode: exit %d\n%s\n%s", code, out, errOut)
	}
	dir = filepath.Join(c.env.Base, "clients", "pipe-shares")
	if code, out, errOut := keygen(dir, "--shares", "2-of-3"); code != 1 || out != "" || !strings.Contains(errOut, "nur auf einem Terminal") || exists(dir) {
		t.Fatalf("pipe mode with --shares: exit %d %q %q", code, out, errOut)
	}
	t.Setenv(testEnvKeygenPipeName, "yes")
	if code, out, errOut := keygen(dir); code != 1 || out != "" || !strings.Contains(errOut, testEnvKeygenPipeName) || exists(dir) {
		t.Fatalf("pipe mode with a wrong value: exit %d %q %q", code, out, errOut)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
