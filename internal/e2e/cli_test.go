package e2e

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRunbook builds the three programs and runs the steps of
// docs/RUNBOOK.md: ceremony, server, keygen, invite, register, mailbox,
// address, mail via SMTP, list, read, inspect, sync.
func TestRunbook(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the programs")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	build := exec.Command("go", "build", "-o", bin+string(os.PathSeparator), "github.com/tim-riep/go-mail/cmd/...")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	data, keys, alice := filepath.Join(dir, "data"), filepath.Join(dir, "keys"), filepath.Join(dir, "alice")
	run := func(stdin string, name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(filepath.Join(bin, name), args...)
		cmd.Env = append(os.Environ(), "GOMAILCTL_PASSPHRASE=correct horse battery staple")
		cmd.Stdin = strings.NewReader(stdin)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, errb.String())
		}
		return out.String()
	}
	common := []string{"--data", data, "--dir", alice, "--platform", filepath.Join(keys, "identity-1.pin"), "--insecure-no-log"}

	// 1. Ceremony.
	run("", "gomail-ceremony", "init", "--dev", "--data", data, "--keys", keys, "--insecure-no-log")

	// 2. Server; without --insecure-no-log it refuses to start.
	if err := exec.Command(filepath.Join(bin, "gomail-server"), "serve", "--data", data, "--ingest-key", filepath.Join(keys, "ingest-1.key")).Run(); err == nil {
		t.Fatal("server started without --insecure-no-log")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := exec.CommandContext(ctx, filepath.Join(bin, "gomail-server"), "serve", "--data", data, "--listen", "127.0.0.1:0",
		"--ingest-key", filepath.Join(keys, "ingest-1.key"), "--insecure-no-log")
	srvLog, _ := srv.StderrPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Wait()
	defer srv.Process.Signal(os.Interrupt)
	addrCh := make(chan string, 1)
	var logs bytes.Buffer
	go func() {
		sc := bufio.NewScanner(srvLog)
		re := regexp.MustCompile(`addr=(127\.0\.0\.1:\d+)`)
		for sc.Scan() {
			logs.WriteString(sc.Text() + "\n")
			if m := re.FindStringSubmatch(sc.Text()); m != nil {
				addrCh <- m[1]
			}
		}
	}()
	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(20 * time.Second):
		t.Fatal("server did not start")
	}

	// 3. keygen: answer the three questions from the words shown.
	kg := exec.Command(filepath.Join(bin, "gomailctl"), append([]string{"keygen"}, common...)...)
	kg.Env = append(os.Environ(), "GOMAILCTL_PASSPHRASE=correct horse battery staple")
	stdin, _ := kg.StdinPipe()
	stdout, _ := kg.StdoutPipe()
	stderr, _ := kg.StderrPipe()
	if err := kg.Start(); err != nil {
		t.Fatal(err)
	}
	words := map[int]string{}
	sc := bufio.NewScanner(stdout)
	wordRe := regexp.MustCompile(`(\d+)\. (\S+)`)
	for sc.Scan() && len(words) < 24 {
		for _, m := range wordRe.FindAllStringSubmatch(sc.Text(), -1) {
			n, _ := strconv.Atoi(m[1])
			words[n] = m[2]
		}
	}
	er := bufio.NewReader(stderr)
	promptRe := regexp.MustCompile(`Wort Nr\. (\d+):$`)
	for i := 0; i < 3; i++ {
		prompt, err := er.ReadString(':')
		if err != nil {
			t.Fatal(err)
		}
		m := promptRe.FindStringSubmatch(prompt)
		if m == nil {
			t.Fatalf("prompt %q", prompt)
		}
		n, _ := strconv.Atoi(m[1])
		io.WriteString(stdin, words[n]+"\n")
	}
	go io.Copy(io.Discard, stdout)
	go io.Copy(io.Discard, er)
	if err := kg.Wait(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// 4. Invitation and registration.
	code := strings.TrimSpace(run("", "gomail-server", "invite", "create", "--data", data))
	run("", "gomailctl", append([]string{"register", "--invite", code}, common...)...)

	// 5. Mailbox and address.
	mbx := strings.TrimSpace(run("", "gomailctl", append([]string{"mailbox", "create", "Büro"}, common...)...))
	run("", "gomail-server", "address", "add", "info@brownbear.example", "--mailbox", mbx, "--data", data,
		"--admin-key", filepath.Join(keys, "admin-1.key"), "--insecure-no-log")

	// 6. A mail via SMTP.
	msg := "From: rechnung@lieferant.example\r\nTo: info@brownbear.example\r\nSubject: Rechnung 4711\r\n\r\nHallo.\r\n"
	if err := smtp.SendMail(addr, nil, "rechnung@lieferant.example", []string{"info@brownbear.example"}, []byte(msg)); err != nil {
		t.Fatal(err)
	}

	// 7. list, read, inspect, sync.
	list := run("", "gomailctl", append([]string{"list", mbx}, common...)...)
	if !strings.Contains(list, "Rechnung 4711") {
		t.Fatalf("list: %q", list)
	}
	mailID := strings.Fields(list)[0]
	content := run("", "gomailctl", append([]string{"read", mbx, mailID}, common...)...)
	if !strings.HasSuffix(content, msg) || !strings.HasPrefix(content, "Received: ") {
		t.Fatalf("read: %q", content)
	}
	run("", "gomailctl", append([]string{"list", mbx, "--folder", "INBOX"}, common...)...)
	insp := run("", "gomailctl", "inspect", filepath.Join(data, "mailboxes", mbx, "epochs", "1", "epoch.rec"))
	if !strings.Contains(insp, `"_type": "gomail/v1/rec/epoch"`) {
		t.Fatalf("inspect: %q", insp)
	}
	run("", "gomailctl", append([]string{"sync"}, common...)...)

	// The server log holds no content and no addresses.
	srv.Process.Signal(os.Interrupt)
	srv.Wait()
	for _, s := range []string{"Rechnung", "lieferant", "brownbear", "Hallo"} {
		if strings.Contains(logs.String(), s) {
			t.Fatalf("server log contains %q", s)
		}
	}
	if !strings.Contains(logs.String(), "status=250") {
		t.Fatalf("server log: %s", logs.String())
	}
}
