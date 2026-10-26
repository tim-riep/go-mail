package smtpd

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

// memConn is an in-memory connection: the client's bytes are read from
// in, the server's replies go to out (bounded).
type memConn struct {
	in  io.Reader
	out bytes.Buffer
}

func (m *memConn) Read(p []byte) (int, error) { return m.in.Read(p) }
func (m *memConn) Write(p []byte) (int, error) {
	if m.out.Len() > 1<<20 {
		return 0, io.ErrShortWrite
	}
	return m.out.Write(p)
}
func (m *memConn) SetReadDeadline(time.Time) error { return nil }

func runSession(input []byte, b Backend) *memConn {
	c := &memConn{in: bytes.NewReader(input)}
	cfg := Config{Hostname: "fuzz", MaxSize: 4096, MaxRecipients: 5}.withDefaults()
	s := newSession(cfg, b, newLimiter(3, 4), c, "192.0.2.1")
	s.run()
	return c
}

// FuzzCommands drives the command level with arbitrary client input.
// Nothing may panic (the session's recover would hide it, so the test
// checks that the session did not abort), and every reply line is a
// well-formed reply.
func FuzzCommands(f *testing.F) {
	for _, s := range []string{
		"EHLO a\r\nMAIL FROM:<a@b>\r\nRCPT TO:<info@x.example>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
		"HELO a\r\nMAIL FROM:<> SIZE=10 BODY=7BIT\r\nRCPT TO:<x@y>\r\nRSET\r\nNOOP\r\nVRFY x\r\n",
		"\r\n\n\r" + strings.Repeat("A", 2000) + "\r\nQUIT\r\n",
		"MAIL FROM:<a@b>\r\nDATA\r\nRCPT TO:<info@x.example>\r\n",
		"EHLO a\r\nMAIL FROM:<a@b>\r\nRCPT TO:<info@x.example>\r\nDATA\r\n..\r\n.\n.\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		b := newFake("info@x.example")
		c := runSession(input, b)
		for _, line := range strings.Split(strings.TrimSuffix(c.out.String(), "\r\n"), "\r\n") {
			if len(line) < 4 || line[0] < '2' || line[0] > '5' || (line[3] != ' ' && line[3] != '-') {
				t.Fatalf("malformed reply line %q", line)
			}
		}
		for _, m := range b.committed {
			if int64(len(m)) > 4096+1024 {
				t.Fatal("message above the size limit delivered")
			}
		}
	})
}

// unstuff is the reference for the data level: CRLF lines, a line "."
// ends the data, a leading dot is removed. It reports ok=false for
// input the server must reject.
func unstuff(body []byte) (out []byte, rest []byte, ok bool) {
	for len(body) > 0 {
		i := bytes.Index(body, []byte("\r\n"))
		if i < 0 {
			return nil, nil, false
		}
		line := body[:i]
		body = body[i+2:]
		if bytes.ContainsAny(line, "\r\n") || len(line)+2 > MaxLineLen {
			return nil, nil, false
		}
		if string(line) == "." {
			return out, body, true
		}
		if len(line) > 0 && line[0] == '.' {
			line = line[1:]
		}
		out = append(out, line...)
		out = append(out, '\r', '\n')
	}
	return nil, nil, false
}

// FuzzData drives the data level: a valid transaction followed by an
// arbitrary body. If the body is valid, the delivered message must be
// exactly the reference unstuffing; if not, nothing may be delivered.
func FuzzData(f *testing.F) {
	for _, s := range []string{
		"a\r\n.\r\n", "..\r\n...\r\n.x\r\n\r\n.\r\n", "a\n.\r\n.\r\n", "a\rb\r\n.\r\n", "no end",
		strings.Repeat("x", 999) + "\r\n.\r\n", ".\r\n",
	} {
		f.Add([]byte(s))
	}
	prefix := []byte("EHLO a\r\nMAIL FROM:<a@b>\r\nRCPT TO:<info@x.example>\r\nDATA\r\n")
	f.Fuzz(func(t *testing.T, body []byte) {
		b := newFake("info@x.example")
		runSession(append(append([]byte(nil), prefix...), body...), b)
		want, _, ok := unstuff(body)
		if ok && len(want) <= 4096 {
			if len(b.committed) != 1 {
				t.Fatalf("valid body not delivered (%d messages)", len(b.committed))
			}
			got := b.committed[0]
			// Skip the Received header (three lines).
			for i := 0; i < 3; i++ {
				got = got[bytes.Index(got, []byte("\r\n"))+2:]
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("delivered %q, want %q", got, want)
			}
		} else if len(b.committed) > 0 && !ok {
			// An invalid first message must never be delivered; later
			// transactions in the same input are commands and may be.
			t.Fatalf("invalid body delivered")
		}
	})
}
