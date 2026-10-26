package smtpd

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// conn is what a session needs from a connection. net.Conn satisfies it;
// tests and fuzzing use in-memory implementations.
type conn interface {
	io.Reader
	io.Writer
	SetReadDeadline(t time.Time) error
}

var (
	errLineTooLong = errors.New("line too long")
	errBareLF      = errors.New("line not terminated by CRLF")
	errTooSlow     = errors.New("data rate below minimum")
	errQuit        = errors.New("quit")
)

type session struct {
	cfg     Config
	backend Backend
	limiter *limiter // nil: no hourly limit (tests)
	ip      string
	c       conn
	r       *bufio.Reader
	w       *bufio.Writer
	info    Session

	helo   bool
	inMail bool
	from   string
	rcpts  []string

	// Counters for the log.
	accepted int
}

func newSessionID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func newSession(cfg Config, b Backend, l *limiter, c conn, ip string) *session {
	return &session{
		cfg: cfg, backend: b, limiter: l, ip: ip, c: c,
		r:    bufio.NewReaderSize(c, 4096),
		w:    bufio.NewWriter(c),
		info: Session{ID: newSessionID(), RemoteIP: ip},
	}
}

func (s *session) reply(code int, text string) error {
	if _, err := fmt.Fprintf(s.w, "%d %s\r\n", code, text); err != nil {
		return err
	}
	return s.w.Flush()
}

func (s *session) log(event string, args ...any) {
	s.cfg.Logger.Info(event, append([]any{"session", s.info.ID}, args...)...)
}

// readLine reads one line up to and including LF. It returns the line
// without CRLF. A line longer than MaxLineLen octets (including CRLF) is
// consumed completely and reported as errLineTooLong; a line ending in a
// bare LF, or containing a bare CR, as errBareLF.
func (s *session) readLine() ([]byte, int, error) {
	var line []byte
	n := 0
	tooLong := false
	for {
		frag, err := s.r.ReadSlice('\n')
		n += len(frag)
		if !tooLong {
			if n > MaxLineLen {
				tooLong = true
				line = nil
			} else {
				line = append(line, frag...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, n, err
		}
		break
	}
	if tooLong {
		return nil, n, errLineTooLong
	}
	// line ends in '\n'.
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, n, errBareLF
	}
	line = line[:len(line)-2]
	if bytes.IndexByte(line, '\r') >= 0 || bytes.IndexByte(line, '\n') >= 0 {
		return nil, n, errBareLF
	}
	return line, n, nil
}

func (s *session) reset() {
	s.inMail = false
	s.from = ""
	s.rcpts = nil
}

// run serves one connection until QUIT, a fatal error or a timeout.
func (s *session) run() {
	defer func() {
		// Defence in depth: a bug must not take the server down, and
		// nothing about the input is logged.
		if r := recover(); r != nil {
			s.log("smtp session aborted", "reason", "internal error")
		}
	}()
	s.log("smtp session start")
	if err := s.reply(220, s.cfg.Hostname+" ESMTP go-mail PoC"); err != nil {
		return
	}
	for {
		s.c.SetReadDeadline(s.cfg.Now().Add(s.cfg.CommandTimeout))
		line, _, err := s.readLine()
		switch {
		case errors.Is(err, errLineTooLong):
			if s.reply(500, "5.5.2 Line too long") != nil {
				return
			}
			continue
		case errors.Is(err, errBareLF):
			if s.reply(500, "5.5.2 Lines must end with CRLF") != nil {
				return
			}
			continue
		case err != nil:
			if isTimeout(err) {
				s.reply(421, "4.4.2 Timeout")
				s.log("smtp session end", "status", 421, "reason", "timeout")
			} else {
				s.log("smtp session end", "status", 0, "accepted", s.accepted)
			}
			return
		}
		if err := s.command(string(line)); err != nil {
			if errors.Is(err, errQuit) {
				s.log("smtp session end", "status", 221, "accepted", s.accepted)
			} else {
				s.log("smtp session end", "status", 421, "reason", reasonOf(err))
			}
			return
		}
	}
}

func reasonOf(err error) string {
	switch {
	case errors.Is(err, errTooSlow):
		return "too slow"
	case isTimeout(err):
		return "timeout"
	}
	return "connection error"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// verb splits a command line into upper-case verb and argument.
func verb(line string) (string, string) {
	v, arg, _ := strings.Cut(line, " ")
	return strings.ToUpper(v), arg
}

func (s *session) command(line string) error {
	v, arg := verb(line)
	switch v {
	case "EHLO", "HELO":
		if arg == "" || len(arg) > 255 || strings.ContainsAny(arg, " \t") {
			return s.reply(501, "5.5.4 Syntax: "+v+" hostname")
		}
		s.reset()
		s.helo = true
		s.info.Helo = arg
		if v == "HELO" {
			return s.reply(250, s.cfg.Hostname)
		}
		_, err := fmt.Fprintf(s.w, "250-%s\r\n250-SIZE %d\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n", s.cfg.Hostname, s.cfg.MaxSize)
		if err != nil {
			return err
		}
		return s.w.Flush()
	case "MAIL":
		return s.mail(arg)
	case "RCPT":
		return s.rcpt(arg)
	case "DATA":
		if arg != "" {
			return s.reply(501, "5.5.4 Syntax: DATA")
		}
		return s.data()
	case "RSET":
		if arg != "" {
			return s.reply(501, "5.5.4 Syntax: RSET")
		}
		s.reset()
		return s.reply(250, "2.0.0 OK")
	case "NOOP":
		return s.reply(250, "2.0.0 OK")
	case "QUIT":
		s.reply(221, "2.0.0 Bye")
		return errQuit
	case "VRFY", "EXPN", "HELP", "TURN", "ETRN", "STARTTLS", "AUTH", "BDAT":
		return s.reply(502, "5.5.1 Command not implemented")
	}
	return s.reply(500, "5.5.2 Command unrecognized")
}

// parsePath parses "<path>" after "FROM:" or "TO:" and returns the path
// and the remaining parameters. Source routes are not accepted.
func parsePath(arg, prefix string) (string, string, bool) {
	if len(arg) < len(prefix) || !strings.EqualFold(arg[:len(prefix)], prefix) {
		return "", "", false
	}
	arg = strings.TrimLeft(arg[len(prefix):], " ")
	if !strings.HasPrefix(arg, "<") {
		return "", "", false
	}
	end := strings.IndexByte(arg, '>')
	if end < 0 {
		return "", "", false
	}
	path := arg[1:end]
	rest := strings.TrimLeft(arg[end+1:], " ")
	if strings.ContainsAny(path, " \t<>\"") || strings.HasPrefix(path, "@") || len(path) > 254 {
		return "", "", false
	}
	return path, rest, true
}

func (s *session) mail(arg string) error {
	if !s.helo {
		return s.reply(503, "5.5.1 Send EHLO or HELO first")
	}
	if s.inMail {
		return s.reply(503, "5.5.1 Nested MAIL command")
	}
	from, params, ok := parsePath(arg, "FROM:")
	if !ok {
		return s.reply(501, "5.5.4 Syntax: MAIL FROM:<address>")
	}
	for _, p := range strings.Fields(params) {
		k, v, _ := strings.Cut(p, "=")
		switch strings.ToUpper(k) {
		case "SIZE":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return s.reply(501, "5.5.4 Invalid SIZE")
			}
			if n > s.cfg.MaxSize {
				return s.reply(552, "5.3.4 Message size exceeds fixed maximum message size")
			}
		case "BODY":
			if u := strings.ToUpper(v); u != "7BIT" && u != "8BITMIME" {
				return s.reply(501, "5.5.4 Invalid BODY")
			}
		default:
			return s.reply(555, "5.5.4 Unsupported parameter")
		}
	}
	if err := s.backend.Accepting(); err != nil {
		if errors.Is(err, ErrDiskFull) {
			return s.reply(452, "4.3.1 Insufficient system storage")
		}
		return s.reply(451, "4.3.0 Temporary failure")
	}
	if s.limiter != nil && !s.limiter.allow(s.ip, s.cfg.Now()) {
		return s.reply(451, "4.7.1 Too many messages, try again later")
	}
	s.inMail = true
	s.from = from
	return s.reply(250, "2.1.0 OK")
}

func (s *session) rcpt(arg string) error {
	if !s.inMail {
		return s.reply(503, "5.5.1 Need MAIL before RCPT")
	}
	to, params, ok := parsePath(arg, "TO:")
	if !ok || to == "" || params != "" {
		return s.reply(501, "5.5.4 Syntax: RCPT TO:<address>")
	}
	if len(s.rcpts) >= s.cfg.MaxRecipients {
		return s.reply(452, "4.5.3 Too many recipients")
	}
	switch err := s.backend.Recipient(to); {
	case err == nil:
	case errors.Is(err, ErrUnknownRecipient):
		return s.reply(550, "5.1.1 Mailbox unavailable")
	default:
		return s.reply(451, "4.3.0 Temporary failure")
	}
	s.rcpts = append(s.rcpts, to)
	return s.reply(250, "2.1.5 OK")
}

// received returns the Received header the server adds (5.2 step 2).
func (s *session) received(now time.Time) string {
	return fmt.Sprintf("Received: from %s ([%s])\r\n\tby %s (go-mail) with ESMTP id %s;\r\n\t%s\r\n",
		sanitizeHelo(s.info.Helo), s.ip, s.cfg.Hostname, s.info.ID, now.UTC().Format(time.RFC1123Z))
}

// sanitizeHelo keeps the HELO argument printable ASCII.
func sanitizeHelo(h string) string {
	b := []byte(h)
	for i, c := range b {
		if c <= 0x20 || c >= 0x7f || c == '(' || c == ')' {
			b[i] = '?'
		}
	}
	return string(b)
}

// data runs the DATA phase. It returns an error only if the connection
// must be closed.
func (s *session) data() error {
	if !s.inMail || len(s.rcpts) == 0 {
		return s.reply(503, "5.5.1 Need RCPT before DATA")
	}
	if err := s.backend.Accepting(); err != nil {
		s.reset()
		if errors.Is(err, ErrDiskFull) {
			return s.reply(452, "4.3.1 Insufficient system storage")
		}
		return s.reply(451, "4.3.0 Temporary failure")
	}
	d, err := s.backend.Begin(s.info, s.from, s.rcpts)
	if err != nil {
		s.reset()
		if errors.Is(err, ErrDiskFull) {
			return s.reply(452, "4.3.1 Insufficient system storage")
		}
		return s.reply(451, "4.3.0 Temporary failure")
	}
	defer s.reset()
	if err := s.reply(354, "Start mail input; end with <CRLF>.<CRLF>"); err != nil {
		d.Abort()
		return err
	}
	start := s.cfg.Now()
	ok := true // still delivering
	var failure struct {
		code int
		text string
	}
	fail := func(code int, text string) {
		if ok {
			d.Abort()
			ok = false
			failure.code, failure.text = code, text
		}
	}
	var size int64
	if _, err := d.Write([]byte(s.received(start))); err != nil {
		fail(451, "4.3.0 Temporary failure")
	}

	// Bytes the client must send per rate window (5.1: 1 KB/s averaged
	// over 60 seconds).
	required := s.cfg.MinRate * int64(s.cfg.RateWindow) / int64(time.Second)
	windowStart, windowBytes := start, int64(0)
	deadline := start.Add(s.cfg.DataTimeout)
	for {
		// The read deadline is the end of the current rate window, or the
		// end of the DATA timeout if that is earlier.
		rd := windowStart.Add(s.cfg.RateWindow)
		if deadline.Before(rd) {
			rd = deadline
		}
		s.c.SetReadDeadline(rd)
		line, n, err := s.readLine()
		now := s.cfg.Now()
		windowBytes += int64(n)
		if err != nil && !errors.Is(err, errLineTooLong) && !errors.Is(err, errBareLF) {
			if isTimeout(err) && now.Before(deadline) && windowBytes >= required {
				// A pause after enough data: start a new window.
				windowStart, windowBytes = now, 0
				continue
			}
			d.Abort()
			if isTimeout(err) {
				if !now.Before(deadline) {
					s.reply(421, "4.4.2 Timeout")
					return err
				}
				s.reply(421, "4.4.2 Data rate too low")
				return errTooSlow
			}
			return err
		}
		if now.Sub(windowStart) >= s.cfg.RateWindow {
			// Average rate over the window (5.1).
			if windowBytes < required {
				d.Abort()
				s.reply(421, "4.4.2 Data rate too low")
				return errTooSlow
			}
			windowStart, windowBytes = now, 0
		}
		if !now.Before(deadline) {
			d.Abort()
			s.reply(421, "4.4.2 Timeout")
			return errTooSlow
		}
		switch {
		case errors.Is(err, errLineTooLong):
			fail(554, "5.6.0 Line too long")
			continue
		case errors.Is(err, errBareLF):
			// Only CRLF.CRLF ends the data; a bare LF or CR is rejected
			// (protection against SMTP smuggling).
			fail(554, "5.6.0 Lines must end with CRLF")
			continue
		}
		if len(line) == 1 && line[0] == '.' {
			break
		}
		if len(line) > 0 && line[0] == '.' {
			line = line[1:]
		}
		size += int64(len(line)) + 2
		if size > s.cfg.MaxSize {
			fail(552, "5.3.4 Message size exceeds fixed maximum message size")
			continue
		}
		if !ok {
			continue
		}
		if _, err := d.Write(append(line, '\r', '\n')); err != nil {
			if errors.Is(err, ErrDiskFull) {
				fail(452, "4.3.1 Insufficient system storage")
			} else {
				fail(451, "4.3.0 Temporary failure")
			}
		}
	}
	if !ok {
		s.log("smtp message rejected", "status", failure.code, "size", size)
		return s.reply(failure.code, failure.text)
	}
	if err := d.Commit(); err != nil {
		if errors.Is(err, ErrDiskFull) {
			s.log("smtp message rejected", "status", 452, "size", size)
			return s.reply(452, "4.3.1 Insufficient system storage")
		}
		s.log("smtp message rejected", "status", 451, "size", size)
		return s.reply(451, "4.3.0 Temporary failure")
	}
	if s.limiter != nil {
		s.limiter.record(s.ip, s.cfg.Now())
	}
	s.accepted++
	s.log("smtp message accepted", "status", 250, "size", size, "recipients", len(s.rcpts))
	return s.reply(250, "2.0.0 OK: queued")
}
