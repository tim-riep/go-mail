// Package smtpd is the SMTP state machine of the PoC (specification 5.1):
// EHLO, HELO, MAIL FROM, RCPT TO, DATA, RSET, NOOP and QUIT, without TLS
// and without authentication, with the limits of 5.1.
//
// The package never stores or logs message content, header values or
// addresses. Its log lines carry only session IDs, sizes and status
// codes. Message bytes are passed, line by line and dot-unstuffed, to a
// Delivery of the Backend, which encrypts them (package ingest).
package smtpd

import (
	"errors"
	"log/slog"
	"time"
)

// Limits of 5.1 (DECISIONS D54 for the units).
const (
	DefaultMaxSize        = 25_000_000 // bytes, advertised as SIZE
	DefaultMaxRecipients  = 100
	MaxLineLen            = 1000 // octets including CRLF (RFC 5321 4.5.3.1.6)
	DefaultCommandTimeout = 5 * time.Minute
	DefaultDataTimeout    = 10 * time.Minute
	DefaultMaxConns       = 20
	DefaultMaxConnsPerIP  = 5
	DefaultMinRate        = 1000 // bytes per second during DATA
	DefaultRateWindow     = 60 * time.Second
	DefaultMaxMailsPerIP  = 1000 // per hour
	DefaultRateMemory     = 65536
)

// Errors a Backend returns to select a reply.
var (
	// ErrUnknownRecipient: 550 5.1.1.
	ErrUnknownRecipient = errors.New("smtpd: unknown recipient")
	// ErrDiskFull: 452 4.3.1, the sender retries later (5.1).
	ErrDiskFull = errors.New("smtpd: insufficient storage")
	// ErrTemporary: 451 4.3.0.
	ErrTemporary = errors.New("smtpd: temporary failure")
)

// Session describes the SMTP session to the backend. It holds no
// addresses of the client.
type Session struct {
	ID       string // random session ID for logs
	Helo     string // HELO or EHLO argument
	RemoteIP string // for the Received header only, never logged
}

// Backend accepts mail.
type Backend interface {
	// Accepting reports whether new mail can be accepted at all; it
	// returns ErrDiskFull when free space is below the limit (5.1).
	Accepting() error
	// Recipient checks one address of RCPT TO and returns nil if it can
	// be delivered, ErrUnknownRecipient if not (5.2 step 1).
	Recipient(address string) error
	// Begin starts the delivery of one message at DATA. from is the
	// reverse path (possibly empty), rcpts the accepted forward paths.
	Begin(s Session, from string, rcpts []string) (Delivery, error)
}

// Delivery receives one message.
type Delivery interface {
	// Write receives the message: the Received header, then the
	// dot-unstuffed lines with CRLF.
	Write(p []byte) (int, error)
	// Commit makes the message durable in every recipient mailbox. The
	// session answers 250 only after Commit returned nil (5.2 step 4).
	Commit() error
	// Abort discards everything written so far.
	Abort()
}

// Config holds the limits; zero values select the defaults.
type Config struct {
	Hostname       string
	MaxSize        int64
	MaxRecipients  int
	CommandTimeout time.Duration
	DataTimeout    time.Duration
	MaxConns       int
	MaxConnsPerIP  int
	MinRate        int64 // bytes per second during DATA
	RateWindow     time.Duration
	MaxMailsPerIP  int // per hour
	RateMemory     int // distinct IP addresses remembered for the hourly limit
	Now            func() time.Time
	Logger         *slog.Logger
}

func (c Config) withDefaults() Config {
	if c.Hostname == "" {
		c.Hostname = "localhost"
	}
	if c.MaxSize == 0 {
		c.MaxSize = DefaultMaxSize
	}
	if c.MaxRecipients == 0 {
		c.MaxRecipients = DefaultMaxRecipients
	}
	if c.CommandTimeout == 0 {
		c.CommandTimeout = DefaultCommandTimeout
	}
	if c.DataTimeout == 0 {
		c.DataTimeout = DefaultDataTimeout
	}
	if c.MaxConns == 0 {
		c.MaxConns = DefaultMaxConns
	}
	if c.MaxConnsPerIP == 0 {
		c.MaxConnsPerIP = DefaultMaxConnsPerIP
	}
	if c.MinRate == 0 {
		c.MinRate = DefaultMinRate
	}
	if c.RateWindow == 0 {
		c.RateWindow = DefaultRateWindow
	}
	if c.MaxMailsPerIP == 0 {
		c.MaxMailsPerIP = DefaultMaxMailsPerIP
	}
	if c.RateMemory == 0 {
		c.RateMemory = DefaultRateMemory
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	return c
}
