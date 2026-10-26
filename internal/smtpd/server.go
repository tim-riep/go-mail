package smtpd

import (
	"errors"
	"net"
	"sync"
	"time"
)

// limiter counts accepted mails per IP address over the last hour
// (5.1: at most 1,000 mails per hour and IP address).
type limiter struct {
	mu     sync.Mutex
	max    int
	memory int
	seen   map[string][]time.Time
}

func newLimiter(max, memory int) *limiter {
	return &limiter{max: max, memory: memory, seen: map[string][]time.Time{}}
}

func (l *limiter) prune(ip string, now time.Time) []time.Time {
	ts := l.seen[ip]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= time.Hour {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(l.seen, ip)
		return nil
	}
	l.seen[ip] = ts
	return ts
}

// allow reports whether ip may send another mail now.
func (l *limiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.prune(ip, now)
	if ts == nil && len(l.seen) >= l.memory {
		// Forget addresses whose hour has passed; if the table is still
		// full, fail closed (temporary error) rather than grow without
		// bound.
		for k := range l.seen {
			l.prune(k, now)
		}
		if len(l.seen) >= l.memory {
			return false
		}
	}
	return len(ts) < l.max
}

func (l *limiter) record(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.prune(ip, now)
	if len(ts) >= l.max {
		return
	}
	l.seen[ip] = append(ts, now)
}

// Server accepts SMTP connections.
type Server struct {
	cfg     Config
	backend Backend
	limiter *limiter

	mu     sync.Mutex
	total  int
	perIP  map[string]int
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// NewServer returns a server with cfg (defaults for zero values).
func NewServer(cfg Config, b Backend) *Server {
	cfg = cfg.withDefaults()
	return &Server{cfg: cfg, backend: b, limiter: newLimiter(cfg.MaxMailsPerIP, cfg.RateMemory), perIP: map[string]int{}, conns: map[net.Conn]struct{}{}}
}

// ErrClosed is returned by Serve after Close.
var ErrClosed = errors.New("smtpd: server closed")

// Serve accepts connections on ln until Close.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	s.ln = ln
	s.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return ErrClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return err
		}
		s.handle(c)
	}
}

func remoteIP(c net.Conn) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

func (s *Server) handle(c net.Conn) {
	ip := remoteIP(c)
	s.mu.Lock()
	if s.closed || s.total >= s.cfg.MaxConns || s.perIP[ip] >= s.cfg.MaxConnsPerIP {
		s.mu.Unlock()
		// Answer without blocking the accept loop.
		go func() {
			c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			c.Write([]byte("421 4.7.0 Too many connections, try again later\r\n"))
			c.Close()
		}()
		s.cfg.Logger.Info("smtp connection refused", "status", 421, "reason", "connection limit")
		return
	}
	s.total++
	s.perIP[ip]++
	s.conns[c] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer func() {
			c.Close()
			s.mu.Lock()
			s.total--
			if s.perIP[ip]--; s.perIP[ip] <= 0 {
				delete(s.perIP, ip)
			}
			delete(s.conns, c)
			s.mu.Unlock()
		}()
		newSession(s.cfg, s.backend, s.limiter, c, ip).run()
	}()
}

// Close stops accepting, closes all connections and waits for the
// sessions to end. Deliveries in progress are aborted by their sessions.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	var err error
	if s.ln != nil {
		err = s.ln.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}
