// Package ui serves the local onboarding page.
//
// The server binds 127.0.0.1 on a random port. The printed URL carries a
// one-time secret. After that, the secret must arrive as the idoris_ui cookie
// or the X-Idoris-UI-Secret header. State-changing requests also need a
// same-origin signal and the CSRF token from the page. Nothing on the page
// is loaded from another host.
package ui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
)

const defaultIdle = 15 * time.Minute

// Services are the wizard operations the page calls. Tests supply fakes.
type Services struct {
	Detect   func() (netdetect.Report, error)
	Probe    func(ctx context.Context, ip string) (netdetect.ProbeResult, error)
	Discover func(ctx context.Context, enrollURL, token string, allowInsecure bool) (*enroll.Discovery, error)
	Apply    func(plan gateway.Plan, opt gateway.ApplyOptions) (gateway.ApplyResult, error)
	Status   func(ctx context.Context) (map[string]any, error)
	Home     func() (string, error)
	Hostname func() (string, error)
}

// Options configures one local page.
type Options struct {
	Services Services
	// EUID and LoginUID are compared before the port opens. LoginUID < 0
	// means the OS did not say who owns the session.
	EUID     int
	LoginUID int
	Secret   string
	CSRF     string
	// Idle is how long the server stays up with no authenticated request.
	// Zero means 15 minutes.
	Idle time.Duration
}

// Server is the loopback wizard.
type Server struct {
	opt    Options
	svc    Services
	idle   time.Duration
	secret string
	csrf   string
	bound  string

	http *http.Server
	once sync.Once
	done chan struct{}

	mu     sync.Mutex
	last   time.Time
	join   *heldJoin
	report *netdetect.Report
	plan   *gateway.Plan
	paths  idorisPaths

	served   chan struct{}
	serveErr error
}

type heldJoin struct {
	EnrollURL     string
	Token         string
	Role          string
	Tenant        string
	Hostname      string
	Approved      []string
	AllowInsecure bool
}

type idorisPaths struct {
	config string
	token  string
	plan   string
}

// CheckSessionUser refuses to serve a page into a different user's session.
// loginUID < 0 means unknown (no /proc loginuid) and is allowed.
func CheckSessionUser(euid, loginUID int) error {
	if loginUID >= 0 && loginUID != euid {
		return fmt.Errorf("ui: refusing to run in a session owned by uid %d (this process is uid %d)", loginUID, euid)
	}
	return nil
}

// CurrentLoginUID reads Linux /proc/self/loginuid. An absent file, an unreadable
// file, or the unset value 4294967295 all mean "unknown" (-1).
func CurrentLoginUID() int {
	b, err := os.ReadFile("/proc/self/loginuid") //nolint:gosec // fixed kernel path, not a user path
	if err != nil {
		return -1
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "4294967295" {
		return -1
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return int(n)
}

// New checks the session user and prepares the server. It does not listen.
func New(opt Options) (*Server, error) {
	if err := CheckSessionUser(opt.EUID, opt.LoginUID); err != nil {
		return nil, err
	}
	secret := opt.Secret
	if secret == "" {
		var err error
		secret, err = randomHex(16)
		if err != nil {
			return nil, err
		}
	}
	csrf := opt.CSRF
	if csrf == "" {
		var err error
		csrf, err = randomHex(16)
		if err != nil {
			return nil, err
		}
	}
	idle := opt.Idle
	if idle <= 0 {
		idle = defaultIdle
	}
	return &Server{
		opt: opt, svc: opt.Services, idle: idle, secret: secret, csrf: csrf,
		done: make(chan struct{}), served: make(chan struct{}), last: time.Now(),
	}, nil
}

// Start listens on 127.0.0.1:0 and returns the URL that carries the secret.
func (s *Server) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	s.bound = ln.Addr().String()
	s.http = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.mu.Lock()
	s.last = time.Now()
	s.mu.Unlock()
	go s.watchIdle()
	go func() {
		s.serveErr = s.http.Serve(ln)
		close(s.served)
	}()
	return "http://" + s.bound + "/?k=" + s.secret, nil
}

// Shutdown stops the listener. It is safe to call more than once.
func (s *Server) Shutdown(ctx context.Context) error {
	s.once.Do(func() { close(s.done) })
	if s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

// Wait blocks until the server has stopped.
func (s *Server) Wait() error {
	<-s.served
	if errors.Is(s.serveErr, http.ErrServerClosed) {
		return nil
	}
	return s.serveErr
}

// BoundHost is 127.0.0.1:port after Start.
func (s *Server) BoundHost() string { return s.bound }

func (s *Server) watchIdle() {
	step := s.idle / 5
	if step < 20*time.Millisecond {
		step = 20 * time.Millisecond
	}
	tick := time.NewTicker(step)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.mu.Lock()
			last := s.last
			s.mu.Unlock()
			if time.Since(last) >= s.idle {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = s.Shutdown(ctx)
				cancel()
				return
			}
		}
	}
}

func (s *Server) routes() http.Handler {
	panic("stub")
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func init() {
	var touch0 Services
	_ = touch0.Detect
	_ = touch0.Probe
	_ = touch0.Discover
	_ = touch0.Apply
	_ = touch0.Status
	_ = touch0.Home
	_ = touch0.Hostname
	var touch2 Server
	_ = touch2.join
	_ = touch2.report
	_ = touch2.plan
	_ = touch2.paths
	var touch3 heldJoin
	_ = touch3.EnrollURL
	_ = touch3.Token
	_ = touch3.Role
	_ = touch3.Tenant
	_ = touch3.Hostname
	_ = touch3.Approved
	_ = touch3.AllowInsecure
	var touch4 idorisPaths
	_ = touch4.config
	_ = touch4.token
	_ = touch4.plan
}
