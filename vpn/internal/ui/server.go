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
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
)

const cookieName = "idoris_ui"
const secretHeader = "X-Idoris-UI-Secret" //nolint:gosec // header name, not a credential
const csrfHeader = "X-CSRF-Token"
const maxBody = 64 << 10
const defaultIdle = 15 * time.Minute
const csp = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

//go:embed index.html app.js app.css
var assets embed.FS

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

type joinView struct {
	Role     string   `json:"role"`
	Tenant   string   `json:"tenant"`
	Hostname string   `json:"hostname"`
	Approved []string `json:"approved,omitempty"`
	Warning  string   `json:"warning,omitempty"`
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

func (s *Server) touch() {
	s.mu.Lock()
	s.last = time.Now()
	s.mu.Unlock()
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /app.js", s.asset("app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /app.css", s.asset("app.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/join", s.handleJoin)
	mux.HandleFunc("POST /api/detect", s.handleDetect)
	mux.HandleFunc("POST /api/probe", s.handleProbe)
	mux.HandleFunc("POST /api/plan", s.handlePlan)
	mux.HandleFunc("POST /api/apply", s.handleApply)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", csp)
		if r.Host != s.bound {
			writeErr(w, http.StatusForbidden, "forbidden host")
			return
		}
		if !s.authorized(r) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if r.Method == http.MethodPost && !sameOrigin(r, s.bound) {
			writeErr(w, http.StatusForbidden, "cross-origin refused")
			return
		}
		if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeader)), []byte(s.csrf)) != 1 {
			writeErr(w, http.StatusForbidden, "csrf refused")
			return
		}
		if r.ContentLength > maxBody {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		s.touch()
		// Secure is left unset: the page is http://127.0.0.1 and a Secure cookie would not be stored.
		http.SetCookie(w, &http.Cookie{ //nolint:gosec // loopback HTTP, HttpOnly + SameSite=Strict
			Name: cookieName, Value: s.secret, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	ok := true
	presented := false
	check := func(v string) {
		if v == "" {
			return
		}
		presented = true
		if subtle.ConstantTimeCompare([]byte(v), []byte(s.secret)) != 1 {
			ok = false
		}
	}
	check(r.URL.Query().Get("k"))
	if c, err := r.Cookie(cookieName); err == nil {
		check(c.Value)
	}
	check(r.Header.Get(secretHeader))
	return presented && ok
}

func sameOrigin(r *http.Request, bound string) bool {
	origin := r.Header.Get("Origin")
	site := r.Header.Get("Sec-Fetch-Site")
	if origin == "" && site == "" {
		return false
	}
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "http" || u.Host != bound {
			return false
		}
	}
	if site != "" && site != "same-origin" {
		return false
	}
	return true
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	b, err := assets.ReadFile("index.html")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "page missing")
		return
	}
	page := strings.ReplaceAll(string(b), "__CSRF__", s.csrf)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, page)
}

func (s *Server) asset(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		b, err := assets.ReadFile(name)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(b)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if s.svc.Status == nil {
		writeJSON(w, http.StatusOK, map[string]any{"phase": "unreachable"})
		return
	}
	st, err := s.svc.Status(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"phase": "unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code          string `json:"code"`
		AllowInsecure bool   `json:"allow_insecure"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	payload, err := join.Decode(body.Code, join.Options{AllowInsecure: body.AllowInsecure})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	host := payload.HostnameHint
	if host == "" && s.svc.Hostname != nil {
		if h, err := s.svc.Hostname(); err == nil {
			host = strings.TrimSpace(h)
		}
	}
	if host == "" {
		host = "idoris"
	}
	view := joinView{Role: payload.Role, Tenant: payload.Tenant, Hostname: host}
	held := heldJoin{
		EnrollURL: payload.EnrollURL, Token: payload.Token, Role: payload.Role,
		Tenant: payload.Tenant, Hostname: host, AllowInsecure: body.AllowInsecure || strings.HasPrefix(payload.EnrollURL, "http://"),
	}
	if s.svc.Discover != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		disc, err := s.svc.Discover(ctx, payload.EnrollURL, payload.Token, held.AllowInsecure)
		cancel()
		if err != nil {
			view.Warning = "could not read the pre-approved list; a gateway route will wait for an admin"
		} else if disc != nil {
			held.Approved = append([]string(nil), disc.LANCIDRs...)
			view.Approved = held.Approved
		}
	}
	paths, err := s.ensurePaths()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mu.Lock()
	s.join = &held
	s.paths = paths
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleDetect(w http.ResponseWriter, _ *http.Request) {
	if s.svc.Detect == nil {
		writeErr(w, http.StatusInternalServerError, "detect is not available")
		return
	}
	rep, err := s.svc.Detect()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.mu.Lock()
	s.report = &rep
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if s.svc.Probe == nil {
		writeErr(w, http.StatusInternalServerError, "probe is not available")
		return
	}
	res, err := s.svc.Probe(r.Context(), body.IP)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ThisMachineIsLocalAI bool     `json:"this_machine_is_local_ai"`
		DeviceIPs            []string `json:"device_ips"`
		WholeSubnet          bool     `json:"whole_subnet"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	s.mu.Lock()
	held := s.join
	rep := s.report
	paths := s.paths
	s.mu.Unlock()
	if held == nil {
		writeErr(w, http.StatusBadRequest, "paste a join code first")
		return
	}
	if paths.config == "" {
		var err error
		paths, err = s.ensurePaths()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	var plan gateway.Plan
	var err error
	if body.ThisMachineIsLocalAI {
		plan, err = gateway.BuildPlan(gateway.Request{
			ThisMachineIsLocalAI: true, Tenant: held.Tenant, Hostname: held.Hostname,
		})
	} else {
		// "No" means this machine is the gateway, whatever role the code carried.
		if rep == nil {
			writeErr(w, http.StatusBadRequest, "detect the network first")
			return
		}
		plan, err = gateway.BuildPlan(gateway.Request{
			DeviceIPs: body.DeviceIPs, WholeSubnet: body.WholeSubnet,
			Detection: *rep, Approved: held.Approved, Tenant: held.Tenant, Hostname: held.Hostname,
		})
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	plan.EnrollURL = held.EnrollURL
	plan.AllowInsecure = held.AllowInsecure
	plan.TokenFile = paths.token
	plan.ConfigPath = paths.config
	s.mu.Lock()
	s.plan = &plan
	s.paths = paths
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) handleApply(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	held := s.join
	plan := s.plan
	paths := s.paths
	s.mu.Unlock()
	if held == nil || plan == nil {
		writeErr(w, http.StatusBadRequest, "build a plan first")
		return
	}
	if plan.Blocked {
		writeErr(w, http.StatusConflict, plan.BlockReason)
		return
	}
	if s.svc.Apply == nil {
		writeErr(w, http.StatusInternalServerError, "apply is not available")
		return
	}
	res, err := s.svc.Apply(*plan, gateway.ApplyOptions{Token: held.Token, PlanPath: paths.plan})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) ensurePaths() (idorisPaths, error) {
	if s.svc.Home == nil {
		return idorisPaths{}, errors.New("ui: home directory is not available")
	}
	home, err := s.svc.Home()
	if err != nil || home == "" {
		return idorisPaths{}, fmt.Errorf("ui: home directory: %w", err)
	}
	base := filepath.Join(home, ".idoris")
	return idorisPaths{
		config: filepath.Join(base, "vpn.json"),
		token:  filepath.Join(base, "enroll.token"),
		plan:   filepath.Join(base, "gateway-plan.json"),
	}, nil
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return false
		}
		writeErr(w, http.StatusBadRequest, "bad request")
		return false
	}
	return true
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
