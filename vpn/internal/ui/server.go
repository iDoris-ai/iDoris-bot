// Package ui serves the local onboarding page.
//
// The listener is 127.0.0.1 on a random port. The HTML, script and stylesheet
// are static and contain no secret. A bootstrap secret is single-use and
// expires after two minutes. The auto-open path puts that secret in a 0600
// launcher file under a 0700 directory; the browser is started with the file
// path only. The manual path puts it in the URL fragment (#k=), which browsers
// do not send. Either path exchanges it once for a session capability. The
// page keeps that capability in sessionStorage (origin-scoped, including the
// port) and sends it as the X-Idoris-UI header. It is never a cookie, so
// another server on 127.0.0.1 cannot receive it. State-changing requests also
// need a same-origin signal and the CSRF token issued at bootstrap.
package ui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
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
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
)

const (
	// SessionHeader is the per-session capability. It is not a cookie.
	SessionHeader = "X-Idoris-UI"
	csrfHeader    = "X-CSRF-Token"
	maxBody       = 64 << 10
	defaultIdle   = 15 * time.Minute
	// BootstrapTTL is how long a bootstrap secret stays valid.
	BootstrapTTL = 2 * time.Minute

	csp = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)

//go:embed index.html app.js app.css
var assets embed.FS

var errBootstrapUsed = errors.New("bootstrap secret already used")
var errBootstrapExpired = errors.New("bootstrap secret expired")

var bootstrapTmpl = template.Must(template.New("bootstrap").Parse(`<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8"><title>iDoris</title></head>
<body><script nonce="{{.Nonce}}">
sessionStorage.setItem("idoris_ui", "{{.Session}}");
sessionStorage.setItem("idoris_csrf", "{{.CSRF}}");
location.replace("/");
</script></body></html>
`))

var launcherTmpl = template.Must(template.New("launcher").Parse(`<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8"><title>iDoris</title></head>
<body>
<form id="boot" method="POST" action="{{.Action}}">
<input type="hidden" name="k" value="{{.Secret}}">
</form>
<script>document.getElementById("boot").submit();</script>
</body></html>
`))

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
	// Secret is the bootstrap secret. Empty means generate one. It is not the
	// session capability and it is never stored in a cookie.
	Secret string
	CSRF   string
	// Idle is how long the server stays up with no authenticated request.
	// Zero means 15 minutes.
	Idle time.Duration
	// BootstrapTTL overrides the two-minute bootstrap lifetime. Zero means
	// two minutes.
	BootstrapTTL time.Duration
}

// Server is the loopback wizard.
type Server struct {
	opt    Options
	svc    Services
	idle   time.Duration
	secret string // bootstrap secret, single-use
	sess   string // session capability, sent as a header
	csrf   string
	bound  string
	bootEx time.Time

	http *http.Server
	once sync.Once
	done chan struct{}

	mu            sync.Mutex
	last          time.Time
	bootstrapUsed bool
	applying      bool
	launcherPath  string
	joinRev       uint64
	detectGen     uint64
	planNote      string
	join          *heldJoin
	report        *netdetect.Report
	plan          *boundPlan
	paths         idorisPaths

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
	discovered    bool
}

// boundPlan is one plan plus the inputs it was built from. Apply refuses
// the plan when any of those inputs has moved on.
type boundPlan struct {
	plan      gateway.Plan
	joinRev   uint64
	detectGen uint64
	localAI   bool
	devices   []string
	whole     bool
}

type idorisPaths struct {
	config string
	token  string
	plan   string
}

type joinView struct {
	Role      string   `json:"role"`
	Tenant    string   `json:"tenant"`
	Hostname  string   `json:"hostname"`
	Authority string   `json:"authority"`
	Approved  []string `json:"approved,omitempty"`
	Warning   string   `json:"warning,omitempty"`
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
	sess, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	csrf := opt.CSRF
	if csrf == "" {
		csrf, err = randomHex(16)
		if err != nil {
			return nil, err
		}
	}
	idle := opt.Idle
	if idle <= 0 {
		idle = defaultIdle
	}
	ttl := opt.BootstrapTTL
	if ttl <= 0 {
		ttl = BootstrapTTL
	}
	return &Server{
		opt: opt, svc: opt.Services, idle: idle, secret: secret, sess: sess, csrf: csrf,
		bootEx: time.Now().Add(ttl),
		done:   make(chan struct{}), served: make(chan struct{}), last: time.Now(),
	}, nil
}

// Start listens on 127.0.0.1:0. The returned URL is for a person to open by
// hand: the bootstrap secret is in the fragment (#k=), which is not sent to
// any server. Automatic open uses WriteLauncher and a file path instead.
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
	return s.ManualURL(), nil
}

// ManualURL is the hand-opened URL. The secret is in the fragment.
func (s *Server) ManualURL() string {
	return "http://" + s.bound + "/#k=" + s.secret
}

// PageURL is the page with no secret. Safe to print and to put in a process list.
func (s *Server) PageURL() string {
	return "http://" + s.bound + "/"
}

// WriteLauncher writes a 0600 HTML file that posts the bootstrap secret to
// this server. dir is created with EnsurePrivateDir (0700, no symlink, owned
// by the current user). The returned path is what a browser opener receives.
func (s *Server) WriteLauncher(dir string) (string, error) {
	if s.bound == "" {
		return "", errors.New("ui: server is not listening")
	}
	if err := fsutil.EnsurePrivateDir(dir); err != nil {
		return "", err
	}
	// EnsurePrivateDir accepts a directory we own that is not writable by
	// anyone else, including mode 0755. The launcher directory has to be
	// 0700 so other local users cannot list the file name.
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	id, err := randomHex(8)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	action := s.PageURL() + "bootstrap"
	if err := launcherTmpl.Execute(&buf, map[string]string{
		"Action": action,
		"Secret": s.secret,
	}); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "launch-"+id+".html")
	if err := fsutil.WriteFileAtomic(path, buf.Bytes(), 0o600); err != nil {
		return "", err
	}
	s.mu.Lock()
	s.launcherPath = path
	s.mu.Unlock()
	return path, nil
}

// Shutdown stops the listener and deletes the launcher file. It is safe to
// call more than once.
func (s *Server) Shutdown(ctx context.Context) error {
	s.once.Do(func() { close(s.done) })
	s.deleteLauncher()
	if s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

func (s *Server) deleteLauncher() {
	s.mu.Lock()
	p := s.launcherPath
	s.launcherPath = ""
	s.mu.Unlock()
	if p != "" {
		_ = os.Remove(p)
	}
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
	mux.HandleFunc("POST /bootstrap", s.handleBootstrapForm)
	mux.HandleFunc("POST /api/bootstrap", s.handleBootstrapAPI)
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
		if r.ContentLength > maxBody {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		if isPublic(r) || isBootstrap(r) {
			mux.ServeHTTP(w, r)
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
		s.touch()
		mux.ServeHTTP(w, r)
	})
}

func isPublic(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	switch r.URL.Path {
	case "/", "/app.js", "/app.css":
		return true
	default:
		return false
	}
}

func isBootstrap(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	return r.URL.Path == "/bootstrap" || r.URL.Path == "/api/bootstrap"
}

// authorized checks only the session header. Query strings and cookies are
// ignored so a stale cookie cannot fail a later launch, and nothing usable is
// attached to requests a browser sends to a different loopback port.
func (s *Server) authorized(r *http.Request) bool {
	got := r.Header.Get(SessionHeader)
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.sess)) == 1
}

func (s *Server) consumeBootstrap(got string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	match := subtle.ConstantTimeCompare([]byte(got), []byte(s.secret)) == 1
	switch {
	case !match:
		return "", "", errors.New("unauthorized")
	case s.bootstrapUsed:
		return "", "", errBootstrapUsed
	case time.Now().After(s.bootEx):
		return "", "", errBootstrapExpired
	default:
		s.bootstrapUsed = true
		return s.sess, s.csrf, nil
	}
}

func (s *Server) finishBootstrap(w http.ResponseWriter, got string, nonce string) {
	sess, csrf, err := s.consumeBootstrap(got)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.deleteLauncher()
	s.touch()
	if nonce == "" {
		writeJSON(w, http.StatusOK, map[string]string{"capability": sess, "csrf": csrf})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'nonce-"+nonce+"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	if err := bootstrapTmpl.Execute(w, map[string]string{
		"Nonce": nonce, "Session": sess, "CSRF": csrf,
	}); err != nil {
		return
	}
}

func (s *Server) handleBootstrapForm(w http.ResponseWriter, r *http.Request) {
	nonce, err := randomHex(16)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "bootstrap page failed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	// PostForm, not Form: a ?k= query must not authenticate.
	s.finishBootstrap(w, r.PostForm.Get("k"), nonce)
}

func (s *Server) handleBootstrapAPI(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r, s.bound) {
		writeErr(w, http.StatusForbidden, "cross-origin refused")
		return
	}
	var body struct {
		K string `json:"k"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	s.finishBootstrap(w, body.K, "")
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
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
	authority, err := authorityHost(payload.EnrollURL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Decode only. Discover sends the enrollment credential, so it waits
	// until the operator has confirmed this authority.
	view := joinView{Role: payload.Role, Tenant: payload.Tenant, Hostname: host, Authority: authority}
	held := heldJoin{
		EnrollURL: payload.EnrollURL, Token: payload.Token, Role: payload.Role,
		Tenant: payload.Tenant, Hostname: host, AllowInsecure: body.AllowInsecure || strings.HasPrefix(payload.EnrollURL, "http://"),
	}
	paths, err := s.ensurePaths()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mu.Lock()
	s.joinRev++
	s.join = &held
	s.paths = paths
	if s.plan != nil {
		s.planNote = stalePlanMsg
	}
	s.plan = nil
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
	s.detectGen++
	if s.plan != nil {
		s.planNote = stalePlanMsg
	}
	s.plan = nil
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
		ConfirmAuthority     bool     `json:"confirm_authority"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	devices := normDevices(body.DeviceIPs)
	s.mu.Lock()
	if s.join == nil {
		s.mu.Unlock()
		writeErr(w, http.StatusBadRequest, "paste a join code first")
		return
	}
	// Reject before dropping a plan or contacting the enrollment service.
	// A missing confirmation is not a failed re-plan.
	if !body.ConfirmAuthority {
		s.mu.Unlock()
		writeErr(w, http.StatusBadRequest, confirmAuthorityMsg)
		return
	}
	if s.plan != nil {
		s.planNote = stalePlanMsg
	}
	s.plan = nil
	copied := *s.join
	held := &copied
	rev := s.joinRev
	det := s.detectGen
	rep := s.report
	paths := s.paths
	s.mu.Unlock()
	if paths.config == "" {
		var err error
		paths, err = s.ensurePaths()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	discoverWarning := s.discoverInto(r.Context(), held)
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
			DeviceIPs: devices, WholeSubnet: body.WholeSubnet,
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
	if discoverWarning != "" {
		plan.Warnings = append(plan.Warnings, netdetect.Notice{Code: "discover", Text: discoverWarning})
	}
	s.mu.Lock()
	if s.joinRev != rev || s.detectGen != det {
		s.plan = nil
		s.planNote = stalePlanMsg
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, stalePlanMsg)
		return
	}
	s.plan = &boundPlan{
		plan: plan, joinRev: rev, detectGen: det,
		localAI: body.ThisMachineIsLocalAI, devices: devices, whole: body.WholeSubnet,
	}
	s.planNote = ""
	s.paths = paths
	if s.join != nil {
		s.join.Approved = append([]string(nil), held.Approved...)
		s.join.discovered = held.discovered
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ThisMachineIsLocalAI bool     `json:"this_machine_is_local_ai"`
		DeviceIPs            []string `json:"device_ips"`
		WholeSubnet          bool     `json:"whole_subnet"`
		ConfirmAuthority     bool     `json:"confirm_authority"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	devices := normDevices(body.DeviceIPs)
	s.mu.Lock()
	if s.applying {
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, "another apply is already running")
		return
	}
	if !body.ConfirmAuthority {
		s.mu.Unlock()
		writeErr(w, http.StatusBadRequest, confirmAuthorityMsg)
		return
	}
	if s.plan == nil || s.join == nil || s.plan.joinRev != s.joinRev || s.plan.detectGen != s.detectGen {
		msg := s.planNote
		s.mu.Unlock()
		if msg == "" {
			msg = "build a plan first"
		}
		code := http.StatusBadRequest
		if msg == stalePlanMsg {
			code = http.StatusConflict
		}
		writeErr(w, code, msg)
		return
	}
	if body.ThisMachineIsLocalAI != s.plan.localAI || body.WholeSubnet != s.plan.whole || !sameStrings(devices, s.plan.devices) {
		s.plan = nil
		s.planNote = answerMismatchMsg
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, answerMismatchMsg)
		return
	}
	if s.plan.plan.Blocked {
		reason := s.plan.plan.BlockReason
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, reason)
		return
	}
	if s.svc.Apply == nil {
		s.mu.Unlock()
		writeErr(w, http.StatusInternalServerError, "apply is not available")
		return
	}
	// Snapshot the plan and the token from the same join revision. A later
	// join cannot be paired with this plan: the revision check above, and
	// this copy, are the only values Apply sees.
	plan := s.plan.plan
	token := s.join.Token
	planPath := s.paths.plan
	s.applying = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.applying = false
		s.mu.Unlock()
	}()
	res, err := s.svc.Apply(plan, gateway.ApplyOptions{Token: token, PlanPath: planPath})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

const stalePlanMsg = "the plan is stale; build it again"
const answerMismatchMsg = "the plan does not match the answers on the page; build it again"
const confirmAuthorityMsg = "confirm this is your organization's server before applying"

// discoverInto contacts the enrollment service only after the operator has
// confirmed the authority. It records the result on held, which is a copy;
// the caller writes Approved back under the lock.
func (s *Server) discoverInto(ctx context.Context, held *heldJoin) string {
	if held.discovered || s.svc.Discover == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	disc, err := s.svc.Discover(ctx, held.EnrollURL, held.Token, held.AllowInsecure)
	if err != nil {
		return "could not read the pre-approved list; a gateway route will wait for an admin"
	}
	held.discovered = true
	if disc != nil {
		held.Approved = append([]string(nil), disc.LANCIDRs...)
	}
	return ""
}

func authorityHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", errors.New("ui: enrollment URL has no host")
	}
	return u.Host, nil
}

func normDevices(in []string) []string {
	var out []string
	for _, d := range in {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
