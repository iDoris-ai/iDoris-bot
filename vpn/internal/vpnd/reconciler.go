package vpnd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

// Phase is the daemon's coarse view of where the node stands.
type Phase string

const (
	PhaseUnknown      Phase = "unknown"
	PhaseConnected    Phase = "connected"
	PhaseStarting     Phase = "starting"
	PhaseSwitching    Phase = "switching-profile"
	PhaseEnrolling    Phase = "enrolling"
	PhaseNeedsApprove Phase = "needs-admin-approval"
	PhaseBlocked      Phase = "blocked-foreign-tailnet"
	PhaseError        Phase = "error"
)

// KeySource yields a fresh node auth key when the reconciler needs one.
// Keys are single-use; the reconciler calls this at most once per attempt.
type KeySource interface {
	AuthKey(ctx context.Context) (string, error)
}

// StaticKey is a KeySource for a pre-provisioned (usually reusable) key.
type StaticKey string

func (k StaticKey) AuthKey(context.Context) (string, error) {
	if k == "" {
		return "", errors.New("no auth key configured")
	}
	return string(k), nil
}

// Options drive one Reconciler.
type Options struct {
	ControlURL    string
	Hostname      string
	AcceptRoutes  bool
	AcceptDNS     bool
	AdvertiseTags []string
	// Takeover allows switching away from a currently *running* foreign
	// tailnet (e.g. the user's own Tailscale SaaS login). When false the
	// daemon reports PhaseBlocked and waits.
	Takeover bool
	// Interval between reconcile passes while healthy. Default 5s.
	Interval time.Duration
	// MaxBackoff caps the retry delay after failures. Default 2m.
	MaxBackoff time.Duration
}

// Snapshot is the observable state exposed over the status API.
type Snapshot struct {
	Phase           Phase     `json:"phase"`
	ControlURL      string    `json:"control_url"`
	BackendState    string    `json:"backend_state,omitempty"`
	CurrentControl  string    `json:"current_control_url,omitempty"`
	TailnetIPs      []string  `json:"tailnet_ips,omitempty"`
	SelfName        string    `json:"self_dns_name,omitempty"`
	PeersOnline     int       `json:"peers_online"`
	KeyExpiry       time.Time `json:"key_expiry,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	Attempts        int       `json:"login_attempts"`
	PreviousProfile string    `json:"previous_profile_id,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Reconciler converges tailscaled onto the configured control server.
type Reconciler struct {
	be   Backend
	keys KeySource
	opt  Options
	log  *slog.Logger
	now  func() time.Time

	mu       sync.RWMutex
	snap     Snapshot
	attempts int
	// previousProfile remembers the profile that was active before takeover so
	// an operator can switch back.
	previousProfile ipn.ProfileID
	// loginStarted is when the last Start()+login was issued; zero when the node
	// has been seen Running since (so the next re-enroll is immediate).
	loginStarted time.Time
	// unconverged counts consecutive login attempts that never reached Running.
	// It stretches the grace period so a persistent failure (control server
	// unreachable, TLS trust broken, ...) cannot burn a single-use key every
	// 20s forever. Reset when the backend reaches Running.
	unconverged int
}

const (
	// loginGrace is how long tailscaled gets to converge after the first login
	// attempt before a new key is minted.
	loginGrace = 20 * time.Second
	// maxLoginGrace caps the exponential growth of the grace period.
	maxLoginGrace = 10 * time.Minute
)

// New builds a Reconciler. Options.ControlURL is required.
func New(be Backend, keys KeySource, opt Options, log *slog.Logger) (*Reconciler, error) {
	if be == nil || keys == nil {
		return nil, errors.New("vpnd: backend and key source are required")
	}
	if NormalizeControlURL(opt.ControlURL) == "" {
		return nil, errors.New("vpnd: control URL is required")
	}
	if ipn.IsLoginServerSynonym(opt.ControlURL) {
		return nil, errors.New("vpnd: control URL must be the iDoris Headscale server, not Tailscale SaaS")
	}
	if opt.Interval <= 0 {
		opt.Interval = 5 * time.Second
	}
	if opt.MaxBackoff <= 0 {
		opt.MaxBackoff = 2 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &Reconciler{be: be, keys: keys, opt: opt, log: log, now: time.Now,
		snap: Snapshot{Phase: PhaseUnknown, ControlURL: opt.ControlURL}}, nil
}

// Snapshot returns the latest observed state.
func (r *Reconciler) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snap
}

func (r *Reconciler) set(mutate func(s *Snapshot)) Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	mutate(&r.snap)
	r.snap.ControlURL = r.opt.ControlURL
	r.snap.Attempts = r.attempts
	r.snap.PreviousProfile = string(r.previousProfile)
	r.snap.UpdatedAt = r.now()
	return r.snap
}

// Run loops Step until ctx is cancelled.
func (r *Reconciler) Run(ctx context.Context) error {
	failures := 0
	for {
		snap, err := r.Step(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		delay := r.opt.Interval
		switch {
		case err != nil:
			failures++
			delay = r.backoff(failures)
			r.log.Warn("reconcile failed", "phase", snap.Phase, "err", err, "retry_in", delay)
		case snap.Phase == PhaseConnected:
			failures = 0
		case snap.Phase == PhaseBlocked:
			failures = 0
			delay = max(r.opt.Interval, 30*time.Second)
		default:
			// transitional state: poll a bit faster than the healthy interval
			failures = 0
			delay = min(r.opt.Interval, 2*time.Second)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

func (r *Reconciler) backoff(failures int) time.Duration {
	d := 2 * time.Second
	for i := 1; i < failures && d < r.opt.MaxBackoff; i++ {
		d *= 2
	}
	if d > r.opt.MaxBackoff {
		d = r.opt.MaxBackoff
	}
	// ±20% jitter so a fleet never re-enrolls in lockstep.
	j := time.Duration(rand.Int64N(int64(d)/5+1)) - d/10 //nolint:gosec // jitter only, not security sensitive
	return d + j
}

// Step performs one reconcile pass and returns the resulting snapshot.
func (r *Reconciler) Step(ctx context.Context) (Snapshot, error) {
	st, err := r.be.Status(ctx)
	if err != nil {
		return r.fail(fmt.Errorf("tailscaled unreachable: %w", err)), err
	}
	prefs, err := r.be.GetPrefs(ctx)
	if err != nil {
		return r.fail(fmt.Errorf("get prefs: %w", err)), err
	}
	state := st.BackendState
	same := SameControlURL(prefs.ControlURL, r.opt.ControlURL)
	r.set(func(s *Snapshot) {
		s.BackendState = state
		s.CurrentControl = prefs.ControlURL
	})

	if !same {
		return r.stepForeign(ctx, st, prefs)
	}

	switch state {
	case ipn.Running.String():
		r.loginStarted = time.Time{}
		r.unconverged = 0
		return r.set(func(s *Snapshot) { fillSelf(s, st); s.Phase = PhaseConnected; s.LastError = "" }), nil
	case ipn.Starting.String():
		return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil
	case ipn.NeedsMachineAuth.String():
		return r.set(func(s *Snapshot) { s.Phase = PhaseNeedsApprove }), nil
	case ipn.Stopped.String():
		if _, err := r.be.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: true}, WantRunningSet: true}); err != nil {
			return r.fail(fmt.Errorf("resume: %w", err)), err
		}
		return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil
	case ipn.NeedsLogin.String(), ipn.NoState.String():
		if r.recentLogin() {
			return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil
		}
		return r.login(ctx, "needs-login")
	default:
		return r.set(func(s *Snapshot) { s.Phase = PhaseUnknown }), nil
	}
}

// recentLogin reports whether the last login was issued within the current
// grace period and tailscaled should be given time to converge before another
// single-use key is burnt.
func (r *Reconciler) recentLogin() bool {
	return !r.loginStarted.IsZero() && r.now().Sub(r.loginStarted) < r.graceFor(r.unconverged)
}

// graceFor returns how long to wait after the n-th consecutive login attempt
// that did not reach Running: 20s, 40s, 80s ... capped at maxLoginGrace.
// n == 0 (no pending attempt) means no grace at all.
func (r *Reconciler) graceFor(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	g := loginGrace
	for i := 1; i < n; i++ {
		g *= 2
		if g >= maxLoginGrace {
			return maxLoginGrace
		}
	}
	return min(g, maxLoginGrace)
}

func (r *Reconciler) stepForeign(ctx context.Context, st *ipnstate.Status, prefs *ipn.Prefs) (Snapshot, error) {
	cur, all, err := r.be.ProfileStatus(ctx)
	if err != nil {
		return r.fail(fmt.Errorf("profile status: %w", err)), err
	}
	for _, p := range all {
		if p.ID != "" && p.ID != cur.ID && SameControlURL(p.ControlURL, r.opt.ControlURL) {
			r.log.Info("switching to existing iDoris profile", "profile", p.ID, "from", cur.ID)
			if cur.ID != "" {
				r.previousProfile = cur.ID
			}
			if err := r.be.SwitchProfile(ctx, p.ID); err != nil {
				return r.fail(fmt.Errorf("switch profile: %w", err)), err
			}
			return r.set(func(s *Snapshot) { s.Phase = PhaseSwitching }), nil
		}
	}
	foreignRunning := st.BackendState == ipn.Running.String() && prefs.ControlURL != ""
	if foreignRunning && !r.opt.Takeover {
		return r.set(func(s *Snapshot) {
			s.Phase = PhaseBlocked
			s.LastError = fmt.Sprintf("tailscaled is logged into %s; takeover disabled", prefs.ControlURL)
		}), nil
	}
	if r.recentLogin() {
		return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil
	}
	if cur.ID != "" {
		r.previousProfile = cur.ID
	}
	if err := r.be.SwitchToEmptyProfile(ctx); err != nil {
		return r.fail(fmt.Errorf("switch to empty profile: %w", err)), err
	}
	return r.login(ctx, "foreign-or-empty-profile")
}

func (r *Reconciler) login(ctx context.Context, reason string) (Snapshot, error) {
	r.mu.Lock()
	r.attempts++
	r.mu.Unlock()
	r.set(func(s *Snapshot) { s.Phase = PhaseEnrolling })
	key, err := r.keys.AuthKey(ctx)
	if err != nil {
		return r.fail(fmt.Errorf("obtain auth key: %w", err)), err
	}
	prefs := ipn.NewPrefs()
	prefs.ControlURL = r.opt.ControlURL
	prefs.WantRunning = true
	prefs.LoggedOut = false
	prefs.CorpDNS = r.opt.AcceptDNS
	prefs.RouteAll = r.opt.AcceptRoutes
	prefs.Hostname = r.opt.Hostname
	prefs.AdvertiseTags = r.opt.AdvertiseTags
	if err := r.be.CheckPrefs(ctx, prefs); err != nil {
		return r.fail(fmt.Errorf("check prefs: %w", err)), err
	}
	r.log.Info("logging tailscaled into iDoris control server", "reason", reason, "control_url", r.opt.ControlURL, "os", runtime.GOOS,
		"unconverged_attempts", r.unconverged+1, "grace", r.graceFor(r.unconverged+1))
	if err := r.be.Start(ctx, ipn.Options{AuthKey: key, UpdatePrefs: prefs}); err != nil {
		return r.fail(fmt.Errorf("start: %w", err)), err
	}
	// Mirror `tailscale up --auth-key`: Start resets the control client (and any
	// stale browser auth URL); login-interactive then registers with the key and
	// forces a fresh node key, which is also what re-enrollment after expiry needs.
	if err := r.be.StartLoginInteractive(ctx); err != nil {
		return r.fail(fmt.Errorf("login: %w", err)), err
	}
	r.loginStarted = r.now()
	r.unconverged++
	return r.set(func(s *Snapshot) { s.Phase = PhaseStarting; s.LastError = "" }), nil
}

func (r *Reconciler) fail(err error) Snapshot {
	return r.set(func(s *Snapshot) { s.Phase = PhaseError; s.LastError = err.Error() })
}

func fillSelf(s *Snapshot, st *ipnstate.Status) {
	s.TailnetIPs = s.TailnetIPs[:0]
	for _, ip := range st.TailscaleIPs {
		s.TailnetIPs = append(s.TailnetIPs, ip.String())
	}
	s.PeersOnline = 0
	for _, p := range st.Peer {
		if p.Online {
			s.PeersOnline++
		}
	}
	if st.Self != nil {
		s.SelfName = st.Self.DNSName
		if st.Self.KeyExpiry != nil {
			s.KeyExpiry = *st.Self.KeyExpiry
		} else {
			s.KeyExpiry = time.Time{}
		}
	}
}
