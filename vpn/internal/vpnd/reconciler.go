package vpnd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"slices"
	"strings"
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
	// PhaseRoutesPending means the node is up and advertising, and Headscale
	// has not approved every configured route yet. The backend stays Running.
	PhaseRoutesPending Phase = "routes-pending-approval"
	PhaseBlocked       Phase = "blocked-foreign-tailnet"
	PhaseError         Phase = "error"
	// PhaseWaitingTailscaled means a local-ai or gateway role needs the
	// official tailscaled and it is not reachable. Embedded mode is not a
	// fallback: it cannot receive inbound connections.
	PhaseWaitingTailscaled Phase = "waiting-for-tailscaled"
	// PhaseMissingTags means the node is up but a tagged role (local-ai,
	// gateway) has no Self.Tags. Enrollment succeeded; the ACL identity did not.
	PhaseMissingTags Phase = "missing-node-tags"
)

// KeySource yields a fresh node auth key when the reconciler needs one.
// Keys are single-use; the reconciler calls this at most once per attempt.
type KeySource interface {
	AuthKey(ctx context.Context) (string, error)
}

// IdentityRefresher is optional on a KeySource. A degraded start leaves
// Identity.Known false. login calls RefreshIdentity before it requests a
// key, so a recovered enrollment service can correct the role before the
// node is registered again. Static keys do not implement it.
type IdentityRefresher interface {
	RefreshIdentity(ctx context.Context) (Identity, string, error)
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
	ControlURL   string
	Hostname     string
	AcceptRoutes bool
	AcceptDNS    bool
	// AdvertiseTags is recorded for operators. It is not sent at login.
	// Headscale v0.29.6 rejects a pre-auth-key registration whose hostinfo
	// requests tags. The key minted by the enrollment service carries
	// tenants[].acl_tags, and that is what tags the node.
	AdvertiseTags []string
	// AdvertiseRoutes, when non-empty, is written into prefs at login and
	// re-applied with EditPrefs while Running if the node has drifted.
	// Empty means "do not manage routes".
	AdvertiseRoutes []netip.Prefix
	// RunSSH is Tailscale SSH (prefs.RunSSH). Nil means unmanaged: login and
	// the running reconcile leave whatever the profile already has. An ACL
	// entry for tcp/22 does not enable Tailscale SSH; the Local AI host sets
	// this explicitly when it should run the SSH server.
	RunSSH *bool
	// Takeover allows switching away from a foreign tailnet in any backend
	// state that still holds that login: Running, Starting, Stopped, and
	// NeedsLogin with a non-empty foreign control URL. When false the daemon
	// reports PhaseBlocked and does not switch profiles or log in. A saved
	// iDoris profile is not permission to displace that login. The daemon
	// default is false.
	Takeover bool
	// LoginWhileStarting treats a Starting backend that does not yet have a
	// node identity as needing an auth-key login immediately. tsnet sits in
	// Starting after a keyless StartLoginInteractive on a brand-new state
	// directory. Set only when EmbeddedLoginMode reports loginNow.
	LoginWhileStarting bool
	// RecoverUnregistered is the interrupted case: tsnet already wrote
	// tailscaled.state, but the registration marker was never written. A
	// Starting backend with no identity waits persistedLoginSettle and then
	// mints once. HaveNodeKey or a public key suppresses that mint and
	// writes the marker instead, so an upgrade of an already enrolled
	// directory does not burn a key.
	RecoverUnregistered bool
	// MarkRegistered records that this state directory has reached a node
	// identity. Nil for system mode and for tests that do not persist it.
	MarkRegistered func() error
	// Role is member, local-ai, gateway, or admin. Empty is treated as member
	// for tag checks. Discovery is the source of truth when it ran.
	Role string
	// Mode is system or embedded. Empty in tests that do not bind a profile.
	// System mode records the LocalAPI profile ID on the identity binding.
	Mode string
	// Identity is the credential from /v1/discover. Known is false when the
	// daemon has no fresh discovery (static key, or enrollment is down).
	Identity Identity
	// State is the binding file. Nil in tests that do not care about identity.
	State *StateFile
	// EnrollUnreachable is set when startup discovery failed and the daemon
	// resumed from a saved or pinned control URL. A later successful AuthKey
	// clears it. The zero value means enrollment is reachable (or unused).
	EnrollUnreachable bool
	// Interval between reconcile passes while healthy. Default 5s.
	Interval time.Duration
	// MaxBackoff caps the retry delay after failures. Default 2m.
	MaxBackoff time.Duration
}

// Snapshot is the observable state exposed over the status API.
type Snapshot struct {
	Phase           Phase           `json:"phase"`
	ControlURL      string          `json:"control_url"`
	BackendState    string          `json:"backend_state,omitempty"`
	CurrentControl  string          `json:"current_control_url,omitempty"`
	TailnetIPs      []string        `json:"tailnet_ips,omitempty"`
	SelfName        string          `json:"self_dns_name,omitempty"`
	PeersOnline     int             `json:"peers_online"`
	KeyExpiry       time.Time       `json:"key_expiry,omitempty"`
	LastError       string          `json:"last_error,omitempty"`
	Attempts        int             `json:"login_attempts"`
	PreviousProfile string          `json:"previous_profile_id,omitempty"`
	UpdatedAt       time.Time       `json:"updated_at"`
	Mode            string          `json:"mode,omitempty"`
	ModeReason      string          `json:"mode_reason,omitempty"`
	Forwards        []ForwardStatus `json:"forwards,omitempty"`
	SOCKS5          *SOCKS5Status   `json:"socks5,omitempty"`
	// Routes is set only when AdvertiseRoutes is configured.
	Routes []RouteReport `json:"routes,omitempty"`
	// AdminHint is the exact Headscale command while any route is unapproved.
	// It is not LastError: the node is still connected.
	AdminHint string `json:"admin_hint,omitempty"`
	// Role is the enrollment role this daemon is holding the node to.
	Role string `json:"role,omitempty"`
	// Warnings are operator-facing notices that do not by themselves change
	// phase. Missing tags uses both a phase and a warning.
	Warnings []string `json:"warnings,omitempty"`
	// EnrollReachable is false while the enrollment service could not be
	// contacted at startup and the daemon is using a saved control URL.
	// A static auth key (no enrollment URL) stays true.
	EnrollReachable bool `json:"enroll_reachable"`
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
	// needsLoginSince is when a persisted node key was first seen in
	// NeedsLogin/NoState. tsnet reports that state briefly while it resumes
	// the stored key; minting immediately cancels that resume.
	needsLoginSince time.Time
	// recoverSince is a separate clock for RecoverUnregistered. It must not
	// share needsLoginSince, or time spent Starting would shorten the
	// NeedsLogin settle window.
	recoverSince time.Time
	// registered is true after MarkRegistered has succeeded in this process.
	registered bool
	// awaitingIdentity is set when the bound tenant or role disagrees with
	// the configured credential. identityLoginOK becomes true only after
	// Start and StartLoginInteractive both return, so a failed attempt cannot
	// rewrite the binding while the old node is still the one that is up.
	awaitingIdentity bool
	identityLoginOK  bool
	// mismatchNode and mismatchProfile are the running IDs that caused the
	// current identity transition. A later Running observation that still
	// shows them has not replaced that node.
	mismatchNode      string
	mismatchProfile   string
	allowNodeBackfill bool
	owner             *LiveOwner
	ownKey            string
	seenNode          string
	seenProfile       string
}

const (
	// loginGrace is how long tailscaled gets to converge after the first login
	// attempt before a new key is minted.
	loginGrace = 20 * time.Second
	// maxLoginGrace caps the exponential growth of the grace period.
	maxLoginGrace = 10 * time.Minute
	// persistedLoginSettle is how long a NeedsLogin state may last when a
	// node key is already stored before it is treated as expiry. Observed on
	// tailscale.com v1.104.2: tsnet.Server.Start resumes that key itself
	// (doLogin regen=false) and is briefly NeedsLogin; a Start(AuthKey) during
	// that window cancels the resume and burns a pre-auth key. A key that is
	// actually expired stays NeedsLogin past this.
	persistedLoginSettle = 15 * time.Second
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
	snap := Snapshot{Phase: PhaseUnknown, ControlURL: opt.ControlURL, EnrollReachable: !opt.EnrollUnreachable}
	if opt.EnrollUnreachable {
		snap.Warnings = []string{EnrollUnreachableWarning}
	}
	return &Reconciler{be: be, keys: keys, opt: opt, log: log, now: time.Now, snap: snap}, nil
}

// Snapshot returns the latest observed state. Slices are copied under the
// lock so a caller can keep the result while the next Step reuses the
// reconciler's backing arrays.
func (r *Reconciler) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneSnapshot(r.snap)
}

func cloneSnapshot(s Snapshot) Snapshot {
	s.TailnetIPs = append([]string(nil), s.TailnetIPs...)
	s.Forwards = append([]ForwardStatus(nil), s.Forwards...)
	s.Routes = append([]RouteReport(nil), s.Routes...)
	s.Warnings = append([]string(nil), s.Warnings...)
	if s.SOCKS5 != nil {
		socks := *s.SOCKS5
		s.SOCKS5 = &socks
	}
	return s
}

func (r *Reconciler) set(mutate func(s *Snapshot)) Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snap.Warnings = nil
	mutate(&r.snap)
	if r.opt.EnrollUnreachable {
		r.snap.Warnings = appendWarning(r.snap.Warnings, EnrollUnreachableWarning)
	}
	r.snap.EnrollReachable = !r.opt.EnrollUnreachable
	r.snap.ControlURL = r.opt.ControlURL
	r.snap.Role = r.opt.Role
	r.snap.Attempts = r.attempts
	r.snap.PreviousProfile = string(r.previousProfile)
	r.snap.UpdatedAt = r.now()
	r.observeLocked()
	return r.snap
}

// observeLocked bumps the access generation when the phase, the live control
// URL, the profile, the node, or the enrollment identity changed. Called with
// r.mu held. Bump only wakes the listener; it does not re-enter the reconciler.
func (r *Reconciler) observeLocked() {
	if r.owner == nil {
		return
	}
	id := r.opt.Identity
	bound := ""
	if r.opt.State != nil {
		b := r.opt.State.Get()
		bound = b.Tenant + "/" + b.Role + "/" + b.NodeID + "/" + b.ProfileID + "/" + b.TokenFingerprint
	}
	key := string(r.snap.Phase) + "\n" + NormalizeControlURL(r.snap.CurrentControl) + "\n" +
		r.seenProfile + "\n" + r.seenNode + "\n" +
		id.Tenant + "/" + id.Role + "/" + id.TokenFingerprint + "\n" +
		r.opt.Role + "\n" + bound + "\n" + fmt.Sprintf("%t", r.awaitingIdentity)
	if key == r.ownKey {
		return
	}
	r.ownKey = key
	r.owner.Bump()
}

// SetOwner attaches the access gate's generation. Nil disables bumps.
// The listener is started after this returns and before Run.
func (r *Reconciler) SetOwner(o *LiveOwner) {
	r.mu.Lock()
	r.owner = o
	r.mu.Unlock()
}

// SetRunMode records system or embedded before the first reconcile pass.
// System mode is what makes the profile ID part of the identity binding.
func (r *Reconciler) SetRunMode(mode string) {
	r.mu.Lock()
	r.opt.Mode = mode
	r.mu.Unlock()
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
		if RequiresSystem(r.opt.Role) {
			msg := WaitingTailscaledMessage(r.opt.Role)
			snap := r.set(func(s *Snapshot) {
				s.Phase = PhaseWaitingTailscaled
				s.LastError = msg
				s.Warnings = []string{msg}
			})
			return snap, fmt.Errorf("%s: %w", msg, err)
		}
		return r.fail(fmt.Errorf("tailscaled unreachable: %w", err)), err
	}
	prefs, err := r.be.GetPrefs(ctx)
	if err != nil {
		return r.fail(fmt.Errorf("get prefs: %w", err)), err
	}
	state := st.BackendState
	same := SameControlURL(prefs.ControlURL, r.opt.ControlURL)
	nodeID := observedNode(st)
	profileID := r.observedProfile(ctx)
	r.seenNode = nodeID
	r.seenProfile = profileID
	r.set(func(s *Snapshot) {
		s.BackendState = state
		s.CurrentControl = prefs.ControlURL
		// Drop route fields from the previous pass. The Running branch sets
		// them again when advertise_routes is configured.
		s.Routes = nil
		s.AdminHint = ""
	})

	if !same {
		return r.stepForeign(ctx, st, prefs, nodeID, profileID)
	}

	switch state {
	case ipn.Running.String():
		r.markRegistered()
		r.recoverSince = time.Time{}
		if snap, err, handled := r.settleIdentity(ctx, st, prefs, profileID); handled {
			return snap, err
		}
		if err := r.clearLoginBackoff(); err != nil {
			return r.fail(fmt.Errorf("clear login backoff: %w", err)), err
		}
		r.needsLoginSince = time.Time{}
		if err := r.reconcileManaged(ctx, prefs); err != nil {
			if errors.Is(err, errOwnershipChanged) {
				return r.guardMutation(ctx, prefs.ControlURL)
			}
			return r.fail(fmt.Errorf("managed prefs: %w", err)), err
		}
		return r.set(func(s *Snapshot) {
			fillSelf(s, st)
			s.LastError = ""
			s.Routes, s.AdminHint, s.Phase = routePhase(r.opt.Hostname, r.opt.AdvertiseRoutes, st)
			if warn, missing := missingNodeTags(r.opt.Role, st); missing {
				s.Phase = PhaseMissingTags
				s.Warnings = append(s.Warnings, warn)
			}
		}), nil
	case ipn.Starting.String():
		if hasNodeIdentity(st) || persistedIdentity(st, prefs) {
			r.markRegistered()
			r.recoverSince = time.Time{}
			return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil
		}
		if r.needsLoginWhileStarting(st, prefs) {
			return r.login(ctx, "starting-without-node", prefs, nodeID, profileID)
		}
		return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil
	case ipn.NeedsMachineAuth.String():
		return r.set(func(s *Snapshot) { s.Phase = PhaseNeedsApprove }), nil
	case ipn.Stopped.String():
		// A credential change while Stopped must enroll, not resume the old
		// node and then enroll again once it is Running.
		if r.shouldReenrollIdentity(nodeID, profileID) {
			return r.login(ctx, "identity-mismatch", prefs, nodeID, profileID)
		}
		if snap, err := r.guardMutation(ctx, prefs.ControlURL); err != nil || snap.Phase != "" {
			return snap, err
		}
		if _, err := r.be.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: true}, WantRunningSet: true}); err != nil {
			return r.fail(fmt.Errorf("resume: %w", err)), err
		}
		return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil
	case ipn.NeedsLogin.String(), ipn.NoState.String():
		if r.recentLogin() {
			return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil
		}
		if persistedIdentity(st, prefs) && !r.persistedLoginDue() {
			r.markRegistered()
			return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil
		}
		return r.login(ctx, "needs-login", prefs, nodeID, profileID)
	default:
		return r.set(func(s *Snapshot) { s.Phase = PhaseUnknown }), nil
	}
}

// observedProfile is the current LocalAPI profile ID in system mode.
// Other modes, and a client that does not expose profiles, return empty.
// A read error leaves the binding's profile alone for this pass.
func (r *Reconciler) observedProfile(ctx context.Context) string {
	if r.opt.Mode != ModeSystem {
		return ""
	}
	cur, _, err := r.be.ProfileStatus(ctx)
	if err != nil {
		return ""
	}
	return string(cur.ID)
}

func observedNode(st *ipnstate.Status) string {
	if st == nil || st.Self == nil {
		return ""
	}
	return string(st.Self.ID)
}

// noteLocalFailure starts the login grace. It covers a CheckPrefs rejection
// (no key minted) and a Start or StartLoginInteractive error after a mint,
// as well as a login call that was accepted but has not reached Running.
// The next attempt waits graceFor(unconverged) instead of minting again.
func (r *Reconciler) noteLocalFailure() {
	r.loginStarted = r.now()
	r.unconverged++
}

// recentLogin reports whether the last login was issued within the current
// grace period and tailscaled should be given time to converge before another
// single-use key is burnt. A persisted NextLoginAt counts too, so a new
// process honours the delay written before the previous key request.
func (r *Reconciler) recentLogin() bool {
	if !r.loginStarted.IsZero() && r.now().Sub(r.loginStarted) < r.graceFor(r.unconverged) {
		return true
	}
	if r.opt.State == nil {
		return false
	}
	next, _ := r.opt.State.LoginBackoff()
	return !next.IsZero() && r.now().Before(next)
}

// armLoginBackoff records the next eligible mint time before a key is
// requested. The file is updated first. Memory moves only after that write
// succeeds, so a crash cannot both forget the delay and already have asked.
func (r *Reconciler) armLoginBackoff() error {
	fails := r.unconverged + 1
	if r.opt.State != nil {
		_, stored := r.opt.State.LoginBackoff()
		if stored+1 > fails {
			fails = stored + 1
		}
	}
	next := r.now().Add(r.graceFor(fails))
	if r.opt.State != nil {
		if err := r.opt.State.SetLoginBackoff(next, fails); err != nil {
			return err
		}
	}
	r.loginStarted = r.now()
	r.unconverged = fails
	return nil
}

// clearLoginBackoff forgets the delay once the node is actually up.
// A failed write keeps the in-memory delay so the next pass retries it
// instead of minting.
func (r *Reconciler) clearLoginBackoff() error {
	if r.opt.State != nil {
		next, n := r.opt.State.LoginBackoff()
		if !next.IsZero() || n != 0 {
			if err := r.opt.State.ClearLoginBackoff(); err != nil {
				return err
			}
		}
	}
	r.loginStarted = time.Time{}
	r.unconverged = 0
	return nil
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

func foreignBlockedMessage(role, url string) string {
	if RequiresSystem(role) {
		return fmt.Sprintf("tailscaled is logged into %s; takeover is disabled. Role %s cannot use embedded mode. Set takeover: true to switch this machine onto the iDoris control server", url, role)
	}
	return fmt.Sprintf("tailscaled is logged into %s; takeover is disabled. Set mode: embedded to run alongside it, or takeover: true to switch this machine", url)
}

func (r *Reconciler) stepForeign(ctx context.Context, st *ipnstate.Status, prefs *ipn.Prefs, nodeID, profileID string) (Snapshot, error) {
	// Ownership first. Switching to a saved iDoris profile, SwitchToEmptyProfile,
	// and login are all mutations of the active profile. A saved profile must
	// not authorise any of them while the active login is foreign.
	if foreignControl(prefs.ControlURL, r.opt.ControlURL, st.BackendState) && !r.opt.Takeover {
		url := strings.TrimSpace(prefs.ControlURL)
		if url == "" {
			url = "an existing tailnet (no control URL reported)"
		}
		return r.set(func(s *Snapshot) {
			s.Phase = PhaseBlocked
			s.LastError = foreignBlockedMessage(r.opt.Role, url)
		}), nil
	}
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
	if r.recentLogin() {
		return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil
	}
	if cur.ID != "" {
		r.previousProfile = cur.ID
	}
	if err := r.be.SwitchToEmptyProfile(ctx); err != nil {
		return r.fail(fmt.Errorf("switch to empty profile: %w", err)), err
	}
	// The empty profile's prefs are the base. The foreign profile's SSH and
	// routes must not be copied onto the iDoris login.
	base, err := r.be.GetPrefs(ctx)
	if err != nil {
		return r.fail(fmt.Errorf("get prefs: %w", err)), err
	}
	return r.login(ctx, "foreign-or-empty-profile", base, nodeID, profileID)
}

// errOwnershipChanged means a re-read of prefs showed a different tailnet
// than the one this pass decided to edit. The mutation was not issued.
var errOwnershipChanged = errors.New("active tailnet changed during reconcile")

// guardMutation re-reads the active prefs immediately before a mutation.
// A zero snapshot and a nil error means the caller may proceed. Any other
// result ends the pass: takeover=false and a foreign URL becomes
// PhaseBlocked, and a changed URL under takeover is left for the next pass.
func (r *Reconciler) guardMutation(ctx context.Context, expectedControl string) (Snapshot, error) {
	prefs, err := r.be.GetPrefs(ctx)
	if err != nil {
		err = fmt.Errorf("re-read prefs: %w", err)
		return r.fail(err), err
	}
	if SameControlURL(prefs.ControlURL, expectedControl) && (r.opt.Takeover || !foreignControl(prefs.ControlURL, r.opt.ControlURL, "")) {
		return Snapshot{}, nil
	}
	if !r.opt.Takeover && foreignControl(prefs.ControlURL, r.opt.ControlURL, "") {
		url := strings.TrimSpace(prefs.ControlURL)
		if url == "" {
			url = "an existing tailnet (no control URL reported)"
		}
		return r.set(func(s *Snapshot) {
			s.Phase = PhaseBlocked
			s.CurrentControl = prefs.ControlURL
			s.LastError = foreignBlockedMessage(r.opt.Role, url)
		}), nil
	}
	return r.set(func(s *Snapshot) {
		s.Phase = PhaseError
		s.CurrentControl = prefs.ControlURL
		s.LastError = "ownership changed during reconcile; not changing preferences"
	}), errOwnershipChanged
}

func (r *Reconciler) login(ctx context.Context, reason string, base *ipn.Prefs, nodeID, profileID string) (Snapshot, error) {
	if r.recentLogin() {
		return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil
	}
	if err := r.refreshIdentity(ctx); err != nil {
		return r.fail(err), err
	}
	// Recognise a credential or node change before the key is minted, on
	// every path that logs in (NeedsLogin, Stopped, Starting, Running).
	// The flag survives until the running node is no longer the one we
	// refused, so reaching Running does not enroll a second time.
	r.beginIdentityTransition(nodeID, profileID)
	r.mu.Lock()
	r.attempts++
	r.mu.Unlock()
	r.set(func(s *Snapshot) { s.Phase = PhaseEnrolling })
	prefs := r.managedPrefs(base)
	if len(r.opt.AdvertiseTags) > 0 {
		r.log.Info("not sending advertise tags; the pre-auth key's acl tags are applied by Headscale")
	}
	// CheckPrefs rejects a prefs set the local client will not apply. Doing
	// it before AuthKey avoids burning a single-use key on a local mistake.
	if err := r.be.CheckPrefs(ctx, prefs); err != nil {
		r.noteLocalFailure()
		return r.fail(fmt.Errorf("check prefs: %w", err)), err
	}
	expected := ""
	if base != nil {
		expected = base.ControlURL
	}
	if snap, err := r.guardMutation(ctx, expected); err != nil || snap.Phase != "" {
		return snap, err
	}
	// Persist the delay before the request. A supervisor that restarts us
	// inside AuthKey must observe the same deadline.
	if err := r.armLoginBackoff(); err != nil {
		return r.fail(fmt.Errorf("persist login backoff: %w", err)), err
	}
	key, err := r.keys.AuthKey(ctx)
	if err != nil {
		return r.fail(fmt.Errorf("obtain auth key: %w", err)), err
	}
	// A key was issued, so the enrollment service answered. Drop the startup
	// degraded flag. Static keys never set it. refreshIdentity may already
	// have cleared it after a successful rediscovery.
	r.mu.Lock()
	r.opt.EnrollUnreachable = false
	r.mu.Unlock()
	if snap, err := r.guardMutation(ctx, expected); err != nil || snap.Phase != "" {
		return snap, err
	}
	r.log.Info("logging tailscaled into iDoris control server", "reason", reason, "control_url", r.opt.ControlURL, "os", runtime.GOOS,
		"unconverged_attempts", r.unconverged, "grace", r.graceFor(r.unconverged))
	if err := r.be.Start(ctx, ipn.Options{AuthKey: key, UpdatePrefs: prefs}); err != nil {
		return r.fail(fmt.Errorf("start: %w", err)), err
	}
	// Start replaced the profile with the prefs we just sent. Compare the
	// login-interactive check against that URL: a switch that lands between
	// the two calls still aborts, and the write we just did does not.
	if snap, err := r.guardMutation(ctx, prefs.ControlURL); err != nil || snap.Phase != "" {
		return snap, err
	}
	// Mirror `tailscale up --auth-key`: Start resets the control client (and any
	// stale browser auth URL); login-interactive then registers with the key and
	// forces a fresh node key, which is also what re-enrollment after expiry needs.
	if err := r.be.StartLoginInteractive(ctx); err != nil {
		return r.fail(fmt.Errorf("login: %w", err)), err
	}
	r.markLoginOK()
	return r.set(func(s *Snapshot) { s.Phase = PhaseStarting; s.LastError = "" }), nil
}

// refreshIdentity rediscovers tenant and role before an enroll that follows
// a degraded start. Without a refresher (static key, tests) it does nothing.
func (r *Reconciler) refreshIdentity(ctx context.Context) error {
	r.mu.Lock()
	need := r.opt.EnrollUnreachable || !r.opt.Identity.Known
	r.mu.Unlock()
	if !need {
		return nil
	}
	ref, ok := r.keys.(IdentityRefresher)
	if !ok {
		return nil
	}
	ident, role, err := ref.RefreshIdentity(ctx)
	if err != nil {
		return fmt.Errorf("rediscover enrollment: %w", err)
	}
	if role != "" && !ValidRole(role) {
		return fmt.Errorf("rediscover role %q: want member, local-ai, gateway, or admin", role)
	}
	if ident.Role == "" {
		ident.Role = role
	}
	r.mu.Lock()
	r.opt.Identity = ident
	if role != "" {
		r.opt.Role = role
	}
	r.opt.EnrollUnreachable = false
	r.mu.Unlock()
	return nil
}

// settleIdentity refuses to call a Running node connected when the configured
// credential, the running node, or (in system mode) the profile is not the
// one the binding file names. The new login uses this same control URL,
// which is allowed. The binding is rewritten only after that login returns
// and the node we see is no longer the one that mismatched. An empty binding
// does not certify a node that was already up; a fresh install that just
// enrolled in this process does, because that login set the transition flag.
// handled is true when the caller should return snap and err as the step result.
func (r *Reconciler) settleIdentity(ctx context.Context, st *ipnstate.Status, prefs *ipn.Prefs, profileID string) (Snapshot, error, bool) {
	nodeID := observedNode(st)
	if r.shouldReenrollIdentity(nodeID, profileID) {
		snap, err := r.login(ctx, "identity-mismatch", prefs, nodeID, profileID)
		return snap, err, true
	}
	awaiting, loginOK := r.identityFlags()
	if awaiting {
		if !loginOK {
			if r.recentLogin() {
				return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil, true
			}
			snap, err := r.login(ctx, "identity-mismatch", prefs, nodeID, profileID)
			return snap, err, true
		}
		mismatchNode, mismatchProfile := r.mismatchIDs()
		stillOld := mismatchNode != "" && nodeID == mismatchNode
		if r.opt.Mode == ModeSystem && mismatchProfile != "" && profileID == mismatchProfile && (mismatchNode == "" || nodeID == mismatchNode) {
			stillOld = true
		}
		if stillOld {
			if r.recentLogin() {
				return r.set(func(s *Snapshot) { s.Phase = PhaseStarting }), nil, true
			}
			snap, err := r.login(ctx, "identity-mismatch", prefs, nodeID, profileID)
			return snap, err, true
		}
		if err := r.writeIdentity(nodeID, profileID); err != nil {
			return r.fail(fmt.Errorf("save identity: %w", err)), err, true
		}
		r.clearIdentityTransition()
		return Snapshot{}, nil, false
	}
	if err := r.writeIdentity(nodeID, profileID); err != nil {
		return r.fail(fmt.Errorf("save identity: %w", err)), err, true
	}
	return Snapshot{}, nil, false
}

func (r *Reconciler) identityFlags() (awaiting, loginOK bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.awaitingIdentity, r.identityLoginOK
}

func (r *Reconciler) mismatchIDs() (nodeID, profileID string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mismatchNode, r.mismatchProfile
}

func (r *Reconciler) markLoginOK() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.awaitingIdentity {
		r.identityLoginOK = true
	}
}

func (r *Reconciler) clearIdentityTransition() {
	r.mu.Lock()
	r.awaitingIdentity = false
	r.identityLoginOK = false
	r.mismatchNode = ""
	r.mismatchProfile = ""
	r.mu.Unlock()
}

// beginIdentityTransition records that this login is replacing the bound
// node. It is a no-op when the binding already matches, so an ordinary
// expiry re-login does not look like an identity change.
func (r *Reconciler) beginIdentityTransition(nodeID, profileID string) {
	if !r.shouldReenrollIdentity(nodeID, profileID) {
		return
	}
	bound := DaemonState{}
	if r.opt.State != nil {
		bound = r.opt.State.Get()
	}
	r.mu.Lock()
	r.awaitingIdentity = true
	r.identityLoginOK = false
	r.mismatchNode = nodeID
	r.mismatchProfile = profileID
	wantTenant, wantRole := r.opt.Identity.Tenant, r.opt.Identity.Role
	r.mu.Unlock()
	r.log.Warn("bound enrollment identity differs from the running node; re-enrolling",
		"bound_tenant", bound.Tenant, "bound_role", bound.Role,
		"bound_node", bound.NodeID, "bound_profile", bound.ProfileID,
		"running_node", nodeID, "running_profile", profileID,
		"want_tenant", wantTenant, "want_role", wantRole)
}

func (r *Reconciler) shouldReenrollIdentity(nodeID, profileID string) bool {
	awaiting, _ := r.identityFlags()
	if awaiting || r.opt.State == nil || !r.boundIdentity().Known {
		return false
	}
	return !r.bindingMatches(nodeID, profileID)
}

// bindingMatches reports whether the stored binding names this credential
// and the node that is actually running. An empty binding matches nothing:
// an already-running node must be enrolled once before it is certified.
// A fingerprint-only change still matches; writeIdentity updates the fingerprint.
func (r *Reconciler) bindingMatches(nodeID, profileID string) bool {
	if r.opt.State == nil {
		return true
	}
	bound := r.opt.State.Get()
	if bound.Tenant == "" && bound.Role == "" && bound.NodeID == "" && bound.ProfileID == "" {
		return false
	}
	ident := r.boundIdentity()
	if bound.Tenant != ident.Tenant || bound.Role != ident.Role {
		return false
	}
	if nodeID != "" && bound.NodeID != "" && bound.NodeID != nodeID {
		return false
	}
	if nodeID != "" && bound.NodeID == "" && !r.nodeBackfill() {
		return false
	}
	if r.opt.Mode == ModeSystem && profileID != "" && bound.ProfileID != "" && bound.ProfileID != profileID {
		return false
	}
	if r.opt.Mode == ModeSystem && profileID != "" && bound.ProfileID == "" && !r.nodeBackfill() {
		return false
	}
	return true
}

func (r *Reconciler) nodeBackfill() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.allowNodeBackfill
}

func (r *Reconciler) boundIdentity() Identity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.opt.Identity
}

func (r *Reconciler) writeIdentity(nodeID, profileID string) error {
	ident := r.boundIdentity()
	if r.opt.State == nil || !ident.Known {
		return nil
	}
	bound := r.opt.State.Get()
	if nodeID == "" {
		nodeID = bound.NodeID
	}
	if profileID == "" {
		profileID = bound.ProfileID
	}
	if r.opt.Mode != ModeSystem {
		// Embedded mode does not pin a profile. Keep the field empty so a
		// later system-mode start cannot inherit an unrelated id.
		profileID = ""
	}
	if err := r.opt.State.SetIdentity(r.opt.ControlURL, ident.Tenant, ident.Role, ident.TokenFingerprint, nodeID, profileID); err != nil {
		return err
	}
	r.mu.Lock()
	r.allowNodeBackfill = true
	r.mu.Unlock()
	return nil
}

// AccessIdentityOK is the gate's view of enrollment. It is false during an
// identity transition that has not finished logging in, and false when the
// binding does not name the node LocalAPI is showing. A degraded start with
// a previously stored binding stays confirmed: discovery did not contradict it.
func (r *Reconciler) AccessIdentityOK(nodeID, profileID string) bool {
	awaiting, loginOK := r.identityFlags()
	if awaiting && !loginOK {
		return false
	}
	if !r.boundIdentity().Known {
		if r.opt.State == nil {
			return true
		}
		b := r.opt.State.Get()
		return b.Tenant != "" || b.Role != "" || b.NodeID != ""
	}
	if r.opt.State == nil {
		return !awaiting
	}
	if awaiting {
		return false
	}
	return r.bindingMatches(nodeID, profileID)
}

// missingNodeTags reports a warning when a tagged role has an empty tag set.
// member and admin are untagged by design. An ACL entry for :22 does not tag
// the node; the enrollment key's acl_tags does.
func missingNodeTags(role string, st *ipnstate.Status) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "local-ai", "gateway":
	default:
		return "", false
	}
	if len(selfTags(st)) > 0 {
		return "", false
	}
	return "role " + role + " expects a non-empty node tag from the enrollment key; the node is online but has no tags, so the Local AI or gateway ACL does not select it", true
}

func selfTags(st *ipnstate.Status) []string {
	if st == nil || st.Self == nil || st.Self.Tags == nil || st.Self.Tags.IsNil() {
		return nil
	}
	return st.Self.Tags.AsSlice()
}

// persistedIdentity reports whether this profile already has a node key.
// That key is what tsnet resumes on process start. A fresh install has none.
//
// LocalAPI GetPrefs strips private keys (ipnlocal.stripKeysFromPrefs in
// tailscale.com v1.104.2), so PublicNodeKeyOK on those prefs is always false.
// Status.HaveNodeKey is computed from the unsanitized profile and is the
// signal a LocalAPI client can see. Prefs are still checked for a backend
// that returns the key in-process.
func persistedIdentity(st *ipnstate.Status, p *ipn.Prefs) bool {
	if st != nil && st.HaveNodeKey {
		return true
	}
	if p == nil || p.Persist == nil {
		return false
	}
	_, ok := p.Persist.PublicNodeKeyOK()
	return ok
}

// persistedLoginDue reports whether a stored node key has stayed logged-out
// long enough to be an expiry rather than tsnet's brief NeedsLogin. The first
// observation only starts the clock.
func (r *Reconciler) persistedLoginDue() bool {
	if r.needsLoginSince.IsZero() {
		r.needsLoginSince = r.now()
		return false
	}
	return !r.now().Before(r.needsLoginSince.Add(persistedLoginSettle))
}

// needsLoginWhileStarting reports whether a Starting backend is the keyless
// login tsnet performs before the node is registered, rather than a login
// this reconciler already issued or a restart of a node that already has an
// identity.
func (r *Reconciler) needsLoginWhileStarting(st *ipnstate.Status, prefs *ipn.Prefs) bool {
	if r.recentLogin() || hasNodeIdentity(st) || persistedIdentity(st, prefs) {
		return false
	}
	if r.opt.LoginWhileStarting {
		return true
	}
	if r.opt.RecoverUnregistered {
		return r.recoverDue()
	}
	return false
}

// hasNodeIdentity is true when LocalAPI shows a node key or a self public
// key. Either one means registration finished, even if the registration
// marker has not been written yet.
func hasNodeIdentity(st *ipnstate.Status) bool {
	if st == nil {
		return false
	}
	if st.HaveNodeKey {
		return true
	}
	return st.Self != nil && !st.Self.PublicKey.IsZero()
}

// recoverDue starts a clock the first time an unregistered state file is
// seen Starting, and reports true once persistedLoginSettle has elapsed.
func (r *Reconciler) recoverDue() bool {
	if r.recoverSince.IsZero() {
		r.recoverSince = r.now()
		return false
	}
	return !r.now().Before(r.recoverSince.Add(persistedLoginSettle))
}

func (r *Reconciler) markRegistered() {
	if r.registered || r.opt.MarkRegistered == nil {
		return
	}
	if err := r.opt.MarkRegistered(); err != nil {
		r.log.Warn("could not record that registration completed", "err", err)
		return
	}
	r.registered = true
}

// managedPrefs starts from the profile's current prefs and overwrites only
// the fields this daemon owns. Start(UpdatePrefs) replaces the whole prefs
// struct, so building a fresh NewPrefs() would clear manually enabled SSH
// and routes. AdvertiseTags is always cleared: Headscale v0.29.6 rejects a
// pre-auth key registration that also requests tags.
func (r *Reconciler) managedPrefs(base *ipn.Prefs) *ipn.Prefs {
	var p ipn.Prefs
	if base != nil {
		if c := base.Clone(); c != nil {
			p = *c
		}
	} else {
		p = *ipn.NewPrefs()
	}
	p.AdvertiseTags = nil
	p.ControlURL = r.opt.ControlURL
	p.WantRunning = true
	p.LoggedOut = false
	p.CorpDNS = r.opt.AcceptDNS
	p.RouteAll = r.opt.AcceptRoutes
	if h := strings.TrimSpace(r.opt.Hostname); h != "" {
		p.Hostname = h
	}
	if len(r.opt.AdvertiseRoutes) > 0 {
		p.AdvertiseRoutes = append([]netip.Prefix(nil), r.opt.AdvertiseRoutes...)
	}
	if r.opt.RunSSH != nil {
		p.RunSSH = *r.opt.RunSSH
	}
	return &p
}

// reconcileManaged pushes managed fields that have drifted while the node is
// already Running. Unset ssh and an empty advertise_routes list are not
// managed, so a manual `tailscale set --ssh` or a manual route survives.
func (r *Reconciler) reconcileManaged(ctx context.Context, prefs *ipn.Prefs) error {
	if prefs == nil {
		return nil
	}
	mp := &ipn.MaskedPrefs{}
	if prefs.RouteAll != r.opt.AcceptRoutes {
		mp.RouteAll = r.opt.AcceptRoutes
		mp.RouteAllSet = true
	}
	if prefs.CorpDNS != r.opt.AcceptDNS {
		mp.CorpDNS = r.opt.AcceptDNS
		mp.CorpDNSSet = true
	}
	if h := strings.TrimSpace(r.opt.Hostname); h != "" && prefs.Hostname != h {
		mp.Hostname = h
		mp.HostnameSet = true
	}
	if r.opt.RunSSH != nil && prefs.RunSSH != *r.opt.RunSSH {
		mp.RunSSH = *r.opt.RunSSH
		mp.RunSSHSet = true
	}
	if len(r.opt.AdvertiseRoutes) > 0 && !sameRoutes(prefs.AdvertiseRoutes, r.opt.AdvertiseRoutes) {
		mp.AdvertiseRoutes = append([]netip.Prefix(nil), r.opt.AdvertiseRoutes...)
		mp.AdvertiseRoutesSet = true
	}
	if !mp.RouteAllSet && !mp.CorpDNSSet && !mp.HostnameSet && !mp.RunSSHSet && !mp.AdvertiseRoutesSet {
		return nil
	}
	snap, err := r.guardMutation(ctx, prefs.ControlURL)
	if err != nil {
		return err
	}
	if snap.Phase != "" {
		return errOwnershipChanged
	}
	r.log.Info("updating managed preferences")
	_, err = r.be.EditPrefs(ctx, mp)
	return err
}

func sameRoutes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]netip.Prefix(nil), a...)
	bb := append([]netip.Prefix(nil), b...)
	slices.SortFunc(aa, func(x, y netip.Prefix) int { return strings.Compare(x.String(), y.String()) })
	slices.SortFunc(bb, func(x, y netip.Prefix) int { return strings.Compare(x.String(), y.String()) })
	return slices.Equal(aa, bb)
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
