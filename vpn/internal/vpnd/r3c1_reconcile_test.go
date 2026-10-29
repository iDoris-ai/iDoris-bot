package vpnd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

// r3c1FlipKey changes the backend's control URL inside AuthKey, while the
// reconciler is blocked on the enrollment call and has already decided the
// tailnet is ours.
type r3c1FlipKey struct {
	be *fakeBackend
	n  int
}

func (k *r3c1FlipKey) AuthKey(context.Context) (string, error) {
	k.n++
	k.be.prefs.ControlURL = "https://foreign.example"
	return "hskey-r3c1", nil
}

type r3c1RefreshKeys struct {
	order []string
	err   error
	auth  int
}

func (k *r3c1RefreshKeys) RefreshIdentity(context.Context) (Identity, string, error) {
	k.order = append(k.order, "refresh")
	if k.err != nil {
		return Identity{}, "", k.err
	}
	return Identity{Tenant: "acme", Role: "local-ai", TokenFingerprint: "fp", Known: true}, "local-ai", nil
}

func (k *r3c1RefreshKeys) AuthKey(context.Context) (string, error) {
	k.auth++
	k.order = append(k.order, "auth")
	return "hskey-r3c1", nil
}

func TestR3C1IdentityFollowsRunningNode(t *testing.T) {
	st := r3c1Open(t)
	if err := st.SetIdentity(ours, "acme", "member", "fp", "node-member", "p-member"); err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		state:   ipn.Running,
		prefs:   ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:    &ipnstate.PeerStatus{ID: "node-admin"},
		current: ipn.LoginProfile{ID: "p-admin", ControlURL: ours},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Mode = ModeSystem
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: "fp", Known: true}
	})
	ctx := context.Background()
	snap, err := r.Step(ctx)
	if err != nil || snap.Phase == PhaseConnected || keys.n != 1 {
		t.Fatalf("profile switch on the same control URL must re-enroll: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if got := st.Get(); got.NodeID != "node-member" || got.ProfileID != "p-member" {
		t.Fatalf("binding certified the admin node: %+v", got)
	}
	be.state = ipn.Running
	be.prefs.ControlURL = ours
	snap, err = r.Step(ctx)
	if err != nil || snap.Phase == PhaseConnected || keys.n != 1 {
		t.Fatalf("still the old node: %+v keys=%d err=%v", snap, keys.n, err)
	}
	be.self = &ipnstate.PeerStatus{ID: "node-member-2"}
	be.current = ipn.LoginProfile{ID: "p-member-2", ControlURL: ours}
	be.state = ipn.Running
	be.prefs.ControlURL = ours
	snap, err = r.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected || keys.n != 1 {
		t.Fatalf("converged node: %+v keys=%d err=%v", snap, keys.n, err)
	}
	got := st.Get()
	if got.NodeID != "node-member-2" || got.ProfileID != "p-member-2" || got.Role != "member" {
		t.Fatalf("binding %+v", got)
	}
}

func TestR3C1EmptyBindingDoesNotCertifyRunningNode(t *testing.T) {
	st := r3c1Open(t)
	be := &fakeBackend{
		state:   ipn.Running,
		prefs:   ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:    &ipnstate.PeerStatus{ID: "node-old"},
		current: ipn.LoginProfile{ID: "p-old", ControlURL: ours},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Mode = ModeSystem
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: "fp", Known: true}
	})
	ctx := context.Background()
	snap, err := r.Step(ctx)
	if err != nil || snap.Phase == PhaseConnected || keys.n != 1 {
		t.Fatalf("empty binding certified a running node: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if st.Get().NodeID != "" || st.Get().Tenant != "" {
		t.Fatalf("wrote the binding before enrollment converged: %+v", st.Get())
	}
	be.self = &ipnstate.PeerStatus{ID: "node-new"}
	be.current = ipn.LoginProfile{ID: "p-new", ControlURL: ours}
	be.state = ipn.Running
	be.prefs.ControlURL = ours
	snap, err = r.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected || keys.n != 1 {
		t.Fatalf("after the confirming enroll: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if st.Get().NodeID != "node-new" || st.Get().ProfileID != "p-new" {
		t.Fatalf("binding %+v", st.Get())
	}
}

func TestR3C1FreshEnrollBindsWithoutSecondKey(t *testing.T) {
	st := r3c1Open(t)
	be := &fakeBackend{state: ipn.NeedsLogin, prefs: ipn.Prefs{ControlURL: ours}}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Mode = ModeSystem
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: "fp", Known: true}
	})
	ctx := context.Background()
	if _, err := r.Step(ctx); err != nil || keys.n != 1 {
		t.Fatalf("fresh install keys=%d err=%v", keys.n, err)
	}
	be.state = ipn.Running
	be.prefs.ControlURL = ours
	be.self = &ipnstate.PeerStatus{ID: "node-fresh"}
	be.current = ipn.LoginProfile{ID: "p-fresh", ControlURL: ours}
	snap, err := r.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected || keys.n != 1 {
		t.Fatalf("second enroll of a node this process just registered: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if st.Get().NodeID != "node-fresh" || st.Get().ProfileID != "p-fresh" {
		t.Fatalf("binding %+v", st.Get())
	}
}

func TestR3C1NeedsLoginIdentityMintsOnce(t *testing.T) {
	st := r3c1Open(t)
	if err := st.SetIdentity(ours, "acme", "admin", "old", "node-a", ""); err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{state: ipn.NeedsLogin, prefs: ipn.Prefs{ControlURL: ours}}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: "new", Known: true}
	})
	ctx := context.Background()
	snap, err := r.Step(ctx)
	if err != nil || keys.n != 1 || snap.Phase == PhaseConnected {
		t.Fatalf("needs-login transition: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if st.Get().Role != "admin" {
		t.Fatalf("binding rewritten before Running: %+v", st.Get())
	}
	be.state = ipn.Running
	be.prefs.ControlURL = ours
	be.self = &ipnstate.PeerStatus{ID: "node-b"}
	snap, err = r.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected || keys.n != 1 {
		t.Fatalf("second enroll after NeedsLogin already minted: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if st.Get().Role != "member" || st.Get().NodeID != "node-b" {
		t.Fatalf("binding %+v", st.Get())
	}
}

func TestR3C1LoginBackoffSurvivesNewReconciler(t *testing.T) {
	path := t.TempDir() + "/vpnd-state.json"
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	be := &fakeBackend{state: ipn.NeedsLogin, prefs: ipn.Prefs{ControlURL: ours}}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) { o.State = st })
	r.now = func() time.Time { return t0 }
	if _, err := r.Step(context.Background()); err != nil || keys.n != 1 {
		t.Fatalf("fresh node must be allowed one immediate attempt: keys=%d err=%v", keys.n, err)
	}
	next, fails := st.LoginBackoff()
	if fails != 1 || !next.Equal(t0.Add(loginGrace)) {
		t.Fatalf("persisted backoff next=%s fails=%d", next, fails)
	}

	st2, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	be2 := &fakeBackend{state: ipn.NeedsLogin, prefs: ipn.Prefs{ControlURL: ours}}
	keys2 := &countingKeys{}
	r2 := newR(t, be2, keys2, func(o *Options) { o.State = st2 })
	r2.now = func() time.Time { return t0.Add(time.Second) }
	snap, err := r2.Step(context.Background())
	if err != nil || keys2.n != 0 || snap.Phase == PhaseConnected {
		t.Fatalf("restart inside the backoff minted again: %+v keys=%d err=%v", snap, keys2.n, err)
	}
	for _, c := range be2.calls {
		if c == "Start" || c == "StartLoginInteractive" {
			t.Fatalf("restart issued a login: %v", be2.calls)
		}
	}

	r2.now = func() time.Time { return t0.Add(loginGrace) }
	if _, err := r2.Step(context.Background()); err != nil || keys2.n != 1 {
		t.Fatalf("backoff elapsed: keys=%d err=%v", keys2.n, err)
	}
}

func TestR3C1TakeoverFalseAbortsWhenControlFlipsDuringAuthKey(t *testing.T) {
	be := &fakeBackend{
		state: ipn.NeedsLogin,
		prefs: ipn.Prefs{ControlURL: ours, RunSSH: true, WantRunning: true},
	}
	keys := &r3c1FlipKey{be: be}
	r := newR(t, be, keys, func(o *Options) { o.Takeover = false })
	snap, err := r.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if keys.n != 1 {
		t.Fatalf("auth calls %d", keys.n)
	}
	for _, c := range be.calls {
		if c == "Start" || c == "EditPrefs" || c == "StartLoginInteractive" {
			t.Fatalf("issued %s after the control URL flipped: %v", c, be.calls)
		}
	}
	if snap.Phase != PhaseBlocked {
		t.Fatalf("phase %s err %q", snap.Phase, snap.LastError)
	}
	if !be.prefs.RunSSH || be.prefs.ControlURL == ours {
		t.Fatalf("prefs were rewritten: %+v", be.prefs)
	}
}

func TestR3C1ReconcilerBumpsOwnershipOnControlChange(t *testing.T) {
	be := &fakeBackend{state: ipn.Running, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true}}
	r := newR(t, be, &countingKeys{}, func(o *Options) { o.Takeover = false })
	owner := NewLiveOwner(LiveOwnerConfig{
		Backend:    be,
		Mode:       ModeSystem,
		OurControl: ours,
		Snapshot:   r.Snapshot,
		Identity:   func(string, string) bool { return true },
	})
	r.SetOwner(owner)
	if _, err := r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := owner.Generation()
	if first == 0 {
		t.Fatal("first pass did not bump ownership")
	}
	be.prefs.ControlURL = "https://foreign.example"
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseBlocked {
		t.Fatalf("%+v err=%v", snap, err)
	}
	if owner.Generation() <= first {
		t.Fatalf("control change left generation at %d", owner.Generation())
	}
}

type r3c1SecondPrefs struct {
	fakeBackend
	reads int
}

func (b *r3c1SecondPrefs) GetPrefs(ctx context.Context) (*ipn.Prefs, error) {
	b.reads++
	if b.reads >= 2 {
		b.prefs.ControlURL = "https://foreign.example"
	}
	return b.fakeBackend.GetPrefs(ctx)
}

func TestR3C1RouteEditAbortedWhenControlFlips(t *testing.T) {
	be := &r3c1SecondPrefs{fakeBackend: fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true, RouteAll: false},
	}}
	r := newR(t, be, &countingKeys{}, func(o *Options) {
		o.Takeover = false
		o.AcceptRoutes = true
	})
	snap, err := r.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range be.calls {
		if c == "EditPrefs" || c == "Start" {
			t.Fatalf("edited after the control URL flipped: %v", be.calls)
		}
	}
	if snap.Phase == PhaseConnected || be.prefs.RouteAll {
		t.Fatalf("applied routes on the foreign tailnet: phase %s prefs %+v", snap.Phase, be.prefs)
	}
}

func TestR3C1RediscoverBeforeEnrollAfterDegradedStart(t *testing.T) {
	be := &fakeBackend{state: ipn.NeedsLogin, prefs: ipn.Prefs{ControlURL: ours}}
	keys := &r3c1RefreshKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.Role = "member"
		o.EnrollUnreachable = true
		o.Identity = Identity{Known: false}
	})
	snap, err := r.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(keys.order, ",") != "refresh,auth" {
		t.Fatalf("order %v", keys.order)
	}
	if r.opt.Role != "local-ai" || !r.opt.Identity.Known || r.opt.EnrollUnreachable {
		t.Fatalf("role %q known %v unreachable %v", r.opt.Role, r.opt.Identity.Known, r.opt.EnrollUnreachable)
	}
	if snap.Role != "local-ai" {
		t.Fatalf("snapshot role %q", snap.Role)
	}

	bad := &r3c1RefreshKeys{err: errors.New("discover down")}
	be2 := &fakeBackend{state: ipn.NeedsLogin, prefs: ipn.Prefs{ControlURL: ours}}
	r2 := newR(t, be2, bad, func(o *Options) {
		o.EnrollUnreachable = true
		o.Identity = Identity{Known: false}
	})
	if _, err := r2.Step(context.Background()); err == nil || bad.auth != 0 {
		t.Fatalf("minted without rediscovery: auth=%d err=%v", bad.auth, err)
	}
}

func r3c1Open(t *testing.T) *StateFile {
	t.Helper()
	st, err := OpenState(t.TempDir() + "/vpnd-state.json")
	if err != nil {
		t.Fatal(err)
	}
	return st
}
