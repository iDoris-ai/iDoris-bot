package vpnd

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

const ours = "https://vpn.idoris.example"

// fakeBackend is a scripted tailscaled.
type fakeBackend struct {
	state     ipn.State
	prefs     ipn.Prefs
	profiles  []ipn.LoginProfile
	current   ipn.LoginProfile
	statusErr error

	calls []string
	// starts records auth keys passed to Start.
	starts []string
	// pendingKey is the auth key handed to Start, consumed by StartLoginInteractive.
	pendingKey string
}

func (f *fakeBackend) rec(s string) { f.calls = append(f.calls, s) }

func (f *fakeBackend) Status(context.Context) (*ipnstate.Status, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	st := &ipnstate.Status{BackendState: f.state.String(), Peer: map[key.NodePublic]*ipnstate.PeerStatus{}}
	if f.state == ipn.Running {
		st.TailscaleIPs = []netip.Addr{netip.MustParseAddr("100.64.0.7")}
		exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
		st.Self = &ipnstate.PeerStatus{DNSName: "mbp.acme.idoris.internal.", KeyExpiry: &exp}
		st.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{Online: true}
		st.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{Online: false}
	}
	return st, nil
}
func (f *fakeBackend) GetPrefs(context.Context) (*ipn.Prefs, error) { p := f.prefs; return &p, nil }
func (f *fakeBackend) EditPrefs(_ context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	f.rec("EditPrefs")
	if mp.WantRunningSet {
		f.prefs.WantRunning = mp.WantRunning
		if mp.WantRunning && f.state == ipn.Stopped {
			f.state = ipn.Starting
		}
	}
	p := f.prefs
	return &p, nil
}
func (f *fakeBackend) CheckPrefs(context.Context, *ipn.Prefs) error { f.rec("CheckPrefs"); return nil }
func (f *fakeBackend) ProfileStatus(context.Context) (ipn.LoginProfile, []ipn.LoginProfile, error) {
	f.rec("ProfileStatus")
	return f.current, f.profiles, nil
}
func (f *fakeBackend) SwitchProfile(_ context.Context, id ipn.ProfileID) error {
	f.rec("SwitchProfile:" + string(id))
	for _, p := range f.profiles {
		if p.ID == id {
			f.current = p
			f.prefs.ControlURL = p.ControlURL
			f.state = ipn.Starting
			return nil
		}
	}
	return errors.New("no such profile")
}
func (f *fakeBackend) SwitchToEmptyProfile(context.Context) error {
	f.rec("SwitchToEmptyProfile")
	f.current = ipn.LoginProfile{}
	f.prefs = ipn.Prefs{}
	f.state = ipn.NeedsLogin
	return nil
}
func (f *fakeBackend) Start(_ context.Context, o ipn.Options) error {
	f.rec("Start")
	f.starts = append(f.starts, o.AuthKey)
	f.prefs = *o.UpdatePrefs
	f.pendingKey = o.AuthKey
	// Real tailscaled: Start without an existing node key stays in NeedsLogin
	// until someone calls login-interactive.
	f.state = ipn.NeedsLogin
	return nil
}
func (f *fakeBackend) StartLoginInteractive(context.Context) error {
	f.rec("StartLoginInteractive")
	if f.pendingKey != "" {
		f.state = ipn.Starting
		f.pendingKey = ""
	}
	return nil
}

type countingKeys struct {
	n   int
	err error
}

func (c *countingKeys) AuthKey(context.Context) (string, error) {
	c.n++
	if c.err != nil {
		return "", c.err
	}
	return "key-" + string(rune('0'+c.n)), nil
}

func newR(t *testing.T, be Backend, keys KeySource, mut func(*Options)) *Reconciler {
	t.Helper()
	opt := Options{ControlURL: ours, AcceptDNS: true, Takeover: true}
	if mut != nil {
		mut(&opt)
	}
	r, err := New(be, keys, opt, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNewRejectsSaaSControlURL(t *testing.T) {
	_, err := New(&fakeBackend{}, StaticKey("k"), Options{ControlURL: "https://controlplane.tailscale.com"}, nil)
	if err == nil {
		t.Fatal("expected refusal of Tailscale SaaS control URL")
	}
	if _, err := New(&fakeBackend{}, StaticKey("k"), Options{}, nil); err == nil {
		t.Fatal("expected error for empty control URL")
	}
}

func TestFreshMachineEnrollsAndConverges(t *testing.T) {
	be := &fakeBackend{state: ipn.NeedsLogin}
	keys := &countingKeys{}
	r := newR(t, be, keys, nil)

	snap, err := r.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Phase != PhaseStarting || keys.n != 1 || len(be.starts) != 1 || be.starts[0] != "key-1" {
		t.Fatalf("after first step: %+v keys=%d starts=%v", snap, keys.n, be.starts)
	}
	if be.state != ipn.Starting {
		t.Fatalf("tailscaled never started logging in (state %v); login-interactive missing?", be.state)
	}
	if be.prefs.ControlURL != ours || !be.prefs.WantRunning || !be.prefs.CorpDNS {
		t.Fatalf("prefs not applied: %+v", be.prefs)
	}
	// tailscaled is still converging: must not burn a second key.
	snap, _ = r.Step(context.Background())
	if snap.Phase != PhaseStarting || keys.n != 1 {
		t.Fatalf("second step burnt a key: %+v keys=%d", snap, keys.n)
	}
	be.state = ipn.Running
	snap, _ = r.Step(context.Background())
	if snap.Phase != PhaseConnected || len(snap.TailnetIPs) != 1 || snap.PeersOnline != 1 || snap.SelfName == "" || snap.KeyExpiry.IsZero() {
		t.Fatalf("not connected: %+v", snap)
	}
	if snap.Attempts != 1 {
		t.Fatalf("attempts %d", snap.Attempts)
	}
}

func TestExpiredKeyReenrollsAfterGrace(t *testing.T) {
	be := &fakeBackend{state: ipn.Running, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true}}
	keys := &countingKeys{}
	r := newR(t, be, keys, nil)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }

	if s, _ := r.Step(context.Background()); s.Phase != PhaseConnected || keys.n != 0 {
		t.Fatalf("healthy node must not enroll: %+v", s)
	}
	// Headscale expired the node: tailscaled drops to NeedsLogin.
	be.state = ipn.NeedsLogin
	if s, _ := r.Step(context.Background()); s.Phase != PhaseStarting || keys.n != 1 {
		t.Fatalf("expected re-enroll: %+v keys=%d", s, keys.n)
	}
	// Headscale rejected the key (e.g. already used): tailscaled falls back to NeedsLogin.
	be.state = ipn.NeedsLogin
	// 5s later: within grace, no new key.
	now = now.Add(5 * time.Second)
	if s, _ := r.Step(context.Background()); keys.n != 1 || s.Phase != PhaseStarting {
		t.Fatalf("grace violated: %+v keys=%d", s, keys.n)
	}
	// 30s later still NeedsLogin: key was probably rejected; try again with a new one.
	now = now.Add(30 * time.Second)
	if s, _ := r.Step(context.Background()); keys.n != 2 || len(be.starts) != 2 {
		t.Fatalf("expected second attempt: %+v keys=%d", s, keys.n)
	}
}

// TestPersistentLoginFailureBacksOff models an outage where every login ends
// back in NeedsLogin (control unreachable, TLS trust broken, ...). Keys are
// single-use, so the grace must grow instead of minting one every 20s forever.
func TestPersistentLoginFailureBacksOff(t *testing.T) {
	be := &fakeBackend{state: ipn.Running, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true}}
	keys := &countingKeys{}
	r := newR(t, be, keys, nil)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	ctx := context.Background()

	if s, _ := r.Step(ctx); s.Phase != PhaseConnected {
		t.Fatalf("not connected: %+v", s)
	}
	// Healthy -> NeedsLogin: the first re-enroll is immediate.
	be.state = ipn.NeedsLogin
	if _, err := r.Step(ctx); err != nil || keys.n != 1 {
		t.Fatalf("first re-enroll must be immediate: keys=%d err=%v", keys.n, err)
	}

	// Each attempt falls straight back to NeedsLogin (login never converges).
	// Attempt k must wait min(20s<<(k-1), 10m) before attempt k+1 is allowed.
	graces := []time.Duration{20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 320 * time.Second, 10 * time.Minute, 10 * time.Minute}
	for i, grace := range graces {
		attempt := i + 1
		if keys.n != attempt {
			t.Fatalf("attempt %d: keys=%d", attempt, keys.n)
		}
		be.state = ipn.NeedsLogin
		now = now.Add(grace - time.Second)
		if s, _ := r.Step(ctx); keys.n != attempt || s.Phase != PhaseStarting {
			t.Fatalf("attempt %d: minted a key 1s before the %v grace expired: keys=%d %+v", attempt, grace, keys.n, s)
		}
		now = now.Add(time.Second)
		if s, err := r.Step(ctx); err != nil || keys.n != attempt+1 || s.Attempts != attempt+1 {
			t.Fatalf("attempt %d: expected a new key after %v: keys=%d %+v err=%v", attempt, grace, keys.n, s, err)
		}
	}
}

// TestLoginGraceResetsOnceRunning: a node that reached Running is healthy
// again, so a later drop to NeedsLogin must re-enroll immediately instead of
// inheriting the stretched grace left over from earlier failures.
func TestLoginGraceResetsOnceRunning(t *testing.T) {
	be := &fakeBackend{state: ipn.NeedsLogin}
	keys := &countingKeys{}
	r := newR(t, be, keys, nil)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	ctx := context.Background()

	// Two failed attempts: the grace in force is now 40s.
	_, _ = r.Step(ctx)
	be.state = ipn.NeedsLogin
	now = now.Add(21 * time.Second)
	_, _ = r.Step(ctx)
	if keys.n != 2 || r.graceFor(r.unconverged) != 40*time.Second {
		t.Fatalf("setup: keys=%d unconverged=%d", keys.n, r.unconverged)
	}
	// Third attempt converges.
	be.state = ipn.Running
	if s, _ := r.Step(ctx); s.Phase != PhaseConnected || r.unconverged != 0 {
		t.Fatalf("expected connected and reset: %+v unconverged=%d", s, r.unconverged)
	}
	// Expiry a second later: immediate re-enroll, and the grace restarts at 20s.
	now = now.Add(time.Second)
	be.state = ipn.NeedsLogin
	if _, err := r.Step(ctx); err != nil || keys.n != 3 {
		t.Fatalf("re-enroll after a healthy period must be immediate: keys=%d err=%v", keys.n, err)
	}
	be.state = ipn.NeedsLogin
	now = now.Add(21 * time.Second)
	if _, err := r.Step(ctx); err != nil || keys.n != 4 {
		t.Fatalf("grace should have restarted at 20s: keys=%d err=%v", keys.n, err)
	}
}

func TestGraceForIsCapped(t *testing.T) {
	r := newR(t, &fakeBackend{}, StaticKey("k"), nil)
	for n, want := range map[int]time.Duration{
		-1: 0, 0: 0,
		1: 20 * time.Second, 2: 40 * time.Second, 3: 80 * time.Second,
		5: 320 * time.Second, 6: 10 * time.Minute, 1000: 10 * time.Minute,
	} {
		if got := r.graceFor(n); got != want {
			t.Errorf("graceFor(%d)=%v want %v", n, got, want)
		}
	}
}

func TestForeignTailnetTakeoverRemembersPreviousProfile(t *testing.T) {
	be := &fakeBackend{
		state:    ipn.Running,
		prefs:    ipn.Prefs{ControlURL: "https://controlplane.tailscale.com", WantRunning: true},
		current:  ipn.LoginProfile{ID: "p-saas", ControlURL: "https://controlplane.tailscale.com"},
		profiles: []ipn.LoginProfile{{ID: "p-saas", ControlURL: "https://controlplane.tailscale.com"}},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, nil)
	snap, err := r.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Phase != PhaseStarting || snap.PreviousProfile != "p-saas" {
		t.Fatalf("takeover: %+v", snap)
	}
	want := []string{"ProfileStatus", "SwitchToEmptyProfile", "CheckPrefs", "Start", "StartLoginInteractive"}
	if len(be.calls) != len(want) {
		t.Fatalf("calls %v", be.calls)
	}
	for i := range want {
		if be.calls[i] != want[i] {
			t.Fatalf("calls %v, want %v", be.calls, want)
		}
	}
}

func TestForeignTailnetBlockedWithoutTakeover(t *testing.T) {
	be := &fakeBackend{
		state:   ipn.Running,
		prefs:   ipn.Prefs{ControlURL: "https://controlplane.tailscale.com", WantRunning: true},
		current: ipn.LoginProfile{ID: "p-saas", ControlURL: "https://controlplane.tailscale.com"},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) { o.Takeover = false })
	snap, err := r.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Phase != PhaseBlocked || keys.n != 0 || len(be.starts) != 0 {
		t.Fatalf("expected blocked: %+v", snap)
	}
}

func TestExistingProfileIsSwitchedNotReenrolled(t *testing.T) {
	be := &fakeBackend{
		state:   ipn.Running,
		prefs:   ipn.Prefs{ControlURL: "https://controlplane.tailscale.com", WantRunning: true},
		current: ipn.LoginProfile{ID: "p-saas", ControlURL: "https://controlplane.tailscale.com"},
		profiles: []ipn.LoginProfile{
			{ID: "p-saas", ControlURL: "https://controlplane.tailscale.com"},
			{ID: "p-idoris", ControlURL: ours + "/"},
		},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, nil)
	snap, _ := r.Step(context.Background())
	if snap.Phase != PhaseSwitching || keys.n != 0 {
		t.Fatalf("expected profile switch: %+v keys=%d", snap, keys.n)
	}
	if be.calls[len(be.calls)-1] != "SwitchProfile:p-idoris" {
		t.Fatalf("calls %v", be.calls)
	}
	be.state = ipn.Running
	if s, _ := r.Step(context.Background()); s.Phase != PhaseConnected {
		t.Fatalf("after switch: %+v", s)
	}
}

func TestStoppedIsResumed(t *testing.T) {
	be := &fakeBackend{state: ipn.Stopped, prefs: ipn.Prefs{ControlURL: ours}}
	r := newR(t, be, &countingKeys{}, nil)
	snap, _ := r.Step(context.Background())
	if snap.Phase != PhaseStarting || be.calls[0] != "EditPrefs" || !be.prefs.WantRunning {
		t.Fatalf("resume: %+v calls=%v", snap, be.calls)
	}
}

func TestUnreachableDaemonAndKeyFailure(t *testing.T) {
	be := &fakeBackend{statusErr: errors.New("dial unix: no such file")}
	r := newR(t, be, &countingKeys{}, nil)
	snap, err := r.Step(context.Background())
	if err == nil || snap.Phase != PhaseError || snap.LastError == "" {
		t.Fatalf("expected error phase: %+v %v", snap, err)
	}
	be2 := &fakeBackend{state: ipn.NeedsLogin}
	r2 := newR(t, be2, &countingKeys{err: errors.New("enroll 401")}, nil)
	snap, err = r2.Step(context.Background())
	if err == nil || snap.Phase != PhaseError || len(be2.starts) != 0 {
		t.Fatalf("expected enroll failure: %+v %v", snap, err)
	}
}

func TestBackoffIsBoundedAndJittered(t *testing.T) {
	r := newR(t, &fakeBackend{}, StaticKey("k"), func(o *Options) { o.MaxBackoff = 30 * time.Second })
	for i := 1; i < 12; i++ {
		d := r.backoff(i)
		if d < time.Second || d > 36*time.Second {
			t.Fatalf("backoff(%d)=%v out of bounds", i, d)
		}
	}
}

func TestNormalizeControlURL(t *testing.T) {
	cases := map[string]string{
		"https://VPN.Example.org/":    "https://vpn.example.org",
		"https://vpn.example.org:443": "https://vpn.example.org",
		"http://h:80/x/":              "http://h/x",
		"":                            "",
	}
	for in, want := range cases {
		if got := NormalizeControlURL(in); got != want {
			t.Errorf("Normalize(%q)=%q want %q", in, got, want)
		}
	}
	if !SameControlURL("https://controlplane.tailscale.com", "https://login.tailscale.com") {
		t.Error("tailscale synonyms must compare equal")
	}
	if SameControlURL(ours, "https://controlplane.tailscale.com") {
		t.Error("ours must differ from SaaS")
	}
}

func TestParseListen(t *testing.T) {
	if n, a, err := ParseListen("unix:/tmp/x.sock"); err != nil || n != "unix" || a != "/tmp/x.sock" {
		t.Fatalf("%v %v %v", n, a, err)
	}
	if _, _, err := ParseListen("tcp:0.0.0.0:7845"); err == nil {
		t.Fatal("non-loopback tcp must be rejected")
	}
	if n, a, err := ParseListen("tcp:127.0.0.1:7845"); err != nil || n != "tcp" || a != "127.0.0.1:7845" {
		t.Fatalf("%v %v %v", n, a, err)
	}
	if _, _, err := ParseListen("foo"); err == nil {
		t.Fatal("expected error")
	}
}
