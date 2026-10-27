package vpnd

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
	"tailscale.com/types/views"
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
	// self, when set, is copied onto Status.Self (overrides the Running fixture).
	self *ipnstate.PeerStatus
	// haveNodeKey is copied onto Status.HaveNodeKey. LocalAPI reports this
	// even after it strips the private key from GetPrefs.
	haveNodeKey bool
}

func (f *fakeBackend) rec(s string) { f.calls = append(f.calls, s) }

func (f *fakeBackend) Status(context.Context) (*ipnstate.Status, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	st := &ipnstate.Status{BackendState: f.state.String(), HaveNodeKey: f.haveNodeKey, Peer: map[key.NodePublic]*ipnstate.PeerStatus{}}
	if f.state == ipn.Running {
		st.TailscaleIPs = []netip.Addr{netip.MustParseAddr("100.64.0.7")}
		exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
		st.Self = &ipnstate.PeerStatus{DNSName: "mbp.acme.idoris.internal.", KeyExpiry: &exp}
		st.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{Online: true}
		st.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{Online: false}
	}
	if f.self != nil {
		st.Self = f.self
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
	if mp.AdvertiseRoutesSet {
		f.prefs.AdvertiseRoutes = append([]netip.Prefix(nil), mp.AdvertiseRoutes...)
	}
	if mp.RouteAllSet {
		f.prefs.RouteAll = mp.RouteAll
	}
	if mp.CorpDNSSet {
		f.prefs.CorpDNS = mp.CorpDNS
	}
	if mp.HostnameSet {
		f.prefs.Hostname = mp.Hostname
	}
	if mp.RunSSHSet {
		f.prefs.RunSSH = mp.RunSSH
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
	if !strings.Contains(snap.LastError, "mode: embedded") {
		t.Fatalf("blocked message should point at mode: embedded: %q", snap.LastError)
	}
}

func TestServiceRoleForeignBlockDoesNotSuggestEmbedded(t *testing.T) {
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: "https://controlplane.tailscale.com", WantRunning: true},
	}
	r := newR(t, be, &countingKeys{}, func(o *Options) {
		o.Takeover = false
		o.Role = "local-ai"
	})
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseBlocked || snap.Role != "local-ai" {
		t.Fatalf("%+v err=%v", snap, err)
	}
	if strings.Contains(snap.LastError, "Set mode: embedded") {
		t.Fatalf("must not suggest embedded: %s", snap.LastError)
	}
	if !strings.Contains(snap.LastError, "takeover: true") || !strings.Contains(snap.LastError, "local-ai") {
		t.Fatalf("message: %s", snap.LastError)
	}
	for _, c := range be.calls {
		if c == "ProfileStatus" || strings.HasPrefix(c, "Switch") || c == "Start" {
			t.Fatalf("mutated profile: %v", be.calls)
		}
	}
}

func TestServiceRoleUnreachableWaits(t *testing.T) {
	be := &fakeBackend{statusErr: errors.New("dial unix: no such file")}
	r := newR(t, be, &countingKeys{}, func(o *Options) { o.Role = "gateway" })
	snap, err := r.Step(context.Background())
	if err == nil || snap.Phase != PhaseWaitingTailscaled || len(snap.Warnings) == 0 {
		t.Fatalf("%+v err=%v", snap, err)
	}
	if !strings.Contains(snap.LastError, "gateway") || strings.Contains(snap.LastError, "mode: embedded") {
		t.Fatalf("message: %s", snap.LastError)
	}
}

func TestForeignStatesBlockedBeforeProfileMutation(t *testing.T) {
	foreign := "https://controlplane.tailscale.com"
	cases := []struct {
		name    string
		state   ipn.State
		control string
		blocked bool
	}{
		{name: "running", state: ipn.Running, control: foreign, blocked: true},
		{name: "starting", state: ipn.Starting, control: foreign, blocked: true},
		{name: "stopped", state: ipn.Stopped, control: foreign, blocked: true},
		{name: "needs login with foreign url", state: ipn.NeedsLogin, control: foreign, blocked: true},
		{name: "running empty url", state: ipn.Running, control: "", blocked: true},
		{name: "needs login empty url may use saved profile", state: ipn.NeedsLogin, control: "", blocked: false},
		{name: "no state empty url", state: ipn.NoState, control: "", blocked: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := &fakeBackend{
				state: tc.state,
				prefs: ipn.Prefs{ControlURL: tc.control, WantRunning: true, RunSSH: true},
				current: ipn.LoginProfile{ID: "p-foreign", ControlURL: tc.control},
				profiles: []ipn.LoginProfile{
					{ID: "p-foreign", ControlURL: tc.control},
					{ID: "p-idoris", ControlURL: ours + "/"},
				},
			}
			keys := &countingKeys{}
			r := newR(t, be, keys, func(o *Options) { o.Takeover = false })
			snap, err := r.Step(context.Background())
			if tc.blocked {
				if err != nil || snap.Phase != PhaseBlocked || keys.n != 0 {
					t.Fatalf("blocked: %+v err=%v keys=%d", snap, err, keys.n)
				}
				for _, c := range be.calls {
					if c == "ProfileStatus" || strings.HasPrefix(c, "Switch") || c == "Start" || c == "CheckPrefs" || c == "StartLoginInteractive" {
						t.Fatalf("mutated or inspected profiles before the takeover refusal: %v", be.calls)
					}
				}
				if be.prefs.ControlURL != tc.control || !be.prefs.RunSSH || be.current.ID != "p-foreign" {
					t.Fatalf("foreign profile changed: prefs=%+v current=%+v", be.prefs, be.current)
				}
				return
			}
			if err != nil || snap.Phase == PhaseBlocked || keys.n != 0 {
				t.Fatalf("fresh profile should switch to the saved iDoris profile without a key: %+v err=%v keys=%d calls=%v", snap, err, keys.n, be.calls)
			}
			if be.current.ID != "p-idoris" {
				t.Fatalf("current profile %q calls %v", be.current.ID, be.calls)
			}
		})
	}
}

func TestIdentityMismatchReenrollsOnSameControlURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpnd-state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentity(ours, "acme", "admin", "old"); err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{state: ipn.Running, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true}}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: "new", Known: true}
	})
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase == PhaseConnected || keys.n != 1 {
		t.Fatalf("admin binding with a member token must re-enroll: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if st.Get().Role != "admin" {
		t.Fatalf("binding rewritten before login completed: %+v", st.Get())
	}
	be.state = ipn.Running
	be.prefs.ControlURL = ours
	snap, err = r.Step(context.Background())
	if err != nil || snap.Phase != PhaseConnected || keys.n != 1 {
		t.Fatalf("after re-enroll: %+v keys=%d err=%v", snap, keys.n, err)
	}
	got := st.Get()
	if got.Tenant != "acme" || got.Role != "member" || got.TokenFingerprint != "new" {
		t.Fatalf("binding %+v", got)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "idv1_") {
		t.Fatalf("token leaked into %s", path)
	}
}

func TestSameControlDifferentTenantReenrolls(t *testing.T) {
	st, err := OpenState(filepath.Join(t.TempDir(), "vpnd-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentity(ours, "acme", "local-ai", "fp"); err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{state: ipn.Running, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true}}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Role = "local-ai"
		o.Identity = Identity{Tenant: "other", Role: "local-ai", TokenFingerprint: "fp2", Known: true}
	})
	if _, err := r.Step(context.Background()); err != nil || keys.n != 1 {
		t.Fatalf("keys=%d err=%v", keys.n, err)
	}
	tags := views.SliceOf([]string{"tag:other-local-ai"})
	be.state = ipn.Running
	be.prefs.ControlURL = ours
	be.self = &ipnstate.PeerStatus{Tags: &tags}
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseConnected || st.Get().Tenant != "other" {
		t.Fatalf("snap %+v binding %+v err=%v", snap, st.Get(), err)
	}
}

func TestTaggedRoleWithoutTagsIsNotConnected(t *testing.T) {
	be := &fakeBackend{state: ipn.Running, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true}}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) { o.Role = "local-ai" })
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseMissingTags || keys.n != 0 || len(snap.Warnings) == 0 {
		t.Fatalf("untagged local-ai must not look connected: %+v keys=%d err=%v", snap, keys.n, err)
	}
	tags := views.SliceOf([]string{"tag:acme-local-ai"})
	be.self = &ipnstate.PeerStatus{Tags: &tags}
	snap, err = r.Step(context.Background())
	if err != nil || snap.Phase != PhaseConnected || keys.n != 0 {
		t.Fatalf("tagged: %+v keys=%d err=%v", snap, keys.n, err)
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

func TestEnrollDownResumesSavedIdentityWithoutMinting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpnd-state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentity(ours, "acme", "member", "fp"); err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{state: ipn.Running, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true}}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Role = "member"
		o.EnrollUnreachable = true
		o.Identity = Identity{Known: false}
	})
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseConnected || keys.n != 0 || snap.EnrollReachable {
		t.Fatalf("resume: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if len(snap.Warnings) != 1 || snap.Warnings[0] != EnrollUnreachableWarning {
		t.Fatalf("warnings %+v", snap.Warnings)
	}
	if got := st.Get(); got.Tenant != "acme" || got.Role != "member" || got.TokenFingerprint != "fp" {
		t.Fatalf("binding changed: %+v", got)
	}
}

func TestEnrollDownMintsOnlyWhenLoginIsRequired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpnd-state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentity(ours, "acme", "local-ai", "fp"); err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{state: ipn.NeedsLogin, prefs: ipn.Prefs{ControlURL: ours}}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Role = "local-ai"
		o.EnrollUnreachable = true
		o.Identity = Identity{Known: false}
	})
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseStarting || keys.n != 1 || !snap.EnrollReachable {
		t.Fatalf("login required: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if got := st.Get(); got.Role != "local-ai" || got.Tenant != "acme" {
		t.Fatalf("binding rewritten without a confirmed identity: %+v", got)
	}
}

func TestSnapshotCopiesSlices(t *testing.T) {
	be := &fakeBackend{state: ipn.Running, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true}}
	r := newR(t, be, &countingKeys{}, func(o *Options) {
		o.EnrollUnreachable = true
		o.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
		o.Hostname = "mbp"
	})
	if _, err := r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap := r.Snapshot()
	if len(snap.TailnetIPs) == 0 || len(snap.Warnings) == 0 || len(snap.Routes) == 0 {
		t.Fatalf("expected copied fields: %+v", snap)
	}
	snap.TailnetIPs[0] = "mutated"
	snap.Warnings[0] = "mutated"
	snap.Routes[0].CIDR = "mutated"
	again := r.Snapshot()
	if again.TailnetIPs[0] == "mutated" || again.Warnings[0] == "mutated" || again.Routes[0].CIDR == "mutated" {
		t.Fatalf("snapshot shares backing arrays: %+v", again)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if _, err := r.Step(ctx); err != nil {
				t.Errorf("step: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			got := r.Snapshot()
			if len(got.TailnetIPs) > 0 {
				got.TailnetIPs[0] = "race"
			}
			if len(got.Warnings) > 0 {
				got.Warnings[0] = "race"
			}
			if len(got.Routes) > 0 {
				got.Routes[0].CIDR = "race"
			}
			_ = got.Forwards
		}
	}()
	wg.Wait()
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

func TestLoginDoesNotSendAdvertiseTags(t *testing.T) {
	want := []netip.Prefix{netip.MustParsePrefix("10.251.73.10/32")}
	be := &fakeBackend{state: ipn.NeedsLogin}
	r := newR(t, be, &countingKeys{}, func(o *Options) {
		o.AdvertiseRoutes = want
		o.AdvertiseTags = []string{"tag:acme-gateway"}
	})
	if _, err := r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(be.prefs.AdvertiseTags) != 0 {
		t.Fatalf("login prefs sent tags %v; Headscale v0.29.6 rejects that on a pre-auth key", be.prefs.AdvertiseTags)
	}
	if !sameRoutes(be.prefs.AdvertiseRoutes, want) {
		t.Fatalf("routes %+v", be.prefs.AdvertiseRoutes)
	}
}

func TestReenrollPreservesUnmanagedSSHAndRoutes(t *testing.T) {
	manual := []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}
	be := &fakeBackend{
		state: ipn.NeedsLogin,
		prefs: ipn.Prefs{
			ControlURL:      ours,
			WantRunning:     true,
			CorpDNS:         true,
			RunSSH:          true,
			Hostname:        "manual-host",
			AdvertiseRoutes: append([]netip.Prefix(nil), manual...),
		},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, nil)
	if _, err := r.Step(context.Background()); err != nil || keys.n != 1 {
		t.Fatalf("keys=%d err=%v", keys.n, err)
	}
	if !be.prefs.RunSSH || be.prefs.Hostname != "manual-host" || !sameRoutes(be.prefs.AdvertiseRoutes, manual) {
		t.Fatalf("unmanaged prefs lost: %+v", be.prefs)
	}
	if len(be.prefs.AdvertiseTags) != 0 || be.prefs.ControlURL != ours || !be.prefs.WantRunning || !be.prefs.CorpDNS {
		t.Fatalf("managed prefs: %+v", be.prefs)
	}
}

func TestManagedDriftAppliesWithoutReenroll(t *testing.T) {
	ssh := true
	be := &fakeBackend{state: ipn.Running, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true}}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.AcceptRoutes = true
		o.RunSSH = &ssh
		o.Hostname = "office-gw"
	})
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseConnected || keys.n != 0 {
		t.Fatalf("drift must not mint: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if !be.prefs.RouteAll || !be.prefs.RunSSH || be.prefs.Hostname != "office-gw" {
		t.Fatalf("managed fields not applied: %+v", be.prefs)
	}
	be.calls = nil
	if _, err := r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range be.calls {
		if c == "EditPrefs" || c == "Start" {
			t.Fatalf("second pass mutated: %v", be.calls)
		}
	}
}

func TestLoginAdvertisesRoutes(t *testing.T) {
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.1.0/24")}
	be := &fakeBackend{state: ipn.NeedsLogin}
	r := newR(t, be, &countingKeys{}, func(o *Options) { o.AdvertiseRoutes = want })
	if _, err := r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !sameRoutes(be.prefs.AdvertiseRoutes, want) {
		t.Fatalf("login prefs routes %+v", be.prefs.AdvertiseRoutes)
	}
}

func TestAdvertisedRoutesReconcileDrift(t *testing.T) {
	want := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	be := &fakeBackend{state: ipn.Running, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true}}
	r := newR(t, be, &countingKeys{}, func(o *Options) { o.AdvertiseRoutes = want })
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseRoutesPending || be.state != ipn.Running {
		t.Fatalf("unapproved routes stay connected: %+v state %v %v", snap, be.state, err)
	}
	if !sameRoutes(be.prefs.AdvertiseRoutes, want) {
		t.Fatalf("routes %+v", be.prefs.AdvertiseRoutes)
	}
	if snap.AdminHint == "" || len(snap.Routes) != 1 || snap.Routes[0].Approved || snap.LastError != "" {
		t.Fatalf("pending report: %+v", snap)
	}
	be.calls = nil
	if _, err := r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range be.calls {
		if c == "EditPrefs" {
			t.Fatal("second pass edited unchanged routes")
		}
	}
}

func TestHaveNodeKeyWaitsOutBriefNeedsLogin(t *testing.T) {
	// LocalAPI shape: private key stripped from prefs, HaveNodeKey still set.
	be := &fakeBackend{
		state:       ipn.NeedsLogin,
		haveNodeKey: true,
		prefs:       ipn.Prefs{ControlURL: ours, Persist: &persist.Persist{}},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, nil)
	now := time.Now()
	r.now = func() time.Time { return now }

	snap, err := r.Step(context.Background())
	if err != nil || keys.n != 0 || snap.Phase != PhaseStarting {
		t.Fatalf("HaveNodeKey NeedsLogin must not mint: %+v keys=%d err=%v", snap, keys.n, err)
	}
	now = now.Add(persistedLoginSettle)
	snap, err = r.Step(context.Background())
	if err != nil || keys.n != 1 || snap.Phase != PhaseStarting {
		t.Fatalf("HaveNodeKey that outlasts the settle window must mint: %+v keys=%d err=%v", snap, keys.n, err)
	}
}

func TestPersistedNodeKeyWaitsOutBriefNeedsLogin(t *testing.T) {
	be := &fakeBackend{
		state: ipn.NeedsLogin,
		prefs: ipn.Prefs{
			ControlURL: ours,
			Persist:    &persist.Persist{PrivateNodeKey: key.NewNode()},
		},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, nil)
	now := time.Now()
	r.now = func() time.Time { return now }

	snap, err := r.Step(context.Background())
	if err != nil || keys.n != 0 || snap.Phase != PhaseStarting {
		t.Fatalf("brief NeedsLogin must not mint: %+v keys=%d err=%v", snap, keys.n, err)
	}
	now = now.Add(persistedLoginSettle - time.Second)
	if _, err := r.Step(context.Background()); err != nil || keys.n != 0 {
		t.Fatalf("still inside the settle window: keys=%d err=%v", keys.n, err)
	}

	be.state = ipn.Running
	snap, err = r.Step(context.Background())
	if err != nil || keys.n != 0 || snap.Phase != PhaseConnected {
		t.Fatalf("resume should reach Running with no key: %+v keys=%d err=%v", snap, keys.n, err)
	}

	be.state = ipn.NeedsLogin
	now = now.Add(time.Second)
	if _, err := r.Step(context.Background()); err != nil || keys.n != 0 {
		t.Fatalf("a new NeedsLogin after Running starts the clock over: keys=%d err=%v", keys.n, err)
	}
	now = now.Add(persistedLoginSettle)
	snap, err = r.Step(context.Background())
	if err != nil || keys.n != 1 || snap.Phase != PhaseStarting {
		t.Fatalf("NeedsLogin that outlasts the settle window must mint: %+v keys=%d err=%v", snap, keys.n, err)
	}
}

func TestStartingWithoutLoginFlagDoesNotMint(t *testing.T) {
	be := &fakeBackend{state: ipn.Starting, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true}}
	keys := &countingKeys{}
	r := newR(t, be, keys, nil)
	snap, err := r.Step(context.Background())
	if err != nil || keys.n != 0 || snap.Phase != PhaseStarting {
		t.Fatalf("Starting without LoginWhileStarting must not mint: %+v keys=%d err=%v", snap, keys.n, err)
	}
}

func TestLoginWhileStartingMintsOnceUntilRunning(t *testing.T) {
	be := &fakeBackend{state: ipn.Starting, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true}}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) { o.LoginWhileStarting = true })
	if _, err := r.Step(context.Background()); err != nil || keys.n != 1 {
		t.Fatalf("fresh Starting must login once: keys=%d err=%v", keys.n, err)
	}
	if _, err := r.Step(context.Background()); err != nil || keys.n != 1 {
		t.Fatalf("grace must hold: keys=%d err=%v", keys.n, err)
	}

	identified := &fakeBackend{
		state: ipn.Starting,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true},
		self:  &ipnstate.PeerStatus{PublicKey: key.NewNode().Public()},
	}
	keys2 := &countingKeys{}
	r2 := newR(t, identified, keys2, func(o *Options) { o.LoginWhileStarting = true })
	snap, err := r2.Step(context.Background())
	if err != nil || keys2.n != 0 || snap.Phase != PhaseStarting {
		t.Fatalf("a Starting node that already has an identity must not mint: %+v keys=%d err=%v", snap, keys2.n, err)
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

func prefixSlice(cidrs ...string) *views.Slice[netip.Prefix] {
	ps := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		ps = append(ps, netip.MustParsePrefix(c))
	}
	s := views.SliceOf(ps)
	return &s
}

func TestRouteApprovalState(t *testing.T) {
	want := []netip.Prefix{netip.MustParsePrefix("10.251.73.10/32")}
	cases := []struct {
		name     string
		self     *ipnstate.PeerStatus
		approved bool
	}{
		{name: "primary exact", self: &ipnstate.PeerStatus{PrimaryRoutes: prefixSlice("10.251.73.10/32")}, approved: true},
		{name: "allowed parent", self: &ipnstate.PeerStatus{AllowedIPs: prefixSlice("10.251.73.0/24")}, approved: true},
		{name: "tailnet address does not approve", self: &ipnstate.PeerStatus{AllowedIPs: prefixSlice("100.64.0.7/32")}, approved: false},
		{name: "narrower does not cover a subnet", self: &ipnstate.PeerStatus{PrimaryRoutes: prefixSlice("10.251.73.10/32")}, approved: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routes := want
			if tc.name == "narrower does not cover a subnet" {
				routes = []netip.Prefix{netip.MustParsePrefix("10.251.73.0/24")}
			}
			be := &fakeBackend{
				state: ipn.Running,
				prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, AdvertiseRoutes: append([]netip.Prefix(nil), routes...)},
				self:  tc.self,
			}
			r := newR(t, be, &countingKeys{}, func(o *Options) {
				o.AdvertiseRoutes = routes
				o.Hostname = "office-gw"
			})
			snap, err := r.Step(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if be.state != ipn.Running || snap.LastError != "" {
				t.Fatalf("node must stay up: state %v %+v", be.state, snap)
			}
			if len(snap.Routes) != 1 || !snap.Routes[0].Advertised || snap.Routes[0].Approved != tc.approved {
				t.Fatalf("routes %+v", snap.Routes)
			}
			if tc.approved {
				if snap.Phase != PhaseConnected || snap.AdminHint != "" {
					t.Fatalf("approved: %+v", snap)
				}
				return
			}
			if snap.Phase != PhaseRoutesPending || !strings.Contains(snap.AdminHint, "office-gw") || !strings.Contains(snap.AdminHint, snap.Routes[0].CIDR) {
				t.Fatalf("pending: %+v", snap)
			}
		})
	}

	// Approval arriving on a later pass clears the waiting phase.
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, AdvertiseRoutes: want},
		self:  &ipnstate.PeerStatus{AllowedIPs: prefixSlice("100.64.0.8/32")},
	}
	r := newR(t, be, &countingKeys{}, func(o *Options) {
		o.AdvertiseRoutes = want
		o.Hostname = "office-gw"
	})
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseRoutesPending {
		t.Fatalf("before: %+v %v", snap, err)
	}
	be.self = &ipnstate.PeerStatus{PrimaryRoutes: prefixSlice("10.251.73.10/32")}
	snap, err = r.Step(context.Background())
	if err != nil || snap.Phase != PhaseConnected || snap.AdminHint != "" || !snap.Routes[0].Approved {
		t.Fatalf("after approval: %+v %v", snap, err)
	}
}

func TestNoRoutesOmitsRouteStatus(t *testing.T) {
	be := &fakeBackend{state: ipn.Running, prefs: ipn.Prefs{ControlURL: ours, WantRunning: true}}
	r := newR(t, be, &countingKeys{}, nil)
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseConnected || snap.Routes != nil || snap.AdminHint != "" {
		t.Fatalf("%+v %v", snap, err)
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
