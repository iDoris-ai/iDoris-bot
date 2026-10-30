package vpnd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

// r5cDiscovery fails the first fails calls, then returns ident.
type r5cDiscovery struct {
	fails int
	calls int
	ident Identity
	role  string
}

func (d *r5cDiscovery) RefreshIdentity(context.Context) (Identity, string, error) {
	d.calls++
	if d.calls <= d.fails {
		return Identity{}, "", errors.New("discovery down")
	}
	return d.ident, d.role, nil
}

func (d *r5cDiscovery) AuthKey(context.Context) (string, error) {
	return "", errors.New("r5c: discovery recovery must not mint")
}

// TestR5CPendingLoginBindsTargetCredential is C#1. An embedded member starts
// enrolling with credential X and the pending login is saved. The operator
// replaces the credential with Y and starts a new process on the same state
// file. The node X's login produced must not be certified as Y.
func TestR5CPendingLoginBindsTargetCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpnd-state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	fpX := TokenFingerprint("credential-x")
	fpY := TokenFingerprint("credential-y")
	if fpX == "" || fpX == fpY {
		t.Fatalf("fingerprints x=%q y=%q", fpX, fpY)
	}
	oldKey := key.NewNode().Public()
	newKey := key.NewNode().Public()
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-x", PublicKey: oldKey},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Mode = ModeEmbedded
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: fpX, Known: true}
	})
	ctx := context.Background()
	snap, err := r.Step(ctx)
	if err != nil || snap.Phase == PhaseConnected || keys.n != 1 {
		t.Fatalf("X enroll: %+v keys=%d err=%v", snap, keys.n, err)
	}
	pending, ok := st.Pending()
	if !ok || !pending.LoginOK || pending.NodeID != "node-x" || pending.NodeKey != oldKey.String() {
		t.Fatalf("pending %+v ok=%v", pending, ok)
	}
	if pending.TokenFingerprint != fpX || pending.Tenant != "acme" || pending.Role != "member" ||
		pending.ControlURL != ours || pending.Mode != ModeEmbedded {
		t.Fatalf("pending target %+v", pending)
	}
	if st.Get().TokenFingerprint != "" || st.Get().NodeID != "" {
		t.Fatalf("binding written before certification: %+v", st.Get())
	}

	// Second process. Y is a different credential. X's login has rotated the
	// node key; that rotation is not evidence for Y.
	st2, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	be2 := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-x", PublicKey: newKey},
	}
	keys2 := &countingKeys{}
	r2 := newR(t, be2, keys2, func(o *Options) {
		o.State = st2
		o.Mode = ModeEmbedded
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: fpY, Known: true}
	})
	snap, err = r2.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := st2.Get()
	if got.TokenFingerprint == fpY || (got.NodeID == "node-x" && got.TokenFingerprint != "") {
		t.Fatalf("Y was certified onto X's node: %+v", got)
	}
	if r2.AccessIdentityOK("node-x", "") {
		t.Fatal("access opened for X's node under Y")
	}
	if snap.Phase == PhaseConnected && keys2.n == 0 {
		t.Fatalf("rotation certified without a login for Y: %+v binding %+v", snap, got)
	}
}

// TestR5CPendingLoginModeAndProfile is the system-mode half of C#1.
// A pending login records the profile it returned under. Resuming it in the
// other backend mode, or on a different profile after the key has rotated,
// must not certify that node.
func TestR5CPendingLoginModeAndProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpnd-state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	fp := TokenFingerprint("credential-x")
	oldKey := key.NewNode().Public()
	newKey := key.NewNode().Public()
	be := &fakeBackend{
		state:   ipn.Running,
		prefs:   ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:    &ipnstate.PeerStatus{ID: "node-x", PublicKey: oldKey},
		current: ipn.LoginProfile{ID: "p-x", ControlURL: ours},
	}
	r := newR(t, be, &countingKeys{}, func(o *Options) {
		o.State = st
		o.Mode = ModeSystem
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: fp, Known: true}
	})
	if _, err := r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending, ok := st.Pending()
	if !ok || pending.Mode != ModeSystem || pending.ProfileID != "p-x" || pending.TokenFingerprint != fp {
		t.Fatalf("pending %+v ok=%v", pending, ok)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	modePath := filepath.Join(t.TempDir(), "mode.json")
	profilePath := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(modePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	st2, err := OpenState(modePath)
	if err != nil {
		t.Fatal(err)
	}
	be2 := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-x", PublicKey: newKey},
	}
	r2 := newR(t, be2, &countingKeys{}, func(o *Options) {
		o.State = st2
		o.Mode = ModeEmbedded
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: fp, Known: true}
	})
	if _, err := r2.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st2.Get().NodeID == "node-x" || r2.AccessIdentityOK("node-x", "") {
		t.Fatalf("embedded resume certified the system login: %+v", st2.Get())
	}

	st3, err := OpenState(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	be3 := &fakeBackend{
		state:   ipn.Running,
		prefs:   ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:    &ipnstate.PeerStatus{ID: "node-x", PublicKey: newKey},
		current: ipn.LoginProfile{ID: "p-other", ControlURL: ours},
	}
	r3 := newR(t, be3, &countingKeys{}, func(o *Options) {
		o.State = st3
		o.Mode = ModeSystem
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: fp, Known: true}
	})
	snap, err := r3.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st3.Get().NodeID == "node-x" || st3.Get().ProfileID == "p-other" || r3.AccessIdentityOK("node-x", "p-other") {
		t.Fatalf("other profile certified: binding %+v snap %+v", st3.Get(), snap)
	}
}

// TestR5CDiscoveryRetryKeepsPending is C#4. The first enrollment saves a
// pending login and the process restarts before the binding is committed.
// Discovery is down, so the resumed node must not drop that pending record.
// Later passes retry discovery, and access stays closed until the binding
// is actually written.
func TestR5CDiscoveryRetryKeepsPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpnd-state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	fp := TokenFingerprint("credential-x")
	ident := Identity{Tenant: "acme", Role: "member", TokenFingerprint: fp, Known: true}
	oldKey := key.NewNode().Public()
	newKey := key.NewNode().Public()
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-x", PublicKey: oldKey},
	}
	if _, err := newR(t, be, &countingKeys{}, func(o *Options) {
		o.State = st
		o.Mode = ModeEmbedded
		o.Role = "member"
		o.Identity = ident
	}).Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pending, ok := st.Pending(); !ok || !pending.LoginOK {
		t.Fatalf("pending %+v ok=%v", pending, ok)
	}
	if st.Get().NodeID != "" {
		t.Fatalf("binding committed before restart: %+v", st.Get())
	}

	st2, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	be2 := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-x", PublicKey: newKey},
	}
	disc := &r5cDiscovery{fails: 2, ident: ident, role: "member"}
	r2 := newR(t, be2, disc, func(o *Options) {
		o.State = st2
		o.Mode = ModeEmbedded
		o.Role = "member"
		o.EnrollUnreachable = true
		o.Identity = Identity{TokenFingerprint: fp, Known: false}
	})
	now := time.Now()
	r2.now = func() time.Time { return now }
	ctx := context.Background()

	snap, err := r2.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if disc.calls != 1 {
		t.Fatalf("discovery calls %d", disc.calls)
	}
	if pending, ok := st2.Pending(); !ok || !pending.LoginOK {
		t.Fatalf("pending dropped while discovery is down: %+v ok=%v snap %+v", pending, ok, snap)
	}
	if st2.Get().NodeID != "" || st2.Get().Tenant != "" {
		t.Fatalf("binding written without discovery: %+v", st2.Get())
	}
	if r2.AccessIdentityOK("node-x", "") {
		t.Fatal("access opened before the binding was persisted")
	}

	snap, err = r2.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if disc.calls != 1 {
		t.Fatalf("discovery retried before the interval: calls %d snap %+v", disc.calls, snap)
	}
	if _, ok := st2.Pending(); !ok {
		t.Fatal("pending dropped on the rate-limited pass")
	}

	now = now.Add(discoveryRetryInterval)
	snap, err = r2.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if disc.calls != 2 {
		t.Fatalf("discovery calls %d, want the recovery attempt; snap %+v", disc.calls, snap)
	}
	if _, ok := st2.Pending(); !ok {
		t.Fatal("pending dropped before discovery recovered")
	}
	if r2.AccessIdentityOK("node-x", "") {
		t.Fatal("access opened on the second failure")
	}

	now = now.Add(discoveryRetryInterval)
	snap, err = r2.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected {
		t.Fatalf("recovery: %+v err=%v", snap, err)
	}
	got := st2.Get()
	if got.Tenant != "acme" || got.Role != "member" || got.TokenFingerprint != fp || got.NodeID != "node-x" {
		t.Fatalf("binding %+v", got)
	}
	if _, ok := st2.Pending(); ok {
		t.Fatalf("pending left after the binding was saved: %+v", got)
	}
	if !r2.AccessIdentityOK("node-x", "") {
		t.Fatal("access stayed closed after discovery persisted the binding")
	}
}
