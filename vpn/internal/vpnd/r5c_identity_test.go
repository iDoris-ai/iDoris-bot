package vpnd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

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
