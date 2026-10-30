package vpnd

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

// TestR4CSameNodeReauthCertifiesOnce is the real Headscale property: a
// re-authentication keeps the stable node ID and rotates the node public
// key. Certifying only when the ID changes never finishes, and each backoff
// mints another key. One mint, then a restarted reconciler must not mint
// again, and the new key on the same ID completes the binding.
func TestR4CSameNodeReauthCertifiesOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpnd-state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentity(ours, "acme", "member", "fp", "node-1", ""); err != nil {
		t.Fatal(err)
	}
	oldKey := key.NewNode().Public()
	newKey := key.NewNode().Public()
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-1", PublicKey: oldKey},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Role = "admin"
		o.Identity = Identity{Tenant: "acme", Role: "admin", TokenFingerprint: "fp2", Known: true}
	})
	ctx := context.Background()
	snap, err := r.Step(ctx)
	if err != nil || snap.Phase == PhaseConnected || keys.n != 1 {
		t.Fatalf("role change must mint once and not certify the old key: %+v keys=%d err=%v", snap, keys.n, err)
	}
	pending, ok := st.Pending()
	if !ok || !pending.LoginOK || pending.NodeID != "node-1" || pending.NodeKey != oldKey.String() {
		t.Fatalf("pending %+v ok=%v", pending, ok)
	}
	if st.Get().Role != "member" {
		t.Fatalf("binding rewritten before the new key: %+v", st.Get())
	}

	st2, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	be2 := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-1", PublicKey: oldKey},
	}
	keys2 := &countingKeys{}
	r2 := newR(t, be2, keys2, func(o *Options) {
		o.State = st2
		o.Role = "admin"
		o.Identity = Identity{Tenant: "acme", Role: "admin", TokenFingerprint: "fp2", Known: true}
	})
	snap, err = r2.Step(ctx)
	if err != nil || keys2.n != 0 || snap.Phase == PhaseConnected {
		t.Fatalf("restart minted again while the old key was still up: %+v keys=%d err=%v", snap, keys2.n, err)
	}
	be2.self = &ipnstate.PeerStatus{ID: "node-1", PublicKey: newKey}
	be2.state = ipn.Running
	be2.prefs.ControlURL = ours
	snap, err = r2.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected || keys2.n != 0 {
		t.Fatalf("same node id, new key: %+v keys=%d err=%v", snap, keys2.n, err)
	}
	got := st2.Get()
	if got.Role != "admin" || got.NodeID != "node-1" || got.TokenFingerprint != "fp2" {
		t.Fatalf("binding %+v", got)
	}
	if _, still := st2.Pending(); still {
		t.Fatalf("pending left after certify: %+v", st2.Get())
	}
	if !r2.AccessIdentityOK("node-1", "") {
		t.Fatal("certified binding did not open access")
	}
}

// TestR4CForeignProfileAfterLoginIsNotCertified is C#3: a profile that
// appears after StartLoginInteractive is not the enrollment, even if that
// profile's node key later changes.
func TestR4CForeignProfileAfterLoginIsNotCertified(t *testing.T) {
	st, err := OpenState(filepath.Join(t.TempDir(), "vpnd-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentity(ours, "acme", "member", "fp", "node-member", "p-member"); err != nil {
		t.Fatal(err)
	}
	oldKey := key.NewNode().Public()
	newKey := key.NewNode().Public()
	be := &fakeBackend{
		state:   ipn.Running,
		prefs:   ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:    &ipnstate.PeerStatus{ID: "node-admin", PublicKey: oldKey},
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
	if snap, err := r.Step(ctx); err != nil || snap.Phase == PhaseConnected || keys.n != 1 {
		t.Fatalf("first login: %+v keys=%d err=%v", snap, keys.n, err)
	}
	be.current = ipn.LoginProfile{ID: "p-other", ControlURL: ours}
	be.state = ipn.Running
	be.prefs.ControlURL = ours
	snap, err := r.Step(ctx)
	if err != nil || snap.Phase == PhaseConnected || keys.n != 1 {
		t.Fatalf("profile switch certified or minted: %+v keys=%d err=%v", snap, keys.n, err)
	}
	be.self = &ipnstate.PeerStatus{ID: "node-admin", PublicKey: newKey}
	be.state = ipn.Running
	be.prefs.ControlURL = ours
	snap, err = r.Step(ctx)
	if err != nil || snap.Phase == PhaseConnected || keys.n != 1 {
		t.Fatalf("key rotation on the other profile: %+v keys=%d err=%v", snap, keys.n, err)
	}
	got := st.Get()
	if got.NodeID != "node-member" || got.ProfileID != "p-member" || got.Role != "member" {
		t.Fatalf("binding %+v", got)
	}
	if r.AccessIdentityOK("node-admin", "p-other") {
		t.Fatal("access opened for the unrelated profile")
	}
	pending, ok := st.Pending()
	if !ok || pending.LoginOK || pending.ProfileID != "p-other" {
		t.Fatalf("transition was not restarted: %+v ok=%v", pending, ok)
	}
}

// TestR4CEmptyIDBindingCertifiesOnce fills node IDs that an older dev build
// left empty, without minting, and does it only once.
func TestR4CEmptyIDBindingCertifiesOnce(t *testing.T) {
	st, err := OpenState(filepath.Join(t.TempDir(), "vpnd-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentity(ours, "acme", "member", "fp", "", ""); err != nil {
		t.Fatal(err)
	}
	k := key.NewNode().Public()
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-1", PublicKey: k},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: "fp", Known: true}
	})
	ctx := context.Background()
	snap, err := r.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected || keys.n != 0 {
		t.Fatalf("empty ids minted or stayed closed: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if st.Get().NodeID != "node-1" || st.Get().Role != "member" {
		t.Fatalf("binding %+v", st.Get())
	}
	snap, err = r.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected || keys.n != 0 {
		t.Fatalf("second pass: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if !r.AccessIdentityOK("node-1", "") {
		t.Fatal("backfilled binding did not open access")
	}
}

func TestR4CMismatchedFingerprintStaysUnconfirmed(t *testing.T) {
	st, err := OpenState(filepath.Join(t.TempDir(), "vpnd-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentity(ours, "acme", "member", "fp-old", "node-1", ""); err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-1"},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Role = "member"
		o.EnrollUnreachable = true
		o.Identity = Identity{TokenFingerprint: "fp-new", Known: false}
	})
	snap, err := r.Step(context.Background())
	if err != nil || keys.n != 0 {
		t.Fatalf("fingerprint mismatch minted: %+v keys=%d err=%v", snap, keys.n, err)
	}
	if r.AccessIdentityOK("node-1", "") {
		t.Fatal("access opened without a confirmed identity")
	}
	if !strings.Contains(snap.LastError, "not confirmed") {
		t.Fatalf("status %q warnings %v", snap.LastError, snap.Warnings)
	}
	found := false
	for _, w := range snap.Warnings {
		if w == IdentityUnconfirmedWarning {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings %v", snap.Warnings)
	}
	if st.Get().TokenFingerprint != "fp-old" || st.Get().NodeID != "node-1" {
		t.Fatalf("binding changed: %+v", st.Get())
	}
}

func TestR4CSameFingerprintDifferentNodeStaysUnconfirmed(t *testing.T) {
	st, err := OpenState(filepath.Join(t.TempDir(), "vpnd-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentity(ours, "acme", "member", "fp", "node-1", "p-1"); err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		state:   ipn.Running,
		prefs:   ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:    &ipnstate.PeerStatus{ID: "node-2"},
		current: ipn.LoginProfile{ID: "p-1", ControlURL: ours},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Mode = ModeSystem
		o.Role = "member"
		o.EnrollUnreachable = true
		o.Identity = Identity{TokenFingerprint: "fp", Known: false}
	})
	snap, err := r.Step(context.Background())
	if err != nil || keys.n != 0 || r.AccessIdentityOK("node-2", "p-1") {
		t.Fatalf("contradicting node was confirmed: %+v keys=%d access=%v err=%v", snap, keys.n, r.AccessIdentityOK("node-2", "p-1"), err)
	}
	if st.Get().NodeID != "node-1" {
		t.Fatalf("binding %+v", st.Get())
	}
}

func TestR4CStaticKeyTrustsRunningNode(t *testing.T) {
	st, err := OpenState(filepath.Join(t.TempDir(), "vpnd-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	k := key.NewNode().Public()
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-static", PublicKey: k},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Identity = Identity{Static: true}
	})
	ctx := context.Background()
	snap, err := r.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected || keys.n != 0 {
		t.Fatalf("static: %+v keys=%d err=%v", snap, keys.n, err)
	}
	got := st.Get()
	if !got.Static || got.NodeID != "node-static" || got.Tenant != "" || got.Role != "" {
		t.Fatalf("binding %+v", got)
	}
	if !r.AccessIdentityOK("node-static", "") {
		t.Fatal("static binding did not open access")
	}
	snap, err = r.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected || keys.n != 0 {
		t.Fatalf("second pass minted: %+v keys=%d err=%v", snap, keys.n, err)
	}
}

func TestR4CEmbeddedDoesNotEnrollSystemRole(t *testing.T) {
	be := &fakeBackend{state: ipn.NeedsLogin, prefs: ipn.Prefs{ControlURL: ours}}
	keys := &r3c1RefreshKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.Mode = ModeEmbedded
		o.Role = "member"
		o.EnrollUnreachable = true
		o.Identity = Identity{Known: false}
	})
	snap, err := r.Step(context.Background())
	if err == nil || keys.auth != 0 || snap.Phase != PhaseError {
		t.Fatalf("embedded enrolled a system role: %+v auth=%d err=%v", snap, keys.auth, err)
	}
	if !strings.Contains(err.Error(), "will not enroll") || !strings.Contains(err.Error(), "system mode") {
		t.Fatalf("err %v", err)
	}
	if strings.Join(keys.order, ",") != "refresh" {
		t.Fatalf("order %v", keys.order)
	}
}
