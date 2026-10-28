package vpnd

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

// r6cDiscoverKeys fails discovery the first fails times, then returns ident.
// AuthKey counts a certification login.
type r6cDiscoverKeys struct {
	fails int
	calls int
	auth  int
	ident Identity
	role  string
}

func (k *r6cDiscoverKeys) RefreshIdentity(context.Context) (Identity, string, error) {
	k.calls++
	if k.calls <= k.fails {
		return Identity{}, "", errors.New("discovery down")
	}
	return k.ident, k.role, nil
}

func (k *r6cDiscoverKeys) AuthKey(context.Context) (string, error) {
	k.auth++
	return "key-r6c", nil
}

// TestR6CDiscardMismatchedPendingClearsCommittedBinding is the case the
// empty-binding C1 test misses. Credential A is committed for node N.
// Credential B's login rotated the node key and saved a LoginOK pending
// record, then the process died before B was committed. Config A is restored.
// Headscale keeps node N. The discarded pending must not leave A's binding
// able to certify that node, including across a restart that happens before
// the replacement login.
func TestR6CDiscardMismatchedPendingClearsCommittedBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpnd-state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	fpA := TokenFingerprint("credential-a")
	fpB := TokenFingerprint("credential-b")
	if fpA == "" || fpA == fpB {
		t.Fatalf("fingerprints a=%q b=%q", fpA, fpB)
	}
	if err := st.SetIdentity(ours, "acme", "member", fpA, "node-n", ""); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	if err := st.SetLoginBackoff(past, 3); err != nil {
		t.Fatal(err)
	}
	oldKey := key.NewNode().Public()
	rotated := key.NewNode().Public()
	if err := st.SetPending(PendingLogin{
		NodeID:           "node-n",
		NodeKey:          oldKey.String(),
		Started:          time.Now().Add(-time.Minute),
		LoginOK:          true,
		TokenFingerprint: fpB,
		Tenant:           "acme",
		Role:             "member",
		ControlURL:       ours,
		Mode:             ModeEmbedded,
	}); err != nil {
		t.Fatal(err)
	}

	// Process that restores config A. Constructing the reconciler discards
	// pending B. This process does not log in.
	st2, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = newR(t, &fakeBackend{}, &countingKeys{}, func(o *Options) {
		o.State = st2
		o.Mode = ModeEmbedded
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: fpA, Known: true}
	})

	// Restart after the discard and before the new login. The state file is
	// re-opened, which is what the next process reads.
	st3, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	before := st3.Get()
	_, pendingOK := st3.Pending()
	next, fails := st3.LoginBackoff()
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-n", PublicKey: rotated},
	}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st3
		o.Mode = ModeEmbedded
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: fpA, Known: true}
	})
	ctx := context.Background()
	snap, err := r.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	access := r.AccessIdentityOK("node-n", "")
	if before.Tenant != "" || before.Role != "" || before.TokenFingerprint != "" || before.NodeID != "" || before.ProfileID != "" || before.Static || pendingOK || before.ControlURL != ours || fails != 3 || next.Unix() != past.Unix() || keys.n != 1 || snap.Phase == PhaseConnected || access {
		t.Fatalf("discard left binding %+v pending=%v backoff=%s/%d; step phase %s keys=%d access=%v", before, pendingOK, next.Format(time.RFC3339), fails, snap.Phase, keys.n, access)
	}

	// StartLoginInteractive has returned. The node key it forced is now
	// visible and the stable id is still N. That pass certifies A.
	certified := key.NewNode().Public()
	be.self = &ipnstate.PeerStatus{ID: "node-n", PublicKey: certified}
	be.state = ipn.Running
	snap, err = r.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected || keys.n != 1 || !r.AccessIdentityOK("node-n", "") {
		t.Fatalf("certify phase %s keys=%d access=%v err=%v snap %+v", snap.Phase, keys.n, r.AccessIdentityOK("node-n", ""), err, snap)
	}
	bound := st3.Get()
	if bound.TokenFingerprint != fpA || bound.NodeID != "node-n" || bound.Tenant != "acme" || bound.Role != "member" {
		t.Fatalf("binding %+v", bound)
	}
	if _, ok := st3.Pending(); ok {
		t.Fatalf("pending left after certification: %+v", st3.Get())
	}
}

// TestR6CSnapshotIdentityUnconfirmed reports identity_unconfirmed while
// enrollment is unreachable and the identity is unknown, and drops the key
// once discovery has certified the binding.
func TestR6CSnapshotIdentityUnconfirmed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpnd-state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	fp := TokenFingerprint("credential-a")
	ident := Identity{Tenant: "acme", Role: "member", TokenFingerprint: fp, Known: true}
	oldKey := key.NewNode().Public()
	newKey := key.NewNode().Public()
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-n", PublicKey: oldKey},
	}
	keys := &r6cDiscoverKeys{fails: 1, ident: ident, role: "member"}
	r := newR(t, be, keys, func(o *Options) {
		o.State = st
		o.Mode = ModeEmbedded
		o.Role = "member"
		o.EnrollUnreachable = true
		o.Identity = Identity{TokenFingerprint: fp, Known: false}
	})
	now := time.Now()
	r.now = func() time.Time { return now }
	ctx := context.Background()

	snap, err := r.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.IdentityUnconfirmed {
		t.Fatalf("unknown identity was confirmed: %+v", snap)
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) || !strings.Contains(string(raw), `"identity_unconfirmed":true`) {
		t.Fatalf("status JSON: %s", raw)
	}

	now = now.Add(discoveryRetryInterval)
	snap, err = r.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if keys.calls != 2 || keys.auth != 1 {
		t.Fatalf("discovery calls %d auth %d snap %+v", keys.calls, keys.auth, snap)
	}
	if snap.Phase == PhaseConnected || r.AccessIdentityOK("node-n", "") {
		t.Fatalf("certified before the new key was visible: %+v", snap)
	}

	be.self = &ipnstate.PeerStatus{ID: "node-n", PublicKey: newKey}
	be.state = ipn.Running
	snap, err = r.Step(ctx)
	if err != nil || snap.Phase != PhaseConnected {
		t.Fatalf("certify: %+v err=%v", snap, err)
	}
	if snap.IdentityUnconfirmed {
		t.Fatalf("confirmed identity still unconfirmed: %+v", snap)
	}
	raw, err = json.Marshal(r.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "identity_unconfirmed") {
		t.Fatalf("confirmed status still has the key: %s", raw)
	}
	got := st.Get()
	if got.Tenant != "acme" || got.Role != "member" || got.TokenFingerprint != fp || got.NodeID != "node-n" {
		t.Fatalf("binding %+v", got)
	}
	if !r.AccessIdentityOK("node-n", "") {
		t.Fatal("access stayed closed after certification")
	}
}
