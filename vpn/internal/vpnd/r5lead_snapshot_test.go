package vpnd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

// TestSnapshotNamesConfiguredIdentity checks the status snapshot carries the
// enrollment identity the daemon is configured with. The local wizard uses it
// to refuse a "done" screen while the daemon still runs the previous
// credential. The snapshot holds the fingerprint, never the token.
func TestSnapshotNamesConfiguredIdentity(t *testing.T) {
	const token = "super-secret-enrollment-token"
	fp := TokenFingerprint(token)
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: ours, WantRunning: true, CorpDNS: true},
		self:  &ipnstate.PeerStatus{ID: "node-1", PublicKey: key.NewNode().Public()},
	}
	r := newR(t, be, &countingKeys{}, func(o *Options) {
		o.Role = "member"
		o.Identity = Identity{Tenant: "acme", Role: "member", TokenFingerprint: fp, Known: true}
	})
	snap, err := r.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Tenant != "acme" || snap.TokenFingerprint != fp || snap.Role != "member" {
		t.Fatalf("snapshot identity %q/%q/%q, want acme/%s/member", snap.Tenant, snap.TokenFingerprint, snap.Role, fp)
	}
	raw, err := json.Marshal(r.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) {
		t.Fatalf("status JSON leaks the token: %s", raw)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back["tenant"] != "acme" || back["token_fingerprint"] != fp {
		t.Fatalf("status JSON names %v / %v", back["tenant"], back["token_fingerprint"])
	}
}
