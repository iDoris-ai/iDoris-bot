package vpnd

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestResolveStartupControl(t *testing.T) {
	const (
		pin  = "https://vpn.example/control"
		disc = "https://vpn.example/control/"
		save = "https://vpn.saved"
		alt  = "https://vpn.other"
	)
	cases := []struct {
		name       string
		pinned     string
		discovered string
		saved      string
		ok         bool
		want       string
		degraded   bool
		wantErr    string
	}{
		{name: "discover uses service url", discovered: disc, ok: true, want: disc},
		{name: "discover prefers matching pin", pinned: pin, discovered: disc, ok: true, want: pin},
		{name: "discover refuses a different pin", pinned: alt, discovered: disc, ok: true, wantErr: "pins"},
		{name: "discover empty", ok: true, wantErr: "empty"},
		{name: "down uses saved", saved: save, degraded: true, want: save},
		{name: "down uses pin when nothing is saved", pinned: pin, degraded: true, want: pin},
		{name: "down uses pin that matches saved", pinned: pin, saved: pin + "/", degraded: true, want: pin},
		{name: "down refuses a pin that differs from saved", pinned: pin, saved: save, wantErr: "differs"},
		{name: "down with nothing", wantErr: "unreachable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, degraded, err := ResolveStartupControl(tc.pinned, tc.discovered, tc.saved, tc.ok)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err != nil || got != tc.want || degraded != tc.degraded {
				t.Fatalf("got %q degraded=%v err=%v", got, degraded, err)
			}
		})
	}
}

func TestRoleWhileEnrollDown(t *testing.T) {
	if got := RoleWhileEnrollDown("member", "local-ai", "fp", "fp"); got != "local-ai" {
		t.Fatal(got)
	}
	if got := RoleWhileEnrollDown("member", "", "fp", "fp"); got != "member" {
		t.Fatal(got)
	}
	if got := RoleWhileEnrollDown("admin", "nope", "fp", "fp"); got != "admin" {
		t.Fatal(got)
	}
	if got := RoleWhileEnrollDown("member", "Gateway", "fp", "fp"); got != "gateway" {
		t.Fatal(got)
	}
	// A saved role from a different token is not this credential.
	if got := RoleWhileEnrollDown("member", "local-ai", "new", "old"); got != "member" {
		t.Fatal(got)
	}
	if got := RoleWhileEnrollDown("local-ai", "member", "fp", "fp"); got != "local-ai" {
		t.Fatal(got)
	}
}

// TestR3C1MemberBindingDoesNotDowngradeLocalAI is the degraded start where a
// saved member binding would otherwise replace an explicit local-ai role and
// let auto mode come up embedded, reporting the old member node connected.
func TestR3C1MemberBindingDoesNotDowngradeLocalAI(t *testing.T) {
	const savedFP = "aaaaaaaaaaaaaaaa"
	const currentFP = "bbbbbbbbbbbbbbbb"
	role := RoleWhileEnrollDown("local-ai", "member", currentFP, savedFP)
	if role != "local-ai" {
		t.Fatalf("role %q", role)
	}
	// Same token, saved role still member: an explicit server role stays.
	if got := RoleWhileEnrollDown("local-ai", "member", savedFP, savedFP); got != "local-ai" {
		t.Fatalf("same fingerprint downgraded to %q", got)
	}
	d, err := DecideMode(ModeAuto, role, false, SystemView{Reachable: false}, ours)
	if err != nil {
		t.Fatal(err)
	}
	if d.Mode != ModeSystem || !d.Waiting {
		t.Fatalf("discovery-down local-ai must wait for tailscaled, not run embedded: %+v", d)
	}
	be := &fakeBackend{statusErr: errors.New("tailscaled down")}
	r := newR(t, be, &countingKeys{}, func(o *Options) {
		o.Role = role
		o.EnrollUnreachable = true
		o.Identity = Identity{Known: false}
	})
	snap, err := r.Step(context.Background())
	if err == nil {
		t.Fatal("unreachable tailscaled must surface")
	}
	if snap.Phase == PhaseConnected || snap.Role == "member" || snap.Phase != PhaseWaitingTailscaled {
		t.Fatalf("reported connected as member: %+v", snap)
	}
}
