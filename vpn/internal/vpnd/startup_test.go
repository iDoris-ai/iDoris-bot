package vpnd

import (
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
	if got := RoleWhileEnrollDown("member", "local-ai"); got != "local-ai" {
		t.Fatal(got)
	}
	if got := RoleWhileEnrollDown("member", ""); got != "member" {
		t.Fatal(got)
	}
	if got := RoleWhileEnrollDown("admin", "nope"); got != "admin" {
		t.Fatal(got)
	}
	if got := RoleWhileEnrollDown("member", "Gateway"); got != "gateway" {
		t.Fatal(got)
	}
}
