package vpnd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestDecideMode(t *testing.T) {
	const our = "https://vpn.idoris.example"
	foreign := "https://controlplane.tailscale.com"
	running := ipn.Running.String()
	starting := ipn.Starting.String()
	needsLogin := ipn.NeedsLogin.String()
	noState := ipn.NoState.String()
	stopped := ipn.Stopped.String()

	cases := []struct {
		name     string
		req      string
		takeover bool
		view     SystemView
		wantMode string
		wantSub  string
	}{
		{"explicit system", ModeSystem, false, SystemView{}, ModeSystem, "configured system"},
		{"explicit embedded", ModeEmbedded, true, SystemView{Reachable: true, ControlURL: our}, ModeEmbedded, "configured embedded"},
		{"auto unreachable", ModeAuto, true, SystemView{}, ModeEmbedded, "unreachable"},
		{"auto empty request is auto", "", false, SystemView{}, ModeEmbedded, "unreachable"},
		{"auto fresh empty url", ModeAuto, false, SystemView{Reachable: true, BackendState: noState}, ModeSystem, "not logged in"},
		{"auto needs login empty url", ModeAuto, false, SystemView{Reachable: true, BackendState: needsLogin}, ModeSystem, "not logged in"},
		{"auto empty url while running is foreign saas", ModeAuto, false, SystemView{Reachable: true, BackendState: running}, ModeEmbedded, "foreign control server"},
		{"auto empty url while starting is foreign", ModeAuto, false, SystemView{Reachable: true, BackendState: starting}, ModeEmbedded, "foreign control server"},
		{"auto empty url while stopped is foreign", ModeAuto, false, SystemView{Reachable: true, BackendState: stopped}, ModeEmbedded, "foreign control server"},
		{"auto empty url running with explicit takeover", ModeAuto, true, SystemView{Reachable: true, BackendState: running}, ModeSystem, "takeover explicitly enabled"},
		{"auto already ours", ModeAuto, false, SystemView{Reachable: true, BackendState: running, ControlURL: our + "/"}, ModeSystem, "already on the iDoris"},
		{"auto stopped on ours", ModeAuto, false, SystemView{Reachable: true, BackendState: stopped, ControlURL: our}, ModeSystem, "already on the iDoris"},
		{"auto has our profile while current is foreign", ModeAuto, false, SystemView{Reachable: true, BackendState: running, ControlURL: foreign, HasOurProfile: true}, ModeSystem, "iDoris profile"},
		{"auto foreign running", ModeAuto, false, SystemView{Reachable: true, BackendState: running, ControlURL: foreign}, ModeEmbedded, "foreign control server"},
		{"auto foreign stopped still embedded", ModeAuto, false, SystemView{Reachable: true, BackendState: stopped, ControlURL: foreign}, ModeEmbedded, "foreign control server"},
		{"auto foreign needs-login still embedded", ModeAuto, false, SystemView{Reachable: true, BackendState: needsLogin, ControlURL: foreign}, ModeEmbedded, "foreign control server"},
		{"auto foreign with explicit takeover", ModeAuto, true, SystemView{Reachable: true, BackendState: running, ControlURL: foreign}, ModeSystem, "takeover explicitly enabled"},
		{"auto unknown prefs while running", ModeAuto, false, SystemView{Reachable: true, BackendState: running, ControlURL: "unknown"}, ModeEmbedded, "foreign control server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecideMode(tc.req, tc.takeover, tc.view, our)
			if err != nil {
				t.Fatal(err)
			}
			if got.Mode != tc.wantMode || !strings.Contains(got.Reason, tc.wantSub) {
				t.Fatalf("got %+v, want mode %s reason containing %q", got, tc.wantMode, tc.wantSub)
			}
		})
	}
	if _, err := DecideMode("both", false, SystemView{}, our); err == nil {
		t.Fatal("invalid mode must fail")
	}
}

func TestForeignControlEmptyURL(t *testing.T) {
	const our = "https://vpn.idoris.example"
	cases := []struct {
		control string
		state   string
		want    bool
	}{
		{"", ipn.NoState.String(), false},
		{"", ipn.NeedsLogin.String(), false},
		{"", "", false},
		{"", ipn.Running.String(), true},
		{"", ipn.Starting.String(), true},
		{"", ipn.Stopped.String(), true},
		{"  ", ipn.Running.String(), true},
		{our, ipn.Running.String(), false},
		{our + "/", ipn.Stopped.String(), false},
		{"https://controlplane.tailscale.com", ipn.NeedsLogin.String(), true},
		{"https://controlplane.tailscale.com", ipn.Stopped.String(), true},
	}
	for _, tc := range cases {
		if got := foreignControl(tc.control, our, tc.state); got != tc.want {
			t.Errorf("foreignControl(%q, ours, %q)=%v, want %v", tc.control, tc.state, got, tc.want)
		}
	}
}

func TestProbeSystem(t *testing.T) {
	be := &fakeBackend{
		state: ipn.Running,
		prefs: ipn.Prefs{ControlURL: "https://controlplane.tailscale.com", WantRunning: true},
		profiles: []ipn.LoginProfile{
			{ID: "p-saas", ControlURL: "https://login.tailscale.com"},
			{ID: "p-idoris", ControlURL: ours + "/"},
		},
	}
	view := ProbeSystem(context.Background(), be, ours)
	if !view.Reachable || !view.HasOurProfile || view.BackendState != ipn.Running.String() {
		t.Fatalf("%+v", view)
	}
	if view.ControlURL != be.prefs.ControlURL {
		t.Fatalf("control %q", view.ControlURL)
	}

	down := &fakeBackend{statusErr: errors.New("no socket")}
	view = ProbeSystem(context.Background(), down, ours)
	if view.Reachable {
		t.Fatal("status error must be unreachable")
	}
}
