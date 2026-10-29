package vpnd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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
		role     string
		takeover bool
		view     SystemView
		wantMode string
		wantSub  string
		waiting  bool
	}{
		{"explicit system", ModeSystem, "", false, SystemView{}, ModeSystem, "configured system", false},
		{"explicit embedded", ModeEmbedded, "", true, SystemView{Reachable: true, ControlURL: our}, ModeEmbedded, "configured embedded", false},
		{"auto unreachable", ModeAuto, "", true, SystemView{}, ModeEmbedded, "unreachable", false},
		{"auto empty request is auto", "", "", false, SystemView{}, ModeEmbedded, "unreachable", false},
		{"auto fresh empty url", ModeAuto, "", false, SystemView{Reachable: true, BackendState: noState}, ModeSystem, "not logged in", false},
		{"auto needs login empty url", ModeAuto, "", false, SystemView{Reachable: true, BackendState: needsLogin}, ModeSystem, "not logged in", false},
		{"auto empty url while running is foreign saas", ModeAuto, "", false, SystemView{Reachable: true, BackendState: running}, ModeEmbedded, "foreign control server", false},
		{"auto empty url while starting is foreign", ModeAuto, "", false, SystemView{Reachable: true, BackendState: starting}, ModeEmbedded, "foreign control server", false},
		{"auto empty url while stopped is foreign", ModeAuto, "", false, SystemView{Reachable: true, BackendState: stopped}, ModeEmbedded, "foreign control server", false},
		{"auto empty url running with explicit takeover", ModeAuto, "", true, SystemView{Reachable: true, BackendState: running}, ModeSystem, "takeover explicitly enabled", false},
		{"auto already ours", ModeAuto, "", false, SystemView{Reachable: true, BackendState: running, ControlURL: our + "/"}, ModeSystem, "already on the iDoris", false},
		{"auto stopped on ours", ModeAuto, "", false, SystemView{Reachable: true, BackendState: stopped, ControlURL: our}, ModeSystem, "already on the iDoris", false},
		{"auto saved iDoris profile does not displace foreign", ModeAuto, "", false, SystemView{Reachable: true, BackendState: running, ControlURL: foreign, HasOurProfile: true}, ModeEmbedded, "foreign control server", false},
		{"auto saved profile while foreign is starting", ModeAuto, "", false, SystemView{Reachable: true, BackendState: starting, ControlURL: foreign, HasOurProfile: true}, ModeEmbedded, "foreign control server", false},
		{"auto saved profile while foreign is stopped", ModeAuto, "", false, SystemView{Reachable: true, BackendState: stopped, ControlURL: foreign, HasOurProfile: true}, ModeEmbedded, "foreign control server", false},
		{"auto saved profile while foreign needs login", ModeAuto, "", false, SystemView{Reachable: true, BackendState: needsLogin, ControlURL: foreign, HasOurProfile: true}, ModeEmbedded, "foreign control server", false},
		{"auto saved profile with explicit takeover", ModeAuto, "", true, SystemView{Reachable: true, BackendState: running, ControlURL: foreign, HasOurProfile: true}, ModeSystem, "takeover explicitly enabled", false},
		{"auto local-ai unreachable waits", ModeAuto, "local-ai", false, SystemView{}, ModeSystem, "waiting-for-tailscaled", true},
		{"auto gateway unreachable waits", ModeAuto, "gateway", true, SystemView{}, ModeSystem, "waiting-for-tailscaled", true},
		{"system local-ai unreachable waits", ModeSystem, "local-ai", false, SystemView{}, ModeSystem, "waiting-for-tailscaled", true},
		{"system local-ai reachable is system", ModeSystem, "local-ai", false, SystemView{Reachable: true, BackendState: running, ControlURL: foreign}, ModeSystem, "configured system", false},
		{"auto local-ai foreign stays system", ModeAuto, "local-ai", false, SystemView{Reachable: true, BackendState: running, ControlURL: foreign, HasOurProfile: true}, ModeSystem, "requires system mode", false},
		{"auto gateway fresh is system", ModeAuto, "gateway", false, SystemView{Reachable: true, BackendState: noState}, ModeSystem, "not logged in", false},
		{"auto admin unreachable stays embedded", ModeAuto, "admin", false, SystemView{}, ModeEmbedded, "unreachable", false},
		{"auto foreign running", ModeAuto, "", false, SystemView{Reachable: true, BackendState: running, ControlURL: foreign}, ModeEmbedded, "foreign control server", false},
		{"auto foreign stopped still embedded", ModeAuto, "", false, SystemView{Reachable: true, BackendState: stopped, ControlURL: foreign}, ModeEmbedded, "foreign control server", false},
		{"auto foreign needs-login still embedded", ModeAuto, "", false, SystemView{Reachable: true, BackendState: needsLogin, ControlURL: foreign}, ModeEmbedded, "foreign control server", false},
		{"auto foreign with explicit takeover", ModeAuto, "", true, SystemView{Reachable: true, BackendState: running, ControlURL: foreign}, ModeSystem, "takeover explicitly enabled", false},
		{"auto unknown prefs while running", ModeAuto, "", false, SystemView{Reachable: true, BackendState: running, ControlURL: "unknown"}, ModeEmbedded, "foreign control server", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecideMode(tc.req, tc.role, tc.takeover, tc.view, our)
			if err != nil {
				t.Fatal(err)
			}
			if got.Mode != tc.wantMode || !strings.Contains(got.Reason, tc.wantSub) || got.Waiting != tc.waiting {
				t.Fatalf("got %+v, want mode %s reason containing %q waiting %v", got, tc.wantMode, tc.wantSub, tc.waiting)
			}
		})
	}
	if _, err := DecideMode("both", "", false, SystemView{}, our); err == nil {
		t.Fatal("invalid mode must fail")
	}
	if _, err := DecideMode(ModeEmbedded, "local-ai", false, SystemView{Reachable: true}, our); err == nil || !strings.Contains(err.Error(), "embedded") {
		t.Fatalf("embedded local-ai: %v", err)
	}
	if _, err := DecideMode(ModeEmbedded, "gateway", false, SystemView{}, our); err == nil {
		t.Fatal("embedded gateway must fail")
	}
	if !RequiresSystem("Local-AI") || RequiresSystem("admin") || RequiresSystem("member") || RequiresSystem("") {
		t.Fatal("RequiresSystem")
	}
}

func TestProbeUntilReadyRetriesThenProceeds(t *testing.T) {
	n := 0
	var slept []time.Duration
	var waits int
	d, err := ProbeUntilReady(context.Background(), ModeAuto, "local-ai", false, ours,
		func(context.Context) SystemView {
			n++
			if n < 3 {
				return SystemView{}
			}
			return SystemView{Reachable: true, BackendState: ipn.NoState.String()}
		},
		func(got ModeDecision) {
			waits++
			if !got.Waiting || got.Mode != ModeSystem {
				t.Fatalf("wait decision %+v", got)
			}
		},
		func(_ context.Context, d time.Duration) error {
			slept = append(slept, d)
			return nil
		},
	)
	if err != nil || d.Waiting || d.Mode != ModeSystem || !strings.Contains(d.Reason, "not logged in") {
		t.Fatalf("got %+v err=%v", d, err)
	}
	if waits != 2 || len(slept) != 2 || slept[0] != 2*time.Second || slept[1] != 4*time.Second {
		t.Fatalf("waits=%d slept=%v", waits, slept)
	}
}

func TestProbeUntilReadyBackoffCapsAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var slept []time.Duration
	_, err := ProbeUntilReady(ctx, ModeSystem, "gateway", false, ours,
		func(context.Context) SystemView { return SystemView{} },
		nil,
		func(ctx context.Context, d time.Duration) error {
			slept = append(slept, d)
			if len(slept) == 6 {
				cancel()
				return ctx.Err()
			}
			return nil
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	if len(slept) != len(want) {
		t.Fatalf("slept %v", slept)
	}
	for i := range want {
		if slept[i] != want[i] {
			t.Fatalf("slept %v", slept)
		}
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
