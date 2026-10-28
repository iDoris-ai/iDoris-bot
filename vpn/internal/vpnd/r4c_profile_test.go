package vpnd

import (
	"context"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

// r4cFlipProfile reports a fresh profile on the first read and a foreign
// profile on the read that happens immediately before the switch.
type r4cFlipProfile struct {
	fakeBackend
	reads int
}

func (b *r4cFlipProfile) ProfileStatus(ctx context.Context) (ipn.LoginProfile, []ipn.LoginProfile, error) {
	b.reads++
	if b.reads >= 2 {
		b.current = ipn.LoginProfile{ID: "p-foreign", ControlURL: "https://foreign.example"}
		b.prefs.ControlURL = "https://foreign.example"
	}
	return b.fakeBackend.ProfileStatus(ctx)
}

func TestR4CProfileFlipBeforeSwitchIsBlocked(t *testing.T) {
	be := &r4cFlipProfile{fakeBackend: fakeBackend{
		state:   ipn.NeedsLogin,
		prefs:   ipn.Prefs{ControlURL: "", WantRunning: true, RunSSH: true},
		current: ipn.LoginProfile{ID: "p-empty", ControlURL: ""},
		profiles: []ipn.LoginProfile{
			{ID: "p-empty", ControlURL: ""},
			{ID: "p-idoris", ControlURL: ours},
		},
	}}
	keys := &countingKeys{}
	r := newR(t, be, keys, func(o *Options) { o.Takeover = false })
	snap, err := r.Step(context.Background())
	if err != nil || snap.Phase != PhaseBlocked || keys.n != 0 {
		t.Fatalf("phase %s err %v keys %d snap %+v", snap.Phase, err, keys.n, snap)
	}
	for _, c := range be.calls {
		if strings.HasPrefix(c, "Switch") || c == "Start" || c == "CheckPrefs" || c == "StartLoginInteractive" {
			t.Fatalf("mutated after the profile changed: %v", be.calls)
		}
	}
	if be.current.ID != "p-foreign" {
		t.Fatalf("second read did not observe the foreign profile: %+v", be.current)
	}
}
