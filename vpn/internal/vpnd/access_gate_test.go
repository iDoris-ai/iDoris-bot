package vpnd

import "testing"

func TestAccessOpen(t *testing.T) {
	const ours = "https://vpn.example.org"
	const foreign = "https://other.example"
	tests := []struct {
		name, mode, current, our string
		phase                    Phase
		want                     bool
	}{
		{name: "embedded ignores phase and control", mode: ModeEmbedded, current: foreign, our: ours, phase: PhaseBlocked, want: true},
		{name: "embedded while unknown", mode: ModeEmbedded, our: ours, phase: PhaseUnknown, want: true},
		{name: "system connected to ours", mode: ModeSystem, current: ours, our: ours, phase: PhaseConnected, want: true},
		{name: "system routes pending still carries traffic", mode: ModeSystem, current: ours + "/", our: ours, phase: PhaseRoutesPending, want: true},
		{name: "system default https port", mode: ModeSystem, current: ours + ":443", our: ours, phase: PhaseConnected, want: true},
		{name: "system foreign control stays shut", mode: ModeSystem, current: foreign, our: ours, phase: PhaseConnected, want: false},
		{name: "system empty current stays shut", mode: ModeSystem, our: ours, phase: PhaseConnected, want: false},
		{name: "system starting stays shut", mode: ModeSystem, current: ours, our: ours, phase: PhaseStarting, want: false},
		{name: "system blocked stays shut", mode: ModeSystem, current: ours, our: ours, phase: PhaseBlocked, want: false},
		{name: "system error stays shut", mode: ModeSystem, current: ours, our: ours, phase: PhaseError, want: false},
		{name: "system waiting for tailscaled stays shut", mode: ModeSystem, current: ours, our: ours, phase: PhaseWaitingTailscaled, want: false},
		{name: "comparing our url to itself is not current control", mode: ModeSystem, current: ours, our: foreign, phase: PhaseConnected, want: false},
		{name: "auto is not a running mode", mode: ModeAuto, current: ours, our: ours, phase: PhaseConnected, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AccessOpen(tc.mode, tc.current, tc.our, tc.phase); got != tc.want {
				t.Fatalf("AccessOpen(%q, %q, %q, %q) = %v, want %v", tc.mode, tc.current, tc.our, tc.phase, got, tc.want)
			}
		})
	}
}
