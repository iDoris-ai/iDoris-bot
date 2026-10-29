package vpnd

import "testing"

func TestAccessOpen(t *testing.T) {
	const ours = "https://vpn.example.org"
	const foreign = "https://other.example"
	tests := []struct {
		name, mode, current, our string
		phase                    Phase
		identity                 bool
		want                     bool
	}{
		// Embedded used to ignore phase, control, and identity. That left an
		// old admin node reachable through forwards after a member credential
		// failed to enroll. Both modes now need a confirmed identity, our
		// control URL, and a phase that still carries traffic.
		{name: "embedded foreign blocked stays shut", mode: ModeEmbedded, current: foreign, our: ours, phase: PhaseBlocked, identity: true, want: false},
		{name: "embedded while unknown stays shut", mode: ModeEmbedded, our: ours, phase: PhaseUnknown, identity: true, want: false},
		{name: "embedded connected without identity stays shut", mode: ModeEmbedded, current: ours, our: ours, phase: PhaseConnected, identity: false, want: false},
		{name: "embedded enrollment failed stays shut", mode: ModeEmbedded, current: ours, our: ours, phase: PhaseError, identity: false, want: false},
		{name: "embedded connected with identity opens", mode: ModeEmbedded, current: ours, our: ours, phase: PhaseConnected, identity: true, want: true},
		{name: "embedded routes pending with identity opens", mode: ModeEmbedded, current: ours + "/", our: ours, phase: PhaseRoutesPending, identity: true, want: true},
		{name: "system connected to ours", mode: ModeSystem, current: ours, our: ours, phase: PhaseConnected, identity: true, want: true},
		{name: "system routes pending still carries traffic", mode: ModeSystem, current: ours + "/", our: ours, phase: PhaseRoutesPending, identity: true, want: true},
		{name: "system default https port", mode: ModeSystem, current: ours + ":443", our: ours, phase: PhaseConnected, identity: true, want: true},
		{name: "system foreign control stays shut", mode: ModeSystem, current: foreign, our: ours, phase: PhaseConnected, identity: true, want: false},
		{name: "system empty current stays shut", mode: ModeSystem, our: ours, phase: PhaseConnected, identity: true, want: false},
		{name: "system starting stays shut", mode: ModeSystem, current: ours, our: ours, phase: PhaseStarting, identity: true, want: false},
		{name: "system blocked stays shut", mode: ModeSystem, current: ours, our: ours, phase: PhaseBlocked, identity: true, want: false},
		{name: "system error stays shut", mode: ModeSystem, current: ours, our: ours, phase: PhaseError, identity: true, want: false},
		{name: "system waiting for tailscaled stays shut", mode: ModeSystem, current: ours, our: ours, phase: PhaseWaitingTailscaled, identity: true, want: false},
		{name: "system without identity stays shut", mode: ModeSystem, current: ours, our: ours, phase: PhaseConnected, identity: false, want: false},
		{name: "comparing our url to itself is not current control", mode: ModeSystem, current: ours, our: foreign, phase: PhaseConnected, identity: true, want: false},
		{name: "auto is not a running mode", mode: ModeAuto, current: ours, our: ours, phase: PhaseConnected, identity: true, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AccessOpen(tc.mode, tc.current, tc.our, tc.phase, tc.identity); got != tc.want {
				t.Fatalf("AccessOpen(%q, %q, %q, %q, %v) = %v, want %v", tc.mode, tc.current, tc.our, tc.phase, tc.identity, got, tc.want)
			}
		})
	}
}
