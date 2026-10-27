package vpnd

import (
	"context"
	"fmt"
	"strings"

	"tailscale.com/ipn"
)

const (
	// ModeAuto probes the system tailscaled once at startup and picks system
	// or embedded. It is the default.
	ModeAuto = "auto"
	// ModeSystem drives the machine's tailscaled through LocalAPI.
	ModeSystem = "system"
	// ModeEmbedded runs an in-process userspace Tailscale node and does not
	// touch the system tailscaled.
	ModeEmbedded = "embedded"
)

// SystemView is a read-only look at the system tailscaled. DecideMode is a
// pure function of this view so the startup choice can be table-tested
// without a live daemon.
type SystemView struct {
	// Reachable is false when the LocalAPI could not be queried (not
	// installed, not running, or the socket timed out).
	Reachable bool
	// BackendState is ipnstate.Status.BackendState when Reachable.
	BackendState string
	// ControlURL is the current profile's control URL. A sentinel of
	// "unknown" means the node answered Status but not GetPrefs; a running
	// node in that state is treated as foreign so auto mode will not touch it.
	ControlURL string
	// HasOurProfile is true when any login profile, including the current
	// one, points at our control URL.
	HasOurProfile bool
}

// ModeDecision is the startup choice and the reason exposed as mode_reason.
type ModeDecision struct {
	Mode   string
	Reason string
}

// DecideMode chooses system or embedded.
//
// requested is auto, system, or embedded. takeoverExplicit is true only when
// the operator set takeover to true (the default is false and is not explicit).
//
// auto uses system only when that cannot hijack a foreign tailnet: tailscaled
// is reachable and it is not logged in, already on our control URL, or already
// has an iDoris profile. A foreign control URL, including an empty URL on a
// backend that is already Running, Starting, or Stopped, uses system only when
// takeover was explicitly enabled. Otherwise auto uses embedded, including when
// tailscaled is not reachable.
func DecideMode(requested string, takeoverExplicit bool, view SystemView, ourControl string) (ModeDecision, error) {
	switch requested {
	case "", ModeAuto:
	case ModeSystem:
		return ModeDecision{Mode: ModeSystem, Reason: "configured system"}, nil
	case ModeEmbedded:
		return ModeDecision{Mode: ModeEmbedded, Reason: "configured embedded"}, nil
	default:
		return ModeDecision{}, fmt.Errorf("mode %q: want auto, system, or embedded", requested)
	}
	if !view.Reachable {
		return ModeDecision{Mode: ModeEmbedded, Reason: "tailscaled unreachable"}, nil
	}
	if ourControl != "" && SameControlURL(view.ControlURL, ourControl) {
		return ModeDecision{Mode: ModeSystem, Reason: "system tailscaled is already on the iDoris control server"}, nil
	}
	if view.HasOurProfile {
		return ModeDecision{Mode: ModeSystem, Reason: "system tailscaled has an iDoris profile"}, nil
	}
	if !foreignControl(view.ControlURL, ourControl, view.BackendState) {
		return ModeDecision{Mode: ModeSystem, Reason: "system tailscaled is not logged in"}, nil
	}
	if takeoverExplicit {
		return ModeDecision{Mode: ModeSystem, Reason: "takeover explicitly enabled"}, nil
	}
	return ModeDecision{
		Mode:   ModeEmbedded,
		Reason: "system tailscaled is logged into a foreign control server and takeover is not enabled",
	}, nil
}

// foreignControl reports whether control is a persisted login to some server
// other than ours. A non-empty foreign URL counts even when the backend is
// NeedsLogin or Stopped: the system client still holds that profile, and the
// reconciler would switch it.
//
// An empty URL is a fresh install only when the backend is logged out
// (NoState, NeedsLogin, or anything else that is not a live session). Older
// Tailscale profiles that are logged into the default SaaS sometimes report
// an empty ControlURL while the backend is Running, Starting, or Stopped.
// Treating that as fresh would let auto mode hijack the user's tailnet.
func foreignControl(control, ours, backendState string) bool {
	control = strings.TrimSpace(control)
	if control == "" {
		return loggedInBackend(backendState)
	}
	if ours != "" && SameControlURL(control, ours) {
		return false
	}
	return true
}

// loggedInBackend reports states where tailscaled already has a session.
// NeedsLogin and NoState are a fresh or logged-out install.
func loggedInBackend(state string) bool {
	switch state {
	case ipn.Running.String(), ipn.Starting.String(), ipn.Stopped.String():
		return true
	default:
		return false
	}
}

// ProbeSystem reads the system tailscaled. It never calls Start, EditPrefs,
// or any profile switch. A Status failure is "not reachable". If Status works
// but GetPrefs does not, a Running, Starting, or Stopped node is reported with
// ControlURL "unknown" so auto mode leaves it alone.
func ProbeSystem(ctx context.Context, be Backend, ourControl string) SystemView {
	st, err := be.Status(ctx)
	if err != nil || st == nil {
		return SystemView{}
	}
	view := SystemView{Reachable: true, BackendState: st.BackendState}
	prefs, err := be.GetPrefs(ctx)
	if err != nil || prefs == nil {
		switch st.BackendState {
		case ipn.Running.String(), ipn.Starting.String(), ipn.Stopped.String():
			view.ControlURL = "unknown"
		}
		return view
	}
	view.ControlURL = prefs.ControlURL
	if ourControl != "" && SameControlURL(prefs.ControlURL, ourControl) {
		view.HasOurProfile = true
	}
	_, all, err := be.ProfileStatus(ctx)
	if err != nil {
		return view
	}
	for _, p := range all {
		if ourControl != "" && SameControlURL(p.ControlURL, ourControl) {
			view.HasOurProfile = true
			break
		}
	}
	return view
}
