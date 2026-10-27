package vpnd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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
	// Waiting is set when a local-ai or gateway role needs the system
	// tailscaled and it is not reachable. The daemon must not start an
	// embedded node; it reports phase waiting-for-tailscaled and retries.
	Waiting bool
}

// RequiresSystem reports whether role serves inbound traffic and therefore
// cannot use embedded mode. member and admin may use either mode.
func RequiresSystem(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "local-ai", "gateway":
		return true
	default:
		return false
	}
}

// WaitingTailscaledMessage is the operator-facing text for phase
// waiting-for-tailscaled.
func WaitingTailscaledMessage(role string) string {
	if strings.TrimSpace(role) == "" {
		role = "local-ai"
	}
	return "role " + role + " requires the official tailscaled because embedded mode cannot receive inbound connections. Install Tailscale, start it, and leave idoris-vpnd running; it keeps retrying"
}

// DecideMode chooses system or embedded.
//
// requested is auto, system, or embedded. takeoverExplicit is true only when
// the operator set takeover to true (the default is false and is not explicit).
//
// auto uses system only when that cannot displace the active profile:
// tailscaled is reachable and the current control URL is already ours, or the
// backend is fresh (no persisted foreign login). A saved iDoris profile does
// not count. HasOurProfile is reported for diagnostics and is ignored here.
// A foreign control URL, including an empty URL on a backend that is already
// Running, Starting, or Stopped, and a non-empty foreign URL in NeedsLogin,
// uses system only when takeover was explicitly enabled. Otherwise auto uses
// embedded, including when tailscaled is not reachable.
//
// local-ai and gateway never select embedded: embedded mode is outbound-only
// and cannot serve inbound traffic. auto and system wait (Waiting) while
// tailscaled is unreachable. A foreign login stays on system mode and is left
// unchanged until takeover is explicit. An explicit embedded request for
// those roles is a configuration error. member and admin keep the desktop
// behaviour above.
func DecideMode(requested, role string, takeoverExplicit bool, view SystemView, ourControl string) (ModeDecision, error) {
	switch requested {
	case "", ModeAuto:
	case ModeSystem:
		if RequiresSystem(role) && !view.Reachable {
			return ModeDecision{Mode: ModeSystem, Reason: "waiting-for-tailscaled", Waiting: true}, nil
		}
		return ModeDecision{Mode: ModeSystem, Reason: "configured system"}, nil
	case ModeEmbedded:
		if RequiresSystem(role) {
			return ModeDecision{}, fmt.Errorf("role %s cannot use embedded mode: embedded mode is outbound-only and cannot serve inbound traffic; set mode to system or auto and run the official tailscaled", role)
		}
		return ModeDecision{Mode: ModeEmbedded, Reason: "configured embedded"}, nil
	default:
		return ModeDecision{}, fmt.Errorf("mode %q: want auto, system, or embedded", requested)
	}
	if RequiresSystem(role) {
		if !view.Reachable {
			return ModeDecision{Mode: ModeSystem, Reason: "waiting-for-tailscaled", Waiting: true}, nil
		}
		return serviceMode(takeoverExplicit, view, ourControl, role), nil
	}
	if !view.Reachable {
		return ModeDecision{Mode: ModeEmbedded, Reason: "tailscaled unreachable"}, nil
	}
	return desktopMode(takeoverExplicit, view, ourControl), nil
}

func serviceMode(takeoverExplicit bool, view SystemView, ourControl, role string) ModeDecision {
	d := desktopMode(takeoverExplicit, view, ourControl)
	if d.Mode == ModeEmbedded {
		return ModeDecision{
			Mode:   ModeSystem,
			Reason: "role " + role + " requires system mode; the foreign tailnet is left unchanged until takeover is enabled",
		}
	}
	return d
}

func desktopMode(takeoverExplicit bool, view SystemView, ourControl string) ModeDecision {
	if ourControl != "" && SameControlURL(view.ControlURL, ourControl) {
		return ModeDecision{Mode: ModeSystem, Reason: "system tailscaled is already on the iDoris control server"}
	}
	if !foreignControl(view.ControlURL, ourControl, view.BackendState) {
		return ModeDecision{Mode: ModeSystem, Reason: "system tailscaled is not logged in"}
	}
	if takeoverExplicit {
		return ModeDecision{Mode: ModeSystem, Reason: "takeover explicitly enabled"}
	}
	return ModeDecision{
		Mode:   ModeEmbedded,
		Reason: "system tailscaled is logged into a foreign control server and takeover is not enabled",
	}
}

const (
	tailscaledWaitMin = 2 * time.Second
	tailscaledWaitMax = 30 * time.Second
)

// ProbeUntilReady repeats a read-only probe until DecideMode is not waiting
// or ctx ends. local-ai and gateway stay here while tailscaled is down.
// Backoff starts at 2s and doubles up to 30s. sleep is called only while
// waiting; a test passes a fake clock. onWait runs before each sleep.
func ProbeUntilReady(ctx context.Context, requested, role string, takeoverExplicit bool, ourControl string, probe func(context.Context) SystemView, onWait func(ModeDecision), sleep func(context.Context, time.Duration) error) (ModeDecision, error) {
	if probe == nil {
		probe = func(context.Context) SystemView { return SystemView{} }
	}
	backoff := tailscaledWaitMin
	for {
		if err := ctx.Err(); err != nil {
			return ModeDecision{}, err
		}
		var view SystemView
		if requested == "" || requested == ModeAuto || RequiresSystem(role) {
			view = probe(ctx)
		}
		d, err := DecideMode(requested, role, takeoverExplicit, view, ourControl)
		if err != nil || !d.Waiting {
			return d, err
		}
		if onWait != nil {
			onWait(d)
		}
		if sleep == nil {
			return d, errors.New("waiting for tailscaled without a retry function")
		}
		if err := sleep(ctx, backoff); err != nil {
			return d, err
		}
		if backoff < tailscaledWaitMax {
			backoff *= 2
			if backoff > tailscaledWaitMax {
				backoff = tailscaledWaitMax
			}
		}
	}
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
