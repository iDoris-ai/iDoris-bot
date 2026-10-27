package vpnd

// AccessOpen reports whether a local forward or SOCKS5 listener may dial.
// Embedded mode is always open: that node is the only path into the tailnet.
// System mode is open only when the reconciler's current control URL is ours
// and the phase still carries traffic. Snapshot.ControlURL is always the URL
// this daemon wants; pass Snapshot.CurrentControl, not that field.
// Any other mode is closed.
func AccessOpen(mode, currentControl, ourControl string, phase Phase) bool {
	if mode == ModeEmbedded {
		return true
	}
	if mode != ModeSystem {
		return false
	}
	if !SameControlURL(currentControl, ourControl) {
		return false
	}
	return phase == PhaseConnected || phase == PhaseRoutesPending
}
