package vpnd

import (
	"net/netip"
	"strings"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/views"
)

// RouteReport is one configured advertise_routes entry and whether Headscale
// has approved it. Approval is read from Status.Self.PrimaryRoutes and
// AllowedIPs (tailscale.com v1.104.2 copies both onto Self). The node stays
// logged in either way; an unapproved route only changes the phase.
type RouteReport struct {
	CIDR       string `json:"cidr"`
	Advertised bool   `json:"advertised"`
	Approved   bool   `json:"approved"`
}

// routePhase reports configured routes. With none configured the phase stays
// connected and the route list is omitted. Any unapproved route switches the
// phase to routes-pending-approval and fills the admin command.
func routePhase(hostname string, want []netip.Prefix, st *ipnstate.Status) (routes []RouteReport, hint string, phase Phase) {
	phase = PhaseConnected
	if len(want) == 0 {
		return nil, "", phase
	}
	var self *ipnstate.PeerStatus
	if st != nil {
		self = st.Self
	}
	var pending []string
	routes = make([]RouteReport, 0, len(want))
	for _, prefix := range want {
		ok := prefixApproved(prefix, self)
		routes = append(routes, RouteReport{CIDR: prefix.String(), Advertised: true, Approved: ok})
		if !ok {
			pending = append(pending, prefix.String())
		}
	}
	if len(pending) > 0 {
		phase = PhaseRoutesPending
		hint = adminApproveCommand(hostname, pending)
	}
	return routes, hint, phase
}

// prefixApproved is true when some approved prefix equals want or covers it.
// A covering prefix is wider (fewer bits) and contains want's address, so a
// tailnet /32 cannot approve an RFC1918 route.
func prefixApproved(want netip.Prefix, self *ipnstate.PeerStatus) bool {
	if !want.IsValid() || self == nil {
		return false
	}
	want = want.Masked()
	return sliceCovers(self.PrimaryRoutes, want) || sliceCovers(self.AllowedIPs, want)
}

func sliceCovers(set *views.Slice[netip.Prefix], want netip.Prefix) bool {
	if set == nil || set.IsNil() {
		return false
	}
	for i := 0; i < set.Len(); i++ {
		p := set.At(i).Masked()
		if !p.IsValid() {
			continue
		}
		if p == want || (p.Bits() <= want.Bits() && p.Contains(want.Addr())) {
			return true
		}
	}
	return false
}

// adminApproveCommand is the Headscale command an operator runs. identifier
// is the node hostname; Headscale also accepts the numeric id from `nodes list`.
func adminApproveCommand(hostname string, routes []string) string {
	id := strings.TrimSpace(hostname)
	if id == "" {
		id = "<NODE>"
	}
	return "headscale nodes approve-routes --identifier " + id + " --routes " + strings.Join(routes, ",")
}
