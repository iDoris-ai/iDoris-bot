// Package netdetect finds the LAN a gateway could advertise.
//
// Detect is a pure function of a Snapshot so the filters can be table-tested.
// Collect is the thin OS adapter: Linux reads net.Interfaces and
// /proc/net/route; other systems do a best-effort interface list and are
// marked unsupported for the gateway role.
package netdetect

import (
	"net/netip"
	"strings"
)

// Notice is a stable warning a UI can translate.
type Notice struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

// Iface is one interface in a snapshot. Addrs are CIDR strings
// ("192.168.1.20/24") as net.Interface.Addrs returns them.
type Iface struct {
	Name     string
	Up       bool
	Loopback bool
	Addrs    []string
}

// DefaultRoute is the IPv4 default route, when the OS has one.
type DefaultRoute struct {
	Iface   string
	Gateway string
	Metric  int
}

// Snapshot is everything Detect needs. Pointer fields are nil when the OS
// adapter could not answer.
type Snapshot struct {
	Platform            string
	Ifaces              []Iface
	Default             *DefaultRoute
	IPForward           *bool
	TunPresent          *bool
	Root                *bool
	TailscaledReachable *bool
	// Mode is the daemon mode that would run: system, embedded, auto, or empty.
	Mode string
}

// Candidate is one RFC1918 IPv4 address that could front a gateway.
type Candidate struct {
	Name     string   `json:"name"`
	Addr     string   `json:"addr"`
	Bits     int      `json:"bits"`
	Network  string   `json:"network"`
	Gateway  string   `json:"gateway,omitempty"`
	Default  bool     `json:"default"`
	Warnings []Notice `json:"warnings,omitempty"`
}

// Check is one prerequisite for advertising a LAN.
type Check struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// Report is the detection result. GatewaySupported is true only on Linux.
type Report struct {
	Platform         string      `json:"platform"`
	GatewaySupported bool        `json:"gateway_supported"`
	Candidates       []Candidate `json:"candidates"`
	Recommended      *Candidate  `json:"recommended,omitempty"`
	Warnings         []Notice    `json:"warnings,omitempty"`
	Checks           []Check     `json:"checks"`
}

// Common home LAN prefixes. Advertising one of these as a subnet route can
// shadow a member's own home network. A /32 does not.
var commonLAN = []netip.Prefix{
	netip.MustParsePrefix("192.168.0.0/24"),
	netip.MustParsePrefix("192.168.1.0/24"),
	netip.MustParsePrefix("192.168.2.0/24"),
	netip.MustParsePrefix("10.0.0.0/24"),
	netip.MustParsePrefix("10.0.1.0/24"),
	netip.MustParsePrefix("172.16.0.0/24"),
	netip.MustParsePrefix("172.16.1.0/24"),
}

var (
	rfc1918 = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
)

// Detect filters snap down to gateway candidates. It does not touch the OS.
func Detect(snap Snapshot) Report {
	rep := Report{
		Platform:         snap.Platform,
		GatewaySupported: snap.Platform == "linux",
	}
	var candidates []Candidate
	for _, ifi := range snap.Ifaces {
		if !ifi.Up || ifi.Loopback || virtualIface(ifi.Name) {
			continue
		}
		for _, raw := range ifi.Addrs {
			c, ok := candidateFrom(ifi.Name, raw, snap.Default)
			if !ok {
				continue
			}
			candidates = append(candidates, c)
		}
	}
	annotateOverlaps(candidates)
	rep.Candidates = candidates
	if rec, ok := recommend(candidates); ok {
		cp := rec
		rep.Recommended = &cp
	} else if len(candidates) > 0 {
		rep.Warnings = append(rep.Warnings, Notice{
			Code: "no-default-route",
			Text: "No default route matches a private LAN address, so there is no recommended interface.",
		})
	}
	if !rep.GatewaySupported {
		rep.Warnings = append(rep.Warnings, Notice{
			Code: "platform",
			Text: "A subnet-router gateway is only supported on Linux. This scan is best-effort and will not be applied.",
		})
	}
	rep.Checks = checks(snap, rep.GatewaySupported)
	return rep
}

func candidateFrom(iface, raw string, def *DefaultRoute) (Candidate, bool) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return Candidate{}, false
	}
	addr := p.Addr()
	if !addr.Is4() || !addr.IsValid() || !isRFC1918(addr) || cgnat.Contains(addr) {
		return Candidate{}, false
	}
	network := p.Masked()
	c := Candidate{
		Name:    iface,
		Addr:    addr.String(),
		Bits:    network.Bits(),
		Network: network.String(),
	}
	if def != nil && def.Iface == iface {
		c.Default = true
		c.Gateway = def.Gateway
	}
	for _, home := range commonLAN {
		if network.Overlaps(home) {
			c.Warnings = append(c.Warnings, Notice{
				Code: "common-lan",
				Text: "Network " + network.String() + " overlaps the common home range " + home.String() + ". Prefer a /32 so a member's own LAN is not shadowed.",
			})
		}
	}
	return c, true
}

func isRFC1918(addr netip.Addr) bool {
	for _, p := range rfc1918 {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func virtualIface(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "docker0", "lo", "lo0":
		return true
	}
	for _, p := range []string{"tailscale", "utun", "br-", "veth", "virbr", "vmnet", "cni", "flannel"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func annotateOverlaps(cs []Candidate) {
	nets := make([]netip.Prefix, len(cs))
	for i, c := range cs {
		nets[i] = netip.MustParsePrefix(c.Network)
	}
	for i := range cs {
		for j := range cs {
			if i == j || cs[i].Name == cs[j].Name {
				continue
			}
			if nets[i].Overlaps(nets[j]) {
				cs[i].Warnings = append(cs[i].Warnings, Notice{
					Code: "overlap-iface",
					Text: "Network " + cs[i].Network + " on " + cs[i].Name + " overlaps " + cs[j].Network + " on " + cs[j].Name + ".",
				})
				break
			}
		}
	}
}

func recommend(cs []Candidate) (Candidate, bool) {
	var best Candidate
	found := false
	for _, c := range cs {
		if !c.Default {
			continue
		}
		if !found || c.Bits > best.Bits {
			best = c
			found = true
		}
	}
	return best, found
}

func checks(snap Snapshot, linux bool) []Check {
	out := []Check{platformCheck(linux)}
	if linux {
		out = append(out, forwardCheck(snap.IPForward), tunCheck(snap.TunPresent))
	}
	out = append(out, rootCheck(snap.Root), tailscaleCheck(snap.TailscaledReachable), modeCheck(snap.Mode))
	return out
}

func platformCheck(linux bool) Check {
	if linux {
		return Check{ID: "platform", OK: true, Detail: "Linux can run a subnet-router gateway."}
	}
	return Check{
		ID:     "platform",
		OK:     false,
		Detail: "Gateway setup is only supported on Linux.",
		Fix:    "Run the gateway wizard on a Linux machine in the office LAN.",
	}
}

func forwardCheck(v *bool) Check {
	if v != nil && *v {
		return Check{ID: "ip_forward", OK: true, Detail: "net.ipv4.ip_forward is 1."}
	}
	return Check{
		ID:     "ip_forward",
		OK:     false,
		Detail: "IPv4 forwarding is off, so a subnet route would not be forwarded.",
		Fix:    "sudo sysctl -w net.ipv4.ip_forward=1  (idoris-vpnd writes /etc/sysctl.d/99-idoris-vpn.conf when run as root)",
	}
}

func tunCheck(v *bool) Check {
	if v != nil && *v {
		return Check{ID: "tun", OK: true, Detail: "/dev/net/tun is present."}
	}
	return Check{
		ID:     "tun",
		OK:     false,
		Detail: "/dev/net/tun is missing, so tailscaled cannot open a TUN device.",
		Fix:    "Load the tun module and pass /dev/net/tun into the host.",
	}
}

func rootCheck(v *bool) Check {
	if v != nil && *v {
		return Check{ID: "root", OK: true, Detail: "Running as root, so forwarding can be enabled."}
	}
	return Check{
		ID:     "root",
		OK:     false,
		Detail: "Not root. The daemon config can still be written. Forwarding will not be changed.",
		Fix:    "Re-run the privileged step with sudo. The wizard prints the exact command.",
	}
}

func tailscaleCheck(v *bool) Check {
	if v != nil && *v {
		return Check{ID: "tailscaled", OK: true, Detail: "tailscaled answered on its local socket."}
	}
	return Check{
		ID:     "tailscaled",
		OK:     false,
		Detail: "tailscaled is not reachable.",
		Fix:    "Install the official Tailscale client and start tailscaled before enabling the gateway.",
	}
}

func modeCheck(mode string) Check {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto", "system":
		detail := "Gateway apply pins mode to system."
		if mode == "system" {
			detail = "Mode is system."
		}
		return Check{ID: "mode", OK: true, Detail: detail}
	case "embedded":
		return Check{
			ID:     "mode",
			OK:     false,
			Detail: "Embedded mode has no TUN and cannot be a subnet router.",
			Fix:    "Set mode to system. An embedded node is left unchanged.",
		}
	default:
		return Check{ID: "mode", OK: false, Detail: "Unknown mode " + mode + ".", Fix: "Set mode to system."}
	}
}
