// Package gateway plans and applies a subnet-router or a plain join.
//
// The narrow plan advertises only the device addresses as /32. A whole-subnet
// route is an explicit choice. The client cannot approve its own routes: a
// route is marked auto-approved only when it sits inside a CIDR the enrollment
// service already published (the same list the operator put in Headscale
// autoApprovers). The plan JSON never contains an enrollment token.
package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
)

const (
	// IPForwardConf is the sysctl drop-in applied on a Linux gateway.
	IPForwardConf = "/etc/sysctl.d/99-idoris-vpn.conf"
	// IPForwardBody enables IPv4 forwarding. It is rewritten verbatim so a
	// second apply does not churn the file.
	IPForwardBody = "# Managed by idoris-vpnd. Lets this Linux host forward the office LAN.\nnet.ipv4.ip_forward = 1\n"
)

// Request is the wizard's answers plus what the machine and the server said.
type Request struct {
	ThisMachineIsLocalAI bool
	DeviceIPs            []string
	WholeSubnet          bool
	Detection            netdetect.Report
	Approved             []string
	Tenant               string
	Hostname             string
}

// Step is one action Apply will take, shown before confirmation.
type Step struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// Plan is JSON-serialisable so a root step can replay it without the token.
type Plan struct {
	Role               string             `json:"role"`
	Tag                string             `json:"tag,omitempty"`
	Routes             []string           `json:"routes,omitempty"`
	RecommendedRoutes  []string           `json:"recommended_routes,omitempty"`
	Network            string             `json:"network,omitempty"`
	Hostname           string             `json:"hostname,omitempty"`
	Tenant             string             `json:"tenant,omitempty"`
	Mode               string             `json:"mode"`
	AcceptRoutes       bool               `json:"accept_routes"`
	Warnings           []netdetect.Notice `json:"warnings,omitempty"`
	WillAutoApprove    bool               `json:"will_auto_approve"`
	NeedsAdminApproval bool               `json:"needs_admin_approval"`
	AdminCommand       string             `json:"admin_command,omitempty"`
	Steps              []Step             `json:"steps,omitempty"`
	PlatformOK         bool               `json:"platform_ok"`
	Blocked            bool               `json:"blocked"`
	BlockReason        string             `json:"block_reason,omitempty"`
	WholeSubnet        bool               `json:"whole_subnet"`
	DeviceIPs          []string           `json:"device_ips,omitempty"`

	EnrollURL     string `json:"enroll_url,omitempty"`
	TokenFile     string `json:"token_file,omitempty"`
	AllowInsecure bool   `json:"allow_insecure,omitempty"`
	ConfigPath    string `json:"config_path,omitempty"`
	Listen        string `json:"listen,omitempty"`
}

// BuildPlan chooses the narrowest route that matches the answers.
// ThisMachineIsLocalAI joins as local-ai and advertises nothing. Otherwise
// the plan is a Linux gateway. A blocked plan is returned (not an error) when
// the OS cannot be a gateway, so the UI can explain it. Malformed input is an error.
func BuildPlan(req Request) (Plan, error) {
	if req.ThisMachineIsLocalAI {
		return localAIPlan(req)
	}
	return gatewayPlan(req)
}

// SimplePlan is a member or admin join: no routes, accept other people's routes.
func SimplePlan(role, tenant, hostname string) (Plan, error) {
	if role != join.RoleMember && role != join.RoleAdmin {
		return Plan{}, fmt.Errorf("gateway: %q is not a member or admin join", role)
	}
	p := Plan{
		Role:            role,
		Hostname:        hostname,
		Tenant:          tenant,
		Mode:            "auto",
		AcceptRoutes:    true,
		WillAutoApprove: true,
		PlatformOK:      true,
	}
	p.Steps = baseSteps(false)
	return p, nil
}

func localAIPlan(req Request) (Plan, error) {
	tag, err := aclTag(req.Tenant, "local-ai")
	if err != nil {
		return Plan{}, err
	}
	p := Plan{
		Role:            join.RoleLocalAI,
		Tag:             tag,
		Hostname:        req.Hostname,
		Tenant:          req.Tenant,
		Mode:            "auto",
		WillAutoApprove: true,
		PlatformOK:      true,
	}
	p.Steps = baseSteps(false)
	return p, nil
}

func gatewayPlan(req Request) (Plan, error) {
	if req.WholeSubnet && len(trimNonEmpty(req.DeviceIPs)) > 0 {
		return Plan{}, fmt.Errorf("gateway: pass device addresses or whole-subnet, not both")
	}
	p := Plan{
		Role:       join.RoleGateway,
		Hostname:   req.Hostname,
		Tenant:     req.Tenant,
		Mode:       "system",
		PlatformOK: req.Detection.GatewaySupported && req.Detection.Platform == "linux",
	}
	if !p.PlatformOK {
		p.Blocked = true
		p.BlockReason = "A subnet-router gateway is only supported on Linux. This machine will not advertise a LAN."
		p.Warnings = append([]netdetect.Notice(nil), req.Detection.Warnings...)
		return p, nil
	}
	devices, err := parseDevices(req.DeviceIPs)
	if err != nil {
		return Plan{}, err
	}
	if !req.WholeSubnet && len(devices) == 0 {
		return Plan{}, fmt.Errorf("gateway: a narrow route needs at least one device IP")
	}
	cand, err := chooseNetwork(req.Detection, devices, req.WholeSubnet)
	if err != nil {
		return Plan{}, err
	}
	p.Network = cand.Network
	p.Warnings = append(p.Warnings, cand.Warnings...)
	if req.WholeSubnet {
		p.WholeSubnet = true
		p.Routes = []string{cand.Network}
		p.Warnings = append(p.Warnings, netdetect.Notice{
			Code: "whole-subnet",
			Text: "Advertising " + cand.Network + " exposes every address on that LAN and can shadow a member whose home network uses the same range. A /32 shadows only one address.",
		})
	} else {
		for _, ip := range devices {
			p.DeviceIPs = append(p.DeviceIPs, ip.String())
			p.Routes = append(p.Routes, ip.String()+"/32")
		}
		p.RecommendedRoutes = append([]string(nil), p.Routes...)
	}
	tag, err := aclTag(req.Tenant, "gateway")
	if err != nil {
		return Plan{}, err
	}
	p.Tag = tag
	p.WillAutoApprove = allCovered(p.Routes, req.Approved)
	if p.WillAutoApprove {
		p.Steps = append(baseSteps(true), Step{ID: "routes", Text: "Advertise " + strings.Join(p.Routes, ", ") + " (pre-approved)"})
	} else {
		p.NeedsAdminApproval = true
		p.AdminCommand = AdminCommand(p.Hostname, p.Routes)
		p.Warnings = append(p.Warnings, netdetect.Notice{
			Code: "needs-approval",
			Text: "These routes are not in the organisation's pre-approved list. The node stays connected and waits for an admin.",
		})
		p.Steps = append(baseSteps(true),
			Step{ID: "routes", Text: "Advertise " + strings.Join(p.Routes, ", ")},
			Step{ID: "approve", Text: "An admin runs: " + p.AdminCommand},
		)
	}
	return p, nil
}

// LoadPlan reads a plan file. Unknown fields are rejected so a token cannot
// hide in an extra key. The reader is capped at 1 MiB.
func LoadPlan(r io.Reader) (Plan, error) {
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	var p Plan
	if err := dec.Decode(&p); err != nil {
		return Plan{}, fmt.Errorf("gateway: plan: %w", err)
	}
	return p, nil
}

// AdminCommand is the Headscale CLI that approves routes. identifier is the
// node hostname; Headscale also accepts the numeric node id from `nodes list`.
func AdminCommand(hostname string, routes []string) string {
	id := hostname
	if id == "" {
		id = "<NODE>"
	}
	return "headscale nodes approve-routes --identifier " + id + " --routes " + strings.Join(routes, ",")
}

func baseSteps(forward bool) []Step {
	steps := []Step{
		{ID: "config", Text: "Write the daemon config"},
		{ID: "token", Text: "Store the enrollment token in a mode 0600 file"},
	}
	if forward {
		steps = append(steps, Step{ID: "forward", Text: "Enable net.ipv4.ip_forward on Linux"})
	}
	steps = append(steps, Step{ID: "service", Text: "Install and start the user service"})
	return steps
}

func chooseNetwork(rep netdetect.Report, devices []netip.Addr, whole bool) (netdetect.Candidate, error) {
	if whole {
		if rep.Recommended != nil {
			return *rep.Recommended, nil
		}
		if len(rep.Candidates) == 1 {
			return rep.Candidates[0], nil
		}
		return netdetect.Candidate{}, fmt.Errorf("gateway: no single LAN to advertise")
	}
	var chosen *netdetect.Candidate
	for _, ip := range devices {
		var match *netdetect.Candidate
		for i := range rep.Candidates {
			p, err := netip.ParsePrefix(rep.Candidates[i].Network)
			if err != nil {
				return netdetect.Candidate{}, fmt.Errorf("gateway: candidate network: %w", err)
			}
			if !p.Contains(ip) {
				continue
			}
			if match == nil || rep.Candidates[i].Bits > match.Bits {
				c := rep.Candidates[i]
				match = &c
			}
		}
		if match == nil {
			return netdetect.Candidate{}, fmt.Errorf("gateway: %s is not on a detected private LAN", ip)
		}
		if chosen == nil {
			chosen = match
			continue
		}
		if match.Network != chosen.Network {
			return netdetect.Candidate{}, fmt.Errorf("gateway: devices span %s and %s", chosen.Network, match.Network)
		}
	}
	if chosen == nil {
		return netdetect.Candidate{}, fmt.Errorf("gateway: no LAN selected")
	}
	return *chosen, nil
}

func parseDevices(ips []string) ([]netip.Addr, error) {
	var out []netip.Addr
	seen := map[netip.Addr]struct{}{}
	for _, s := range ips {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			return nil, fmt.Errorf("gateway: %q is a network; pass one device address", s)
		}
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("gateway: %q is not an IPv4 address", s)
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out, nil
}

func trimNonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func allCovered(routes, approved []string) bool {
	if len(routes) == 0 {
		return true
	}
	for _, route := range routes {
		if !covered(route, approved) {
			return false
		}
	}
	return true
}

// covered reports whether route is equal to or a subset of some approved prefix.
func covered(route string, approved []string) bool {
	r, err := netip.ParsePrefix(route)
	if err != nil {
		return false
	}
	for _, a := range approved {
		p, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil {
			continue
		}
		if p.Bits() <= r.Bits() && p.Overlaps(r) {
			return true
		}
	}
	return false
}

func aclTag(tenant, suffix string) (string, error) {
	if tenant == "" {
		return "", fmt.Errorf("gateway: tenant is required")
	}
	for _, r := range tenant {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		default:
			return "", fmt.Errorf("gateway: tenant %q cannot be used in an ACL tag", tenant)
		}
	}
	return "tag:" + tenant + "-" + suffix, nil
}
