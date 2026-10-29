package netdetect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ProbePorts are the listeners a Local AI box or office device commonly has.
// The probe dials one address on these ports. It never walks a subnet.
var ProbePorts = []int{11434, 8740, 8742, 443, 80}

// DialFunc dials one TCP address. Tests supply a fake. Nil uses a dialer
// with a one-second timeout.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ProbeResult is the outcome of dialing one device address.
type ProbeResult struct {
	IP        string `json:"ip"`
	Reachable bool   `json:"reachable"`
	Port      int    `json:"port,omitempty"`
	Tried     []int  `json:"tried"`
	Error     string `json:"error,omitempty"`
}

// ProbeDevice dials ip on ProbePorts and stops at the first success.
// ip must be a single IPv4 address. A CIDR, a hostname, or a range is refused
// so a caller cannot turn this into a scan.
func ProbeDevice(ctx context.Context, ip string, dial DialFunc) (ProbeResult, error) {
	if strings.ContainsAny(ip, "/-") || strings.Contains(ip, " ") {
		return ProbeResult{}, errors.New("netdetect: refusing to scan more than one address")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Is4() {
		return ProbeResult{}, fmt.Errorf("netdetect: %q is not one IPv4 address", ip)
	}
	if addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() || !isRFC1918(addr) || cgnat.Contains(addr) {
		return ProbeResult{}, fmt.Errorf("netdetect: %s is not a private device address", addr)
	}
	if dial == nil {
		d := &net.Dialer{Timeout: time.Second}
		dial = d.DialContext
	}
	res := ProbeResult{IP: addr.String(), Tried: append([]int(nil), ProbePorts...)}
	for _, port := range ProbePorts {
		pctx, cancel := context.WithTimeout(ctx, time.Second)
		conn, err := dial(pctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)))
		cancel()
		if err != nil {
			continue
		}
		_ = conn.Close()
		res.Reachable = true
		res.Port = port
		return res, nil
	}
	res.Error = "no common port answered"
	return res, nil
}
