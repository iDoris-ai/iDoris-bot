package netdetect

import (
	"bufio"
	"encoding/hex"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
)

// ParseProcNetRoute reads Linux /proc/net/route and returns the IPv4 default
// route with the lowest metric. The destination and gateway fields are
// little-endian hex, which is what Linux writes on little-endian hosts.
func ParseProcNetRoute(r io.Reader) (DefaultRoute, bool) {
	sc := bufio.NewScanner(r)
	bestMetric := math.MaxInt
	var best DefaultRoute
	found := false
	header := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if header {
			header = false
			continue
		}
		f := strings.Fields(line)
		// Iface, Destination, Gateway, Flags, RefCnt, Use, Metric, Mask.
		// Destination 00000000 is 0.0.0.0. Mask must be 00000000 (/0).
		// An OpenVPN split route is destination 0.0.0.0 with mask /1
		// (little-endian hex 00000080) and is not the default route.
		if len(f) < 8 || !strings.EqualFold(f[1], "00000000") || !strings.EqualFold(f[7], "00000000") {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 64)
		// RTF_UP is 0x1. RTF_REJECT is 0x200 and must not win.
		if err != nil || flags&0x1 == 0 || flags&0x200 != 0 {
			continue
		}
		gw, err := parseLEHexIPv4(f[2])
		if err != nil {
			continue
		}
		metric, err := strconv.Atoi(f[6])
		if err != nil {
			continue
		}
		if !found || metric < bestMetric {
			best = DefaultRoute{Iface: f[0], Gateway: gw, Metric: metric}
			bestMetric = metric
			found = true
		}
	}
	return best, found
}

// ParseIPRoute reads Linux `ip route` text and returns the IPv4 default route
// with the lowest metric. Only destination "default" or "0.0.0.0/0" counts.
// A split default such as 0.0.0.0/1 is not a default route.
func ParseIPRoute(r io.Reader) (DefaultRoute, bool) {
	return parseDefaultLines(r, func(f []string) (DefaultRoute, bool) {
		if len(f) < 3 {
			return DefaultRoute{}, false
		}
		if f[0] != "default" && f[0] != "0.0.0.0/0" {
			return DefaultRoute{}, false
		}
		rt := DefaultRoute{}
		for i := 1; i < len(f); i++ {
			switch f[i] {
			case "via":
				if i+1 < len(f) {
					rt.Gateway = f[i+1]
				}
			case "dev":
				if i+1 < len(f) {
					rt.Iface = f[i+1]
				}
			case "metric":
				if i+1 < len(f) {
					if n, err := strconv.Atoi(f[i+1]); err == nil {
						rt.Metric = n
					}
				}
			}
		}
		if rt.Iface == "" {
			return DefaultRoute{}, false
		}
		return rt, true
	})
}

// ParseNetstatRN reads macOS/BSD `netstat -rn` text. Only a destination of
// "default" counts. 0/1 and 0.0.0.0/1 are split routes, not the default.
// The first default row wins; BSD prints the selected route first and the
// table has no metric column we can trust across releases.
func ParseNetstatRN(r io.Reader) (DefaultRoute, bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || !strings.EqualFold(f[0], "default") {
			continue
		}
		iface := f[len(f)-1]
		if _, err := strconv.Atoi(iface); err == nil && len(f) >= 5 {
			iface = f[len(f)-2]
		}
		if iface == "" || strings.EqualFold(iface, "expire") {
			continue
		}
		return DefaultRoute{Iface: iface, Gateway: f[1]}, true
	}
	return DefaultRoute{}, false
}

func parseDefaultLines(r io.Reader, parse func([]string) (DefaultRoute, bool)) (DefaultRoute, bool) {
	sc := bufio.NewScanner(r)
	bestMetric := math.MaxInt
	var best DefaultRoute
	found := false
	for sc.Scan() {
		rt, ok := parse(strings.Fields(sc.Text()))
		if !ok {
			continue
		}
		if !found || rt.Metric < bestMetric {
			best = rt
			bestMetric = rt.Metric
			found = true
		}
	}
	return best, found
}

func parseLEHexIPv4(s string) (string, error) {
	if len(s) != 8 {
		return "", hex.ErrLength
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	ip := netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]})
	return ip.String(), nil
}
