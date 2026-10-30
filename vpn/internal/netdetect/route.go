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
		// Destination 00000000 with any other mask is a split route (0.0.0.0/1),
		// which OpenVPN redirect-gateway def1 installs. It is not the default.
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
