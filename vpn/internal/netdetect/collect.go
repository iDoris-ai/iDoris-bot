package netdetect

import (
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// Collect reads the local machine. On Linux it also reads /proc/net/route,
// ip_forward, and /dev/net/tun. On macOS and Windows the interface list is
// best-effort and GatewaySupported stays false.
func Collect(mode string) (Snapshot, error) {
	snap := Snapshot{Platform: runtime.GOOS, Mode: mode}
	ifaces, err := net.Interfaces()
	if err != nil {
		return snap, err
	}
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		item := Iface{
			Name:         ifi.Name,
			Up:           ifi.Flags&net.FlagUp != 0,
			Loopback:     ifi.Flags&net.FlagLoopback != 0,
			PointToPoint: ifi.Flags&net.FlagPointToPoint != 0,
		}
		for _, a := range addrs {
			item.Addrs = append(item.Addrs, a.String())
		}
		snap.Ifaces = append(snap.Ifaces, item)
	}
	if runtime.GOOS == "linux" {
		fillLinux(&snap)
	}
	root := os.Geteuid() == 0
	snap.Root = &root
	up := tailscaledReachable()
	snap.TailscaledReachable = &up
	return snap, nil
}

func fillLinux(snap *Snapshot) {
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		if route, ok := ParseProcNetRoute(strings.NewReader(string(b))); ok {
			snap.Default = &route
		}
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		on := strings.TrimSpace(string(b)) == "1"
		snap.IPForward = &on
	}
	st, err := os.Stat("/dev/net/tun")
	present := err == nil && !st.IsDir()
	snap.TunPresent = &present
}

func tailscaledReachable() bool {
	paths := []string{
		"/var/run/tailscale/tailscaled.sock",
		"/var/run/tailscaled.socket",
	}
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			paths = append(paths, home+"/.local/share/tailscale/tailscaled.sock")
		}
	}
	for _, p := range paths {
		c, err := net.DialTimeout("unix", p, 300*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
	}
	return false
}
