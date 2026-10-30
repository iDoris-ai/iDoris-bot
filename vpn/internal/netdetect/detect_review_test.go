package netdetect

import "testing"

func TestDetectHostRouteDoesNotWarnCommonLAN(t *testing.T) {
	snap := linuxSnap()
	snap.Ifaces = []Iface{{Name: "eth0", Up: true, Addrs: []string{"192.168.1.20/32"}}}
	rep := Detect(snap)
	if len(rep.Candidates) != 1 || rep.Candidates[0].Network != "192.168.1.20/32" {
		t.Fatalf("%+v", rep.Candidates)
	}
	if hasCode(rep.Candidates[0].Warnings, "common-lan") {
		t.Fatalf("/32 warned: %+v", rep.Candidates[0].Warnings)
	}
}

func TestDetectSkipsTunnelInterfaces(t *testing.T) {
	snap := Snapshot{
		Platform: "linux",
		Ifaces: []Iface{
			{Name: "wg0", Up: true, Addrs: []string{"10.8.0.2/24"}},
			{Name: "tun0", Up: true, Addrs: []string{"10.8.0.2/24"}},
			{Name: "tap0", Up: true, Addrs: []string{"10.8.0.2/24"}},
			{Name: "zt0abc", Up: true, Addrs: []string{"10.8.0.2/24"}},
			{Name: "ppp0", Up: true, Addrs: []string{"10.8.0.2/24"}},
			{Name: "ipsec0", Up: true, Addrs: []string{"10.8.0.2/24"}},
			{Name: "eth0", Up: true, Addrs: []string{"10.251.73.4/24"}},
		},
	}
	rep := Detect(snap)
	if len(rep.Candidates) != 1 || rep.Candidates[0].Name != "eth0" {
		t.Fatalf("%+v", rep.Candidates)
	}
}
