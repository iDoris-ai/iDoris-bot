package netdetect

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func boolp(v bool) *bool { return &v }

func linuxSnap() Snapshot {
	return Snapshot{
		Platform: "linux",
		Ifaces: []Iface{
			{Name: "lo", Up: true, Loopback: true, Addrs: []string{"127.0.0.1/8"}},
			{Name: "eth0", Up: true, Addrs: []string{"192.168.1.20/24", "fe80::1/64"}},
			{Name: "docker0", Up: true, Addrs: []string{"172.17.0.1/16"}},
			{Name: "br-ab", Up: true, Addrs: []string{"172.18.0.1/16"}},
			{Name: "veth123", Up: true, Addrs: []string{"10.1.1.1/24"}},
			{Name: "tailscale0", Up: true, Addrs: []string{"100.64.0.7/32"}},
			{Name: "utun3", Up: true, Addrs: []string{"10.9.9.9/32"}},
			{Name: "eth1", Up: false, Addrs: []string{"10.50.0.5/24"}},
			{Name: "eth2", Up: true, Addrs: []string{"100.64.1.8/32", "10.251.73.4/24"}},
		},
		Default:             &DefaultRoute{Iface: "eth0", Gateway: "192.168.1.1", Metric: 100},
		IPForward:           boolp(false),
		TunPresent:          boolp(true),
		Root:                boolp(false),
		TailscaledReachable: boolp(true),
		Mode:                "system",
	}
}

func TestDetectFiltersAndRecommendsDefault(t *testing.T) {
	rep := Detect(linuxSnap())
	if !rep.GatewaySupported {
		t.Fatal("linux must be supported")
	}
	got := map[string]Candidate{}
	for _, c := range rep.Candidates {
		got[c.Name+"/"+c.Addr] = c
	}
	if _, ok := got["eth0/192.168.1.20"]; !ok {
		t.Fatalf("missing eth0: %+v", rep.Candidates)
	}
	if _, ok := got["eth2/10.251.73.4"]; !ok {
		t.Fatalf("missing lab iface: %+v", rep.Candidates)
	}
	for _, banned := range []string{"lo", "docker0", "br-ab", "veth123", "tailscale0", "utun3", "eth1"} {
		for _, c := range rep.Candidates {
			if c.Name == banned {
				t.Fatalf("kept %s", banned)
			}
		}
	}
	if rep.Recommended == nil || rep.Recommended.Name != "eth0" || !rep.Recommended.Default || rep.Recommended.Gateway != "192.168.1.1" {
		t.Fatalf("recommended %+v", rep.Recommended)
	}
	if !hasCode(rep.Recommended.Warnings, "common-lan") {
		t.Fatalf("expected common-lan on 192.168.1.0/24: %+v", rep.Recommended.Warnings)
	}
	lab := got["eth2/10.251.73.4"]
	if hasCode(lab.Warnings, "common-lan") {
		t.Fatalf("unusual lab prefix should not warn: %+v", lab.Warnings)
	}
	if lab.Network != "10.251.73.0/24" {
		t.Fatalf("network %s", lab.Network)
	}
}

func TestDetectOverlapAndNoDefault(t *testing.T) {
	snap := Snapshot{
		Platform: "linux",
		Ifaces: []Iface{
			{Name: "eth0", Up: true, Addrs: []string{"10.0.0.4/24"}},
			{Name: "eth1", Up: true, Addrs: []string{"10.0.0.9/16"}},
		},
		IPForward: boolp(true), TunPresent: boolp(true), Root: boolp(true),
		TailscaledReachable: boolp(true), Mode: "auto",
	}
	rep := Detect(snap)
	if rep.Recommended != nil {
		t.Fatal("no default route should not recommend")
	}
	if !hasNotice(rep.Warnings, "no-default-route") {
		t.Fatalf("warnings %+v", rep.Warnings)
	}
	if len(rep.Candidates) != 2 {
		t.Fatalf("candidates %+v", rep.Candidates)
	}
	for _, c := range rep.Candidates {
		if !hasCode(c.Warnings, "overlap-iface") {
			t.Fatalf("%s missing overlap: %+v", c.Name, c.Warnings)
		}
		if c.Name == "eth0" && !hasCode(c.Warnings, "common-lan") {
			t.Fatal("10.0.0.0/24 should warn")
		}
	}
}

func TestDetectDarwinIsUnsupported(t *testing.T) {
	snap := linuxSnap()
	snap.Platform = "darwin"
	rep := Detect(snap)
	if rep.GatewaySupported || !hasNotice(rep.Warnings, "platform") {
		t.Fatalf("%+v", rep)
	}
	var platform Check
	for _, c := range rep.Checks {
		if c.ID == "platform" {
			platform = c
		}
		if c.ID == "ip_forward" || c.ID == "tun" {
			t.Fatalf("non-linux should not claim a linux check: %+v", c)
		}
	}
	if platform.OK {
		t.Fatal("platform check should fail")
	}
}

func TestDetectChecks(t *testing.T) {
	rep := Detect(linuxSnap())
	want := map[string]bool{"platform": true, "ip_forward": false, "tun": true, "root": false, "tailscaled": true, "mode": true}
	seen := map[string]Check{}
	for _, c := range rep.Checks {
		seen[c.ID] = c
		if c.OK != want[c.ID] {
			t.Fatalf("%s ok=%v detail=%s", c.ID, c.OK, c.Detail)
		}
		if !c.OK && c.Fix == "" {
			t.Fatalf("%s missing fix", c.ID)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("checks %+v", seen)
	}
	snap := linuxSnap()
	snap.Mode = "embedded"
	rep = Detect(snap)
	if check(rep, "mode").OK {
		t.Fatal("embedded must not pass the mode check")
	}
}

func TestParseProcNetRoute(t *testing.T) {
	const table = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
eth1	00000000	0101A8C0	0003	0	0	300	00000000	0	0	0
eth0	00000000	0100A8C0	0003	0	0	100	00000000	0	0	0
wlan0	00000000	0102A8C0	0002	0	0	50	00000000	0	0	0
`
	// wlan0 has a lower metric but flags lack RTF_UP (0x1). eth0 metric 100 wins over eth1 metric 300.
	rt, ok := ParseProcNetRoute(strings.NewReader(table))
	if !ok {
		t.Fatal("no route")
	}
	if rt.Iface != "eth0" || rt.Gateway != "192.168.0.1" || rt.Metric != 100 {
		t.Fatalf("%+v", rt)
	}
	if _, ok := ParseProcNetRoute(strings.NewReader("Iface Destination\n")); ok {
		t.Fatal("header only")
	}
}

func TestProbeDevice(t *testing.T) {
	var dialed []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		if addr == "10.1.2.3:8740" {
			return &fakeConn{}, nil
		}
		return nil, errors.New("refused")
	}
	res, err := ProbeDevice(context.Background(), "10.1.2.3", dial)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reachable || res.Port != 8740 {
		t.Fatalf("%+v", res)
	}
	if len(dialed) != 2 || dialed[0] != "10.1.2.3:11434" || dialed[1] != "10.1.2.3:8740" {
		t.Fatalf("dialed %v", dialed)
	}
	for _, bad := range []string{"10.1.2.0/24", "10.1.2.3-10", "example.com", "100.64.0.1", ""} {
		dialed = nil
		if _, err := ProbeDevice(context.Background(), bad, dial); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
		if len(dialed) != 0 {
			t.Fatalf("%q dialed %v", bad, dialed)
		}
	}
	res, err = ProbeDevice(context.Background(), "10.9.9.9", dial)
	if err != nil || res.Reachable || res.Error == "" {
		t.Fatalf("unreachable %+v %v", res, err)
	}
}

func TestCollectDoesNotPanic(t *testing.T) {
	snap, err := Collect("auto")
	if err != nil {
		t.Fatal(err)
	}
	rep := Detect(snap)
	if snap.Platform == "linux" && !rep.GatewaySupported {
		t.Fatal("linux collect should be supported")
	}
	if snap.Platform != "linux" && rep.GatewaySupported {
		t.Fatal("non-linux collect must not recommend a gateway")
	}
}

func hasCode(ns []Notice, code string) bool {
	for _, n := range ns {
		if n.Code == code {
			return true
		}
	}
	return false
}

func hasNotice(ns []Notice, code string) bool { return hasCode(ns, code) }

func check(rep Report, id string) Check {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c
		}
	}
	return Check{}
}

type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, errors.New("closed") }
func (fakeConn) Write([]byte) (int, error)        { return 0, errors.New("closed") }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return nil }
func (fakeConn) RemoteAddr() net.Addr             { return nil }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }
