package netdetect

import (
	"strings"
	"testing"
)

func TestParseProcNetRouteSkipsSplitRejectAndBadMetric(t *testing.T) {
	const table = "" +
		"Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0\n" +
		"tun0 00000000 0101A8C0 0003 0 0 50 00000080 0 0 0\n" +
		"eth1 00000000 0201A8C0 0201 0 0 0 00000000 0 0 0\n" +
		"eth2 00000000 0301A8C0 0003 0 0 zzz 00000000 0 0 0\n"
	got, ok := ParseProcNetRoute(strings.NewReader(table))
	if !ok || got.Iface != "eth0" || got.Gateway != "192.168.1.1" || got.Metric != 100 {
		t.Fatalf("%+v ok=%v", got, ok)
	}
	// A reject route is the only row, so there is no default.
	const rejectOnly = "Iface Destination Gateway Flags RefCnt Use Metric Mask\n" +
		"eth1 00000000 0201A8C0 0201 0 0 0 00000000\n"
	if _, ok := ParseProcNetRoute(strings.NewReader(rejectOnly)); ok {
		t.Fatal("RTF_REJECT was accepted")
	}
}
