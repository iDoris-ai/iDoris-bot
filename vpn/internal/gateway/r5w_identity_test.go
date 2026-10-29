package gateway

import (
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

func TestR5WApplyReportsDiscoveryIdentityWhenThePinIsDropped(t *testing.T) {
	const (
		hsB   = "https://hs-b.example"
		token = "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	p, err := SimplePlan(join.RoleMember, "beta", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = "https://b.example"
	p.ConfigPath = "/home/acme/.idoris/vpn.json"
	p.TokenFile = "/home/acme/.idoris/enroll.token"
	p.DiscoveryControlURL = hsB
	h := newMemHost(false, "darwin")
	h.files[p.ConfigPath] = []byte("{\n  \"enroll_url\": \"https://a.example\",\n  \"control_url\": \"https://hs-a.example\",\n  \"hostname\": \"old\"\n}\n")
	res, err := Apply(p, h, ApplyOptions{Token: token, NoService: true, ReplaceExisting: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ControlPinDropped || res.ControlURL != "" {
		t.Fatalf("pin kept: dropped=%v control=%q", res.ControlPinDropped, res.ControlURL)
	}
	fp := vpnd.TokenFingerprint(token)
	if res.DiscoveryControlURL != hsB || res.Tenant != "beta" || res.TokenFingerprint != fp || fp == "" || strings.Contains(fp, token) {
		t.Fatalf("identity %+v fingerprint %q", res, fp)
	}
}
