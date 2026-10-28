package gateway

import (
	"bytes"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

func TestR4WUnknownConfigKeysAreRejectedBeforeWrite(t *testing.T) {
	p, err := SimplePlan(join.RoleMember, "acme", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = "https://enroll.example.org"
	p.ConfigPath = "/home/acme/.idoris/vpn.json"
	p.TokenFile = "/home/acme/.idoris/enroll.token"
	const existing = `{
  "enroll_url": "https://enroll.example.org",
  "hostname": "old",
  "extra_kept": true,
  "site_note": "keep-me"
}
`
	h := newMemHost(false, "darwin")
	h.files[p.ConfigPath] = []byte(existing)
	before := append([]byte(nil), h.files[p.ConfigPath]...)
	_, err = Apply(p, h, ApplyOptions{Token: "idv1_secretsecretsecretsecretsecretse", PlanPath: "/home/acme/.idoris/gateway-plan.json"})
	if err == nil || !strings.Contains(err.Error(), "extra_kept") || !strings.Contains(err.Error(), "site_note") {
		t.Fatalf("err=%v", err)
	}
	if !bytes.Equal(h.files[p.ConfigPath], before) {
		t.Fatalf("config changed:\n%s", h.files[p.ConfigPath])
	}
	if _, ok := h.files[p.TokenFile]; ok {
		t.Fatal("token file was written")
	}
	if _, ok := h.files["/home/acme/.idoris/gateway-plan.json"]; ok {
		t.Fatal("plan file was written")
	}
	if len(h.services) != 0 {
		t.Fatalf("service installed: %v", h.services)
	}
}
