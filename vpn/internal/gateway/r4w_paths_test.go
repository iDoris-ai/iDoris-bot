package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

func TestR4WSidecarUsesTheWholeFileName(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "h")
	jsonPath := filepath.Join(home, "org", "office.json")
	confPath := filepath.Join(home, "org", "office.conf")
	jsonP := PathsFor(home, jsonPath)
	confP := PathsFor(home, confPath)
	if jsonP.Token != jsonPath+".enroll-token" || jsonP.Plan != jsonPath+".gateway-plan.json" {
		t.Fatalf("json sidecars %+v", jsonP)
	}
	if confP.Token != confPath+".enroll-token" || confP.Plan != confPath+".gateway-plan.json" {
		t.Fatalf("conf sidecars %+v", confP)
	}
	if jsonP.Token == confP.Token || jsonP.Plan == confP.Plan {
		t.Fatal("office.json and office.conf share a sidecar")
	}
	def := PathsFor(home, "")
	if def.Token != filepath.Join(home, ".idoris", "enroll.token") || def.Plan != filepath.Join(home, ".idoris", "gateway-plan.json") {
		t.Fatalf("default %+v", def)
	}
	historical := PathsFor("", filepath.Join(home, ".idoris", "vpn.json"))
	if historical.Token != def.Token || historical.Plan != def.Plan {
		t.Fatalf("historical default without home: %+v", historical)
	}
}

func TestR4WLegacySharedTokenIsNotOverwritten(t *testing.T) {
	const shared = "/home/acme/.idoris/enroll.token"
	const cfg = "/home/acme/org/office.json"
	p, err := SimplePlan(join.RoleMember, "acme", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = "https://b.example"
	p.ConfigPath = cfg
	// A plan left over from the shared-token layout still names that file.
	p.TokenFile = shared
	h := newMemHost(false, "darwin")
	h.files[shared] = []byte("OLD-SHARED\n")
	h.files[cfg] = []byte("{\n  \"enroll_url\": \"https://a.example\",\n  \"enroll_token_file\": \"/home/acme/.idoris/enroll.token\"\n}\n")
	if _, err := Apply(p, h, ApplyOptions{Token: "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", NoService: true, ReplaceExisting: true}); err != nil {
		t.Fatal(err)
	}
	if string(h.files[shared]) != "OLD-SHARED\n" {
		t.Fatalf("shared token overwritten: %q", h.files[shared])
	}
	own := cfg + ".enroll-token"
	if string(h.files[own]) != "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n" {
		t.Fatalf("sidecar %q", h.files[own])
	}
	body := string(h.files[cfg])
	if !strings.Contains(body, `"enroll_token_file": "`+own+`"`) || strings.Contains(body, shared) {
		t.Fatalf("config still points at the shared token:\n%s", body)
	}
}
