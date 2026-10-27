package vpnd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigFileAndEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vpnd.json")
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("idv1_abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"control_url":"https://vpn.example.org","enroll_url":"https://enroll.example.org","enroll_token_file":"`+tok+`","listen":"tcp:127.0.0.1:7845"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IDORIS_VPN_HOSTNAME", "from-env")
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Resolve(); err != nil {
		t.Fatal(err)
	}
	if cfg.EnrollToken != "idv1_abc" || cfg.Hostname != "from-env" || !cfg.AcceptDNSValue() || cfg.TakeoverValue() {
		t.Fatalf("%+v", cfg)
	}
	if cfg.Mode != ModeAuto {
		t.Fatalf("mode %q", cfg.Mode)
	}
}

func TestResolveRejectsIncomplete(t *testing.T) {
	c := &Config{ControlURL: "https://x"}
	if err := c.Resolve(); err == nil {
		t.Fatal("no credentials must fail")
	}
	c = &Config{EnrollURL: "https://e"}
	if err := c.Resolve(); err == nil {
		t.Fatal("enroll url without token must fail")
	}
	c = &Config{AuthKey: "k"}
	if err := c.Resolve(); err == nil {
		t.Fatal("static key without control url must fail")
	}
	c = &Config{AuthKey: "k", ControlURL: "https://x", Listen: "tcp:0.0.0.0:1"}
	if err := c.Resolve(); err == nil {
		t.Fatal("non-loopback listen must fail")
	}
	c = &Config{AuthKey: "k", ControlURL: "https://x"}
	if err := c.Resolve(); err != nil || c.Listen == "" {
		t.Fatalf("defaults: %v %+v", err, c)
	}
}

func TestTakeoverEnvAndEmbeddedRoutes(t *testing.T) {
	t.Setenv("IDORIS_VPN_AUTH_KEY", "k")
	t.Setenv("IDORIS_VPN_CONTROL_URL", "https://vpn.example")
	t.Setenv("IDORIS_VPN_TAKEOVER", "true")
	t.Setenv("IDORIS_VPN_MODE", "system")
	t.Setenv("IDORIS_VPN_ADVERTISE_ROUTES", "192.168.1.0/24, 10.0.0.0/8")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Resolve(); err != nil {
		t.Fatal(err)
	}
	if !cfg.TakeoverValue() || cfg.Mode != ModeSystem {
		t.Fatalf("%+v", cfg)
	}
	routes, err := cfg.RoutePrefixes()
	if err != nil || len(routes) != 2 {
		t.Fatalf("%v %v", routes, err)
	}

	t.Setenv("IDORIS_VPN_MODE", "embedded")
	cfg, err = LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Resolve(); err == nil || !strings.Contains(err.Error(), "embedded") {
		t.Fatalf("embedded routes must be rejected, got %v", err)
	}
}

func TestForwardsRejectNonLoopback(t *testing.T) {
	c := &Config{
		AuthKey:    "k",
		ControlURL: "https://x",
		Forwards:   []Forward{{Listen: "0.0.0.0:11434", Target: "acme-local-ai:11434"}},
	}
	if err := c.Resolve(); err == nil {
		t.Fatal("non-loopback forward must fail")
	}
	c.Forwards = []Forward{{Listen: "127.0.0.1:11434", Target: "not-a-target"}}
	if err := c.Resolve(); err == nil {
		t.Fatal("target without port must fail")
	}
	c.Forwards = []Forward{{Listen: "127.0.0.1:11434", Target: "acme-local-ai:11434"}}
	c.SOCKS5Listen = "127.0.0.1:1055"
	if err := c.Resolve(); err != nil {
		t.Fatal(err)
	}
	c.AdvertiseRoutes = []string{"192.168.1.1/24"}
	if err := c.Resolve(); err == nil {
		t.Fatal("non-canonical CIDR must fail")
	}
	c.AdvertiseRoutes = []string{"not-a-cidr"}
	if err := c.Resolve(); err == nil {
		t.Fatal("invalid CIDR must fail")
	}
}

func TestLoadConfigUnknownField(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(p, []byte(`{"control_url":"https://x","typo":1}`), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}
