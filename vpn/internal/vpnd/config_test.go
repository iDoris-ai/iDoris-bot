package vpnd

import (
	"os"
	"path/filepath"
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
	if cfg.EnrollToken != "idv1_abc" || cfg.Hostname != "from-env" || !cfg.AcceptDNSValue() || !cfg.TakeoverValue() {
		t.Fatalf("%+v", cfg)
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

func TestLoadConfigUnknownField(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(p, []byte(`{"control_url":"https://x","typo":1}`), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}
