package vpnd

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
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

func TestRoleDefaultsAndRejectsEmbeddedService(t *testing.T) {
	c := &Config{AuthKey: "k", ControlURL: "https://x"}
	if err := c.Resolve(); err != nil || c.Role != "member" {
		t.Fatalf("default role: %v %+v", err, c.Role)
	}
	c = &Config{AuthKey: "k", ControlURL: "https://x", Role: "nope"}
	if err := c.Resolve(); err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("bad role: %v", err)
	}
	for _, role := range []string{"local-ai", "gateway", "Local-AI"} {
		c = &Config{AuthKey: "k", ControlURL: "https://x", Mode: ModeEmbedded, Role: role}
		if err := c.Resolve(); err == nil || !strings.Contains(err.Error(), "embedded") {
			t.Fatalf("role %s: %v", role, err)
		}
	}
	c = &Config{AuthKey: "k", ControlURL: "https://x", Mode: ModeSystem, Role: "local-ai"}
	if err := c.Resolve(); err != nil || c.Role != "local-ai" {
		t.Fatalf("system local-ai: %v %s", err, c.Role)
	}
	c = &Config{AuthKey: "k", ControlURL: "https://x", Mode: ModeAuto, Role: "gateway"}
	if err := c.Resolve(); err != nil {
		t.Fatal(err)
	}
}

func TestEnvCoversEveryJSONField(t *testing.T) {
	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := jsonFieldName(field)
		if name == "" {
			t.Fatalf("%s has no json name, so it has no IDORIS_VPN_ variable", field.Name)
		}
		sample, err := envSample(field.Type)
		if err != nil {
			t.Fatalf("%s (%s): %v", field.Name, name, err)
		}
		t.Setenv(EnvName(name), sample)
	}
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	got := reflect.ValueOf(cfg).Elem()
	for i := 0; i < typ.NumField(); i++ {
		if got.Field(i).IsZero() {
			t.Fatalf("%s was not set via %s", typ.Field(i).Name, EnvName(jsonFieldName(typ.Field(i))))
		}
	}
	if cfg.Forwards[0].Listen != "127.0.0.1:1" || len(cfg.AdvertiseRoutes) != 2 || !cfg.EnrollAllowInsecure || !cfg.AcceptRoutes {
		t.Fatalf("%+v", cfg)
	}
}

func envSample(t reflect.Type) (string, error) {
	switch t {
	case reflect.TypeOf(""):
		return "value", nil
	case reflect.TypeOf(false):
		return "true", nil
	case reflect.TypeOf((*bool)(nil)):
		return "true", nil
	case reflect.TypeOf([]string(nil)):
		return "a,b", nil
	case reflect.TypeOf([]Forward(nil)):
		return `[{"listen":"127.0.0.1:1","target":"h:2"}]`, nil
	case reflect.TypeOf(0):
		return "1", nil
	default:
		return "", fmt.Errorf("no env sample for %s; assignEnv must learn this kind", t)
	}
}

func TestUnknownVPNEnvIsRejected(t *testing.T) {
	t.Setenv("IDORIS_VPN_NOT_A_REAL_KEY", "1")
	_, err := LoadConfig("")
	if err == nil || !strings.Contains(err.Error(), "IDORIS_VPN_NOT_A_REAL_KEY") {
		t.Fatalf("%v", err)
	}
}

func TestInlineSecretAndTokenFileMustBeOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vpnd.json")
	body := []byte(`{"enroll_url":"https://enroll.example","enroll_token":"idv1_inline"}`)
	if err := os.WriteFile(cfgPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("inline secret: %v", err)
	}
	if err := os.Chmod(cfgPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath); err != nil {
		t.Fatal(err)
	}

	loose := []byte(`{"enroll_url":"https://enroll.example","enroll_token_file":"` + filepath.Join(dir, "token") + `"}`)
	loosePath := filepath.Join(dir, "loose.json")
	if err := os.WriteFile(loosePath, loose, 0o644); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("idv1_file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(loosePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Resolve(); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("token file: %v", err)
	}
	if err := os.Chmod(tok, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Resolve(); err != nil || c.EnrollToken != "idv1_file" {
		t.Fatalf("resolve: %v token=%q", err, c.EnrollToken)
	}

	key := filepath.Join(dir, "authkey")
	if err := os.WriteFile(key, []byte("hskey\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	auth := &Config{ControlURL: "https://vpn.example", AuthKeyFile: key}
	if err := auth.Resolve(); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("auth key file: %v", err)
	}
}

func TestAccessConfigValidation(t *testing.T) {
	base := func() *Config {
		return &Config{AuthKey: "k", ControlURL: "https://x"}
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "fwd.sock")
	socks := filepath.Join(dir, "socks.sock")
	okUNIX := base()
	okUNIX.Forwards = []Forward{{Listen: "unix:" + sock, Target: "acme-local-ai:11434"}}
	okUNIX.SOCKS5Listen = "unix:" + socks
	okUNIX.MaxConnections = 0
	okUNIX.DialTimeout = "10s"
	okUNIX.SOCKS5AuthFile = filepath.Join(dir, "socks5.auth")
	if err := okUNIX.Resolve(); err != nil {
		t.Fatal(err)
	}
	if okUNIX.DialTimeoutDuration() != 10*time.Second {
		t.Fatalf("dial %s", okUNIX.DialTimeoutDuration())
	}

	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "tcp loopback", mutate: func(c *Config) {
			c.Forwards = []Forward{{Listen: "127.0.0.1:11434", Target: "acme:11434"}}
			c.SOCKS5Listen = "[::1]:1055"
		}},
		{name: "non-loopback forward", mutate: func(c *Config) {
			c.Forwards = []Forward{{Listen: "0.0.0.0:1", Target: "acme:1"}}
		}, wantErr: "forwards[0].listen"},
		{name: "relative unix", mutate: func(c *Config) {
			c.SOCKS5Listen = "unix:relative.sock"
		}, wantErr: "socks5_listen"},
		{name: "world-writable parent", mutate: func(c *Config) {
			c.Forwards = []Forward{{Listen: "unix:" + filepath.Join(open, "s"), Target: "acme:1"}}
		}, wantErr: "world-writable"},
		{name: "bad dial", mutate: func(c *Config) { c.DialTimeout = "nope" }, wantErr: "dial_timeout"},
		{name: "zero dial", mutate: func(c *Config) { c.DialTimeout = "0s" }, wantErr: "dial_timeout"},
		{name: "negative dial", mutate: func(c *Config) { c.DialTimeout = "-1s" }, wantErr: "dial_timeout"},
		{name: "negative cap", mutate: func(c *Config) { c.MaxConnections = -1 }, wantErr: "max_connections"},
		{name: "anonymous with auth file", mutate: func(c *Config) {
			c.SOCKS5AllowAnonymous = true
			c.SOCKS5AuthFile = filepath.Join(dir, "a")
		}, wantErr: "socks5_allow_anonymous"},
		{name: "anonymous alone", mutate: func(c *Config) {
			c.SOCKS5Listen = "127.0.0.1:1055"
			c.SOCKS5AllowAnonymous = true
		}},
		{name: "empty dial is default", mutate: func(c *Config) { c.DialTimeout = "" }},
		{name: "cap zero is default", mutate: func(c *Config) { c.MaxConnections = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			err := c.Resolve()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err %v, want %q", err, tc.wantErr)
			}
		})
	}

	t.Setenv("IDORIS_VPN_AUTH_KEY", "k")
	t.Setenv("IDORIS_VPN_CONTROL_URL", "https://x")
	t.Setenv("IDORIS_VPN_SOCKS5_AUTH_FILE", filepath.Join(dir, "from-env"))
	t.Setenv("IDORIS_VPN_SOCKS5_ALLOW_ANONYMOUS", "false")
	t.Setenv("IDORIS_VPN_MAX_CONNECTIONS", "8")
	t.Setenv("IDORIS_VPN_DIAL_TIMEOUT", "3s")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Resolve(); err != nil {
		t.Fatal(err)
	}
	if cfg.SOCKS5AuthFile == "" || cfg.SOCKS5AllowAnonymous || cfg.MaxConnections != 8 || cfg.DialTimeoutDuration() != 3*time.Second {
		t.Fatalf("%+v", cfg)
	}
	t.Setenv("IDORIS_VPN_MAX_CONNECTIONS", "nope")
	if _, err := LoadConfig(""); err == nil || !strings.Contains(err.Error(), "IDORIS_VPN_MAX_CONNECTIONS") {
		t.Fatalf("bad int env: %v", err)
	}
}

func TestLoadConfigUnknownField(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(p, []byte(`{"control_url":"https://x","typo":1}`), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}
