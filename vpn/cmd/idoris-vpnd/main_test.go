package main

import (
	"flag"
	"strings"
	"testing"
)

func TestRunFlagsOverrideModeTakeoverAndForward(t *testing.T) {
	t.Setenv("IDORIS_VPN_AUTH_KEY", "k")
	t.Setenv("IDORIS_VPN_CONTROL_URL", "https://vpn.example")
	t.Setenv("IDORIS_VPN_MODE", "system")
	t.Setenv("IDORIS_VPN_TAKEOVER", "true")
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfg, err := loadConfig([]string{
		"--mode", "embedded",
		"--no-takeover",
		"--forward", "127.0.0.1:11434=acme-local-ai:11434",
		"--socks5-listen", "127.0.0.1:1055",
	}, fs)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "embedded" || cfg.TakeoverValue() {
		t.Fatalf("mode=%s takeover=%v", cfg.Mode, cfg.TakeoverValue())
	}
	if len(cfg.Forwards) != 1 || cfg.Forwards[0].Listen != "127.0.0.1:11434" || cfg.Forwards[0].Target != "acme-local-ai:11434" {
		t.Fatalf("forwards %+v", cfg.Forwards)
	}
	if cfg.SOCKS5Listen != "127.0.0.1:1055" {
		t.Fatalf("socks5 %q", cfg.SOCKS5Listen)
	}
}

func TestTakeoverFlagAndEmbeddedRoutes(t *testing.T) {
	t.Setenv("IDORIS_VPN_AUTH_KEY", "k")
	t.Setenv("IDORIS_VPN_CONTROL_URL", "https://vpn.example")
	t.Setenv("IDORIS_VPN_TAKEOVER", "false")
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfg, err := loadConfig([]string{"--takeover", "--mode", "system", "--advertise-routes", "192.168.1.0/24,10.0.0.0/8"}, fs)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TakeoverValue() || cfg.Mode != "system" {
		t.Fatalf("%+v", cfg)
	}
	routes, err := cfg.RoutePrefixes()
	if err != nil || len(routes) != 2 {
		t.Fatalf("%v %v", routes, err)
	}

	fs = flag.NewFlagSet("run", flag.ContinueOnError)
	_, err = loadConfig([]string{"--mode", "embedded", "--advertise-routes", "192.168.1.0/24"}, fs)
	if err == nil || !strings.Contains(err.Error(), "embedded") {
		t.Fatalf("embedded routes: %v", err)
	}
}

func TestAcceptDNSAndAdvertiseTagsFlags(t *testing.T) {
	t.Setenv("IDORIS_VPN_AUTH_KEY", "k")
	t.Setenv("IDORIS_VPN_CONTROL_URL", "https://vpn.example")
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfg, err := loadConfig([]string{"--accept-dns", "false", "--advertise-tags", "tag:a, tag:b", "--mode", "system"}, fs)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AcceptDNS == nil || *cfg.AcceptDNS {
		t.Fatalf("accept_dns %+v", cfg.AcceptDNS)
	}
	if len(cfg.AdvertiseTags) != 2 || cfg.AdvertiseTags[1] != "tag:b" {
		t.Fatalf("tags %+v", cfg.AdvertiseTags)
	}
	fs = flag.NewFlagSet("run", flag.ContinueOnError)
	if _, err := loadConfig([]string{"--accept-dns", "maybe"}, fs); err == nil || !strings.Contains(err.Error(), "accept-dns") {
		t.Fatalf("%v", err)
	}
}

func TestTakeoverAndNoTakeoverExclusive(t *testing.T) {
	t.Setenv("IDORIS_VPN_AUTH_KEY", "k")
	t.Setenv("IDORIS_VPN_CONTROL_URL", "https://vpn.example")
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	_, err := loadConfig([]string{"--takeover", "--no-takeover"}, fs)
	if err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("%v", err)
	}
}
