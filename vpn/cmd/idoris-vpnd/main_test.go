package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR3c2CredentialLayers(t *testing.T) {
	for _, kind := range []string{"enroll", "auth"} {
		t.Run(kind, func(t *testing.T) {
			cases := []r3c2CredCase{
				{name: "file inline loses to env file", fileInline: "from-file", envBody: "from-env-file", want: "from-env-file"},
				{name: "file path loses to env inline", fileBody: "from-file-path", envInline: "from-env", want: "from-env"},
				{name: "env inline loses to flag file", envInline: "from-env", flagBody: r3c2P("from-flag-file"), want: "from-flag-file"},
				{name: "env file loses to flag inline", envBody: "from-env-file", flagInline: r3c2P("from-flag"), want: "from-flag"},
				{name: "file inline loses to flag file", fileInline: "from-file", flagBody: r3c2P("from-flag-file"), want: "from-flag-file"},
				{name: "file path loses to flag inline", fileBody: "from-file-path", flagInline: r3c2P("from-flag"), want: "from-flag"},
				{name: "blank env does not replace file inline", fileInline: "from-file", envInline: "   ", want: "from-file"},
				{name: "empty flag clears file inline", fileInline: "from-file", flagInline: r3c2P(""), wantErr: kind},
				{name: "file sets both", fileInline: "from-file", fileBody: "from-file-path", wantErr: "both"},
				{name: "env sets both", envInline: "from-env", envBody: "from-env-file", wantErr: "both"},
				{name: "flags set both", flagInline: r3c2P("from-flag"), flagBody: r3c2P("from-flag-file"), wantErr: "both"},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					r3c2RunCredCase(t, kind, tc)
				})
			}
		})
	}
}

type r3c2CredCase struct {
	name                 string
	fileInline, fileBody string
	envInline, envBody   string
	flagInline, flagBody *string
	want, wantErr        string
}

func r3c2P(s string) *string { return &s }

func r3c2RunCredCase(t *testing.T, kind string, tc r3c2CredCase) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	doc := map[string]string{}
	if kind == "enroll" {
		doc["enroll_url"] = "https://enroll.example"
		t.Setenv("IDORIS_VPN_ENROLL_URL", "https://enroll.example")
	} else {
		doc["control_url"] = "https://vpn.example"
		t.Setenv("IDORIS_VPN_CONTROL_URL", "https://vpn.example")
	}
	inlineKey, fileKey := "enroll_token", "enroll_token_file"
	envInline, envFile := "IDORIS_VPN_ENROLL_TOKEN", "IDORIS_VPN_ENROLL_TOKEN_FILE"
	flagInline, flagFile := "--enroll-token", "--enroll-token-file"
	if kind == "auth" {
		inlineKey, fileKey = "auth_key", "auth_key_file"
		envInline, envFile = "IDORIS_VPN_AUTH_KEY", "IDORIS_VPN_AUTH_KEY_FILE"
		flagInline, flagFile = "--auth-key", "--auth-key-file"
	}
	if tc.fileInline != "" {
		doc[inlineKey] = tc.fileInline
	}
	if tc.fileBody != "" {
		doc[fileKey] = write("file-secret", tc.fileBody)
	}
	var args []string
	if tc.fileInline != "" || tc.fileBody != "" {
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, "--config", write("vpnd.json", string(b)))
	}
	if tc.envInline != "" {
		t.Setenv(envInline, tc.envInline)
	}
	if tc.envBody != "" {
		t.Setenv(envFile, write("env-secret", tc.envBody))
	}
	if tc.flagInline != nil {
		args = append(args, flagInline, *tc.flagInline)
	}
	if tc.flagBody != nil {
		args = append(args, flagFile, write("flag-secret", *tc.flagBody))
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfg, err := loadConfig(args, fs)
	if tc.wantErr != "" {
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("error %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	got, path := cfg.EnrollToken, cfg.EnrollTokenFile
	if kind == "auth" {
		got, path = cfg.AuthKey, cfg.AuthKeyFile
	}
	if got != tc.want {
		t.Fatalf("secret %q", got)
	}
	if tc.envBody == "" && tc.fileBody == "" && (tc.flagBody == nil) && path != "" {
		t.Fatalf("inline winner left a file path %q", path)
	}
}

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

func TestAccessFlags(t *testing.T) {
	t.Setenv("IDORIS_VPN_AUTH_KEY", "k")
	t.Setenv("IDORIS_VPN_CONTROL_URL", "https://vpn.example")
	t.Setenv("IDORIS_VPN_MAX_CONNECTIONS", "4")
	dir := t.TempDir()
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfg, err := loadConfig([]string{
		"--socks5-listen", "unix:" + dir + "/socks.sock",
		"--socks5-auth-file", dir + "/socks5.auth",
		"--max-connections", "8",
		"--dial-timeout", "3s",
		"--mode", "embedded",
	}, fs)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SOCKS5Listen != "unix:"+dir+"/socks.sock" || cfg.SOCKS5AuthFile != dir+"/socks5.auth" {
		t.Fatalf("socks %+v", cfg)
	}
	if cfg.SOCKS5AllowAnonymous || cfg.MaxConnections != 8 || cfg.DialTimeout != "3s" {
		t.Fatalf("flags did not override env: anon=%v max=%d dial=%s", cfg.SOCKS5AllowAnonymous, cfg.MaxConnections, cfg.DialTimeout)
	}

	fs = flag.NewFlagSet("run", flag.ContinueOnError)
	if _, err := loadConfig([]string{"--socks5-allow-anonymous", "--socks5-auth-file", "/tmp/a"}, fs); err == nil || !strings.Contains(err.Error(), "socks5_allow_anonymous") {
		t.Fatalf("conflict: %v", err)
	}
	fs = flag.NewFlagSet("run", flag.ContinueOnError)
	if _, err := loadConfig([]string{"--dial-timeout", "0s"}, fs); err == nil || !strings.Contains(err.Error(), "dial_timeout") {
		t.Fatalf("zero dial: %v", err)
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
