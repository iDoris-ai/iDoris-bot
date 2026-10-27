package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

type stubMinter struct{}

func (stubMinter) CreatePreAuthKey(context.Context, headscale.CreatePreAuthKeyRequest) (*headscale.PreAuthKey, error) {
	return &headscale.PreAuthKey{}, nil
}

func TestInviteStdoutIsOnlyTheCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	body := `{
  "control_url": "https://vpn.example.org",
  "tenants": [{
    "name": "acme",
    "headscale_user_id": "1",
    "role": "gateway",
    "lan_cidrs": ["10.9.9.9/32"],
    "token_hashes": ["` + enroll.HashToken("seed") + `"]
  }]
}`
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := inviteCmd([]string{
		"--config", path,
		"--entry", "acme",
		"--hostname-hint", "office-gw",
		"--enroll-url", "https://enroll.example.org",
	}, &stdout); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("stdout %q", out)
	}
	code := strings.TrimSpace(out)
	got, err := join.Decode(code, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != join.RoleGateway || got.HostnameHint != "office-gw" {
		t.Fatalf("payload %+v", got)
	}
	if strings.Contains(string(mustRead(t, path)), got.Token) {
		t.Fatal("config contains the plaintext token")
	}
	var revokeOut bytes.Buffer
	if err := revokeCmd([]string{"--config", path, "--entry", "acme", "--hash-prefix", enroll.HashToken(got.Token)[:8]}, &revokeOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(revokeOut.String(), "revoked acme ") {
		t.Fatalf("revoke stdout %q", revokeOut.String())
	}
}

func TestReloadFromDiskKeepsPreviousConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	tok := "idv1_seedseedseedseedseedseedseedseed"
	write := func(hash, role string) {
		t.Helper()
		body := `{
  "control_url": "https://vpn.example.org",
  "tenants": [{
    "name": "acme",
    "headscale_user_id": "1",
    "role": "` + role + `",
    "token_hashes": ["` + hash + `"]
  }]
}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(enroll.HashToken(tok), "member")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := enroll.NewServer(*cfg, stubMinter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadFromDisk(srv, path); err == nil {
		t.Fatal("broken file was accepted")
	}
	if _, err := (&enroll.Client{URL: ts.URL, Token: tok, AllowInsecure: true}).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := "idv1_nextnextnextnextnextnextnextnext"
	write(enroll.HashToken(next), "local-ai")
	if err := reloadFromDisk(srv, path); err != nil {
		t.Fatal(err)
	}
	d, err := (&enroll.Client{URL: ts.URL, Token: next, AllowInsecure: true}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Role != "local-ai" {
		t.Fatalf("role %s", d.Role)
	}
	if _, err := (&enroll.Client{URL: ts.URL, Token: tok, AllowInsecure: true}).Discover(context.Background()); err == nil {
		t.Fatal("old token still accepted after reload")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
