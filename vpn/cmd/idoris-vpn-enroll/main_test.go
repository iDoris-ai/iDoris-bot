package main

import (
	"bytes"
	"context"
	"net/http"
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
	if strings.Contains(revokeOut.String(), enroll.HashToken(got.Token)) {
		t.Fatalf("revoke printed the full hash: %q", revokeOut.String())
	}
}

func TestListCredentialsAndRevokeByLabel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	seed := "idv1_seedseedseedseedseedseedseedseed"
	body := `{
  "control_url": "https://vpn.example.org",
  "tenants": [{
    "name": "acme",
    "headscale_user_id": "1",
    "token_hashes": ["` + enroll.HashToken(seed) + `"]
  }]
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := inviteCmd([]string{"--config", path, "--entry", "acme", "--label", "laptop", "--enroll-url", "https://enroll.example.org"}, &stdout); err != nil {
		t.Fatal(err)
	}
	got, err := join.Decode(strings.TrimSpace(stdout.String()), join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	full := enroll.HashToken(got.Token)
	var list bytes.Buffer
	if err := listCredentialsCmd([]string{"--config", path, "--entry", "acme"}, &list); err != nil {
		t.Fatal(err)
	}
	text := list.String()
	if strings.Contains(text, full) || strings.Contains(text, got.Token) || strings.Contains(text, "LABEL") {
		t.Fatalf("list leaked a secret or added a header:\n%s", text)
	}
	if !strings.Contains(text, "laptop\t"+enroll.HashPrefix(full)+"\t") {
		t.Fatalf("list:\n%s", text)
	}
	var sink bytes.Buffer
	if err := revokeCmd([]string{"--config", path, "--entry", "acme", "--label", "laptop", "--hash-prefix", full[:8]}, &sink); err == nil {
		t.Fatal("both selectors were accepted")
	}
	if err := revokeCmd([]string{"--config", path, "--entry", "acme"}, &sink); err == nil {
		t.Fatal("missing selector was accepted")
	}

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
	if _, err := (&enroll.Client{URL: ts.URL, Token: got.Token, AllowInsecure: true}).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	var revoked bytes.Buffer
	if err := revokeCmd([]string{"--config", path, "--entry", "acme", "--label", "laptop"}, &revoked); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(revoked.String(), "revoked acme laptop "+enroll.HashPrefix(full)) || strings.Contains(revoked.String(), full) {
		t.Fatalf("revoke stdout %q", revoked.String())
	}
	if err := reloadFromDisk(srv, path); err != nil {
		t.Fatal(err)
	}
	if _, err := (&enroll.Client{URL: ts.URL, Token: got.Token, AllowInsecure: true}).Discover(context.Background()); err == nil {
		t.Fatal("revoked credential accepted after reload")
	}
	if _, err := (&enroll.Client{URL: ts.URL, Token: seed, AllowInsecure: true}).Discover(context.Background()); err != nil {
		t.Fatal(err)
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

func TestReloadFromDiskAppliesLimitFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	tok := "idv1_seedseedseedseedseedseedseedseed"
	hash := enroll.HashToken(tok)
	body := func(extra string) {
		t.Helper()
		raw := `{
  "control_url": "https://vpn.example.org",
  ` + extra + `
  "tenants": [{
    "name": "acme",
    "headscale_user_id": "1",
    "token_hashes": ["` + hash + `"]
  }]
}`
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	body(`"global_rate_per_minute": 100, "per_ip_rate_per_minute": 1, "trusted_proxies": ["10.0.0.0/8"],`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := enroll.NewServer(*cfg, stubMinter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	body(`"trusted_proxies": ["not-a-cidr"],`)
	if err := reloadFromDisk(srv, path); err == nil {
		t.Fatal("invalid trusted_proxies was accepted")
	}
	call := func(remote, xff string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "/v1/discover", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+tok)
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		return rr.Code
	}
	// The rejected reload must leave the trusted-proxy list in place: the
	// bucket key is the forwarded client, so a later direct connection from
	// that client is already spent.
	if call("10.1.1.1:443", "203.0.113.9") != http.StatusOK {
		t.Fatal("trusted proxy request failed")
	}
	if call("203.0.113.9:9", "") != http.StatusTooManyRequests {
		t.Fatal("X-Forwarded-For was not honored after the rejected reload")
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
