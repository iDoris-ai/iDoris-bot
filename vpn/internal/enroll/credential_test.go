package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

func TestCredentialRoundTripKeepsTenantFields(t *testing.T) {
	created := time.Date(2026, 10, 27, 1, 2, 3, 0, time.UTC)
	hash := HashToken("seed-token")
	cfg := &Config{
		ControlURL:          "https://vpn.example.org",
		HeadscaleURL:        "https://hs.example.org",
		GlobalRatePerMinute: 12,
		PerIPRatePerMinute:  3,
		TrustedProxies:      []string{"10.0.0.0/8"},
		Tenants: []Tenant{{
			Name:            "acme",
			HeadscaleUserID: "7",
			TokenHashes:     []string{hash},
			Credentials: []Credential{{
				Hash:      hash,
				Label:     "seed",
				CreatedAt: created,
			}},
			ACLTags:       []string{"tag:member"},
			Role:          join.RoleGateway,
			LANCIDRs:      []string{"10.1.0.0/24"},
			PreAuthTTL:    Duration(10 * time.Minute),
			Ephemeral:     true,
			RatePerMinute: 4,
		}},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	in, out := cfg.Tenants[0], got.Tenants[0]
	if out.Name != in.Name || out.HeadscaleUserID != in.HeadscaleUserID || out.Role != in.Role || out.Ephemeral != in.Ephemeral || out.RatePerMinute != in.RatePerMinute {
		t.Fatalf("tenant %+v", out)
	}
	if len(out.TokenHashes) != 1 || out.TokenHashes[0] != hash || out.Credentials[0].Label != "seed" || !out.Credentials[0].CreatedAt.Equal(created) {
		t.Fatalf("credential %+v hashes %+v", out.Credentials, out.TokenHashes)
	}
	if len(out.ACLTags) != 1 || out.ACLTags[0] != "tag:member" || len(out.LANCIDRs) != 1 || out.LANCIDRs[0] != "10.1.0.0/24" {
		t.Fatalf("tags %+v cidrs %+v", out.ACLTags, out.LANCIDRs)
	}
	if out.PreAuthTTL != in.PreAuthTTL {
		t.Fatalf("ttl %s", time.Duration(out.PreAuthTTL))
	}
	if got.HeadscaleURL != cfg.HeadscaleURL || got.GlobalRatePerMinute != 12 || len(got.trusted) != 1 {
		t.Fatalf("config %+v", got)
	}
}

func TestLegacyAndObjectTokenHashes(t *testing.T) {
	hash := HashToken("seed-token")
	other := HashToken("other-token")
	raw := []byte(`{
	  "control_url": "https://vpn.example.org",
	  "tenants": [{
	    "name": "acme",
	    "headscale_user_id": "1",
	    "token_hashes": [
	      "` + hash + `",
	      {"hash": "` + other + `", "label": "phone", "created_at": "2026-10-27T00:00:00Z"}
	    ]
	  }]
	}`)
	cfg, err := parseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tenants[0].Credentials[0].Label != "" || cfg.Tenants[0].Credentials[1].Label != "phone" {
		t.Fatalf("%+v", cfg.Tenants[0].Credentials)
	}
	if cfg.Tenants[0].TokenHashes[0] != hash || cfg.Tenants[0].TokenHashes[1] != other {
		t.Fatalf("hashes %+v", cfg.Tenants[0].TokenHashes)
	}
	listed := FormatCredentialList(cfg.Tenants[0].Credentials)
	if strings.Contains(listed, hash) || strings.Contains(listed, other) {
		t.Fatalf("list printed a full hash:\n%s", listed)
	}
	if !strings.Contains(listed, "-\t"+HashPrefix(hash)+"\t-") || !strings.Contains(listed, "phone\t"+HashPrefix(other)+"\t2026-10-27T00:00:00Z") {
		t.Fatalf("list:\n%s", listed)
	}
	if strings.Contains(listed, "LABEL") {
		t.Fatal("list has a header")
	}

	bad := strings.Replace(string(raw), `"label": "phone"`, `"label": "phone", "secret": "no"`, 1)
	if _, err := parseConfig([]byte(bad)); err == nil {
		t.Fatal("unknown credential field was accepted")
	}
	invalid := strings.Replace(string(raw), `"label": "phone"`, `"label": "bad label"`, 1)
	if _, err := parseConfig([]byte(invalid)); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("invalid label: %v", err)
	}
	dup := `{
	  "control_url": "https://vpn.example.org",
	  "tenants": [{
	    "name": "acme",
	    "headscale_user_id": "1",
	    "token_hashes": [
	      {"hash": "` + hash + `", "label": "phone"},
	      {"hash": "` + other + `", "label": "phone"}
	    ]
	  }]
	}`
	if _, err := parseConfig([]byte(dup)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestInviteLabelRulesDoNotWriteOnFailure(t *testing.T) {
	path := writeTenantFile(t, 0o600)
	before := string(mustRead(t, path))
	if _, err := Invite(path, "acme", "office-gw", "https://enroll.example.org", "bad label", false); err == nil {
		t.Fatal("invalid label accepted")
	}
	if string(mustRead(t, path)) != before {
		t.Fatal("invalid label changed the file")
	}
	if _, err := Invite(path, "acme", "office gw", "https://enroll.example.org", "", false); err == nil {
		t.Fatal("hostname hint with a space was accepted")
	}
	if string(mustRead(t, path)) != before {
		t.Fatal("rejected hostname hint changed the file")
	}
	if _, err := Invite(path, "acme", "", "https://enroll.example.org", "", false); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.Tenants[0].Credentials[1].Label, "cred-") {
		t.Fatalf("label %q", cfg.Tenants[0].Credentials[1].Label)
	}
	if _, err := Invite(path, "acme", "", "https://enroll.example.org", cfg.Tenants[0].Credentials[1].Label, false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate label: %v", err)
	}
	cfg2, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg2.Tenants[0].TokenHashes) != 2 {
		t.Fatalf("duplicate label wrote a hash: %+v", cfg2.Tenants[0].TokenHashes)
	}
}

func TestInviteEnrollRevokeReload(t *testing.T) {
	seed, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	body := `{
  "control_url": "https://vpn.example.org",
  "tenants": [{
    "name": "acme",
    "headscale_user_id": "1",
    "role": "member",
    "lan_cidrs": ["10.8.0.0/24"],
    "preauth_ttl": "5m",
    "token_hashes": ["` + HashToken(seed) + `"]
  }]
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &fakeMinter{}
	buf := &logBuf{}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(*cfg, m, slog.New(buf))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	code, err := Invite(path, "acme", "desk", "https://enroll.example.org", "laptop", false)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := join.Decode(code, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tenants[0].Credentials[1].Label != "laptop" || cfg.Tenants[0].LANCIDRs[0] != "10.8.0.0/24" || cfg.Tenants[0].PreAuthTTL != Duration(5*time.Minute) {
		t.Fatalf("after invite %+v", cfg.Tenants[0])
	}
	if err := srv.Reload(*cfg); err != nil {
		t.Fatal(err)
	}
	client := &Client{URL: ts.URL, Token: payload.Token, AllowInsecure: true}
	if _, err := client.Fetch(context.Background(), Request{Hostname: "mbp", OS: "darwin"}); err != nil {
		t.Fatal(err)
	}
	audit := buf.joined()
	if !strings.Contains(audit, "label=laptop") || !strings.Contains(audit, "remote=127.0.0.1") {
		t.Fatalf("audit %s", audit)
	}
	if strings.Contains(audit, payload.Token) || strings.Contains(audit, HashToken(payload.Token)) {
		t.Fatal("audit line included the token or its full hash")
	}
	if len(m.calls) != 1 {
		t.Fatalf("minted %d", len(m.calls))
	}

	removed, err := RevokeLabel(path, "acme", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if removed != HashToken(payload.Token) {
		t.Fatalf("removed %s", removed)
	}
	cfg, err = LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(*cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Fetch(context.Background(), Request{Hostname: "mbp", OS: "darwin"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("after revoke: %v", err)
	}
	if len(m.calls) != 1 {
		t.Fatal("revoked credential still minted a key")
	}
	if _, err := (&Client{URL: ts.URL, Token: seed, AllowInsecure: true}).Fetch(context.Background(), Request{Hostname: "mbp", OS: "darwin"}); err != nil {
		t.Fatal(err)
	}
	if len(m.calls) != 2 {
		t.Fatalf("seed enroll minted %d", len(m.calls))
	}
	listed, err := ListCredentials(path, "acme")
	if err != nil {
		t.Fatal(err)
	}
	text := FormatCredentialList(listed)
	if strings.Contains(text, "laptop") || strings.Contains(text, HashToken(payload.Token)) || strings.Contains(text, HashToken(seed)) {
		t.Fatalf("list after revoke:\n%s", text)
	}
}
