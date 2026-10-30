package enroll

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

func writeTenantFile(t *testing.T, mode os.FileMode, tenants ...Tenant) string {
	t.Helper()
	if len(tenants) == 0 {
		tenants = []Tenant{{
			Name:            "acme",
			HeadscaleUserID: "1",
			TokenHashes:     []string{HashToken("seed-token")},
			Role:            join.RoleGateway,
			LANCIDRs:        []string{"10.251.73.10/32"},
		}}
	}
	cfg := &Config{ControlURL: "https://vpn.example.org", Tenants: tenants}
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	raw := []byte("{\n  \"control_url\": \"https://vpn.example.org\",\n  \"tenants\": [\n    {\n      \"name\": \"acme\",\n      \"headscale_user_id\": \"1\",\n      \"token_hashes\": [\"" + cfg.Tenants[0].TokenHashes[0] + "\"],\n      \"role\": \"" + cfg.Tenants[0].Role + "\",\n      \"lan_cidrs\": [\"10.251.73.10/32\"]\n    }\n  ]\n}\n")
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInviteAppendsHashAndPreservesMode(t *testing.T) {
	path := writeTenantFile(t, 0o640)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	code, err := Invite(path, "acme", "office-gw", "https://enroll.example.org", false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := join.Decode(code, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != join.RoleGateway || got.Tenant != "acme" || got.HostnameHint != "office-gw" || got.Token == "" {
		t.Fatalf("payload %+v", got)
	}
	if strings.Contains(string(mustRead(t, path)), got.Token) {
		t.Fatal("config file contains the plaintext token")
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tenants[0].TokenHashes) != 2 {
		t.Fatalf("hashes %+v", cfg.Tenants[0].TokenHashes)
	}
	if cfg.Tenants[0].TokenHashes[1] != HashToken(got.Token) {
		t.Fatal("appended hash does not match the code")
	}
	if cfg.Tenants[0].TokenHashes[0] != HashToken("seed-token") {
		t.Fatal("original hash was dropped")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	code2, err := Invite(path, "acme", "", "https://enroll.example.org", false)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := join.Decode(code2, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got2.Token == got.Token || HashToken(got2.Token) == HashToken(got.Token) {
		t.Fatal("second invite reused the token")
	}
	cfg, err = LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tenants[0].TokenHashes) != 3 || cfg.Tenants[0].LANCIDRs[0] != "10.251.73.10/32" {
		t.Fatalf("after second invite %+v", cfg.Tenants[0])
	}
	_ = before
}

func TestInviteRefusesUnknownEntryAndBadURL(t *testing.T) {
	path := writeTenantFile(t, 0o600)
	before := mustRead(t, path)
	if _, err := Invite(path, "other", "", "https://enroll.example.org", false); err == nil || !strings.Contains(err.Error(), "unknown entry") {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := Invite(path, "acme", "", "http://enroll.example.org", false); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http: %v", err)
	}
	after := mustRead(t, path)
	if string(before) != string(after) {
		t.Fatal("failed invite changed the file")
	}
	code, err := Invite(path, "acme", "", "http://enroll.lab", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := join.Decode(code, join.Options{}); err == nil {
		t.Fatal("http code decoded without the insecure flag")
	}
}

func TestRevokeByPrefix(t *testing.T) {
	path := writeTenantFile(t, 0o600)
	code, err := Invite(path, "acme", "", "https://enroll.example.org", false)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := join.Decode(code, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	sum := HashToken(payload.Token)
	removed, err := Revoke(path, "acme", sum[:6])
	if err != nil {
		t.Fatal(err)
	}
	if removed != sum {
		t.Fatalf("removed %s want %s", removed, sum)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tenants[0].TokenHashes) != 1 || cfg.Tenants[0].TokenHashes[0] == sum {
		t.Fatalf("hashes %+v", cfg.Tenants[0].TokenHashes)
	}
	if _, err := Revoke(path, "acme", cfg.Tenants[0].TokenHashes[0][:4]); err == nil || !strings.Contains(err.Error(), "last") {
		t.Fatalf("last hash: %v", err)
	}
	if _, err := Revoke(path, "missing", "abcd"); err == nil {
		t.Fatal("unknown entry")
	}
	if _, err := Revoke(path, "acme", "zzzz"); err == nil {
		t.Fatal("non-hex")
	}
	if _, err := Revoke(path, "acme", "abc"); err == nil {
		t.Fatal("short prefix")
	}
	if _, err := Revoke(path, "acme", "deadbeef"); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("absent: %v", err)
	}
}

func TestRevokeAmbiguousPrefix(t *testing.T) {
	h1 := HashToken("alpha-token-value")
	h2 := HashToken("beta-token-value")
	// Force a shared prefix by writing the hashes directly.
	shared := "abc123"
	if strings.HasPrefix(h1, shared) || strings.HasPrefix(h2, shared) {
		t.Fatal("fixture collided with the forced prefix")
	}
	a := shared + h1[len(shared):]
	b := shared + h2[len(shared):]
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	body := `{
  "control_url": "https://vpn.example.org",
  "tenants": [{
    "name": "acme",
    "headscale_user_id": "1",
    "token_hashes": ["` + a + `", "` + b + `"]
  }]
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, path)
	if _, err := Revoke(path, "acme", shared); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("ambiguous: %v", err)
	}
	if string(mustRead(t, path)) != string(before) {
		t.Fatal("ambiguous revoke changed the file")
	}
	removed, err := Revoke(path, "acme", a[:12])
	if err != nil {
		t.Fatal(err)
	}
	if removed != a {
		t.Fatalf("removed %s", removed)
	}
}

func TestEmptyRoleInviteDefaultsToMember(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	body := `{
  "control_url": "https://vpn.example.org",
  "tenants": [{
    "name": "acme",
    "headscale_user_id": "1",
    "token_hashes": ["` + HashToken("seed") + `"]
  }]
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	code, err := Invite(path, "acme", "", "https://enroll.example.org", false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := join.Decode(code, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != join.RoleMember {
		t.Fatalf("role %s", got.Role)
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
