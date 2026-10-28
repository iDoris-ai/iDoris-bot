package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

func TestR4WInlineTokenIsRemovedWhenTheTokenFileIsInstalled(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "office.json")
	authFile := filepath.Join(dir, "auth.key")
	const inlineToken = "idv1_inlineinlineinlineinlineinline"
	const inlineKey = "tskey-auth-inlineinlineinlineinlin"
	const newToken = "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	p, err := SimplePlan(join.RoleMember, "acme", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = "https://b.example"
	p.ConfigPath = cfgPath
	p.TokenFile = cfgPath + ".enroll-token"
	h := newMemHost(false, "darwin")
	h.files[cfgPath] = []byte("{\n" +
		"  \"enroll_url\": \"https://a.example\",\n" +
		"  \"enroll_token\": \"" + inlineToken + "\",\n" +
		"  \"auth_key\": \"" + inlineKey + "\",\n" +
		"  \"auth_key_file\": \"" + authFile + "\",\n" +
		"  \"control_url\": \"https://hs-a.example\"\n" +
		"}\n")
	if _, err := Apply(p, h, ApplyOptions{Token: newToken, NoService: true, ReplaceExisting: true}); err != nil {
		t.Fatal(err)
	}
	body := string(h.files[cfgPath])
	if strings.Contains(body, `"enroll_token"`) || strings.Contains(body, inlineToken) || strings.Contains(body, `"auth_key"`) || strings.Contains(body, inlineKey) {
		t.Fatalf("inline credentials kept:\n%s", body)
	}
	if !strings.Contains(body, `"enroll_token_file": "`+p.TokenFile+`"`) || !strings.Contains(body, `"auth_key_file": "`+authFile+`"`) {
		t.Fatalf("file credentials missing:\n%s", body)
	}
	if string(h.files[p.TokenFile]) != newToken+"\n" {
		t.Fatalf("token file %q", h.files[p.TokenFile])
	}
	if err := os.WriteFile(cfgPath, h.files[cfgPath], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.TokenFile, h.files[p.TokenFile], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authFile, []byte(inlineKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := vpnd.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EnrollToken != "" || cfg.EnrollTokenFile != p.TokenFile || cfg.AuthKey != "" || cfg.AuthKeyFile != authFile {
		t.Fatalf("loader %+v", cfg)
	}
	if err := cfg.Resolve(); err != nil {
		t.Fatal(err)
	}
	if cfg.EnrollToken != newToken {
		t.Fatalf("resolved token %q", cfg.EnrollToken)
	}
}
