package gateway

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

const (
	r5wOldToken = "idv1_oldoldoldoldoldoldoldoldold\n"
	r5wNewToken = "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	r5wEnroll   = "https://enroll.example"
)

func TestR5WDefaultConfigLeavesSharedLegacyToken(t *testing.T) {
	t.Run("default first explicit shared path", func(t *testing.T) {
		r5wAssertDefaultLeavesShared(t, true)
	})
	t.Run("default first own path", func(t *testing.T) {
		r5wAssertDefaultLeavesShared(t, false)
	})
	t.Run("non-default first", func(t *testing.T) {
		r5wAssertSidecarFirst(t)
	})
}

func TestR5WRefusesASidecarTwoConfigsAlreadyShare(t *testing.T) {
	dir := r5wPrivateIdoris(t)
	cfg := filepath.Join(dir, "vpn.json")
	other := filepath.Join(dir, "other.json")
	side := filepath.Join(dir, "vpn.json.enroll-token")
	beforeCfg := r5wWriteJSON(t, cfg, r5wEnroll, side)
	beforeOther := r5wWriteJSON(t, other, r5wEnroll, side)
	if err := os.WriteFile(side, []byte(r5wOldToken), 0o600); err != nil {
		t.Fatal(err)
	}
	p := r5wMemberPlan(t, cfg, side)
	_, err := Apply(p, r3w2DiskHost{}, ApplyOptions{Token: r5wNewToken, NoService: true})
	if err == nil || !strings.Contains(err.Error(), "refusing to write") || !strings.Contains(err.Error(), cfg) || !strings.Contains(err.Error(), other) {
		t.Fatalf("err %v", err)
	}
	r5wSameFile(t, cfg, beforeCfg)
	r5wSameFile(t, other, beforeOther)
	r5wSameFile(t, side, []byte(r5wOldToken))
}

func TestR5WPlanTokenFileIsNotAShare(t *testing.T) {
	dir := r5wPrivateIdoris(t)
	cfg := filepath.Join(dir, "vpn.json")
	side := filepath.Join(dir, "vpn.json.enroll-token")
	planPath := filepath.Join(dir, "gateway-plan.json")
	if err := os.WriteFile(planPath, []byte("{\n  \"token_file\": \""+side+"\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := r5wMemberPlan(t, cfg, side)
	if _, err := Apply(p, r3w2DiskHost{}, ApplyOptions{Token: r5wNewToken, NoService: true}); err != nil {
		t.Fatal(err)
	}
	r5wSameFile(t, side, []byte(r5wNewToken+"\n"))
}

func TestR5WBrokenSiblingConfigIsAnError(t *testing.T) {
	dir := r5wPrivateIdoris(t)
	cfg := filepath.Join(dir, "vpn.json")
	side := filepath.Join(dir, "vpn.json.enroll-token")
	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := r5wMemberPlan(t, cfg, side)
	_, err := Apply(p, r3w2DiskHost{}, ApplyOptions{Token: r5wNewToken, NoService: true})
	if err == nil || !strings.Contains(err.Error(), "broken.json") {
		t.Fatalf("err %v", err)
	}
	if _, statErr := os.Stat(side); !os.IsNotExist(statErr) {
		t.Fatal("apply wrote a token after a broken sibling config")
	}
}

func r5wAssertDefaultLeavesShared(t *testing.T, explicitShared bool) {
	t.Helper()
	dir := r5wPrivateIdoris(t)
	shared := filepath.Join(dir, "enroll.token")
	if err := os.WriteFile(shared, []byte(r5wOldToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o444); err != nil {
		t.Fatal(err)
	}
	vpnd := filepath.Join(dir, "vpnd.json")
	// A relative reference has to count. The legacy file is in this directory.
	before := r5wWriteJSON(t, vpnd, r5wEnroll, "enroll.token")
	cfg := filepath.Join(dir, "vpn.json")
	tokenFile := shared
	if !explicitShared {
		tokenFile = PathsFor("", cfg).Token
	}
	p := r5wMemberPlan(t, cfg, tokenFile)
	res, err := Apply(p, r3w2DiskHost{}, ApplyOptions{Token: r5wNewToken, NoService: true})
	if err != nil {
		t.Fatal(err)
	}
	r5wSameFile(t, shared, []byte(r5wOldToken))
	if runtime.GOOS != "windows" {
		st, err := os.Stat(shared)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o444 {
			t.Fatalf("legacy token mode %o", st.Mode().Perm())
		}
	}
	r5wSameFile(t, vpnd, before)
	own := filepath.Join(dir, "vpn.json.enroll-token")
	if res.TokenFile != own {
		t.Fatalf("token file %s", res.TokenFile)
	}
	r5wSameFile(t, own, []byte(r5wNewToken+"\n"))
	body, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := jsonStringField(body, "enroll_token_file"); !ok || got != own {
		t.Fatalf("selected config token pointer %q", got)
	}
	if strings.Contains(string(body), "enroll.token") {
		t.Fatal("selected config still names the legacy token")
	}
}

func r5wAssertSidecarFirst(t *testing.T) {
	t.Helper()
	dir := r5wPrivateIdoris(t)
	shared := filepath.Join(dir, "enroll.token")
	if err := os.WriteFile(shared, []byte(r5wOldToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o444); err != nil {
		t.Fatal(err)
	}
	vpn := filepath.Join(dir, "vpn.json")
	vpnd := filepath.Join(dir, "vpnd.json")
	beforeVPN := r5wWriteJSON(t, vpn, r5wEnroll, shared)
	r5wWriteJSON(t, vpnd, r5wEnroll, shared)
	first := r5wMemberPlan(t, vpnd, shared)
	if _, err := Apply(first, r3w2DiskHost{}, ApplyOptions{Token: r5wNewToken, NoService: true}); err != nil {
		t.Fatal(err)
	}
	r5wSameFile(t, shared, []byte(r5wOldToken))
	r5wSameFile(t, vpn, beforeVPN)
	ownVPND := vpnd + ".enroll-token"
	r5wSameFile(t, ownVPND, []byte(r5wNewToken+"\n"))
	second := r5wMemberPlan(t, vpn, shared)
	if _, err := Apply(second, r3w2DiskHost{}, ApplyOptions{Token: "idv1_cccccccccccccccccccccccccccccc", NoService: true}); err != nil {
		t.Fatal(err)
	}
	r5wSameFile(t, shared, []byte(r5wOldToken))
	if runtime.GOOS != "windows" {
		st, err := os.Stat(shared)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o444 {
			t.Fatalf("legacy token mode %o", st.Mode().Perm())
		}
	}
	r5wSameFile(t, ownVPND, []byte(r5wNewToken+"\n"))
	body, err := os.ReadFile(vpnd)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := jsonStringField(body, "enroll_token_file"); !ok || got != ownVPND {
		t.Fatalf("vpnd pointer %q", got)
	}
	vpnBody, err := os.ReadFile(vpn)
	if err != nil {
		t.Fatal(err)
	}
	ownVPN := filepath.Join(dir, "vpn.json.enroll-token")
	if got, ok := jsonStringField(vpnBody, "enroll_token_file"); !ok || got != ownVPN {
		t.Fatalf("vpn pointer %q", got)
	}
	if bytes.Contains(vpnBody, []byte(shared)) {
		t.Fatal("default config still names the legacy token")
	}
}

func r5wMemberPlan(t *testing.T, cfg, token string) Plan {
	t.Helper()
	p, err := SimplePlan(join.RoleMember, "acme", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = r5wEnroll
	p.ConfigPath = cfg
	p.TokenFile = token
	return p
}

func r5wPrivateIdoris(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, ".idoris")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func r5wWriteJSON(t *testing.T, path, enroll, tokenFile string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]string{
		"enroll_url":        enroll,
		"enroll_token_file": tokenFile,
		"hostname":          "laptop",
		"role":              "member",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func r5wSameFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s changed", filepath.Base(path))
	}
}
