package vpnd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenFingerprintIsNotTheToken(t *testing.T) {
	const token = "idv1_super-secret-token"
	got := TokenFingerprint(token)
	if got == "" || got == token || strings.Contains(got, "super-secret") || len(got) != 16 {
		t.Fatalf("fingerprint %q", got)
	}
	if TokenFingerprint(token) != got {
		t.Fatal("fingerprint must be stable")
	}
	if TokenFingerprint("other") == got || TokenFingerprint("  ") != "" {
		t.Fatal("fingerprint must change with the token and ignore empty")
	}
}

func TestStateFileRoundTripAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idoris", "vpnd-state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RememberControl(ours); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if err := st.SetIdentity(ours, "acme", "admin", TokenFingerprint("idv1_secret")); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "idv1_secret") {
		t.Fatalf("state file contains the token:\n%s", body)
	}
	again, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	got := again.Get()
	if got.ControlURL != ours || got.Tenant != "acme" || got.Role != "admin" || got.TokenFingerprint == "" {
		t.Fatalf("%+v", got)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("loose state file: %v", err)
	}
}

func TestDefaultStateFileHonoursXDG(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("xdg")
	}
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	got, err := DefaultStateFile()
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(dir, "idoris", "vpnd-state.json") {
		t.Fatalf("path %s", got)
	}
}
