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
	if err := st.SetIdentity(ours, "acme", "admin", TokenFingerprint("idv1_secret"), "", ""); err != nil {
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

func TestR3C1StateWriteDoesNotFollowTempSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The old saver used path+".tmp" and followed a symlink planted there.
	link := filepath.Join(dir, "vpnd-state.json.tmp")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	st, err := OpenState(filepath.Join(dir, "vpnd-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentity(ours, "acme", "member", "fp", "node-1", "prof-1"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "keep-me" {
		t.Fatalf("temp symlink was followed, victim is now %q", body)
	}
	got, err := os.Readlink(link)
	if err != nil || got != victim {
		t.Fatalf("planted symlink changed: %q %v", got, err)
	}
	saved, err := os.ReadFile(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), `"node_id": "node-1"`) {
		t.Fatalf("state file %s", saved)
	}
}

func TestR3C1StateMemoryStaysOldWhenWriteFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := OpenState(filepath.Join(dir, "vpnd-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentity(ours, "acme", "admin", "fp", "node-a", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.RememberControl(ours); err != nil {
		t.Fatal(err)
	}
	// Directory stays readable so the failure is the write, not the lookup.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := st.SetIdentity(ours, "acme", "member", "fp2", "node-b", "p2"); err == nil {
		t.Fatal("read-only directory accepted SetIdentity")
	}
	got := st.Get()
	if got.Role != "admin" || got.NodeID != "node-a" || got.TokenFingerprint != "fp" {
		t.Fatalf("memory committed a failed identity write: %+v", got)
	}
	if err := st.RememberControl("https://other.example"); err == nil {
		t.Fatal("read-only directory accepted RememberControl")
	}
	if st.Get().ControlURL != ours {
		t.Fatalf("memory committed a failed control write: %+v", st.Get())
	}
	again, err := OpenState(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	disk := again.Get()
	if disk.Role != "admin" || disk.NodeID != "node-a" {
		t.Fatalf("disk changed: %+v", disk)
	}
}

func TestDefaultStateFileHonoursXDG(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("xdg")
	}
	dir := t.TempDir()
	t.Setenv("STATE_DIRECTORY", "")
	t.Setenv("XDG_STATE_HOME", dir)
	got, err := DefaultStateFile()
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(dir, "idoris", "vpnd-state.json") {
		t.Fatalf("path %s", got)
	}
}
