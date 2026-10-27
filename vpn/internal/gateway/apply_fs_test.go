package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

// r3w2DiskHost is the real filesystem. It is the host Apply uses in production
// (osHost calls the same two fsutil functions).
type r3w2DiskHost struct{}

func (r3w2DiskHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	return fsutil.WriteFileAtomic(path, data, mode)
}
func (r3w2DiskHost) MkdirAll(path string, mode os.FileMode) error {
	if mode.Perm()&0o077 == 0 {
		return fsutil.EnsurePrivateDir(path)
	}
	return os.MkdirAll(path, mode)
}
func (r3w2DiskHost) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }
func (r3w2DiskHost) Chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}
func (r3w2DiskHost) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) } //nolint:gosec // test path
func (r3w2DiskHost) IsRoot() bool                         { return false }
func (r3w2DiskHost) GOOS() string                         { return "darwin" }
func (r3w2DiskHost) EnableIPForward(string, string) error { return nil }
func (r3w2DiskHost) InstallService(string) error          { return nil }

func TestR3W2ApplySecretWriteReplacesLooseFileAndSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix modes")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "vpn.json")
	if err := os.WriteFile(cfg, []byte("{\n  \"control_url\": \"https://hs.example\"\n}\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg, 0o666); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "enroll.token")
	if err := os.Symlink(victim, token); err != nil {
		t.Fatal(err)
	}
	p, err := SimplePlan(join.RoleMember, "acme", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = "https://enroll.example.org"
	p.ConfigPath = cfg
	p.TokenFile = token
	if _, err := Apply(p, r3w2DiskHost{}, ApplyOptions{Token: "token-a", NoService: true}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("symlink target was written: %q", b)
	}
	st, err := os.Lstat(token)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		t.Fatal("token path is still a symlink")
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("token mode %o", st.Mode().Perm())
	}
	if b, _ := os.ReadFile(token); string(b) != "token-a\n" {
		t.Fatalf("token %q", b)
	}
	cst, err := os.Stat(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cst.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %o", cst.Mode().Perm())
	}
	body, _ := os.ReadFile(cfg)
	if !bytesContains(body, "https://hs.example") || !bytesContains(body, "127.0.0.1:1080") {
		t.Fatalf("config %s", body)
	}

	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	p.ConfigPath = filepath.Join(loose, "vpn.json")
	p.TokenFile = filepath.Join(loose, "enroll.token")
	if _, err := Apply(p, r3w2DiskHost{}, ApplyOptions{Token: "token-a", NoService: true}); err == nil {
		t.Fatal("group-writable directory was accepted")
	}
}

func bytesContains(b []byte, s string) bool {
	return len(b) >= len(s) && (string(b) == s || len(s) == 0 || containsString(string(b), s))
}

func containsString(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && (s[:len(sub)] == sub || containsString(s[1:], sub))))
}
