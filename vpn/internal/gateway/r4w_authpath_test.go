package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

func TestR4WSOCKSAuthPathUsesDaemonStateDir(t *testing.T) {
	// Apply scans the real directory of the config for sibling configs, so
	// the home must be a real, readable directory: a literal /root exists and
	// is unreadable on a Linux CI runner and does not exist on a Mac.
	home := t.TempDir()
	t.Setenv("STATE_DIRECTORY", "/var/lib/idoris")
	t.Setenv("HOME", home)
	p, err := SimplePlan(join.RoleMember, "acme", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = "https://enroll.example.org"
	p.ConfigPath = filepath.Join(home, ".idoris", "vpn.json")
	p.TokenFile = filepath.Join(home, ".idoris", "enroll.token")
	h := newMemHost(false, "linux")
	res, err := Apply(p, h, ApplyOptions{Token: "idv1_secretsecretsecretsecretsecretse", NoService: true})
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(res.AccessInfo, "\n")
	want := "/var/lib/idoris/node/socks5.auth"
	if !strings.Contains(text, want) || strings.Contains(text, filepath.Join(home, ".idoris", "vpn-state", "socks5.auth")) {
		t.Fatalf("access %q", text)
	}
	got, err := vpnd.SOCKSAuthPath("", "")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := vpnd.ResolveStateDir("")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(dir, "socks5.auth") || got != want {
		t.Fatalf("helper %q resolver %q", got, dir)
	}
	explicit, err := vpnd.SOCKSAuthPath("/root/.idoris/custom.auth", "/var/lib/custom")
	if err != nil || explicit != "/root/.idoris/custom.auth" {
		t.Fatalf("explicit auth %q %v", explicit, err)
	}
	fromState, err := vpnd.SOCKSAuthPath("", "/var/lib/custom")
	if err != nil || fromState != "/var/lib/custom/socks5.auth" {
		t.Fatalf("explicit state %q %v", fromState, err)
	}
}
