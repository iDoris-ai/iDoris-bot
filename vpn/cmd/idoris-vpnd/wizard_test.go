package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
)

const testToken = "idv1_secretsecretsecretsecretsecretse"

func officeReport() netdetect.Report {
	rec := netdetect.Candidate{
		Name: "eth0", Addr: "10.251.73.4", Bits: 24, Network: "10.251.73.0/24",
		Gateway: "10.251.73.1", Default: true,
	}
	return netdetect.Report{
		Platform: "linux", GatewaySupported: true,
		Candidates:  []netdetect.Candidate{rec},
		Recommended: &rec,
		Checks:      []netdetect.Check{{ID: "ip_forward", OK: false, Detail: "off", Fix: "enable forwarding"}},
	}
}

func testDeps(host *fakeOS, in string) deps {
	return deps{
		stdin:  strings.NewReader(in),
		stdout: &bytes.Buffer{},
		stderr: &bytes.Buffer{},
		host:   host,
		detect: func(string) (netdetect.Report, error) { return officeReport(), nil },
		discover: func(context.Context, string, string, bool) (*enroll.Discovery, error) {
			return &enroll.Discovery{ControlURL: "https://vpn.example", Tenant: "acme", LANCIDRs: []string{"10.251.73.10/32"}}, nil
		},
		home:     func() (string, error) { return "/home/acme", nil },
		hostname: func() (string, error) { return "box", nil },
	}
}

func (d deps) out() string { return d.stdout.(*bytes.Buffer).String() }
func (d deps) errOut() string {
	return d.stderr.(*bytes.Buffer).String()
}

func codeFor(t *testing.T, role, rawURL string, insecure bool) string {
	t.Helper()
	c, err := join.Encode(join.Payload{
		V: 1, EnrollURL: rawURL, Token: testToken, Role: role, Tenant: "acme", HostnameHint: "office-gw",
	}, join.Options{AllowInsecure: insecure})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestJoinMemberDoesNotPrintTheCode(t *testing.T) {
	host := newFakeOS(false, "linux")
	code := codeFor(t, join.RoleMember, "https://enroll.example.org", false)
	d := testDeps(host, "")
	if err := joinCmd([]string{"--yes", code}, d); err != nil {
		t.Fatal(err)
	}
	text := d.out() + d.errOut()
	if strings.Contains(text, testToken) || strings.Contains(text, code) {
		t.Fatal("join output contains the secret")
	}
	if !strings.Contains(d.out(), "role: member") || !strings.Contains(d.out(), "routes: (none)") {
		t.Fatalf("stdout:\n%s", d.out())
	}
	cfg := host.files["/home/acme/.idoris/vpn.json"]
	if !bytes.Contains(cfg, []byte(`"accept_routes": true`)) || bytes.Contains(cfg, []byte("advertise_routes")) || bytes.Contains(cfg, []byte(testToken)) {
		t.Fatalf("config %s", cfg)
	}
	if host.modes["/home/acme/.idoris/enroll.token"] != 0o600 {
		t.Fatalf("token mode %#o", host.modes["/home/acme/.idoris/enroll.token"])
	}
}

func TestJoinGatewayYesAdvertisesDevice(t *testing.T) {
	host := newFakeOS(false, "linux")
	code := codeFor(t, join.RoleGateway, "https://enroll.example.org", false)
	d := testDeps(host, "")
	if err := joinCmd([]string{"--yes", "--device", "10.251.73.10", "--no-service", code}, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.out()+d.errOut(), testToken) {
		t.Fatal("secret leaked")
	}
	if !strings.Contains(d.out(), "routes: 10.251.73.10/32") || !strings.Contains(d.out(), "auto-approve: yes") {
		t.Fatalf("stdout:\n%s", d.out())
	}
	if !strings.Contains(d.out(), "sudo: "+gateway.SudoApplyCommand("/home/acme/.idoris/gateway-plan.json")) {
		t.Fatalf("sudo line missing:\n%s", d.out())
	}
	if host.forwards != 0 {
		t.Fatal("non-root join enabled forwarding")
	}
	cfg := host.files["/home/acme/.idoris/vpn.json"]
	if !bytes.Contains(cfg, []byte("10.251.73.10/32")) || bytes.Contains(cfg, []byte("10.251.73.0/24")) {
		t.Fatalf("config %s", cfg)
	}
}

func TestJoinGatewayYesRequiresDevice(t *testing.T) {
	d := testDeps(newFakeOS(false, "linux"), "")
	code := codeFor(t, join.RoleGateway, "https://enroll.example.org", false)
	if err := joinCmd([]string{"--yes", code}, d); err == nil || !strings.Contains(err.Error(), "--device") {
		t.Fatalf("%v", err)
	}
}

func TestJoinGatewayPrompts(t *testing.T) {
	host := newFakeOS(true, "linux")
	code := codeFor(t, join.RoleGateway, "https://enroll.example.org", false)
	d := testDeps(host, "n\n10.251.73.10\ny\n")
	if err := joinCmd([]string{code}, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.out(), qLocalAI) || !strings.Contains(d.out(), "ip-forward: enabled") {
		t.Fatalf("stdout:\n%s", d.out())
	}
	if host.forwards != 1 || !bytes.Contains(host.files[gateway.IPForwardConf], []byte("net.ipv4.ip_forward = 1")) {
		t.Fatal("root prompt path did not enable forwarding")
	}
}

func TestJoinGatewayYesToLocalAI(t *testing.T) {
	host := newFakeOS(false, "darwin")
	code := codeFor(t, join.RoleGateway, "https://enroll.example.org", false)
	d := testDeps(host, "y\ny\n")
	if err := joinCmd([]string{code}, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.out(), "role: local-ai") || strings.Contains(d.out(), "10.251.73.10/32") {
		t.Fatalf("stdout:\n%s", d.out())
	}
}

func TestJoinRoleOverrideAndHTTP(t *testing.T) {
	host := newFakeOS(false, "linux")
	code := codeFor(t, join.RoleGateway, "http://enroll.example.org", true)
	d := testDeps(host, "")
	if err := joinCmd([]string{"--yes", code}, d); err == nil {
		t.Fatal("http code without --allow-insecure")
	}
	d = testDeps(host, "")
	if err := joinCmd([]string{"--yes", "--allow-insecure", "--role-override", "member", code}, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.out(), "role: member") {
		t.Fatalf("stdout:\n%s", d.out())
	}
	if !bytes.Contains(host.files["/home/acme/.idoris/vpn.json"], []byte(`"enroll_allow_insecure": true`)) {
		t.Fatalf("config %s", host.files["/home/acme/.idoris/vpn.json"])
	}
}

func TestJoinDeclineDoesNotWrite(t *testing.T) {
	host := newFakeOS(false, "linux")
	code := codeFor(t, join.RoleMember, "https://enroll.example.org", false)
	d := testDeps(host, "n\n")
	if err := joinCmd([]string{code}, d); err == nil || !strings.Contains(err.Error(), "not applied") {
		t.Fatalf("%v", err)
	}
	if len(host.files) != 0 {
		t.Fatalf("wrote %v", host.files)
	}
}

func TestGatewayDetectAndBlockedPlatform(t *testing.T) {
	host := newFakeOS(false, "linux")
	d := testDeps(host, "")
	if err := gatewayCmd([]string{"detect", "--json"}, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.out(), `"gateway_supported": true`) || !strings.Contains(d.out(), "10.251.73.0/24") {
		t.Fatalf("detect:\n%s", d.out())
	}
	d.detect = func(string) (netdetect.Report, error) {
		return netdetect.Report{Platform: "darwin", GatewaySupported: false}, nil
	}
	code := codeFor(t, join.RoleGateway, "https://enroll.example.org", false)
	if err := joinCmd([]string{"--yes", "--whole-subnet", code}, d); err == nil || !strings.Contains(err.Error(), "Linux") {
		t.Fatalf("%v\n%s", err, d.out())
	}
}

func TestGatewaySetupAndApply(t *testing.T) {
	host := newFakeOS(false, "linux")
	tokenPath := "/home/acme/.idoris/enroll.token"
	host.files["/home/acme/.idoris/vpn.json"] = []byte(`{"enroll_url":"https://enroll.example.org","enroll_token_file":"` + tokenPath + `","hostname":"office-gw"}` + "\n")
	host.files[tokenPath] = []byte(testToken + "\n")
	d := testDeps(host, "")
	if err := gatewayCmd([]string{"setup", "--yes", "--device", "10.251.73.10", "--no-service"}, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.out()+d.errOut(), testToken) {
		t.Fatal("setup leaked the token")
	}
	planPath := "/home/acme/.idoris/gateway-plan.json"
	if bytes.Contains(host.files[planPath], []byte(testToken)) {
		t.Fatal("plan contains the token")
	}
	d = testDeps(host, "")
	if err := gatewayCmd([]string{"apply", "--plan", planPath, "--no-service"}, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.out(), "sudo: ") || strings.Contains(d.out(), testToken) {
		t.Fatalf("apply:\n%s", d.out())
	}
}

type fakeOS struct {
	files    map[string][]byte
	modes    map[string]os.FileMode
	root     bool
	goos     string
	forwards int
}

func newFakeOS(root bool, goos string) *fakeOS {
	return &fakeOS{files: map[string][]byte{}, modes: map[string]os.FileMode{}, root: root, goos: goos}
}

func (m *fakeOS) WriteFile(path string, data []byte, mode os.FileMode) error {
	m.files[path] = append([]byte(nil), data...)
	m.modes[path] = mode
	return nil
}
func (m *fakeOS) MkdirAll(string, os.FileMode) error { return nil }
func (m *fakeOS) Stat(path string) (os.FileInfo, error) {
	if _, ok := m.files[path]; !ok {
		return nil, os.ErrNotExist
	}
	return fakeInfo{name: filepath.Base(path)}, nil
}
func (m *fakeOS) Chmod(path string, mode os.FileMode) error {
	if _, ok := m.files[path]; !ok {
		return os.ErrNotExist
	}
	m.modes[path] = mode
	return nil
}
func (m *fakeOS) ReadFile(path string) ([]byte, error) {
	b, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}
func (m *fakeOS) IsRoot() bool { return m.root }
func (m *fakeOS) GOOS() string { return m.goos }
func (m *fakeOS) EnableIPForward(path, content string) error {
	m.forwards++
	return m.WriteFile(path, []byte(content), 0o644)
}
func (m *fakeOS) InstallService(string) error { return nil }

type fakeInfo struct{ name string }

func (m fakeInfo) Name() string       { return m.name }
func (m fakeInfo) Size() int64        { return 0 }
func (m fakeInfo) Mode() os.FileMode  { return 0 }
func (m fakeInfo) ModTime() time.Time { return time.Time{} }
func (m fakeInfo) IsDir() bool        { return false }
func (m fakeInfo) Sys() any           { return nil }
