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
	d := testDeps(host, "y\nn\n10.251.73.10\ny\n")
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
	// Confirm the authority, then claim this gateway code belongs on the Local AI.
	d := testDeps(host, "y\ny\n")
	err := joinCmd([]string{code}, d)
	if err == nil || !strings.Contains(err.Error(), "local-ai") {
		t.Fatalf("%v", err)
	}
	if len(host.files) != 0 {
		t.Fatalf("mismatch wrote %v", host.files)
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
	mkdirs   int
	installs int
}

func newFakeOS(root bool, goos string) *fakeOS {
	return &fakeOS{files: map[string][]byte{}, modes: map[string]os.FileMode{}, root: root, goos: goos}
}

// WriteFile matches os.WriteFile: an existing file keeps its mode. The real
// osHost uses fsutil.WriteFileAtomic, which replaces the inode.
func (m *fakeOS) WriteFile(path string, data []byte, mode os.FileMode) error {
	if _, exists := m.files[path]; exists {
		m.files[path] = append([]byte(nil), data...)
		return nil
	}
	m.files[path] = append([]byte(nil), data...)
	m.modes[path] = mode
	return nil
}
func (m *fakeOS) MkdirAll(string, os.FileMode) error {
	m.mkdirs++
	return nil
}
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
func (m *fakeOS) InstallService(string) error {
	m.installs++
	return nil
}

type fakeInfo struct{ name string }

func (m fakeInfo) Name() string       { return m.name }
func (m fakeInfo) Size() int64        { return 0 }
func (m fakeInfo) Mode() os.FileMode  { return 0 }
func (m fakeInfo) ModTime() time.Time { return time.Time{} }
func (m fakeInfo) IsDir() bool        { return false }
func (m fakeInfo) Sys() any           { return nil }

func TestR3W2JoinCodeInputsMatchAndWarn(t *testing.T) {
	code := codeFor(t, join.RoleMember, "https://enroll.example.org", false)
	run := func(t *testing.T, args []string, in string, term bool, hidden string) (string, string) {
		t.Helper()
		host := newFakeOS(false, "linux")
		d := testDeps(host, in)
		if term {
			d.term = func() bool { return true }
			d.readPassword = func() (string, error) { return hidden, nil }
		}
		if err := joinCmd(args, d); err != nil {
			t.Fatal(err)
		}
		cfg := host.files["/home/acme/.idoris/vpn.json"]
		if bytes.Contains(cfg, []byte(testToken)) || bytes.Contains(cfg, []byte(code)) {
			t.Fatalf("config holds a secret: %s", cfg)
		}
		return string(cfg), d.out() + "\n" + d.errOut()
	}
	fileHost := newFakeOS(false, "linux")
	fileHost.files["/tmp/join.code"] = []byte(code + "\nrest\n")
	d := testDeps(fileHost, "")
	if err := joinCmd([]string{"--yes", "--code-file", "/tmp/join.code"}, d); err != nil {
		t.Fatal(err)
	}
	fromFile := string(fileHost.files["/home/acme/.idoris/vpn.json"])
	fromStdin, _ := run(t, []string{"--yes", "--code-stdin"}, code+"\n", false, "")
	fromPrompt, _ := run(t, []string{"--yes"}, "", true, code)
	fromArg, text := run(t, []string{"--yes", code}, "", false, "")
	if fromFile != fromStdin || fromFile != fromPrompt || fromFile != fromArg {
		t.Fatalf("plans differ\nfile %s\nstdin %s\nprompt %s\narg %s", fromFile, fromStdin, fromPrompt, fromArg)
	}
	if !strings.Contains(fromFile, `"socks5_listen": "127.0.0.1:1080"`) {
		t.Fatalf("member config %s", fromFile)
	}
	if !strings.Contains(text, "process list") || !strings.Contains(text, "shell history") || strings.Contains(text, code) || strings.Contains(text, testToken) {
		t.Fatalf("positional warning:\n%s", text)
	}
	if !strings.Contains(fromArg, "127.0.0.1:1080") {
		t.Fatal("positional plan dropped socks")
	}
	// The prompt path prints the access lines and the authority, and never the code.
	host := newFakeOS(false, "linux")
	d = testDeps(host, "")
	d.term = func() bool { return true }
	d.readPassword = func() (string, error) { return code, nil }
	if err := joinCmd([]string{"--yes"}, d); err != nil {
		t.Fatal(err)
	}
	out := d.out()
	for _, want := range []string{
		"enrollment-authority: enroll.example.org",
		"access: SOCKS5 127.0.0.1:1080",
		"access: SOCKS5 credential file /home/acme/.idoris/vpn-state/socks5.auth",
		"access: Reach the Local AI through this proxy by its MagicDNS name <local-ai-hostname>.idoris.internal (your administrator gives you the exact name)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out+d.errOut(), code) || strings.Contains(out, testToken) {
		t.Fatal("prompt path printed a secret")
	}

	d = testDeps(newFakeOS(false, "linux"), "")
	if err := joinCmd([]string{"--code-file", "/tmp/join.code", "--code-stdin"}, d); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("%v", err)
	}
	d = testDeps(newFakeOS(false, "linux"), code+"\n")
	if err := joinCmd([]string{"--code-stdin", code}, d); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("%v", err)
	}
	d = testDeps(newFakeOS(false, "linux"), "")
	if err := joinCmd([]string{"--yes"}, d); err == nil || !strings.Contains(err.Error(), "--code-file") {
		t.Fatalf("%v", err)
	}
}

func TestR3W2JoinAuthorityConfirm(t *testing.T) {
	code := codeFor(t, join.RoleMember, "https://enroll.example.org:8443", false)
	var calls int
	withDiscover := func(in string, args ...string) (deps, *fakeOS, error) {
		host := newFakeOS(false, "linux")
		d := testDeps(host, in)
		d.discover = func(context.Context, string, string, bool) (*enroll.Discovery, error) {
			calls++
			return &enroll.Discovery{Tenant: "acme"}, nil
		}
		err := joinCmd(args, d)
		return d, host, err
	}
	calls = 0
	d, host, err := withDiscover("", "--yes", "--expect-authority", "evil.example", code)
	if err == nil || !strings.Contains(err.Error(), "does not match") || !strings.Contains(d.out(), "enrollment-authority: enroll.example.org:8443") {
		t.Fatalf("%v\n%s", err, d.out())
	}
	if calls != 0 || len(host.files) != 0 {
		t.Fatalf("mismatch contacted the server (%d) or wrote %v", calls, host.files)
	}
	calls = 0
	d, host, err = withDiscover("n\n", code)
	if err == nil || !strings.Contains(err.Error(), "not applied") || calls != 0 || len(host.files) != 0 {
		t.Fatalf("decline: %v calls %d files %v\n%s", err, calls, host.files, d.out())
	}
	if !strings.Contains(d.out(), "Contact enrollment authority enroll.example.org:8443?") {
		t.Fatalf("stdout:\n%s", d.out())
	}
	calls = 0
	d, _, err = withDiscover(code+"\n", "--yes", "--expect-authority", "Enroll.Example.Org:8443", "--code-stdin")
	if err != nil || calls != 1 || !strings.Contains(d.out(), "enrollment-authority: enroll.example.org:8443") {
		t.Fatalf("%v calls %d\n%s", err, calls, d.out())
	}
}

func TestR3W2JoinRoleUsesDiscovery(t *testing.T) {
	host := newFakeOS(false, "linux")
	code := codeFor(t, join.RoleGateway, "https://enroll.example.org", false)
	d := testDeps(host, "")
	d.discover = func(context.Context, string, string, bool) (*enroll.Discovery, error) {
		return &enroll.Discovery{Tenant: "acme", Role: join.RoleLocalAI, LANCIDRs: []string{"10.251.73.10/32"}}, nil
	}
	err := joinCmd([]string{"--yes", "--device", "10.251.73.10", "--no-service", code}, d)
	if err == nil || !strings.Contains(err.Error(), "local-ai") || len(host.files) != 0 {
		t.Fatalf("%v files %v", err, host.files)
	}

	host = newFakeOS(false, "linux")
	d = testDeps(host, "")
	d.discover = func(context.Context, string, string, bool) (*enroll.Discovery, error) {
		return &enroll.Discovery{Tenant: "acme", Role: join.RoleGateway}, nil
	}
	err = joinCmd([]string{"--yes", "--role-override", "member", "--no-service", code}, d)
	if err == nil || !strings.Contains(err.Error(), "--role-override") || len(host.files) != 0 {
		t.Fatalf("%v files %v", err, host.files)
	}

	// Discovery agrees with the code, so the plan is a gateway and not a guess.
	host = newFakeOS(false, "linux")
	d = testDeps(host, code+"\n")
	d.discover = func(context.Context, string, string, bool) (*enroll.Discovery, error) {
		return &enroll.Discovery{Tenant: "acme", Role: join.RoleGateway, LANCIDRs: []string{"10.251.73.10/32"}}, nil
	}
	if err := joinCmd([]string{"--yes", "--device", "10.251.73.10", "--no-service", "--code-stdin"}, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.out(), "role: gateway") {
		t.Fatalf("stdout:\n%s", d.out())
	}

	// gateway setup refuses a discovered local-ai role when this machine is not one.
	host = newFakeOS(false, "linux")
	tokenPath := "/home/acme/.idoris/enroll.token"
	original := []byte(`{"enroll_url":"https://enroll.example.org","enroll_token_file":"` + tokenPath + `","hostname":"office-gw"}` + "\n")
	host.files["/home/acme/.idoris/vpn.json"] = append([]byte(nil), original...)
	host.files[tokenPath] = []byte(testToken + "\n")
	d = testDeps(host, "")
	d.discover = func(context.Context, string, string, bool) (*enroll.Discovery, error) {
		return &enroll.Discovery{Tenant: "acme", Role: join.RoleLocalAI}, nil
	}
	if err := gatewayCmd([]string{"setup", "--yes", "--device", "10.251.73.10", "--no-service"}, d); err == nil || !strings.Contains(err.Error(), "local-ai") {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(host.files["/home/acme/.idoris/vpn.json"], original) {
		t.Fatalf("setup rewrote the config: %s", host.files["/home/acme/.idoris/vpn.json"])
	}
}

func TestR3W2JoinDistinctConfigsAndReplace(t *testing.T) {
	encode := func(t *testing.T, rawURL, token string) string {
		t.Helper()
		c, err := join.Encode(join.Payload{
			V: 1, EnrollURL: rawURL, Token: token, Role: join.RoleMember, Tenant: "acme", HostnameHint: "laptop",
		}, join.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	codeA := encode(t, "https://a.example", "idv1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	codeB := encode(t, "https://b.example", "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	host := newFakeOS(false, "linux")
	host.files["/tmp/a.code"] = []byte(codeA + "\n")
	host.files["/tmp/b.code"] = []byte(codeB + "\n")
	d := testDeps(host, "")
	if err := joinCmd([]string{"--yes", "--no-service", "--config", "/home/acme/orgA/vpn.json", "--code-file", "/tmp/a.code"}, d); err != nil {
		t.Fatal(err)
	}
	d = testDeps(host, "")
	if err := joinCmd([]string{"--yes", "--no-service", "--config", "/home/acme/orgB/vpn.json", "--code-file", "/tmp/b.code"}, d); err != nil {
		t.Fatal(err)
	}
	tokA := "/home/acme/orgA/vpn.json.enroll-token"
	tokB := "/home/acme/orgB/vpn.json.enroll-token"
	if string(host.files[tokA]) != "idv1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" || string(host.files[tokB]) != "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n" {
		t.Fatalf("tokens %q %q", host.files[tokA], host.files[tokB])
	}
	if _, ok := host.files["/home/acme/.idoris/enroll.token"]; ok {
		t.Fatal("custom configs wrote the shared token path")
	}
	if bytes.Contains(host.files["/home/acme/orgA/vpn.json"], []byte("b.example")) {
		t.Fatal("B overwrote A")
	}
	d = testDeps(host, "")
	err := joinCmd([]string{"--yes", "--no-service", "--config", "/home/acme/orgA/vpn.json", "--code-file", "/tmp/b.code"}, d)
	if err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("%v", err)
	}
	if string(host.files[tokA]) != "idv1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" {
		t.Fatal("refused join replaced A's token")
	}
	d = testDeps(host, "")
	if err := joinCmd([]string{"--yes", "--no-service", "--replace", "--config", "/home/acme/orgA/vpn.json", "--code-file", "/tmp/b.code"}, d); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(host.files["/home/acme/orgA/vpn.json"], []byte("https://b.example")) || string(host.files[tokA]) != "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n" {
		t.Fatalf("replace: %s", host.files["/home/acme/orgA/vpn.json"])
	}
	if string(host.files[tokB]) != "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n" {
		t.Fatal("replacing A changed B")
	}

	// gateway apply --replace is the same switch for a plan that names another URL.
	planPath := "/home/acme/orgA/vpn.json.gateway-plan.json"
	plan := bytes.ReplaceAll(host.files[planPath], []byte("https://b.example"), []byte("https://c.example"))
	host.files[planPath] = plan
	before := append([]byte(nil), host.files["/home/acme/orgA/vpn.json"]...)
	d = testDeps(host, "")
	if err := gatewayCmd([]string{"apply", "--plan", planPath, "--no-service"}, d); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(before, host.files["/home/acme/orgA/vpn.json"]) {
		t.Fatal("apply without --replace changed the config")
	}
	d = testDeps(host, "")
	if err := gatewayCmd([]string{"apply", "--plan", planPath, "--no-service", "--replace"}, d); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(host.files["/home/acme/orgA/vpn.json"], []byte("https://c.example")) {
		t.Fatalf("apply --replace: %s", host.files["/home/acme/orgA/vpn.json"])
	}
}

// TestR4WRootApplyForwardsOnly checks that a root `gateway apply` enables
// forwarding and does not rewrite the files the unprivileged user owns.
func TestR4WRootApplyForwardsOnly(t *testing.T) {
	const (
		planPath = "/home/acme/.idoris/gateway-plan.json"
		cfgPath  = "/home/acme/.idoris/vpn.json"
		tokPath  = "/home/acme/.idoris/enroll.token"
	)
	planBody := []byte(`{"role":"gateway","routes":["10.1.2.0/24"],"mode":"auto","enroll_url":"https://enroll.example","token_file":"` + tokPath + `","config_path":"` + cfgPath + `"}` + "\n")
	host := newFakeOS(true, "linux")
	host.files[planPath] = append([]byte(nil), planBody...)
	const userConfig = "{\"hostname\":\"office-gw\"}\n"
	host.files[cfgPath] = []byte(userConfig)
	host.files[tokPath] = []byte("idv1_userownedtokenuserownedtokenu\n")
	prev := readPlanHandoff
	readPlanHandoff = func(string) (gateway.PlanHandoff, error) {
		return gateway.PlanHandoff{Regular: true, Mode: 0o600, UID: 1000, Root: true, SudoUID: "1000"}, nil
	}
	t.Cleanup(func() { readPlanHandoff = prev })
	d := testDeps(host, "")
	if err := gatewayCmd([]string{"apply", "--plan", planPath}, d); err != nil {
		t.Fatal(err)
	}
	if host.forwards != 1 || host.mkdirs != 0 || host.installs != 0 {
		t.Fatalf("forwards=%d mkdirs=%d installs=%d", host.forwards, host.mkdirs, host.installs)
	}
	if string(host.files[cfgPath]) != userConfig || string(host.files[tokPath]) != "idv1_userownedtokenuserownedtokenu\n" {
		t.Fatalf("root apply rewrote user files\nconfig %s\ntoken %s", host.files[cfgPath], host.files[tokPath])
	}
	if !bytes.Equal(host.files[planPath], planBody) {
		t.Fatal("root apply rewrote the plan")
	}
	if !strings.Contains(d.out(), "ip-forward: enabled") {
		t.Fatalf("stdout:\n%s", d.out())
	}
	// A rejected handoff never enables forwarding.
	for _, tc := range []struct {
		name string
		h    gateway.PlanHandoff
		want string
	}{
		{"foreign", gateway.PlanHandoff{Regular: true, Mode: 0o600, UID: 1001, Root: true, SudoUID: "1000"}, "uid 1001"},
		{"symlink", gateway.PlanHandoff{Symlink: true, Mode: 0o600, UID: 1000, Root: true, SudoUID: "1000"}, "symlink"},
		{"mode", gateway.PlanHandoff{Regular: true, Mode: 0o666, UID: 1000, Root: true, SudoUID: "1000"}, "0600"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host.forwards = 0
			readPlanHandoff = func(string) (gateway.PlanHandoff, error) { return tc.h, nil }
			d := testDeps(host, "")
			err := gatewayCmd([]string{"apply", "--plan", planPath}, d)
			if err == nil || !strings.Contains(err.Error(), tc.want) || host.forwards != 0 {
				t.Fatalf("err=%v forwards=%d", err, host.forwards)
			}
		})
	}
}
