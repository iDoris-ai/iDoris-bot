package gateway

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

func officeReport() netdetect.Report {
	rec := netdetect.Candidate{
		Name: "eth0", Addr: "10.251.73.4", Bits: 24, Network: "10.251.73.0/24",
		Gateway: "10.251.73.1", Default: true,
		Warnings: []netdetect.Notice{{Code: "common-lan", Text: "overlaps a common range"}},
	}
	// 10.251.73.0/24 does not overlap the built-in common list. The warning
	// above is injected so the planner is seen copying candidate warnings.
	return netdetect.Report{
		Platform: "linux", GatewaySupported: true,
		Candidates:  []netdetect.Candidate{rec, {Name: "eth1", Addr: "10.9.0.4", Bits: 24, Network: "10.9.0.0/24"}},
		Recommended: &rec,
	}
}

func TestPlanNarrowRouteAndApproval(t *testing.T) {
	req := Request{
		DeviceIPs: []string{"10.251.73.10"},
		Detection: officeReport(),
		Approved:  []string{"10.251.73.0/24"},
		Tenant:    "acme",
		Hostname:  "office-gw",
	}
	p, err := BuildPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if p.Blocked || p.Role != join.RoleGateway || p.Mode != "system" || p.Tag != "tag:acme-gateway" {
		t.Fatalf("%+v", p)
	}
	if len(p.Routes) != 1 || p.Routes[0] != "10.251.73.10/32" {
		t.Fatalf("routes %v", p.Routes)
	}
	if joined(p.Routes) == "10.251.73.0/24" || p.WholeSubnet {
		t.Fatal("narrow plan advertised the subnet")
	}
	if !p.WillAutoApprove || p.NeedsAdminApproval || p.AdminCommand != "" {
		t.Fatalf("approval %+v", p)
	}
	if !hasNotice(p.Warnings, "common-lan") {
		t.Fatalf("warnings %+v", p.Warnings)
	}

	req.Approved = []string{"192.168.50.0/24"}
	p, err = BuildPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if p.WillAutoApprove || !p.NeedsAdminApproval {
		t.Fatalf("expected admin approval: %+v", p)
	}
	want := "headscale nodes approve-routes --identifier <ID> --routes 10.251.73.10/32  # <ID> is the numeric id of office-gw from `headscale nodes list`"
	if p.AdminCommand != want {
		t.Fatalf("command %q", p.AdminCommand)
	}

	req.Approved = nil
	req.WholeSubnet = true
	req.DeviceIPs = nil
	p, err = BuildPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Routes) != 1 || p.Routes[0] != "10.251.73.0/24" || !p.WholeSubnet || !hasNotice(p.Warnings, "whole-subnet") {
		t.Fatalf("whole %+v", p)
	}
	if p.WillAutoApprove {
		t.Fatal("unlisted subnet must not auto-approve")
	}
}

func TestPlanRefusesGatewayOffLinuxAndBadInput(t *testing.T) {
	rep := officeReport()
	rep.Platform = "darwin"
	rep.GatewaySupported = false
	p, err := BuildPlan(Request{Detection: rep, Tenant: "acme", DeviceIPs: []string{"10.251.73.10"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Blocked || p.PlatformOK || len(p.Routes) != 0 {
		t.Fatalf("%+v", p)
	}
	if _, err := BuildPlan(Request{Detection: officeReport(), Tenant: "acme"}); err == nil {
		t.Fatal("missing device")
	}
	if _, err := BuildPlan(Request{Detection: officeReport(), Tenant: "acme", DeviceIPs: []string{"10.1.1.1"}}); err == nil {
		t.Fatal("device outside LAN")
	}
	if _, err := BuildPlan(Request{Detection: officeReport(), Tenant: "acme", WholeSubnet: true, DeviceIPs: []string{"10.251.73.10"}}); err == nil {
		t.Fatal("both choices")
	}
	if _, err := BuildPlan(Request{Detection: officeReport(), Tenant: "acme", DeviceIPs: []string{"10.251.73.0/24"}}); err == nil {
		t.Fatal("prefix accepted as a device")
	}
}

func TestR3W2AdvertisedPrefixMustBePrivate(t *testing.T) {
	huge := netdetect.Candidate{Name: "eth0", Addr: "10.1.2.3", Bits: 1, Network: "0.0.0.0/1", Default: true}
	rep := netdetect.Report{
		Platform: "linux", GatewaySupported: true,
		Candidates:  []netdetect.Candidate{huge},
		Recommended: &huge,
	}
	if _, err := BuildPlan(Request{Detection: rep, Tenant: "acme", WholeSubnet: true, Hostname: "gw"}); err == nil || !strings.Contains(err.Error(), "RFC1918") {
		t.Fatalf("whole subnet of /1: %v", err)
	}
	if _, err := BuildPlan(Request{Detection: rep, Tenant: "acme", DeviceIPs: []string{"8.8.8.8"}, Hostname: "gw"}); err == nil || !strings.Contains(err.Error(), "RFC1918") {
		t.Fatalf("public device: %v", err)
	}
	if _, err := BuildPlan(Request{Detection: rep, Tenant: "acme", DeviceIPs: []string{"10.1.2.3"}, Hostname: "gw"}); err == nil || !strings.Contains(err.Error(), "RFC1918") {
		t.Fatalf("private device inside a public prefix: %v", err)
	}
	for _, ip := range []string{"169.254.1.1", "100.64.0.1", "127.0.0.1", "1.2.3.4"} {
		if _, err := BuildPlan(Request{Detection: officeReport(), Tenant: "acme", DeviceIPs: []string{ip}, Hostname: "gw"}); err == nil || !strings.Contains(err.Error(), "RFC1918") {
			t.Fatalf("%s: %v", ip, err)
		}
	}

	wide := netdetect.Candidate{Name: "eth0", Addr: "10.1.2.3", Bits: 8, Network: "10.0.0.0/8", Default: true}
	wideRep := netdetect.Report{Platform: "linux", GatewaySupported: true, Candidates: []netdetect.Candidate{wide}, Recommended: &wide}
	p, err := BuildPlan(Request{Detection: wideRep, Tenant: "acme", DeviceIPs: []string{"10.1.2.3"}, Hostname: "gw"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Routes) != 1 || p.Routes[0] != "10.1.2.3/32" {
		t.Fatalf("routes %v", p.Routes)
	}
	if _, err := BuildPlan(Request{Detection: wideRep, Tenant: "acme", WholeSubnet: true, Hostname: "gw"}); err != nil {
		t.Fatal(err)
	}

	uncertain := netdetect.Candidate{Name: "corp0", Addr: "10.9.0.4", Bits: 24, Network: "10.9.0.0/24", Default: true, Uncertain: true}
	uRep := netdetect.Report{Platform: "linux", GatewaySupported: true, Candidates: []netdetect.Candidate{uncertain}, Recommended: &uncertain}
	if _, err := BuildPlan(Request{Detection: uRep, Tenant: "acme", WholeSubnet: true, Hostname: "gw"}); err == nil || !strings.Contains(err.Error(), "not a confirmed LAN") {
		t.Fatalf("uncertain whole subnet: %v", err)
	}
	p, err = BuildPlan(Request{Detection: uRep, Tenant: "acme", DeviceIPs: []string{"10.9.0.9"}, Hostname: "gw"})
	if err != nil || len(p.Routes) != 1 || p.Routes[0] != "10.9.0.9/32" {
		t.Fatalf("explicit device on an uncertain LAN: %v %+v", err, p.Routes)
	}
}

func TestPlanLocalAIAndMember(t *testing.T) {
	p, err := BuildPlan(Request{ThisMachineIsLocalAI: true, Tenant: "acme", Hostname: "ai-box"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Role != join.RoleLocalAI || p.Tag != "tag:acme-local-ai" || len(p.Routes) != 0 || p.Mode != "auto" || !p.WillAutoApprove {
		t.Fatalf("%+v", p)
	}
	m, err := SimplePlan(join.RoleMember, "acme", "laptop")
	if err != nil || !m.AcceptRoutes || len(m.Routes) != 0 || m.Role != join.RoleMember {
		t.Fatalf("%v %+v", err, m)
	}
}

func TestApplyIdempotentRootAndNonRoot(t *testing.T) {
	p, err := BuildPlan(Request{
		DeviceIPs: []string{"10.251.73.10"},
		Detection: officeReport(),
		Approved:  []string{"10.251.73.10/32"},
		Tenant:    "acme",
		Hostname:  "office-gw",
	})
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = "https://enroll.example.org"
	p.TokenFile = "/home/acme/.idoris/enroll.token"
	p.ConfigPath = "/home/acme/.idoris/vpn.json"
	p.AllowInsecure = false
	const token = "idv1_secretsecretsecretsecretsecretse"
	const planPath = "/home/acme/.idoris/gateway-plan.json"

	root := newMemHost(true, "linux")
	res, err := Apply(p, root, ApplyOptions{Token: token, PlanPath: planPath})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IPForwardApplied || res.SudoCommand != "" || !res.ServiceInstalled || root.forwards != 1 {
		t.Fatalf("%+v forwards %d", res, root.forwards)
	}
	if string(root.files[IPForwardConf]) != IPForwardBody {
		t.Fatalf("sysctl %q", root.files[IPForwardConf])
	}
	if bytes.Contains(root.files[planPath], []byte(token)) || bytes.Contains(root.files[p.ConfigPath], []byte(token)) {
		t.Fatal("token leaked into the plan or the config")
	}
	if root.modes[p.TokenFile] != 0o600 || root.modes[planPath] != 0o600 || root.modes[p.ConfigPath] != 0o600 {
		t.Fatalf("modes %#o %#o %#o", root.modes[p.TokenFile], root.modes[planPath], root.modes[p.ConfigPath])
	}
	if !bytes.Contains(root.files[p.ConfigPath], []byte(`"advertise_routes"`)) || bytes.Contains(root.files[p.ConfigPath], []byte("10.251.73.0/24")) {
		t.Fatalf("config %s", root.files[p.ConfigPath])
	}
	var loaded vpnd.Config
	dec := json.NewDecoder(bytes.NewReader(root.files[p.ConfigPath]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.EnrollToken != "" || loaded.AuthKey != "" || loaded.Role != join.RoleGateway || loaded.Mode != "system" {
		t.Fatalf("loaded %+v", loaded)
	}
	first := append([]byte(nil), root.files[p.ConfigPath]...)
	res2, err := Apply(p, root, ApplyOptions{Token: token, PlanPath: planPath})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, root.files[p.ConfigPath]) || !res2.IPForwardApplied {
		t.Fatal("second apply changed the config or skipped forwarding")
	}

	user := newMemHost(false, "linux")
	res, err = Apply(p, user, ApplyOptions{Token: token, PlanPath: planPath})
	if err != nil {
		t.Fatal(err)
	}
	if res.IPForwardApplied || user.forwards != 0 {
		t.Fatal("non-root apply changed forwarding")
	}
	if res.SudoCommand != SudoApplyCommand(planPath) {
		t.Fatalf("sudo %q", res.SudoCommand)
	}
	if !bytes.Contains(user.files[p.ConfigPath], []byte("10.251.73.10/32")) {
		t.Fatal("non-root apply skipped the config")
	}
}

func TestApplyBlockedAndMissingToken(t *testing.T) {
	p := Plan{Blocked: true, BlockReason: "Linux only", ConfigPath: "/c", TokenFile: "/t"}
	if _, err := Apply(p, newMemHost(true, "linux"), ApplyOptions{Token: "t"}); err == nil {
		t.Fatal("blocked plan applied")
	}
	ok, err := BuildPlan(Request{ThisMachineIsLocalAI: true, Tenant: "acme", Hostname: "ai"})
	if err != nil {
		t.Fatal(err)
	}
	ok.ConfigPath = "/home/acme/.idoris/vpn.json"
	ok.TokenFile = "/home/acme/.idoris/enroll.token"
	ok.EnrollURL = "https://enroll.example.org"
	h := newMemHost(false, "darwin")
	res, err := Apply(ok, h, ApplyOptions{Token: "idv1_abc", NoService: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.SudoCommand != "" || h.forwards != 0 || !bytes.Contains(h.files[ok.ConfigPath], []byte("local-ai")) {
		t.Fatalf("%+v %s", res, h.files[ok.ConfigPath])
	}
}

type memHost struct {
	files    map[string][]byte
	modes    map[string]os.FileMode
	links    map[string]string
	root     bool
	goos     string
	forwards int
	services []string
}

func newMemHost(root bool, goos string) *memHost {
	return &memHost{files: map[string][]byte{}, modes: map[string]os.FileMode{}, root: root, goos: goos}
}

// WriteFile matches os.WriteFile: a new file takes mode, an existing file keeps
// its mode, and a symlink is followed. Apply's real host uses fsutil instead,
// which is what TestR3W2ApplySecretWrite checks.
func (m *memHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	if target, ok := m.links[path]; ok {
		return m.WriteFile(target, data, mode)
	}
	if _, exists := m.files[path]; exists {
		m.files[path] = append([]byte(nil), data...)
		return nil
	}
	m.files[path] = append([]byte(nil), data...)
	m.modes[path] = mode
	return nil
}
func (m *memHost) MkdirAll(string, os.FileMode) error { return nil }
func (m *memHost) Stat(path string) (os.FileInfo, error) {
	if target, ok := m.links[path]; ok {
		return m.Stat(target)
	}
	if _, ok := m.files[path]; !ok {
		return nil, os.ErrNotExist
	}
	return memInfo{name: filepath.Base(path), mode: m.modes[path]}, nil
}
func (m *memHost) ReadFile(path string) ([]byte, error) {
	if target, ok := m.links[path]; ok {
		return m.ReadFile(target)
	}
	b, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}
func (m *memHost) Chmod(path string, mode os.FileMode) error {
	if _, ok := m.files[path]; !ok {
		return os.ErrNotExist
	}
	m.modes[path] = mode
	return nil
}
func (m *memHost) IsRoot() bool { return m.root }
func (m *memHost) GOOS() string { return m.goos }
func (m *memHost) EnableIPForward(path, content string) error {
	m.forwards++
	return m.WriteFile(path, []byte(content), 0o644)
}
func (m *memHost) InstallService(configPath string) error {
	m.services = append(m.services, configPath)
	return nil
}

type memInfo struct {
	name string
	mode os.FileMode
}

func (m memInfo) Name() string       { return m.name }
func (m memInfo) Size() int64        { return 0 }
func (m memInfo) Mode() os.FileMode  { return m.mode }
func (m memInfo) ModTime() time.Time { return time.Time{} }
func (m memInfo) IsDir() bool        { return false }
func (m memInfo) Sys() any           { return nil }

func TestR3W2ApplyPreservesUnownedKeys(t *testing.T) {
	p, err := BuildPlan(Request{
		DeviceIPs: []string{"10.251.73.10"},
		Detection: officeReport(),
		Approved:  []string{"10.251.73.10/32"},
		Tenant:    "acme",
		Hostname:  "office-gw",
	})
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = "https://enroll.example.org"
	p.TokenFile = "/home/acme/.idoris/enroll.token"
	p.ConfigPath = "/home/acme/.idoris/vpn.json"
	const existing = `{
  "control_url": "https://hs.example/headscale",
  "accept_dns": false,
  "tailscale_socket": "/run/tailscale/tailscaled.sock",
  "state_dir": "/var/lib/idoris/state",
  "forwards": [
    {"listen": "127.0.0.1:11434", "target": "ai.example:11434"}
  ],
  "takeover": false,
  "hostname": "old-name"
}
`
	h := newMemHost(false, "linux")
	h.files[p.ConfigPath] = []byte(existing)
	h.modes[p.ConfigPath] = 0o600
	if _, err := Apply(p, h, ApplyOptions{Token: "idv1_secretsecretsecretsecretsecretse", NoService: true, PlanPath: "/home/acme/.idoris/gateway-plan.json"}); err != nil {
		t.Fatal(err)
	}
	got := h.files[p.ConfigPath]
	beforeKeys, beforeVals := mustObject(t, []byte(existing))
	afterKeys, afterVals := mustObject(t, got)
	unowned := map[string]struct{}{
		"control_url": {}, "accept_dns": {}, "tailscale_socket": {}, "state_dir": {},
		"forwards": {}, "takeover": {},
	}
	for key := range unowned {
		if string(beforeVals[key]) != string(afterVals[key]) {
			t.Fatalf("key %s changed from %s to %s", key, beforeVals[key], afterVals[key])
		}
	}
	if string(afterVals["hostname"]) != `"office-gw"` {
		t.Fatalf("hostname %s", afterVals["hostname"])
	}
	if string(afterVals["control_url"]) != `"https://hs.example/headscale"` {
		t.Fatalf("control_url %s", afterVals["control_url"])
	}
	if bytes.Contains(got, []byte("site_note")) {
		t.Fatalf("unknown key written:\n%s", got)
	}
	// Non-owned keys stay ahead of keys the wizard appended.
	if indexOf(afterKeys, "control_url") > indexOf(afterKeys, "enroll_url") {
		t.Fatalf("order %v", afterKeys)
	}
	if indexOf(beforeKeys, "hostname") != indexOf(afterKeys, "hostname") {
		t.Fatalf("hostname moved: %v -> %v", beforeKeys, afterKeys)
	}
	first := append([]byte(nil), got...)
	if _, err := Apply(p, h, ApplyOptions{Token: "idv1_secretsecretsecretsecretsecretse", NoService: true, PlanPath: "/home/acme/.idoris/gateway-plan.json"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, h.files[p.ConfigPath]) {
		t.Fatalf("second apply changed the config\nfirst:\n%s\nsecond:\n%s", first, h.files[p.ConfigPath])
	}
}

func TestR3W2DistinctConfigsAndReplace(t *testing.T) {
	mk := func(url, cfg, token, host string) Plan {
		p, err := SimplePlan(join.RoleMember, "acme", host)
		if err != nil {
			t.Fatal(err)
		}
		p.EnrollURL = url
		p.ConfigPath = cfg
		p.TokenFile = token
		return p
	}
	h := newMemHost(false, "darwin")
	a := mk("https://a.example", "/home/acme/orgA/vpn.json", "/home/acme/orgA/vpn.enroll-token", "host-a")
	b := mk("https://b.example", "/home/acme/orgB/vpn.json", "/home/acme/orgB/vpn.enroll-token", "host-b")
	if _, err := Apply(a, h, ApplyOptions{Token: "token-a", NoService: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(b, h, ApplyOptions{Token: "token-b", NoService: true}); err != nil {
		t.Fatal(err)
	}
	if string(h.files[a.TokenFile]) != "token-a\n" || string(h.files[b.TokenFile]) != "token-b\n" {
		t.Fatalf("tokens %q %q", h.files[a.TokenFile], h.files[b.TokenFile])
	}
	if bytes.Contains(h.files[a.ConfigPath], []byte("b.example")) || bytes.Contains(h.files[b.ConfigPath], []byte("a.example")) {
		t.Fatal("configs shared an enrollment URL")
	}
	swapped := a
	swapped.EnrollURL = b.EnrollURL
	if _, err := Apply(swapped, h, ApplyOptions{Token: "token-b", NoService: true}); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("same config, other URL: %v", err)
	}
	if string(h.files[a.TokenFile]) != "token-a\n" || bytes.Contains(h.files[a.ConfigPath], []byte("b.example")) {
		t.Fatal("refused apply still changed A")
	}
	if _, err := Apply(a, h, ApplyOptions{Token: "token-a", NoService: true}); err != nil {
		t.Fatalf("same URL must be idempotent: %v", err)
	}
	if _, err := Apply(swapped, h, ApplyOptions{Token: "token-b", NoService: true, ReplaceExisting: true}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(h.files[a.ConfigPath], []byte("https://b.example")) || string(h.files[a.TokenFile]) != "token-b\n" {
		t.Fatalf("replace did not switch A: %s", h.files[a.ConfigPath])
	}
	if string(h.files[b.TokenFile]) != "token-b\n" {
		t.Fatal("replacing A changed B's token")
	}
}

func TestR3W2MemberAndAdminSOCKS(t *testing.T) {
	t.Setenv("HOME", "/home/acme")
	t.Setenv("USERPROFILE", `C:\Users\acme`)
	t.Setenv("STATE_DIRECTORY", "")
	const token = "idv1_secretsecretsecretsecretsecretse"
	applyRole := func(t *testing.T, role, mode string) (ApplyResult, []byte) {
		t.Helper()
		var p Plan
		var err error
		switch role {
		case join.RoleLocalAI:
			p, err = BuildPlan(Request{ThisMachineIsLocalAI: true, Tenant: "acme", Hostname: "ai-box"})
		case join.RoleGateway:
			p, err = BuildPlan(Request{
				DeviceIPs: []string{"10.251.73.10"}, Detection: officeReport(),
				Approved: []string{"10.251.73.10/32"}, Tenant: "acme", Hostname: "office-gw",
			})
		default:
			p, err = SimplePlan(role, "acme", "laptop")
		}
		if err != nil {
			t.Fatal(err)
		}
		if mode != "" {
			p.Mode = mode
		}
		p.EnrollURL = "https://enroll.example.org"
		p.ConfigPath = "/home/acme/.idoris/" + role + ".json"
		p.TokenFile = "/home/acme/.idoris/" + role + ".enroll-token"
		// A gateway plan enables IP forwarding, which Apply refuses off Linux.
		goos, root := "darwin", false
		if role == join.RoleGateway {
			goos, root = "linux", true
		}
		h := newMemHost(root, goos)
		res, err := Apply(p, h, ApplyOptions{Token: token, NoService: true})
		if err != nil {
			t.Fatal(err)
		}
		return res, h.files[p.ConfigPath]
	}
	for _, role := range []string{join.RoleMember, join.RoleAdmin} {
		res, cfg := applyRole(t, role, "")
		if !bytes.Contains(cfg, []byte(`"socks5_listen": "127.0.0.1:1080"`)) || bytes.Contains(cfg, []byte("socks5_allow_anonymous")) || bytes.Contains(cfg, []byte(token)) {
			t.Fatalf("%s config %s", role, cfg)
		}
		text := strings.Join(res.AccessInfo, "\n")
		if !strings.Contains(text, "127.0.0.1:1080") || !strings.Contains(text, "/home/acme/.idoris/vpn-state/socks5.auth") || !strings.Contains(text, "<local-ai-hostname>.idoris.internal") || strings.Contains(text, "laptop.idoris.internal") {
			t.Fatalf("%s access %q", role, text)
		}
		if strings.Contains(text, token) || strings.Contains(text, ":") && strings.Contains(text, "password") {
			t.Fatalf("access text looks like it carries a secret: %s", text)
		}
	}
	for _, role := range []string{join.RoleLocalAI, join.RoleGateway} {
		res, cfg := applyRole(t, role, "")
		if bytes.Contains(cfg, []byte("socks5_listen")) || len(res.AccessInfo) != 0 {
			t.Fatalf("%s should not enable SOCKS5: %s %+v", role, cfg, res.AccessInfo)
		}
	}
	if _, cfg := applyRole(t, join.RoleMember, "system"); bytes.Contains(cfg, []byte("socks5_listen")) {
		t.Fatalf("explicit system member got SOCKS5: %s", cfg)
	}
	if _, cfg := applyRole(t, join.RoleMember, "embedded"); !bytes.Contains(cfg, []byte(`"socks5_listen": "127.0.0.1:1080"`)) {
		t.Fatalf("embedded member: %s", cfg)
	}

	p, err := SimplePlan(join.RoleMember, "acme", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = "https://enroll.example.org"
	p.ConfigPath = "/home/acme/.idoris/custom.json"
	p.TokenFile = "/home/acme/.idoris/custom.json.enroll-token"
	h := newMemHost(false, "darwin")
	h.files[p.ConfigPath] = []byte("{\n  \"socks5_listen\": \"127.0.0.1:1055\",\n  \"socks5_auth_file\": \"/home/acme/.idoris/custom.auth\",\n  \"state_dir\": \"/var/lib/idoris/state\"\n}\n")
	res, err := Apply(p, h, ApplyOptions{Token: token, NoService: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(h.files[p.ConfigPath], []byte(`"socks5_listen": "127.0.0.1:1055"`)) {
		t.Fatalf("custom socks listener replaced:\n%s", h.files[p.ConfigPath])
	}
	text := strings.Join(res.AccessInfo, "\n")
	if !strings.Contains(text, "127.0.0.1:1055") || !strings.Contains(text, "/home/acme/.idoris/custom.auth") {
		t.Fatalf("access %q", text)
	}
	first := append([]byte(nil), h.files[p.ConfigPath]...)
	if _, err := Apply(p, h, ApplyOptions{Token: token, NoService: true}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, h.files[p.ConfigPath]) {
		t.Fatal("second member apply changed the config")
	}
}

func TestR3W2SudoQuoteRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh")
	}
	samples := []string{
		`$(id)`,
		"`id`",
		"a b",
		"it's",
		"a\nb",
		`has "quotes"`,
		"$(id) and `id` and 'quote'",
		"/tmp/plan.json",
	}
	for _, sample := range samples {
		cmd := SudoApplyCommand(sample)
		quoted := strings.TrimPrefix(cmd, "sudo idoris-vpnd gateway apply --plan ")
		out, err := exec.Command("sh", "-c", "printf %s "+quoted).Output() //nolint:gosec // quoted is the function under test
		if err != nil {
			t.Fatalf("%q: %v", sample, err)
		}
		if string(out) != sample {
			t.Fatalf("quoted %s\n got %q want %q", quoted, out, sample)
		}
		if strings.Contains(cmd, `$(id)`) && !strings.Contains(quoted, `'$(id)'`) && sample == `$(id)` {
			t.Fatalf("command substitution is not single-quoted: %s", cmd)
		}
	}
}

func TestR3W2MemHostWriteFileKeepsModeAndFollowsLinks(t *testing.T) {
	m := newMemHost(false, "linux")
	m.files["/t"] = []byte("old")
	m.modes["/t"] = 0o666
	if err := m.WriteFile("/t", []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if m.modes["/t"] != 0o666 || string(m.files["/t"]) != "new" {
		t.Fatalf("mode %#o body %q", m.modes["/t"], m.files["/t"])
	}
	m.links = map[string]string{"/link": "/victim"}
	m.files["/victim"] = []byte("keep")
	m.modes["/victim"] = 0o644
	if err := m.WriteFile("/link", []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if string(m.files["/victim"]) != "secret" {
		t.Fatalf("fake did not follow the link: %q", m.files["/victim"])
	}
}

func mustObject(t *testing.T, data []byte) ([]string, map[string]json.RawMessage) {
	t.Helper()
	keys, vals, err := parseObject(data)
	if err != nil {
		t.Fatal(err)
	}
	return keys, vals
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

func hasNotice(ns []netdetect.Notice, code string) bool {
	for _, n := range ns {
		if n.Code == code {
			return true
		}
	}
	return false
}

func joined(ss []string) string {
	if len(ss) == 1 {
		return ss[0]
	}
	return ""
}
