package gateway

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
	want := "headscale nodes approve-routes --identifier office-gw --routes 10.251.73.10/32"
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
	root     bool
	goos     string
	forwards int
	services []string
}

func newMemHost(root bool, goos string) *memHost {
	return &memHost{files: map[string][]byte{}, modes: map[string]os.FileMode{}, root: root, goos: goos}
}

func (m *memHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	m.files[path] = append([]byte(nil), data...)
	m.modes[path] = mode
	return nil
}
func (m *memHost) MkdirAll(string, os.FileMode) error { return nil }
func (m *memHost) Stat(path string) (os.FileInfo, error) {
	if _, ok := m.files[path]; !ok {
		return nil, os.ErrNotExist
	}
	return memInfo{name: filepath.Base(path), mode: m.modes[path]}, nil
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
