//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

const wizPKIDir = ".pki-wiz"

// wizSecretRE matches join codes and enrollment tokens so a failure log cannot
// keep them. Headscale auth keys use the tskey- prefix.
var wizSecretRE = regexp.MustCompile(`idoris-join-v1\.[A-Za-z0-9_-]+\.[0-9a-fA-F]{8}|idv1_[0-9a-fA-F]+|tskey-[A-Za-z0-9_-]+`)

// wizNets is one office LAN (gateways + echo devices) and one home LAN (member).
type wizNets struct {
	officeCIDR string
	officeGW   string
	homeCIDR   string
	homeGW     string
	echo       string
	echoB      string
}

func wizChooseNets() (wizNets, error) {
	panic("stub")
}
func wizProjectName() (string, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "idoris-vpn-wizard-" + hex.EncodeToString(b[:]), nil
}

type wizEnv struct {
	project      string
	baseEnv      []string
	secrets      []string
	approveCalls int
	// hostnameApprove is true when `approve-routes --identifier <hostname>`
	// succeeded. False means the test fell back to the numeric node id.
	hostnameApprove bool
}

func (e *wizEnv) redact(s string) string {
	for _, sec := range e.secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return wizSecretRE.ReplaceAllString(s, "[redacted]")
}

func (e *wizEnv) run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", append([]string{
		"compose", "-p", e.project, "-f", "wizard/compose.yaml",
	}, args...)...)
	cmd.Env = e.baseEnv
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (e *wizEnv) exec(d time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return e.run(ctx, args...)
}

func (e *wizEnv) must(t *testing.T, d time.Duration, args ...string) string {
	t.Helper()
	out, err := e.exec(d, args...)
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", e.redact(strings.Join(args, " ")), err, e.redact(out))
	}
	return out
}

func (e *wizEnv) down(t *testing.T) {
	t.Helper()
	if t.Failed() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		out, _ := e.run(ctx, "logs", "--no-color", "--tail=160")
		cancel()
		t.Logf("compose logs:\n%s", e.redact(out))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, _ = e.run(ctx, "down", "-v", "--remove-orphans")
}

func wizPolicy(echo, echoB string) string {
	panic("stub")
}
func wizInvite(t *testing.T, bin, cfgPath, hint, enrollURL string) (string, join.Payload) {
	panic("stub")
}
func buildHostBin(t *testing.T, pkg, out string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", out, pkg)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
}

// TestWizardGatewayJoin runs the join wizard inside a Linux gateway container.
// The office echo at .10 is pre-approved (enroll lan_cidrs and Headscale
// autoApprovers both list that exact /32) and must come up with no
// approve-routes. The echo at .11 is not pre-approved: status stays
// routes-pending-approval and a remote member cannot reach it until
// `headscale nodes approve-routes`.
func TestWizardGatewayJoin(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	nets, err := wizChooseNets()
	if err != nil {
		t.Fatal(err)
	}
	project, err := wizProjectName()
	if err != nil {
		t.Fatal(err)
	}
	roots := writeTestPKI(t, wizPKIDir, []string{"headscale"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err := os.WriteFile(filepath.Join(wizPKIDir, "policy.active.hujson"), []byte(wizPolicy(nets.echo, nets.echoB)), 0o644); err != nil {
		t.Fatal(err)
	}

	vpndBin := filepath.Join("..", "bin", "idoris-vpnd-linux")
	enrollBin := filepath.Join("..", "bin", "idoris-vpn-enroll")
	buildLinuxBin(t, "../cmd/idoris-vpnd", vpndBin)
	buildHostBin(t, "../cmd/idoris-vpn-enroll", enrollBin)
	absVPND, err := filepath.Abs(vpndBin)
	if err != nil {
		t.Fatal(err)
	}

	e := &wizEnv{
		project: project,
		baseEnv: append(os.Environ(),
			"WIZ_OFFICE_CIDR="+nets.officeCIDR,
			"WIZ_OFFICE_GW="+nets.officeGW,
			"WIZ_HOME_CIDR="+nets.homeCIDR,
			"WIZ_HOME_GW="+nets.homeGW,
			"WIZ_ECHO="+nets.echo,
			"WIZ_ECHO_B="+nets.echoB,
			"WIZ_VPND="+absVPND,
		),
	}
	t.Cleanup(func() { e.down(t) })
	t.Logf("project %s office %s home %s echo %s echoB %s", project, nets.officeCIDR, nets.homeCIDR, nets.echo, nets.echoB)

	upCtx, upCancel := context.WithTimeout(context.Background(), 6*time.Minute)
	upOut, upErr := e.run(upCtx, "up", "-d", "--wait", "--remove-orphans")
	upCancel()
	if upErr != nil {
		t.Fatalf("compose up: %v\n%s", upErr, e.redact(upOut))
	}

	portOut := strings.TrimSpace(e.must(t, 20*time.Second, "port", "headscale", "443"))
	keyOut := e.must(t, 20*time.Second, "exec", "-T", "headscale", "headscale", "apikeys", "create", "--expiration", "1h")
	apiKey := strings.TrimSpace(keyOut)
	e.secrets = append(e.secrets, apiKey)
	hs := &headscale.Client{
		BaseURL: "https://" + portOut,
		APIKey:  apiKey,
		HTTP: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				MinVersion: tls.VersionTLS12,
			}},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	if err := hs.Health(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	user, err := hs.EnsureUser(ctx, "wiz")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	check := e.must(t, 20*time.Second, "exec", "-T", "headscale", "headscale", "policy", "check", "-f", "/etc/headscale/runtime/policy.active.hujson")
	t.Logf("policy check: %s", strings.TrimSpace(check))
	gotPolicy := e.must(t, 15*time.Second, "exec", "-T", "headscale", "headscale", "policy", "get")
	// The approved prefix is an autoApprovers key ("<echo>/32"). The other
	// prefix appears only as an ACL destination ("<echoB>/32:8740"), so a
	// quoted /32 with nothing after it must not match echo B.
	if !strings.Contains(gotPolicy, `"`+nets.echo+`/32"`) || strings.Contains(gotPolicy, `"`+nets.echoB+`/32"`) {
		t.Fatalf("policy get does not match the fixture autoApprovers:\n%s", gotPolicy)
	}

	seed, err := enroll.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	seedHash := enroll.HashToken(seed)
	seed = ""
	cfgPath := filepath.Join(t.TempDir(), "enroll.json")
	rawCfg, err := json.MarshalIndent(enroll.Config{
		ControlURL: "https://headscale",
		Tenants: []enroll.Tenant{{
			Name:            "wiz",
			HeadscaleUserID: user.ID,
			TokenHashes:     []string{seedHash},
			ACLTags:         []string{"tag:wiz-gateway"},
			Role:            join.RoleGateway,
			LANCIDRs:        []string{nets.echo + "/32"},
			PreAuthTTL:      enroll.Duration(10 * time.Minute),
		}},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, append(rawCfg, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	enrollPort := ln.Addr().(*net.TCPAddr).Port
	enrollURL := fmt.Sprintf("http://host.docker.internal:%d", enrollPort)
	codeA, payA := wizInvite(t, enrollBin, cfgPath, "wiz-gw", enrollURL)
	codeB, payB := wizInvite(t, enrollBin, cfgPath, "wiz-gw-wait", enrollURL)
	e.secrets = append(e.secrets, codeA, codeB, payA.Token, payB.Token)
	if codeA == codeB || payA.Token == payB.Token {
		t.Fatal("the two invites were not distinct")
	}
	loaded, err := enroll.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Tenants) != 1 || len(loaded.Tenants[0].TokenHashes) != 3 || loaded.Tenants[0].LANCIDRs[0] != nets.echo+"/32" {
		t.Fatalf("invite did not append two hashes (have %d)", len(loaded.Tenants[0].TokenHashes))
	}
	var enrollLog bytes.Buffer
	srv, err := enroll.NewServer(*loaded, hs, slog.New(slog.NewTextHandler(&enrollLog, nil)))
	if err != nil {
		t.Fatal(err)
	}
	hsrv := &http.Server{Handler: srv.Handler()}
	go func() { _ = hsrv.Serve(ln) }()
	t.Cleanup(func() {
		_ = hsrv.Close()
		if t.Failed() {
			t.Logf("enroll log:\n%s", e.redact(enrollLog.String()))
		}
	})

	e.waitTailscaled(t, "wiz-gw")
	e.waitTailscaled(t, "wiz-gw-wait")
	e.waitTailscaled(t, "wiz-member")
	reach := e.probeEnroll(t, "wiz-gw", enrollURL)
	// wget -qO- hides the JSON body on 401 and prints the status line instead.
	// Either form means the container reached this process.
	if !strings.Contains(reach, "401") && !strings.Contains(reach, "Unauthorized") && !strings.Contains(reach, "missing bearer token") && !strings.Contains(reach, "invalid token") {
		t.Fatalf("gateway cannot reach the enrollment service:\n%s", e.redact(reach))
	}

	e.memberUp(t, hs, user.ID)
	if err := lanCheckOK(e.nc(t, "wiz-gw", nets.echo, "8740", 3)); err != nil {
		t.Fatalf("gateway cannot reach the echo on the office LAN: %v", err)
	}

	t.Log("case auto-approved /32")
	joined := e.join(t, "wiz-gw", codeA, nets.echo)
	e.assertJoinPlan(t, joined, nets, nets.echo+"/32", true)
	e.assertWrittenConfig(t, "wiz-gw", nets.echo+"/32", nets.officeCIDR, true)
	if e.approveCalls != 0 {
		t.Fatal("approve-routes ran before the auto-approved case finished")
	}
	e.startDaemon(t, "wiz-gw")
	st := e.waitStatus(t, "wiz-gw", 120*time.Second, func(st wizSnap) (bool, string) {
		if st.Phase != string(vpnd.PhaseConnected) || len(st.Routes) != 1 {
			return false, fmt.Sprintf("phase=%s routes=%v err=%s state=%s", st.Phase, st.Routes, st.LastError, st.BackendState)
		}
		r := st.Routes[0]
		return r.CIDR == nets.echo+"/32" && r.Advertised && r.Approved && st.BackendState == "Running" && st.AdminHint == "", st.Phase
	})
	e.mustHealth(t, "wiz-gw", true)
	node := e.waitRoutes(t, "wiz-gw", 60*time.Second, func(n gwRouteNode) (bool, string) {
		ok := gwHas(n.ApprovedRoutes, nets.echo+"/32") && gwHas(n.AvailableRoutes, nets.echo+"/32") && !gwHas(n.AvailableRoutes, nets.officeCIDR) && !gwHas(n.ApprovedRoutes, nets.officeCIDR)
		return ok, "approved=" + strings.Join(n.ApprovedRoutes, ",") + " available=" + strings.Join(n.AvailableRoutes, ",")
	})
	if !gwHas(node.Tags, "tag:wiz-gateway") && !e.nodeHasTag(t, "wiz-gw", "tag:wiz-gateway") {
		t.Fatalf("wiz-gw is not tagged tag:wiz-gateway (list-routes tags %v)", node.Tags)
	}
	if e.approveCalls != 0 {
		t.Fatal("auto-approved route required approve-routes")
	}
	e.waitMemberRoute(t, nets.echo, true)
	e.waitEcho(t, nets.echo)
	t.Logf("EVIDENCE auto-approved %s on %s (%s) with no approve-routes; status phase %s", nets.echo+"/32", "wiz-gw", node.ID, st.Phase)

	t.Log("case waiting for admin approval")
	joinedB := e.join(t, "wiz-gw-wait", codeB, nets.echoB)
	e.assertJoinPlan(t, joinedB, nets, nets.echoB+"/32", false)
	if !strings.Contains(joinedB, "warning: needs-approval:") || !strings.Contains(joinedB, "admin: ") || !strings.Contains(joinedB, nets.echoB+"/32") {
		t.Fatalf("pending plan missing the admin warning:\n%s", e.redact(joinedB))
	}
	e.assertWrittenConfig(t, "wiz-gw-wait", nets.echoB+"/32", nets.officeCIDR, false)
	e.startDaemon(t, "wiz-gw-wait")
	pending := e.waitStatus(t, "wiz-gw-wait", 120*time.Second, func(st wizSnap) (bool, string) {
		if st.Phase != string(vpnd.PhaseRoutesPending) || st.BackendState != "Running" || len(st.Routes) != 1 {
			return false, fmt.Sprintf("phase=%s state=%s routes=%v err=%s", st.Phase, st.BackendState, st.Routes, st.LastError)
		}
		r := st.Routes[0]
		return r.CIDR == nets.echoB+"/32" && r.Advertised && !r.Approved && strings.Contains(st.AdminHint, "approve-routes") && strings.Contains(st.AdminHint, "wiz-gw-wait") && strings.Contains(st.AdminHint, nets.echoB+"/32"), st.AdminHint
	})
	e.mustHealth(t, "wiz-gw-wait", false)
	waiting := e.waitRoutes(t, "wiz-gw-wait", 45*time.Second, func(n gwRouteNode) (bool, string) {
		if gwHas(n.ApprovedRoutes, nets.echoB+"/32") {
			t.Fatalf("echo B was approved before approve-routes: %v", n.ApprovedRoutes)
		}
		return gwHas(n.AvailableRoutes, nets.echoB+"/32"), "available=" + strings.Join(n.AvailableRoutes, ",") + " approved=" + strings.Join(n.ApprovedRoutes, ",")
	})
	if err := lanCheckDenied(e.nc(t, "wiz-member", nets.echoB, "8740", 2)); err != nil {
		t.Fatal(err)
	}
	e.approve(t, "wiz-gw-wait", waiting.ID, nets.echoB+"/32")
	e.waitRoutes(t, "wiz-gw-wait", 45*time.Second, func(n gwRouteNode) (bool, string) {
		return gwHas(n.ApprovedRoutes, nets.echoB+"/32"), "approved=" + strings.Join(n.ApprovedRoutes, ",")
	})
	e.waitStatus(t, "wiz-gw-wait", 60*time.Second, func(st wizSnap) (bool, string) {
		if st.Phase != string(vpnd.PhaseConnected) || len(st.Routes) != 1 {
			return false, st.Phase
		}
		return st.Routes[0].Approved && st.AdminHint == "", st.Phase
	})
	e.mustHealth(t, "wiz-gw-wait", true)
	e.waitMemberRoute(t, nets.echoB, true)
	e.waitEcho(t, nets.echoB)
	t.Logf("EVIDENCE pending hint %q; approve-routes by hostname=%v; member reached %s after approval", pending.AdminHint, e.hostnameApprove, nets.echoB)
}

type wizSnap struct {
	Phase        string             `json:"phase"`
	BackendState string             `json:"backend_state"`
	LastError    string             `json:"last_error"`
	AdminHint    string             `json:"admin_hint"`
	Routes       []vpnd.RouteReport `json:"routes"`
}

func (e *wizEnv) waitTailscaled(t *testing.T, host string) {
	t.Helper()
	waitFor(t, host+" tailscaled", 40*time.Second, func() (bool, string) {
		out, err := e.exec(8*time.Second, "exec", "-T", host, "tailscale", "status", "--json")
		if err != nil {
			return false, e.redact(err.Error() + " " + out)
		}
		return strings.Contains(out, "BackendState"), "no BackendState"
	})
}

func (e *wizEnv) probeEnroll(t *testing.T, host, enrollURL string) string {
	t.Helper()
	out, _ := e.exec(15*time.Second, "exec", "-T", host, "wget", "-T", "5", "-qO-", enrollURL+"/v1/discover")
	return out
}

func (e *wizEnv) memberUp(t *testing.T, hs *headscale.Client, userID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	key, err := hs.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		UserID:     userID,
		Reusable:   true,
		Expiration: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.secrets = append(e.secrets, key.Key)
	e.pinHeadscale(t, "wiz-member")
	e.must(t, 70*time.Second, "exec", "-T", "wiz-member", "tailscale", "up",
		"--reset",
		"--login-server=https://headscale",
		"--auth-key="+key.Key,
		"--accept-routes",
		"--accept-dns=true",
		"--hostname=wiz-member",
		"--timeout=45s",
	)
	waitFor(t, "wiz-member online", 60*time.Second, func() (bool, string) {
		st, err := e.exec(15*time.Second, "exec", "-T", "wiz-member", "tailscale", "status", "--json")
		if err != nil {
			return false, e.redact(err.Error())
		}
		parsed, err := lanParseStatus(st)
		if err != nil {
			return false, err.Error()
		}
		if parsed.BackendState != "Running" {
			return false, parsed.BackendState
		}
		nodes, err := hs.ListNodes(context.Background(), "wiz")
		if err != nil {
			return false, err.Error()
		}
		for _, n := range nodes {
			if lanNodeHost(n) == "wiz-member" && n.Online {
				return true, ""
			}
		}
		return false, "running, not online in headscale yet"
	})
}

func (e *wizEnv) pinHeadscale(t *testing.T, host string) {
	t.Helper()
	out := e.must(t, 15*time.Second, "exec", "-T", host, "getent", "hosts", "headscale")
	ip := lanFirstIPv4(out)
	if ip == "" {
		t.Fatalf("getent headscale on %s: %q", host, out)
	}
	script := fmt.Sprintf("grep -q '[[:space:]]headscale$' /etc/hosts || echo '%s headscale' >> /etc/hosts", ip)
	e.must(t, 10*time.Second, "exec", "-T", host, "sh", "-c", script)
}

func (e *wizEnv) join(t *testing.T, host, code, device string) string {
	t.Helper()
	out, err := e.exec(60*time.Second, "exec", "-e", "HOME=/root", "-T", host,
		"/opt/idoris-vpnd", "join",
		"--yes", "--device", device, "--no-service", "--allow-insecure", code)
	red := e.redact(out)
	if err != nil {
		t.Fatalf("join %s: %v\n%s", host, err, red)
	}
	if strings.Contains(out, code) || strings.Contains(out, "idv1_") {
		t.Fatal("join stdout contains the join code or token")
	}
	return red
}

func (e *wizEnv) assertJoinPlan(t *testing.T, out string, nets wizNets, route string, auto bool) {
	panic("stub")
}
func (e *wizEnv) assertWrittenConfig(t *testing.T, host, route, office string, auto bool) {
	t.Helper()
	raw := e.must(t, 10*time.Second, "exec", "-T", host, "cat", "/root/.idoris/vpn.json")
	if strings.Contains(raw, "idv1_") || strings.Contains(raw, office) {
		t.Fatalf("vpn.json leaked a token or advertised the office prefix:\n%s", e.redact(raw))
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg vpnd.Config
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("vpn.json: %v\n%s", err, raw)
	}
	if cfg.Mode != "system" || cfg.Role != join.RoleGateway || cfg.AcceptRoutes || !cfg.EnrollAllowInsecure {
		t.Fatalf("config mode=%s role=%s accept=%v insecure=%v", cfg.Mode, cfg.Role, cfg.AcceptRoutes, cfg.EnrollAllowInsecure)
	}
	if len(cfg.AdvertiseRoutes) != 1 || cfg.AdvertiseRoutes[0] != route {
		t.Fatalf("advertise_routes %v", cfg.AdvertiseRoutes)
	}
	if len(cfg.AdvertiseTags) != 1 || cfg.AdvertiseTags[0] != "tag:wiz-gateway" {
		t.Fatalf("tags %v", cfg.AdvertiseTags)
	}
	if cfg.EnrollToken != "" || cfg.AuthKey != "" || cfg.EnrollTokenFile == "" {
		t.Fatal("config stored a plaintext secret or missed the token file")
	}
	planRaw := e.must(t, 10*time.Second, "exec", "-T", host, "cat", "/root/.idoris/gateway-plan.json")
	if strings.Contains(planRaw, "idv1_") {
		t.Fatal("plan file contains a token")
	}
	var plan gateway.Plan
	if err := json.Unmarshal([]byte(planRaw), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 1 || plan.Routes[0] != route || plan.Network != office || plan.WholeSubnet || plan.WillAutoApprove != auto {
		t.Fatalf("plan routes %v network %s whole %v auto %v", plan.Routes, plan.Network, plan.WholeSubnet, plan.WillAutoApprove)
	}
	fwd := e.must(t, 10*time.Second, "exec", "-T", host, "cat", "/etc/sysctl.d/99-idoris-vpn.conf")
	if !strings.Contains(fwd, "net.ipv4.ip_forward = 1") {
		t.Fatalf("sysctl drop-in:\n%s", fwd)
	}
	proc := e.must(t, 10*time.Second, "exec", "-T", host, "cat", "/proc/sys/net/ipv4/ip_forward")
	if strings.TrimSpace(proc) != "1" {
		t.Fatalf("ip_forward=%q", proc)
	}
}

func (e *wizEnv) startDaemon(t *testing.T, host string) {
	t.Helper()
	e.must(t, 20*time.Second, "exec", "-d", "-e", "HOME=/root", "-T", host,
		"/opt/idoris-vpnd", "run",
		"--config", "/root/.idoris/vpn.json",
		"--tailscale-socket", "/var/run/tailscale/tailscaled.sock",
		"--listen", "tcp:127.0.0.1:7845",
		"--interval", "2s")
}

func (e *wizEnv) status(t *testing.T, host string) (wizSnap, string, error) {
	t.Helper()
	out, err := e.exec(12*time.Second, "exec", "-T", host, "wget", "-T", "5", "-qO-", "http://127.0.0.1:7845/v1/status")
	if err != nil {
		return wizSnap{}, out, err
	}
	var st wizSnap
	raw := lanExtractJSON(out)
	if jerr := json.Unmarshal(raw, &st); jerr != nil {
		return wizSnap{}, out, jerr
	}
	return st, out, nil
}

func (e *wizEnv) waitStatus(t *testing.T, host string, budget time.Duration, cond func(wizSnap) (bool, string)) wizSnap {
	panic("stub")
}
func (e *wizEnv) mustHealth(t *testing.T, host string, connected bool) {
	panic("stub")
}
func (e *wizEnv) waitRoutes(t *testing.T, host string, budget time.Duration, cond func(gwRouteNode) (bool, string)) gwRouteNode {
	panic("stub")
}
func (e *wizEnv) nodeHasTag(t *testing.T, host, tag string) bool {
	t.Helper()
	out := e.must(t, 15*time.Second, "exec", "-T", "headscale", "headscale", "nodes", "list", "-o", "json")
	raw := lanExtractJSON(out)
	var nodes []struct {
		GivenName string   `json:"givenName"`
		Name      string   `json:"name"`
		Tags      []string `json:"tags"`
	}
	if err := json.Unmarshal(raw, &nodes); err != nil {
		var wrap struct {
			Nodes []struct {
				GivenName string   `json:"givenName"`
				Name      string   `json:"name"`
				Tags      []string `json:"tags"`
			} `json:"nodes"`
		}
		if err2 := json.Unmarshal(raw, &wrap); err2 != nil {
			t.Logf("nodes list: %v / %v", err, err2)
			return false
		}
		nodes = wrap.Nodes
	}
	for _, n := range nodes {
		if n.GivenName != host && !strings.HasPrefix(n.Name, host+".") && n.Name != host {
			continue
		}
		if gwHas(n.Tags, tag) {
			return true
		}
	}
	return false
}

func (e *wizEnv) approve(t *testing.T, host, numericID, cidr string) {
	t.Helper()
	e.approveCalls++
	out, err := e.exec(20*time.Second, "exec", "-T", "headscale", "headscale", "nodes", "approve-routes",
		"--identifier", host, "--routes", cidr)
	if err == nil {
		e.hostnameApprove = true
		t.Logf("approve-routes accepted hostname %s", host)
		return
	}
	t.Logf("approve-routes by hostname failed (%s); retrying with numeric id %s", e.redact(strings.TrimSpace(out+" "+err.Error())), numericID)
	e.must(t, 20*time.Second, "exec", "-T", "headscale", "headscale", "nodes", "approve-routes",
		"--identifier", numericID, "--routes", cidr)
}

func (e *wizEnv) waitEcho(t *testing.T, ip string) {
	panic("stub")
}
func (e *wizEnv) nc(t *testing.T, container, host, port string, waitSec int) (string, error) {
	t.Helper()
	out, err := e.exec(time.Duration(waitSec+8)*time.Second, "exec", "-T", container, "nc", "-w", fmt.Sprintf("%d", waitSec), host, port)
	t.Logf("nc %s %s:%s -> err=%v out=%q", container, host, port, err, strings.TrimSpace(e.redact(out)))
	return out, err
}

func (e *wizEnv) waitMemberRoute(t *testing.T, ip string, want bool) {
	t.Helper()
	waitFor(t, "wiz-member route "+ip, 45*time.Second, func() (bool, string) {
		out, err := e.exec(10*time.Second, "exec", "-T", "wiz-member", "ip", "route", "get", ip)
		text := strings.TrimSpace(out)
		if err != nil {
			text = text + " " + err.Error()
		}
		return strings.Contains(text, "tailscale0") == want, text
	})
}
