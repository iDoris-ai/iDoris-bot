//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
)

const (
	lanPKIDir        = ".pki-lan"
	lanPolicyLabCIDR = "10.251.73.0/24"
	lanBaseDomain    = "lan.idoris.internal"
	lanAllowPort     = "8740"
	lanDenyPort      = "8080"
	lanDERPRegion    = "lan"
)

// lanNets is one run's underlay. The lab prefix is also written into the HuJSON policy.
type lanNets struct {
	officeCIDR string
	officeGW   string
	homeCIDR   string
	homeGW     string
	labCIDR    string
	labGW      string
	labBackend string
}

type lanEnv struct {
	project string
	profile string
	nets    lanNets
	baseEnv []string
	hs      *headscale.Client
	userID  string
}

type lanTSPeer struct {
	HostName      string   `json:"HostName"`
	DNSName       string   `json:"DNSName"`
	TailscaleIPs  []string `json:"TailscaleIPs"`
	Relay         string   `json:"Relay"`
	CurAddr       string   `json:"CurAddr"`
	Online        bool     `json:"Online"`
	PrimaryRoutes []string `json:"PrimaryRoutes"`
	AllowedIPs    []string `json:"AllowedIPs"`
}

type lanTSStatus struct {
	BackendState string               `json:"BackendState"`
	Self         lanTSPeer            `json:"Self"`
	Peer         map[string]lanTSPeer `json:"Peer"`
}

type lanPong struct {
	Via  string
	DERP string
	IP   string
	RTT  time.Duration
}

type gwRouteNode struct {
	ID              string
	GivenName       string
	Name            string
	ApprovedRoutes  []string
	AvailableRoutes []string
	SubnetRoutes    []string
	Tags            []string
	Online          bool
}

var lanPongRE = regexp.MustCompile(`pong from \S+ \(([^)]+)\) via (\S+) in (\S+)`)

func TestLanDirect(t *testing.T) {
	e := lanStack(t, "lan")
	lanUp(t, e, "member-office", nil)
	ai := lanUp(t, e, "ai-office", []string{"tag:acme-local-ai"})
	lanRequireTag(t, ai, "tag:acme-local-ai")
	lanRequireTUN(t, e, "member-office")
	lanRequireTUN(t, e, "ai-office")

	underlay := lanUnderlayIP(t, e, "ai-office", e.nets.officeCIDR)
	lanEvidence(t, "office underlay IP of ai-office", underlay)
	if err := lanCheckOK(lanNC(t, e, "member-office", underlay, lanAllowPort, 3)); err != nil {
		t.Fatal(err)
	}

	aiV4 := lanV4(ai.IPAddresses)
	if aiV4 == "" {
		t.Fatalf("ai-office has no IPv4: %v", ai.IPAddresses)
	}
	pingOut := lanPingUntil(t, e, "member-office", aiV4, true, 60*time.Second)
	pongs := lanParsePongs(pingOut)
	direct, ok := lanLastDirect(pongs)
	if !ok {
		t.Fatalf("tailscale ping did not establish a direct path:\n%s", pingOut)
	}
	if !lanAddrInCIDR(direct.IP, e.nets.officeCIDR) {
		t.Fatalf("direct path %s is outside office subnet %s\n%s", direct.IP, e.nets.officeCIDR, pingOut)
	}
	lanEvidence(t, "direct RTT", direct.RTT.String()+" via "+direct.Via)

	st := lanStatus(t, e, "member-office")
	peer, ok := lanPeerByHost(st, "ai-office")
	if !ok {
		t.Fatalf("member-office status has no ai-office peer:\n%s", lanMustStatusText(t, e, "member-office"))
	}
	peerJSON, _ := json.Marshal(peer)
	lanEvidence(t, "status peer ai-office", string(peerJSON))
	if peer.CurAddr == "" || !lanAddrInCIDR(peer.CurAddr, e.nets.officeCIDR) {
		t.Fatalf("CurAddr %q is not a direct office endpoint", peer.CurAddr)
	}
	// Tailscale 1.104 keeps Peer.Relay set to the home DERP region even after
	// the active path is direct. CurAddr plus the ping line are the active path.
	if direct.DERP != "" {
		t.Fatalf("ping path is DERP(%s), want a direct office address", direct.DERP)
	}

	magic := "ai-office." + lanBaseDomain
	dnsOut := lanMust(t, e, 20*time.Second, "exec", "-T", "member-office", "tailscale", "dns", "query", magic)
	lanEvidence(t, "magicdns query", dnsOut)
	if !strings.Contains(dnsOut, aiV4) {
		t.Fatalf("MagicDNS %s did not resolve to %s\n%s", magic, aiV4, dnsOut)
	}
	// OS nc through tailscale0. `tailscale nc` closes on stdin EOF before the
	// echo process writes, so an empty stdout is not a data-plane result.
	if err := lanCheckOK(lanNC(t, e, "member-office", magic, lanAllowPort, 5)); err != nil {
		t.Fatal(err)
	}
	if err := lanCheckOK(lanNC(t, e, "member-office", aiV4, lanAllowPort, 5)); err != nil {
		t.Fatal(err)
	}
	if err := lanCheckDenied(lanNC(t, e, "member-office", magic, lanDenyPort, 4)); err != nil {
		t.Fatal(err)
	}
	if err := lanCheckDenied(lanNC(t, e, "member-office", aiV4, lanDenyPort, 4)); err != nil {
		t.Fatal(err)
	}
	t.Logf("LAN direct: via %s rtt %s magic %s", direct.Via, direct.RTT, magic)
}

func TestLanAwayRelay(t *testing.T) {
	e := lanStack(t, "relay")
	lanUp(t, e, "member-home", nil)
	ai := lanUp(t, e, "ai-office", []string{"tag:acme-local-ai"})
	aiV4 := lanV4(ai.IPAddresses)
	if aiV4 == "" {
		t.Fatalf("ai-office has no IPv4: %v", ai.IPAddresses)
	}

	lanRequireTUN(t, e, "member-home")
	lanRequireTUN(t, e, "ai-office")
	officeIP := lanUnderlayIP(t, e, "ai-office", e.nets.officeCIDR)
	lanEvidence(t, "ai-office underlay", officeIP)
	if out, err := lanNC(t, e, "member-home", officeIP, lanAllowPort, 2); err == nil && strings.Contains(out, "ok") {
		t.Fatalf("isolation broken: member-home reached office underlay %s:%s\n%s", officeIP, lanAllowPort, out)
	}

	pingOut, pongs, skipped := lanPingRelay(t, e, "member-home", aiV4)
	if skipped {
		return
	}
	for _, p := range pongs {
		if p.DERP == "" || p.IP != "" {
			t.Fatalf("expected only DERP pongs, got via %s\n%s", p.Via, pingOut)
		}
		if p.DERP != lanDERPRegion {
			t.Fatalf("pong relayed via DERP(%s), want embedded region %s\n%s", p.DERP, lanDERPRegion, pingOut)
		}
	}
	st := lanStatus(t, e, "member-home")
	peer, ok := lanPeerByHost(st, "ai-office")
	if !ok {
		t.Fatalf("member-home status has no ai-office:\n%s", lanMustStatusText(t, e, "member-home"))
	}
	peerJSON, _ := json.Marshal(peer)
	lanEvidence(t, "relay status peer", string(peerJSON))
	if peer.Relay == "" {
		t.Fatalf("status Relay is empty; path is not a DERP relay: %s", peerJSON)
	}
	if peer.Relay != lanDERPRegion {
		t.Fatalf("status Relay %q, want %q", peer.Relay, lanDERPRegion)
	}
	if peer.CurAddr != "" {
		t.Fatalf("status CurAddr %q set; path is direct, not relayed", peer.CurAddr)
	}
	if err := lanCheckOK(lanNC(t, e, "member-home", aiV4, lanAllowPort, 8)); err != nil {
		t.Fatal(err)
	}
	t.Logf("away relay: DERP(%s) sample rtt %s", pongs[len(pongs)-1].DERP, pongs[len(pongs)-1].RTT)
}

func TestGatewaySubnetRoute(t *testing.T) {
	e := lanStack(t, "gw")
	lanUp(t, e, "member-home", nil, "--accept-routes")
	lanUp(t, e, "member-noroute", nil)
	gw := lanUp(t, e, "gateway", []string{"tag:acme-gateway"}, "--advertise-routes="+e.nets.labCIDR)
	lanRequireTag(t, gw, "tag:acme-gateway")
	lanRequireTUN(t, e, "member-home")
	lanRequireTUN(t, e, "member-noroute")
	lanRequireTUN(t, e, "gateway")
	fwd := lanMust(t, e, 10*time.Second, "exec", "-T", "gateway", "sysctl", "net.ipv4.ip_forward")
	lanEvidence(t, "gateway ip_forward", fwd)
	if !strings.Contains(fwd, "= 1") {
		t.Fatalf("gateway ip_forward is not 1: %s", fwd)
	}
	// The box itself is up on both ports; ACL is what later hides 8080.
	if err := lanCheckOK(lanNC(t, e, "gateway", e.nets.labBackend, lanAllowPort, 3)); err != nil {
		t.Fatal(err)
	}
	if err := lanCheckOK(lanNC(t, e, "gateway", e.nets.labBackend, lanDenyPort, 3)); err != nil {
		t.Fatal(err)
	}

	t.Run("ManualApprove", func(t *testing.T) {
		gwRoutes := gwWaitRoutes(t, e, "gateway", 30*time.Second, func(n gwRouteNode) (bool, string) {
			if !gwHas(n.AvailableRoutes, e.nets.labCIDR) {
				return false, "available=" + strings.Join(n.AvailableRoutes, ",")
			}
			if gwHas(n.ApprovedRoutes, e.nets.labCIDR) {
				t.Fatalf("route approved before CLI approve-routes: approved=%v", n.ApprovedRoutes)
			}
			return true, ""
		})
		table := lanMust(t, e, 20*time.Second, "exec", "-T", "headscale", "headscale", "nodes", "list-routes")
		lanEvidence(t, "routes before approve", table)
		if lanRouteViaTailscale(t, e, "member-home") {
			t.Fatalf("member-home installed %s before approval", e.nets.labCIDR)
		}
		if err := lanCheckDenied(lanNC(t, e, "member-home", e.nets.labBackend, lanAllowPort, 2)); err != nil {
			t.Fatal(err)
		}

		approved := lanMust(t, e, 20*time.Second, "exec", "-T", "headscale", "headscale", "nodes", "approve-routes",
			"--identifier", gwRoutes.ID, "--routes", e.nets.labCIDR)
		lanEvidence(t, "approve-routes", approved)
		gwWaitRoutes(t, e, "gateway", 30*time.Second, func(n gwRouteNode) (bool, string) {
			return gwHas(n.ApprovedRoutes, e.nets.labCIDR), "approved=" + strings.Join(n.ApprovedRoutes, ",")
		})
		lanWaitTailscaleRoute(t, e, "member-home", true)
		lanEvidence(t, "member-home route get", lanRouteGet(t, e, "member-home"))
		if err := lanCheckOK(lanNC(t, e, "member-home", e.nets.labBackend, lanAllowPort, 5)); err != nil {
			t.Fatal(err)
		}
		if err := lanCheckDenied(lanNC(t, e, "member-home", e.nets.labBackend, lanDenyPort, 4)); err != nil {
			t.Fatal(err)
		}

		if lanRouteViaTailscale(t, e, "member-noroute") {
			t.Fatalf("member-noroute installed %s without --accept-routes", e.nets.labCIDR)
		}
		lanEvidence(t, "member-noroute route get", lanRouteGet(t, e, "member-noroute"))
		if err := lanCheckDenied(lanNC(t, e, "member-noroute", e.nets.labBackend, lanAllowPort, 2)); err != nil {
			t.Fatal(err)
		}
		peer, ok := lanPeerByHost(lanStatus(t, e, "member-home"), "gateway")
		if !ok {
			t.Fatal("member-home cannot see gateway")
		}
		peerJSON, _ := json.Marshal(peer)
		lanEvidence(t, "gateway peer after approve", string(peerJSON))
		if !gwHas(peer.AllowedIPs, e.nets.labCIDR) && !gwHas(peer.PrimaryRoutes, e.nets.labCIDR) {
			t.Fatalf("approved route not visible on member-home: %s", peerJSON)
		}
	})

	t.Run("AutoApprovers", func(t *testing.T) {
		if err := lanActivatePolicy("headscale-lan/policy.auto.hujson", e.nets.labCIDR); err != nil {
			t.Fatal(err)
		}
		check := lanMust(t, e, 20*time.Second, "exec", "-T", "headscale", "headscale", "policy", "check", "-f", "/etc/headscale/runtime/policy.active.hujson")
		lanEvidence(t, "policy check auto", check)
		lanMust(t, e, 15*time.Second, "kill", "-s", "HUP", "headscale")
		waitFor(t, "policy reload", 20*time.Second, func() (bool, string) {
			out, err := e.execTimeout(10*time.Second, "exec", "-T", "headscale", "headscale", "policy", "get")
			if err != nil {
				return false, err.Error() + " " + out
			}
			return strings.Contains(out, "autoApprovers") && strings.Contains(out, e.nets.labCIDR), out
		})
		autoNode := lanUp(t, e, "gateway-auto", []string{"tag:acme-gateway"}, "--advertise-routes="+e.nets.labCIDR)
		lanRequireTag(t, autoNode, "tag:acme-gateway")
		got := gwWaitRoutes(t, e, "gateway-auto", 40*time.Second, func(n gwRouteNode) (bool, string) {
			return gwHas(n.ApprovedRoutes, e.nets.labCIDR), "approved=" + strings.Join(n.ApprovedRoutes, ",") + " available=" + strings.Join(n.AvailableRoutes, ",")
		})
		if got.ID == gw.ID {
			t.Fatalf("auto-approved node id %s is the manually approved gateway", got.ID)
		}
		table := lanMust(t, e, 20*time.Second, "exec", "-T", "headscale", "headscale", "nodes", "list-routes")
		lanEvidence(t, "routes after autoApprovers", table)
		t.Logf("autoApprovers approved %s on node %s (%s) without approve-routes", e.nets.labCIDR, got.GivenName, got.ID)
	})
}

func lanStack(t *testing.T, profile string) *lanEnv {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		e, err := lanBoot(t, profile)
		if err == nil {
			t.Cleanup(func() {
				if t.Failed() {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					out, _ := e.run(ctx, "--profile", profile, "logs", "--no-color", "--tail=160")
					cancel()
					t.Logf("compose logs:\n%s", out)
				}
				e.down()
				_ = os.RemoveAll(lanPKIDir)
			})
			lanCheckPolicies(t, e)
			return e
		}
		lastErr = err
		t.Logf("compose up attempt %d: %v", attempt, err)
	}
	t.Fatalf("compose up failed: %v", lastErr)
	return nil
}

func lanBoot(t *testing.T, profile string) (*lanEnv, error) {
	t.Helper()
	nets, err := lanChooseNets()
	if err != nil {
		return nil, err
	}
	project, err := lanProjectName()
	if err != nil {
		return nil, err
	}
	if err := os.RemoveAll(lanPKIDir); err != nil {
		return nil, err
	}
	roots, err := lanWritePKI()
	if err != nil {
		return nil, err
	}
	if err := lanActivatePolicy("headscale-lan/policy.manual.hujson", nets.labCIDR); err != nil {
		return nil, err
	}
	e := &lanEnv{
		project: project,
		profile: profile,
		nets:    nets,
		baseEnv: lanComposeEnv(nets),
	}
	t.Logf("project %s profile %s office %s home %s lab %s backend %s", project, profile, nets.officeCIDR, nets.homeCIDR, nets.labCIDR, nets.labBackend)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	out, err := e.run(ctx, "--profile", profile, "up", "-d", "--wait", "--remove-orphans")
	cancel()
	if err != nil {
		logCtx, logCancel := context.WithTimeout(context.Background(), 20*time.Second)
		logs, _ := e.run(logCtx, "--profile", profile, "logs", "--no-color", "--tail=120")
		logCancel()
		e.down()
		_ = os.RemoveAll(lanPKIDir)
		return nil, fmt.Errorf("%w\n%s\n--- logs ---\n%s", err, out, logs)
	}
	portOut, err := e.execTimeout(20*time.Second, "port", "headscale", "443")
	if err != nil {
		e.down()
		_ = os.RemoveAll(lanPKIDir)
		return nil, fmt.Errorf("compose port: %w\n%s", err, portOut)
	}
	keyOut, err := e.execTimeout(20*time.Second, "exec", "-T", "headscale", "headscale", "apikeys", "create", "--expiration", "1h")
	if err != nil {
		e.down()
		_ = os.RemoveAll(lanPKIDir)
		return nil, fmt.Errorf("apikeys create: %w\n%s", err, keyOut)
	}
	e.hs = &headscale.Client{
		BaseURL: "https://" + strings.TrimSpace(portOut),
		APIKey:  lanLastLine(keyOut),
		HTTP: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				MinVersion: tls.VersionTLS12,
			}},
		},
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := e.hs.Health(ctx); err != nil {
		e.down()
		_ = os.RemoveAll(lanPKIDir)
		return nil, err
	}
	user, err := e.hs.EnsureUser(ctx, "acme")
	if err != nil {
		e.down()
		_ = os.RemoveAll(lanPKIDir)
		return nil, err
	}
	e.userID = user.ID
	return e, nil
}

func lanCheckPolicies(t *testing.T, e *lanEnv) {
	t.Helper()
	for _, f := range []string{
		"/etc/headscale/lan/policy.manual.hujson",
		"/etc/headscale/lan/policy.auto.hujson",
		"/etc/headscale/runtime/policy.active.hujson",
	} {
		out := lanMust(t, e, 20*time.Second, "exec", "-T", "headscale", "headscale", "policy", "check", "-f", f)
		lanEvidence(t, "policy check "+f, out)
	}
}

func (e *lanEnv) run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", append([]string{
		"compose", "-p", e.project, "-f", "compose.lan.yaml",
	}, args...)...)
	cmd.Env = e.baseEnv
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (e *lanEnv) execTimeout(d time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return e.run(ctx, args...)
}

func (e *lanEnv) down() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, _ = e.run(ctx, "--profile", "lan", "--profile", "relay", "--profile", "gw", "down", "-v", "--remove-orphans")
}

func lanMust(t *testing.T, e *lanEnv, d time.Duration, args ...string) string {
	t.Helper()
	out, err := e.execTimeout(d, args...)
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func lanUp(t *testing.T, e *lanEnv, host string, tags []string, extra ...string) headscale.Node {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	key, err := e.hs.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		UserID:     e.userID,
		Reusable:   true,
		Expiration: time.Now().Add(time.Hour),
		ACLTags:    tags,
	})
	if err != nil {
		t.Fatal(err)
	}
	lanPinControl(t, e, host)
	args := []string{
		"exec", "-T", host, "tailscale", "up",
		"--reset",
		"--login-server=https://headscale",
		"--auth-key=" + key.Key,
		"--accept-dns=true",
		"--hostname=" + host,
		"--timeout=45s",
	}
	args = append(args, extra...)
	out := lanMust(t, e, 70*time.Second, args...)
	lanEvidence(t, "tailscale up "+host, out)
	var node headscale.Node
	waitFor(t, host+" online", 60*time.Second, func() (bool, string) {
		st, err := e.execTimeout(15*time.Second, "exec", "-T", host, "tailscale", "status", "--json")
		if err != nil {
			return false, err.Error()
		}
		parsed, err := lanParseStatus(st)
		if err != nil {
			return false, err.Error()
		}
		if parsed.BackendState != "Running" {
			return false, parsed.BackendState
		}
		nodes, err := e.hs.ListNodes(context.Background(), "")
		if err != nil {
			return false, err.Error()
		}
		for _, n := range nodes {
			if lanNodeHost(n) == host && n.Online && lanV4(n.IPAddresses) != "" {
				node = n
				return true, ""
			}
		}
		return false, "running, node not online in headscale yet"
	})
	return node
}

func lanPinControl(t *testing.T, e *lanEnv, host string) {
	t.Helper()
	out := lanMust(t, e, 15*time.Second, "exec", "-T", host, "getent", "hosts", "headscale")
	ip := lanFirstIPv4(out)
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		t.Fatalf("getent headscale on %s: %q", host, out)
	}
	script := fmt.Sprintf("grep -q '[[:space:]]headscale$' /etc/hosts || echo '%s headscale' >> /etc/hosts", addr)
	lanMust(t, e, 10*time.Second, "exec", "-T", host, "sh", "-c", script)
}

func lanRequireTag(t *testing.T, node headscale.Node, tag string) {
	t.Helper()
	for _, got := range node.Tags {
		if got == tag {
			if node.User != nil {
				t.Logf("%s user=%s tags=%v", node.GivenName, node.User.Name, node.Tags)
			}
			return
		}
	}
	t.Fatalf("node %s tags %v, want %s", node.GivenName, node.Tags, tag)
}

func lanRequireTUN(t *testing.T, e *lanEnv, host string) {
	t.Helper()
	out, err := e.execTimeout(10*time.Second, "exec", "-T", host, "ip", "link", "show", "tailscale0")
	if err != nil || !strings.Contains(out, "tailscale0") {
		t.Fatalf("%s has no tailscale0 TUN (%v)\n%s", host, err, out)
	}
}

func lanPingUntil(t *testing.T, e *lanEnv, from, target string, untilDirect bool, budget time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(budget)
	var last string
	for time.Now().Before(deadline) {
		args := []string{"exec", "-T", from, "tailscale", "ping", "--timeout=5s", "--c=10"}
		if !untilDirect {
			args = append(args, "--until-direct=false")
		}
		args = append(args, target)
		out, err := e.execTimeout(40*time.Second, args...)
		last = out
		pongs := lanParsePongs(out)
		if untilDirect {
			if _, ok := lanLastDirect(pongs); ok {
				lanEvidence(t, "ping "+from+" -> "+target, out)
				return out
			}
		} else if len(pongs) > 0 {
			lanEvidence(t, "ping "+from+" -> "+target, out)
			return out
		}
		t.Logf("ping %s -> %s waiting: %v\n%s", from, target, err, out)
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("ping %s -> %s produced no usable pong within %s\nlast:\n%s", from, target, budget, last)
	return ""
}

// lanPingRelay retries until every pong in one sample is the embedded DERP.
// A direct pong fails the test (isolation is broken). No pong at all skips:
// Docker did not produce a DERP path, and the skip text says what was tried.
func lanPingRelay(t *testing.T, e *lanEnv, from, target string) (string, []lanPong, bool) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var last string
	var lastErr error
	for time.Now().Before(deadline) {
		out, err := e.execTimeout(40*time.Second, "exec", "-T", from, "tailscale", "ping", "--until-direct=false", "--timeout=5s", "--c=5", target)
		last, lastErr = out, err
		pongs := lanParsePongs(out)
		if len(pongs) == 0 {
			t.Logf("relay ping waiting: %v\n%s", err, out)
			time.Sleep(2 * time.Second)
			continue
		}
		direct := false
		allLAN := true
		for _, p := range pongs {
			if p.IP != "" {
				direct = true
			}
			if p.DERP != lanDERPRegion {
				allLAN = false
			}
		}
		if direct {
			t.Fatalf("home reached the office node directly; DERP was not required:\n%s", out)
		}
		if allLAN {
			lanEvidence(t, "relay ping "+from+" -> "+target, out)
			return out, pongs, false
		}
		t.Logf("relay ping not on embedded DERP yet:\n%s", out)
		time.Sleep(2 * time.Second)
	}
	netcheck, _ := e.execTimeout(40*time.Second, "exec", "-T", from, "tailscale", "netcheck")
	t.Skipf("DERP relay did not come up in Docker within 90s (embedded region %s, verify_clients, STUN :3478, urls: []). last ping err=%v\nping:\n%s\nnetcheck:\n%s", lanDERPRegion, lastErr, last, netcheck)
	return "", nil, true
}

func lanStatus(t *testing.T, e *lanEnv, host string) lanTSStatus {
	t.Helper()
	out := lanMust(t, e, 15*time.Second, "exec", "-T", host, "tailscale", "status", "--json")
	st, err := lanParseStatus(out)
	if err != nil {
		t.Fatalf("status json: %v\n%s", err, out)
	}
	return st
}

func lanMustStatusText(t *testing.T, e *lanEnv, host string) string {
	t.Helper()
	return lanMust(t, e, 15*time.Second, "exec", "-T", host, "tailscale", "status")
}

func lanParseStatus(out string) (lanTSStatus, error) {
	raw := lanExtractJSON(out)
	var st lanTSStatus
	err := json.Unmarshal(raw, &st)
	return st, err
}

func lanPeerByHost(st lanTSStatus, host string) (lanTSPeer, bool) {
	wantDNS := host + "." + lanBaseDomain
	for _, p := range st.Peer {
		dns := strings.TrimSuffix(p.DNSName, ".")
		if p.HostName == host || dns == wantDNS || strings.HasPrefix(dns, host+".") {
			return p, true
		}
	}
	return lanTSPeer{}, false
}

func lanNC(t *testing.T, e *lanEnv, container, host, port string, waitSec int) (string, error) {
	t.Helper()
	out, err := e.execTimeout(time.Duration(waitSec+8)*time.Second, "exec", "-T", container, "nc", "-w", strconv.Itoa(waitSec), host, port)
	t.Logf("nc %s %s:%s -> err=%v out=%q", container, host, port, err, strings.TrimSpace(out))
	return out, err
}

func lanCheckOK(out string, err error) error {
	if err != nil || !strings.Contains(out, "ok") {
		if err == nil {
			return fmt.Errorf("want ok, out=%q", out)
		}
		return fmt.Errorf("want ok: %w out=%q", err, out)
	}
	return nil
}

func lanCheckDenied(out string, err error) error {
	if err == nil && strings.Contains(out, "ok") {
		return fmt.Errorf("connection succeeded, want deny or unreachable: %q", out)
	}
	return nil
}

func gwSameHost(n gwRouteNode, host string) bool {
	if n.GivenName == host {
		return true
	}
	base := strings.Split(n.Name, ".")[0]
	return n.Name == host || base == host
}

func lanRouteGet(t *testing.T, e *lanEnv, host string) string {
	t.Helper()
	out, err := e.execTimeout(10*time.Second, "exec", "-T", host, "ip", "route", "get", e.nets.labBackend)
	if err != nil {
		return strings.TrimSpace(out + "\n" + err.Error())
	}
	return strings.TrimSpace(out)
}

func lanRouteViaTailscale(t *testing.T, e *lanEnv, host string) bool {
	t.Helper()
	return strings.Contains(lanRouteGet(t, e, host), "tailscale0")
}

func lanWaitTailscaleRoute(t *testing.T, e *lanEnv, host string, want bool) {
	t.Helper()
	waitFor(t, host+" route "+e.nets.labCIDR, 40*time.Second, func() (bool, string) {
		got := lanRouteViaTailscale(t, e, host)
		return got == want, lanRouteGet(t, e, host)
	})
}

func gwWaitRoutes(t *testing.T, e *lanEnv, host string, budget time.Duration, cond func(gwRouteNode) (bool, string)) gwRouteNode {
	t.Helper()
	var found gwRouteNode
	waitFor(t, host+" routes", budget, func() (bool, string) {
		nodes, raw, err := e.listRoutes()
		if err != nil {
			return false, err.Error() + "\n" + raw
		}
		for _, n := range nodes {
			if gwSameHost(n, host) {
				ok, note := cond(n)
				if ok {
					found = n
				}
				return ok, note
			}
		}
		return false, "node not in list-routes\n" + raw
	})
	return found
}

func (e *lanEnv) listRoutes() ([]gwRouteNode, string, error) {
	raw, err := e.execTimeout(20*time.Second, "exec", "-T", "headscale", "headscale", "nodes", "list-routes", "-o", "json")
	if err != nil {
		return nil, raw, err
	}
	nodes, err := gwParseRoutes(raw)
	return nodes, raw, err
}

func gwParseRoutes(out string) ([]gwRouteNode, error) {
	raw := lanExtractJSON(out)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var rows []map[string]any
	if err := dec.Decode(&rows); err != nil {
		return nil, err
	}
	nodes := make([]gwRouteNode, 0, len(rows))
	for _, row := range rows {
		nodes = append(nodes, gwRouteNode{
			ID:              gwAnyString(row, "id"),
			GivenName:       gwAnyString(row, "givenName", "given_name"),
			Name:            gwAnyString(row, "name"),
			ApprovedRoutes:  gwAnyStrings(row, "approvedRoutes", "approved_routes"),
			AvailableRoutes: gwAnyStrings(row, "availableRoutes", "available_routes"),
			SubnetRoutes:    gwAnyStrings(row, "subnetRoutes", "subnet_routes"),
			Tags:            gwAnyStrings(row, "tags"),
			Online:          gwAnyBool(row, "online"),
		})
	}
	return nodes, nil
}

func gwAnyString(row map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := row[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				return t
			}
		case json.Number:
			return t.String()
		}
	}
	return ""
}

func gwAnyStrings(row map[string]any, keys ...string) []string {
	for _, k := range keys {
		v, ok := row[k]
		if !ok || v == nil {
			continue
		}
		arr, ok := v.([]any)
		if !ok {
			continue
		}
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func gwAnyBool(row map[string]any, key string) bool {
	v, ok := row[key].(bool)
	return ok && v
}

func gwHas(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func lanParsePongs(out string) []lanPong {
	var pongs []lanPong
	for _, m := range lanPongRE.FindAllStringSubmatch(out, -1) {
		p := lanPong{Via: m[2]}
		if d, err := time.ParseDuration(m[3]); err == nil {
			p.RTT = d
		}
		if strings.HasPrefix(p.Via, "DERP(") && strings.HasSuffix(p.Via, ")") {
			p.DERP = strings.TrimSuffix(strings.TrimPrefix(p.Via, "DERP("), ")")
		} else if host, _, err := net.SplitHostPort(p.Via); err == nil {
			p.IP = host
		} else if ip, err := netip.ParseAddr(p.Via); err == nil {
			p.IP = ip.String()
		}
		pongs = append(pongs, p)
	}
	return pongs
}

func lanLastDirect(pongs []lanPong) (lanPong, bool) {
	for i := len(pongs) - 1; i >= 0; i-- {
		if pongs[i].IP != "" {
			return pongs[i], true
		}
	}
	return lanPong{}, false
}

func lanUnderlayIP(t *testing.T, e *lanEnv, host, cidr string) string {
	t.Helper()
	out := lanMust(t, e, 10*time.Second, "exec", "-T", host, "ip", "-4", "-o", "addr", "show")
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "tailscale") {
			continue
		}
		for _, field := range strings.Fields(line) {
			p, err := netip.ParsePrefix(field)
			if err != nil || !p.Addr().Is4() {
				continue
			}
			if prefix.Contains(p.Addr()) {
				return p.Addr().String()
			}
		}
	}
	t.Fatalf("no underlay address in %s on %s\n%s", cidr, host, out)
	return ""
}

func lanNodeHost(n headscale.Node) string {
	if n.GivenName != "" {
		return n.GivenName
	}
	return strings.Split(n.Name, ".")[0]
}

func lanV4(ips []string) string {
	for _, s := range ips {
		ip, err := netip.ParseAddr(s)
		if err == nil && ip.Is4() {
			return ip.String()
		}
	}
	return ""
}

func lanFirstIPv4(s string) string {
	for _, field := range strings.Fields(s) {
		ip, err := netip.ParseAddr(field)
		if err == nil && ip.Is4() {
			return ip.String()
		}
	}
	return ""
}

func lanAddrInCIDR(addr, cidr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	return prefix.Contains(ip)
}

func lanExtractJSON(out string) []byte {
	out = strings.TrimSpace(out)
	startObj := strings.Index(out, "{")
	startArr := strings.Index(out, "[")
	start := startObj
	if startArr >= 0 && (start < 0 || startArr < start) {
		start = startArr
	}
	if start < 0 {
		return nil
	}
	return []byte(out[start:])
}

func lanLastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func lanEvidence(t *testing.T, title, body string) {
	t.Helper()
	t.Logf("EVIDENCE %s:\n%s", title, strings.TrimSpace(body))
}

func lanChooseNets() (lanNets, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return lanNets{}, err
	}
	second := 240 + int(b[0]%15) // 240-254
	third := int(b[1] % 240)     // leave room for +2
	octet := func(n int) string { return strconv.Itoa(n) }
	cidr := func(th int) string {
		return "10." + octet(second) + "." + octet(th) + ".0/24"
	}
	host := func(th, last int) string {
		return "10." + octet(second) + "." + octet(th) + "." + octet(last)
	}
	return lanNets{
		officeCIDR: cidr(third),
		officeGW:   host(third, 1),
		homeCIDR:   cidr(third + 1),
		homeGW:     host(third+1, 1),
		labCIDR:    cidr(third + 2),
		labGW:      host(third+2, 1),
		labBackend: host(third+2, 10),
	}, nil
}

func lanProjectName() (string, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "idoris-vpn-lan-" + hex.EncodeToString(b[:]), nil
}

func lanComposeEnv(n lanNets) []string {
	return append(os.Environ(),
		"LAN_OFFICE_CIDR="+n.officeCIDR,
		"LAN_OFFICE_GW="+n.officeGW,
		"LAN_HOME_CIDR="+n.homeCIDR,
		"LAN_HOME_GW="+n.homeGW,
		"LAN_LAB_CIDR="+n.labCIDR,
		"LAN_LAB_GW="+n.labGW,
		"LAN_LAB_BACKEND="+n.labBackend,
	)
}

func lanActivatePolicy(src, labCIDR string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if !strings.Contains(string(b), lanPolicyLabCIDR) {
		return fmt.Errorf("policy %s has no template prefix %s", src, lanPolicyLabCIDR)
	}
	out := strings.ReplaceAll(string(b), lanPolicyLabCIDR, labCIDR)
	return os.WriteFile(lanPKIDir+"/policy.active.hujson", []byte(out), 0o644)
}

func lanWritePKI() (*x509.CertPool, error) {
	if err := os.MkdirAll(lanPKIDir, 0o755); err != nil {
		return nil, err
	}
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "idoris-vpn-lan CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "headscale"},
		DNSNames:     []string{"headscale"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	write := func(name, blockType string, der []byte) error {
		body := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
		// 0644: the Headscale and tailscaled users differ from the test user.
		return os.WriteFile(lanPKIDir+"/"+name, body, 0o644)
	}
	if err := write("ca.pem", "CERTIFICATE", caDER); err != nil {
		return nil, err
	}
	if err := write("tls.crt", "CERTIFICATE", leafDER); err != nil {
		return nil, err
	}
	if err := write("tls.key", "EC PRIVATE KEY", leafKeyDER); err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, nil
}
