//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
)

const (
	embeddedPKIDir   = ".pki-embedded"
	echoBytes        = 64*1024 + 17
	forwardListen    = "127.0.0.1:11434"
	magicShortTarget = "acme-local-ai:11434"
	statusURL        = "http://127.0.0.1:7845/v1/status"
	tsSock           = "/var/run/tailscale/tailscaled.sock"
)

// emb runs docker compose against the embedded fixture with its own project
// name, so it does not collide with the registration fixture or other agents.
type emb struct{ project string }

func (e emb) compose(t *testing.T, args ...string) string {
	t.Helper()
	out, err := e.composeOK(args...)
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (e emb) composeOK(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"compose", "-p", e.project, "-f", "embedded/compose.yaml"}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func buildLinuxBin(t *testing.T, pkg, out string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
}

// TestEmbeddedAutoLeavesForeignTailscale proves three things:
//   - a system tailscaled already logged into a foreign Headscale stays there
//     while idoris-vpnd in auto mode enrolls an in-process node on ours;
//   - a loopback forward reaches a tagged node by its MagicDNS name;
//   - restarting the daemon reuses the state file and mints no pre-auth key.
//
// It also expires the embedded node and checks that re-enrollment still works.
func TestEmbeddedAutoLeavesForeignTailscale(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	buildLinuxBin(t, "../cmd/idoris-vpnd", filepath.Join("..", "bin", "idoris-vpnd-linux"))
	buildLinuxBin(t, "./echosrv", filepath.Join("..", "bin", "echosrv-linux"))
	roots := writeTestPKI(t, embeddedPKIDir,
		[]string{"headscale", "headscale-foreign"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)

	e := emb{project: fmt.Sprintf("idoris-vpn-client-%d", os.Getpid())}
	_, _ = e.composeOK("down", "-v", "--remove-orphans")
	e.compose(t, "up", "-d", "--wait", "--wait-timeout", "180")
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := e.composeOK("logs", "--no-color", "--tail=120")
			t.Logf("compose logs:\n%s", logs)
			vpnd, _ := e.composeOK("exec", "-T", "member", "cat", "/tmp/vpnd.log")
			t.Logf("vpnd log:\n%s", vpnd)
			ai, _ := e.composeOK("exec", "-T", "local-ai", "/usr/local/bin/tailscale", "--socket", tsSock, "status")
			t.Logf("local-ai status:\n%s", ai)
		}
		_, _ = e.composeOK("down", "-v", "--remove-orphans")
	})

	ctx := context.Background()
	our := e.headscaleClient(t, roots, "headscale")
	foreign := e.headscaleClient(t, roots, "headscale-foreign")
	if err := our.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if err := foreign.Health(ctx); err != nil {
		t.Fatal(err)
	}
	acme, err := our.EnsureUser(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	foreignUser, err := foreign.EnsureUser(ctx, "foreign")
	if err != nil {
		t.Fatal(err)
	}

	e.waitSock(t, "local-ai")
	e.waitSock(t, "member")
	_, _ = e.composeOK("exec", "-d", "local-ai", "/opt/echosrv", "listen", "0.0.0.0:11434")

	aiKey, err := our.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		UserID:     acme.ID,
		Expiration: time.Now().Add(30 * time.Minute),
		ACLTags:    []string{"tag:acme-local-ai"},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.compose(t, "exec", "-T", "local-ai", "/usr/local/bin/tailscale", "--socket", tsSock, "up",
		"--login-server", "https://headscale", "--auth-key", aiKey.Key,
		"--hostname", "acme-local-ai", "--accept-dns=false", "--timeout", "90s")

	frKey, err := foreign.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		UserID:     foreignUser.ID,
		Expiration: time.Now().Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.compose(t, "exec", "-T", "member", "/usr/local/bin/tailscale", "--socket", tsSock, "up",
		"--login-server", "https://headscale-foreign", "--auth-key", frKey.Key,
		"--hostname", "it-foreign", "--accept-dns=false", "--timeout", "90s")
	before := e.foreignIdentity(t)
	if before.BackendState != "Running" || before.SelfID == "" || !strings.Contains(before.ControlURL, "headscale-foreign") {
		t.Fatalf("foreign tailscale not ready: %+v", before)
	}
	t.Logf("foreign before: id=%s control=%s state=%s", before.SelfID, before.ControlURL, before.BackendState)

	var ai headscale.Node
	waitFor(t, "tagged local-ai online", 60*time.Second, func() (bool, string) {
		nodes, err := our.ListNodes(ctx, "")
		if err != nil {
			return false, err.Error()
		}
		for _, n := range nodes {
			if n.GivenName == "acme-local-ai" || strings.HasPrefix(n.Name, "acme-local-ai") {
				ai = n
				if n.Online && hasTag(n, "tag:acme-local-ai") {
					return true, ""
				}
				return false, fmt.Sprintf("online=%v tags=%v", n.Online, n.Tags)
			}
		}
		return false, fmt.Sprintf("%d nodes", len(nodes))
	})
	t.Logf("local-ai: id=%s ips=%v tags=%v", ai.ID, ai.IPAddresses, ai.Tags)

	token, err := enroll.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	mints := &countingMinter{inner: our}
	srv, err := enroll.NewServer(enroll.Config{
		ControlURL: "https://headscale",
		Tenants: []enroll.Tenant{{
			Name: "acme", HeadscaleUserID: acme.ID,
			TokenHashes: []string{enroll.HashToken(token)},
			PreAuthTTL:  enroll.Duration(5 * time.Minute),
		}},
	}, mints, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	hsrv := &http.Server{Handler: srv.Handler()}
	go func() { _ = hsrv.Serve(ln) }()
	t.Cleanup(func() { _ = hsrv.Close() })
	enrollURL := fmt.Sprintf("http://host.docker.internal:%d", ln.Addr().(*net.TCPAddr).Port)

	startDaemon := func() {
		t.Helper()
		script := fmt.Sprintf(
			"/opt/idoris-vpnd run --mode auto --enroll-url %s --enroll-token %s --enroll-allow-insecure --hostname it-embedded --state-dir /var/lib/idoris/vpn-state --listen tcp:127.0.0.1:7845 --interval 2s --log-level debug --forward %s=%s > /tmp/vpnd.log 2>&1",
			enrollURL, token, forwardListen, magicShortTarget,
		)
		e.compose(t, "exec", "-d", "member", "sh", "-c", script)
	}
	startDaemon()

	var connected map[string]any
	waitFor(t, "embedded daemon connected", 120*time.Second, func() (bool, string) {
		m, err := e.daemonStatus()
		if err != nil {
			return false, err.Error()
		}
		connected = m
		return m["phase"] == "connected" && m["mode"] == "embedded",
			fmt.Sprintf("phase=%v mode=%v reason=%v err=%v", m["phase"], m["mode"], m["mode_reason"], m["last_error"])
	})
	reason, _ := connected["mode_reason"].(string)
	if !strings.Contains(reason, "foreign") {
		t.Fatalf("mode_reason %q does not mention the foreign tailnet", reason)
	}
	if connected["login_attempts"] != float64(1) {
		t.Fatalf("first connect minted more than one login: %v (keys %d)", connected["login_attempts"], mints.n.Load())
	}
	t.Logf("embedded connected: mode_reason=%q attempts=%v keys=%d", reason, connected["login_attempts"], mints.n.Load())
	e.sameForeign(t, before, "after enroll")

	var embNode headscale.Node
	waitFor(t, "embedded node online", 45*time.Second, func() (bool, string) {
		nodes, err := our.ListNodes(ctx, "acme")
		if err != nil {
			return false, err.Error()
		}
		for _, n := range nodes {
			if n.GivenName == "it-embedded" || strings.HasPrefix(n.Name, "it-embedded") {
				embNode = n
				if n.Online {
					return true, ""
				}
			}
		}
		return false, fmt.Sprintf("%d acme nodes", len(nodes))
	})
	t.Logf("embedded node: id=%s ips=%v", embNode.ID, embNode.IPAddresses)

	waitFor(t, "magicdns forward", 90*time.Second, func() (bool, string) {
		out, err := e.composeOK("exec", "-T", "member", "/opt/echosrv", "dial", forwardListen, fmt.Sprint(echoBytes))
		if err != nil {
			return false, strings.TrimSpace(out)
		}
		return true, strings.TrimSpace(out)
	})
	t.Logf("forward %s -> %s echoed %d bytes", forwardListen, magicShortTarget, echoBytes)
	e.sameForeign(t, before, "after forward")

	if err := our.ExpireNode(ctx, embNode.ID); err != nil {
		t.Fatal(err)
	}
	mintedAtExpiry := mints.n.Load()
	waitFor(t, "embedded re-enrolled after expiry", 120*time.Second, func() (bool, string) {
		m, err := e.daemonStatus()
		if err != nil {
			return false, err.Error()
		}
		attempts, _ := m["login_attempts"].(float64)
		return m["phase"] == "connected" && m["mode"] == "embedded" && attempts >= 2,
			fmt.Sprintf("phase=%v mode=%v attempts=%v err=%v", m["phase"], m["mode"], attempts, m["last_error"])
	})
	if got := mints.n.Load(); got != mintedAtExpiry+1 {
		t.Fatalf("re-enroll minted %d keys, want 1 (before %d after %d)", got-mintedAtExpiry, mintedAtExpiry, got)
	}
	waitFor(t, "same embedded node online again", 60*time.Second, func() (bool, string) {
		nodes, err := our.ListNodes(ctx, "acme")
		if err != nil {
			return false, err.Error()
		}
		for _, n := range nodes {
			if n.ID == embNode.ID && n.Online && (n.Expiry.IsZero() || n.Expiry.After(time.Now())) {
				return true, ""
			}
		}
		return false, "node not back"
	})
	t.Logf("re-enrolled node %s keys=%d", embNode.ID, mints.n.Load())
	e.sameForeign(t, before, "after re-enroll")

	mintedBeforeRestart := mints.n.Load()
	_, _ = e.composeOK("exec", "-T", "member", "pkill", "idoris-vpnd")
	time.Sleep(2 * time.Second)
	startDaemon()
	waitFor(t, "embedded restarted without a new key", 90*time.Second, func() (bool, string) {
		m, err := e.daemonStatus()
		if err != nil {
			return false, err.Error()
		}
		return m["phase"] == "connected" && m["mode"] == "embedded" && m["login_attempts"] == float64(0),
			fmt.Sprintf("phase=%v mode=%v attempts=%v err=%v", m["phase"], m["mode"], m["login_attempts"], m["last_error"])
	})
	if got := mints.n.Load(); got != mintedBeforeRestart {
		t.Errorf("restart minted %d extra pre-auth key(s)", got-mintedBeforeRestart)
	}
	waitFor(t, "forward still works after restart", 60*time.Second, func() (bool, string) {
		out, err := e.composeOK("exec", "-T", "member", "/opt/echosrv", "dial", forwardListen, fmt.Sprint(echoBytes))
		if err != nil {
			return false, strings.TrimSpace(out)
		}
		return true, ""
	})
	e.sameForeign(t, before, "after restart")
	t.Logf("restart reused state; pre-auth keys minted in total: %d", mints.n.Load())
}

func (e emb) headscaleClient(t *testing.T, roots *x509.CertPool, service string) *headscale.Client {
	t.Helper()
	apiKey := strings.TrimSpace(e.compose(t, "exec", "-T", service, "headscale", "apikeys", "create", "--expiration", "1h"))
	hostPort := strings.TrimSpace(e.compose(t, "port", service, "443"))
	return &headscale.Client{
		BaseURL: "https://" + hostPort,
		APIKey:  apiKey,
		HTTP: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		},
	}
}

func (e emb) waitSock(t *testing.T, service string) {
	t.Helper()
	waitFor(t, service+" tailscaled socket", 60*time.Second, func() (bool, string) {
		out, err := e.composeOK("exec", "-T", service, "/usr/local/bin/tailscale", "--socket", tsSock, "status", "--json")
		if strings.Contains(out, "BackendState") {
			return true, ""
		}
		if err != nil {
			return false, strings.TrimSpace(out + " " + err.Error())
		}
		return false, strings.TrimSpace(out)
	})
}

type foreignNode struct {
	BackendState string
	SelfID       string
	ControlURL   string
}

func (e emb) foreignIdentity(t *testing.T) foreignNode {
	t.Helper()
	raw := e.compose(t, "exec", "-T", "member", "/usr/local/bin/tailscale", "--socket", tsSock, "status", "--json")
	var st struct {
		BackendState string `json:"BackendState"`
		Self         *struct {
			ID string `json:"ID"`
		} `json:"Self"`
	}
	if err := json.Unmarshal([]byte(jsonObject(raw)), &st); err != nil {
		t.Fatalf("tailscale status: %v\n%s", err, raw)
	}
	prefsRaw := e.compose(t, "exec", "-T", "member", "/usr/local/bin/tailscale", "--socket", tsSock, "debug", "prefs")
	var prefs struct {
		ControlURL string `json:"ControlURL"`
	}
	if err := json.Unmarshal([]byte(jsonObject(prefsRaw)), &prefs); err != nil {
		t.Fatalf("tailscale prefs: %v\n%s", err, prefsRaw)
	}
	id := ""
	if st.Self != nil {
		id = st.Self.ID
	}
	return foreignNode{BackendState: st.BackendState, SelfID: id, ControlURL: prefs.ControlURL}
}

func (e emb) sameForeign(t *testing.T, before foreignNode, when string) {
	t.Helper()
	got := e.foreignIdentity(t)
	if got.SelfID != before.SelfID || got.BackendState != "Running" || got.ControlURL != before.ControlURL {
		t.Fatalf("foreign tailscale changed %s: before %+v now %+v", when, before, got)
	}
}

func (e emb) daemonStatus() (map[string]any, error) {
	out, err := e.composeOK("exec", "-T", "member", "wget", "-qO-", statusURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return nil, err
	}
	return m, nil
}

func hasTag(n headscale.Node, tag string) bool {
	for _, got := range n.Tags {
		if got == tag {
			return true
		}
	}
	return false
}

func jsonObject(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i < 0 || j < i {
		return s
	}
	return s[i : j+1]
}
