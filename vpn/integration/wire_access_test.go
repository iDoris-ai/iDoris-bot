//go:build integration

package integration

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
)

const (
	wireTCPListen  = "127.0.0.1:18434"
	wireUNIXListen = "unix:/var/lib/idoris/wire/fwd.sock"
	wireUNIXPath   = "/var/lib/idoris/wire/fwd.sock"
	wireSOCKS      = "127.0.0.1:11080"
	wireAuthFile   = "/var/lib/idoris/vpn-state/socks5.auth"
	wireEchoTarget = "acme-local-ai:11434"
	wireEchoBytes  = 1024
)

// TestWireAccessForwardsAndSOCKS5 joins an embedded node to the fixture
// Headscale and checks both forward transports, SOCKS5 authentication, the
// connection cap, and the unix socket mode. The SOCKS5 client is wireclient.
func TestWireAccessForwardsAndSOCKS5(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	buildLinuxBin(t, "../cmd/idoris-vpnd", filepath.Join("..", "bin", "idoris-vpnd-linux"))
	buildLinuxBin(t, "./echosrv", filepath.Join("..", "bin", "echosrv-linux"))
	buildLinuxBin(t, "./wireclient", filepath.Join("..", "bin", "wireclient-linux"))
	roots := writeTestPKI(t, embeddedPKIDir,
		[]string{"headscale", "headscale-foreign"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)

	e := emb{project: fmt.Sprintf("wire-%d", os.Getpid())}
	_, _ = e.composeOK("down", "-v", "--remove-orphans")
	e.compose(t, "up", "-d", "--wait", "--wait-timeout", "180")
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := e.composeOK("logs", "--no-color", "--tail=80")
			vpnd, _ := e.composeOK("exec", "-T", "member", "cat", "/tmp/vpnd.log")
			t.Logf("compose logs:\n%s", logs)
			t.Logf("vpnd log:\n%s", redactSecret(vpnd, wireSecret(e)))
		}
		_, _ = e.composeOK("down", "-v", "--remove-orphans")
	})

	ctx := context.Background()
	our := e.headscaleClient(t, roots, "headscale")
	if err := our.Health(ctx); err != nil {
		t.Fatal(err)
	}
	acme, err := our.EnsureUser(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	e.waitSock(t, "local-ai")
	e.compose(t, "exec", "-d", "local-ai", "/opt/echosrv", "listen", "0.0.0.0:11434")
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
	waitFor(t, "tagged local-ai online", 60*time.Second, func() (bool, string) {
		nodes, err := our.ListNodes(ctx, "")
		if err != nil {
			return false, err.Error()
		}
		for _, n := range nodes {
			if n.GivenName == "acme-local-ai" || strings.HasPrefix(n.Name, "acme-local-ai") {
				return n.Online && hasTag(n, "tag:acme-local-ai"), fmt.Sprintf("online=%v tags=%v", n.Online, n.Tags)
			}
		}
		return false, fmt.Sprintf("%d nodes", len(nodes))
	})

	token, err := enroll.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := enroll.NewServer(enroll.Config{
		ControlURL: "https://headscale",
		Tenants: []enroll.Tenant{{
			Name: "acme", HeadscaleUserID: acme.ID,
			TokenHashes: []string{enroll.HashToken(token)},
			PreAuthTTL:  enroll.Duration(5 * time.Minute),
		}},
	}, our, slog.New(slog.NewTextHandler(os.Stderr, nil)))
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

	e.compose(t, "cp", filepath.Join("..", "bin", "wireclient-linux"), "member:/opt/wireclient")
	e.compose(t, "exec", "-T", "member", "chmod", "0755", "/opt/wireclient")
	script := fmt.Sprintf(
		"mkdir -p /var/lib/idoris/wire && chmod 700 /var/lib/idoris /var/lib/idoris/wire; /opt/idoris-vpnd run --mode embedded --enroll-url %s --enroll-token %s --enroll-allow-insecure --hostname wire-member --state-dir /var/lib/idoris/vpn-state --listen tcp:127.0.0.1:7845 --interval 2s --log-level info --max-connections 1 --dial-timeout 8s --forward %s=%s --forward %s=%s --socks5-listen %s > /tmp/vpnd.log 2>&1",
		enrollURL, token, wireTCPListen, wireEchoTarget, wireUNIXListen, wireEchoTarget, wireSOCKS,
	)
	e.compose(t, "exec", "-d", "member", "sh", "-c", script)

	waitFor(t, "wire daemon connected", 120*time.Second, func() (bool, string) {
		m, err := e.daemonStatus()
		if err != nil {
			return false, err.Error()
		}
		return m["phase"] == "connected" && m["mode"] == "embedded",
			fmt.Sprintf("phase=%v mode=%v err=%v", m["phase"], m["mode"], m["last_error"])
	})

	waitFor(t, "tcp forward", 90*time.Second, func() (bool, string) {
		out, err := e.composeOK("exec", "-T", "member", "/opt/echosrv", "dial", wireTCPListen, strconv.Itoa(wireEchoBytes))
		if err != nil {
			return false, strings.TrimSpace(out)
		}
		return strings.Contains(out, "echoed"), strings.TrimSpace(out)
	})
	unixOut := e.compose(t, "exec", "-T", "member", "/opt/echosrv", "dial", wireUNIXListen, strconv.Itoa(wireEchoBytes))
	if !strings.Contains(unixOut, "echoed") {
		t.Fatalf("unix forward: %s", unixOut)
	}
	if mode := wireMode(t, e, wireUNIXPath); mode != "600" {
		t.Fatalf("unix socket mode %q", mode)
	}
	if mode := wireMode(t, e, wireAuthFile); mode != "600" {
		t.Fatalf("socks5 auth mode %q", mode)
	}

	none := e.compose(t, "exec", "-T", "member", "/opt/wireclient", "none", wireSOCKS, wireEchoTarget)
	if !strings.Contains(none, "rejected") {
		t.Fatalf("anonymous SOCKS5 was not rejected:\n%s", none)
	}
	wrong := e.compose(t, "exec", "-T", "member", "/opt/wireclient", "wrong", wireSOCKS, wireEchoTarget)
	if !strings.Contains(wrong, "rejected") {
		t.Fatalf("wrong SOCKS5 credentials were not rejected:\n%s", wrong)
	}
	authed := e.compose(t, "exec", "-T", "member", "/opt/wireclient", "auth", wireSOCKS, wireEchoTarget, wireAuthFile, strconv.Itoa(wireEchoBytes))
	if !strings.Contains(authed, "echoed") {
		t.Fatalf("authenticated SOCKS5 did not reach the tailnet:\n%s", authed)
	}

	e.compose(t, "exec", "-d", "member", "/opt/wireclient", "hold", wireSOCKS, wireEchoTarget, wireAuthFile, "/tmp/wire-hold.ready")
	waitFor(t, "held SOCKS5 connection", 20*time.Second, func() (bool, string) {
		out, err := e.composeOK("exec", "-T", "member", "cat", "/tmp/wire-hold.ready")
		return err == nil && strings.Contains(out, "up"), strings.TrimSpace(out)
	})
	start := time.Now()
	over, err := e.composeOK("exec", "-T", "member", "/opt/wireclient", "auth", wireSOCKS, wireEchoTarget, wireAuthFile, strconv.Itoa(wireEchoBytes))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("connection past max_connections was accepted:\n%s", over)
	}
	if ms, ok := wireElapsed(over); ok {
		elapsed = time.Duration(ms) * time.Millisecond
	}
	if elapsed > 2*time.Second {
		t.Fatalf("connection past max_connections took %s, want a quick refusal\n%s", elapsed, over)
	}
	t.Logf("max_connections refusal in %s", elapsed)

	text := e.compose(t, "exec", "-T", "member", "/opt/idoris-vpnd", "status", "--listen", "tcp:127.0.0.1:7845")
	if !strings.Contains(text, "auth="+wireAuthFile) {
		t.Fatalf("status text missing auth path:\n%s", text)
	}
	logText, _ := e.composeOK("exec", "-T", "member", "cat", "/tmp/vpnd.log")
	secret := wireSecret(e)
	if secret != "" && strings.Contains(logText, secret) {
		t.Fatal("vpnd log contains the SOCKS5 password")
	}
	if !strings.Contains(logText, wireAuthFile) || !strings.Contains(logText, "SOCKS5 auth file created") {
		t.Fatalf("vpnd log missing auth path:\n%s", redactSecret(logText, secret))
	}
	st, err := e.daemonStatus()
	if err != nil {
		t.Fatal(err)
	}
	s5, _ := st["socks5"].(map[string]any)
	if s5["state"] != "listening" || s5["auth_file"] != wireAuthFile {
		t.Fatalf("socks5 status %+v", s5)
	}
	t.Logf("wire access ok: tcp, unix mode 0600, socks5 auth, cap refusal %s", elapsed)
}

func wireMode(t *testing.T, e emb, path string) string {
	t.Helper()
	out := e.compose(t, "exec", "-T", "member", "stat", "-c", "%a", path)
	return strings.TrimSpace(out)
}

func wireElapsed(out string) (int, bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if n, ok := strings.CutPrefix(line, "elapsed_ms "); ok {
			ms, err := strconv.Atoi(strings.TrimSpace(n))
			return ms, err == nil
		}
	}
	return 0, false
}

func wireSecret(e emb) string {
	out, err := e.composeOK("exec", "-T", "member", "cat", wireAuthFile)
	if err != nil {
		return ""
	}
	_, pass, ok := strings.Cut(strings.TrimSpace(out), ":")
	if !ok {
		return ""
	}
	return pass
}

func redactSecret(text, secret string) string {
	if secret == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, "[redacted]")
}
