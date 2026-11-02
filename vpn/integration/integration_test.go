//go:build integration

// Package integration exercises idoris-vpnd against a real Headscale and a real
// tailscaled in Docker. Run with:
//
//	make integration
//
// Requirements: docker compose v2, network access to pull images once.
package integration

import (
	"context"
	"crypto/tls"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
)

const statusAddr = "127.0.0.1:7845"

func compose(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", append([]string{"compose", "-f", "compose.yaml"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func composeOK(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"compose", "-f", "compose.yaml"}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func buildDaemon(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll("../bin", 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join("..", "bin", "idoris-vpnd-linux")
	cmd := exec.Command("go", "build", "-o", out, "../cmd/idoris-vpnd")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build daemon: %v\n%s", err, b)
	}
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		ok, note := cond()
		if ok {
			return
		}
		last = note
		time.Sleep(time.Second)
	}
	t.Fatalf("timeout waiting for %s (last: %s)", what, last)
}

func TestEnrollConnectAndReauth(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	buildDaemon(t)
	roots := generatePKI(t)

	compose(t, "down", "-v", "--remove-orphans")
	compose(t, "up", "-d", "--wait")
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := composeOK("logs", "--no-color", "--tail=80")
			t.Logf("compose logs:\n%s", out)
		}
		_, _ = composeOK("down", "-v", "--remove-orphans")
	})

	// --- control plane bootstrap (what deploy/vpn/bootstrap.sh does) ---
	compose(t, "exec", "-T", "headscale", "headscale", "users", "create", "acme")
	usersJSON := compose(t, "exec", "-T", "headscale", "headscale", "users", "list", "-o", "json")
	var users []struct {
		ID   json.Number `json:"id"`
		Name string      `json:"name"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(usersJSON)), &users); err != nil {
		t.Fatalf("users list: %v\n%s", err, usersJSON)
	}
	var userID string
	for _, u := range users {
		if u.Name == "acme" {
			userID = u.ID.String()
		}
	}
	if userID == "" {
		t.Fatalf("user acme not found in %s", usersJSON)
	}
	apiKey := strings.TrimSpace(compose(t, "exec", "-T", "headscale", "headscale", "apikeys", "create", "--expiration", "1h"))
	hostPort := strings.TrimSpace(compose(t, "port", "headscale", "443")) // e.g. 127.0.0.1:55012
	hs := &headscale.Client{
		BaseURL: "https://" + hostPort,
		APIKey:  apiKey,
		HTTP: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		},
	}
	ctx := context.Background()
	if err := hs.Health(ctx); err != nil {
		t.Fatal(err)
	}

	// --- enrollment service on the host, reachable from the container ---
	token, err := enroll.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	mints := &countingMinter{inner: hs}
	srv, err := enroll.NewServer(enroll.Config{
		ControlURL: "https://headscale",
		Tenants: []enroll.Tenant{{
			Name: "acme", HeadscaleUserID: userID,
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
	enrollPort := ln.Addr().(*net.TCPAddr).Port
	enrollURL := fmt.Sprintf("http://host.docker.internal:%d", enrollPort)

	// --- start the daemon inside the tailscaled container ---
	startDaemon := func() {
		compose(t, "exec", "-T", "-d", "ts-node", "/opt/idoris-vpnd", "run",
			"--enroll-url", enrollURL, "--enroll-token", token, "--enroll-allow-insecure",
			"--tailscale-socket", "/var/run/tailscale/tailscaled.sock",
			"--listen", "tcp:"+statusAddr, "--interval", "2s", "--log-level", "debug")
	}
	startDaemon()

	daemonStatus := func() (map[string]any, error) {
		out, err := composeOK("exec", "-T", "ts-node", "wget", "-qO-", "http://"+statusAddr+"/v1/status")
		if err != nil {
			return nil, fmt.Errorf("%w: %s", err, out)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			return nil, err
		}
		return m, nil
	}

	waitFor(t, "daemon connected", 90*time.Second, func() (bool, string) {
		m, err := daemonStatus()
		if err != nil {
			return false, err.Error()
		}
		return m["phase"] == "connected", fmt.Sprintf("phase=%v err=%v", m["phase"], m["last_error"])
	})

	var node headscale.Node
	waitFor(t, "node online in headscale", 30*time.Second, func() (bool, string) {
		nodes, err := hs.ListNodes(ctx, "acme")
		if err != nil {
			return false, err.Error()
		}
		for _, n := range nodes {
			if n.Online {
				node = n
				return true, ""
			}
		}
		return false, fmt.Sprintf("%d nodes, none online", len(nodes))
	})
	if node.GivenName != "it-member" && !strings.HasPrefix(node.Name, "it-member") {
		t.Errorf("unexpected node name %q / %q", node.Name, node.GivenName)
	}
	if len(node.IPAddresses) == 0 {
		t.Errorf("node has no tailnet IPs: %+v", node)
	}
	st, _ := daemonStatus()
	if ips, ok := st["tailnet_ips"].([]any); !ok || len(ips) == 0 {
		t.Errorf("daemon reports no tailnet ips: %v", st)
	}
	if st["login_attempts"] != float64(1) {
		t.Errorf("expected exactly one login attempt, got %v", st["login_attempts"])
	}
	t.Logf("connected: node=%s ips=%v", node.Name, node.IPAddresses)

	// --- re-auth: operator expires the node; daemon must re-enroll on its own ---
	if err := hs.ExpireNode(ctx, node.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "daemon re-enrolled after expiry", 120*time.Second, func() (bool, string) {
		m, err := daemonStatus()
		if err != nil {
			return false, err.Error()
		}
		attempts, _ := m["login_attempts"].(float64)
		return m["phase"] == "connected" && attempts >= 2, fmt.Sprintf("phase=%v attempts=%v err=%v", m["phase"], attempts, m["last_error"])
	})
	waitFor(t, "node online again", 60*time.Second, func() (bool, string) {
		nodes, err := hs.ListNodes(ctx, "acme")
		if err != nil {
			return false, err.Error()
		}
		for _, n := range nodes {
			if n.ID == node.ID && n.Online && (n.Expiry.IsZero() || n.Expiry.After(time.Now())) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("%d nodes", len(nodes))
	})

	// --- daemon restart must be idempotent: profile exists, no extra key ---
	mintedBeforeRestart := mints.n.Load()
	_, _ = composeOK("exec", "-T", "ts-node", "pkill", "idoris-vpnd")
	time.Sleep(2 * time.Second)
	startDaemon()
	waitFor(t, "daemon reconnected after restart", 60*time.Second, func() (bool, string) {
		m, err := daemonStatus()
		if err != nil {
			return false, err.Error()
		}
		return m["phase"] == "connected" && m["login_attempts"] == float64(0), fmt.Sprintf("phase=%v attempts=%v", m["phase"], m["login_attempts"])
	})
	if got := mints.n.Load(); got != mintedBeforeRestart {
		t.Errorf("daemon restart minted %d extra pre-auth key(s); discovery must not mint", got-mintedBeforeRestart)
	}
	t.Logf("pre-auth keys minted in total: %d", mints.n.Load())
}

// countingMinter counts keys the enrollment service asks Headscale for.
type countingMinter struct {
	inner enroll.Minter
	n     atomic.Int64
}

func (c *countingMinter) CreatePreAuthKey(ctx context.Context, req headscale.CreatePreAuthKeyRequest) (*headscale.PreAuthKey, error) {
	c.n.Add(1)
	return c.inner.CreatePreAuthKey(ctx, req)
}
