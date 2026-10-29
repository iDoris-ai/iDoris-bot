//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

// TestR4CEmbeddedStaticAndRoleSwap uses a real Headscale and a real embedded
// tsnet node. A static auth key reaches connected and the forward listener
// accepts. A later credential swap (member to admin, same user, same state
// directory) mints exactly one new key, stays on the same Headscale node id,
// and reports the new binding.
func TestR4CEmbeddedStaticAndRoleSwap(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	buildLinuxBin(t, "../cmd/idoris-vpnd", filepath.Join("..", "bin", "idoris-vpnd-linux"))
	buildLinuxBin(t, "./echosrv", filepath.Join("..", "bin", "echosrv-linux"))
	roots := writeTestPKI(t, embeddedPKIDir,
		[]string{"headscale", "headscale-foreign"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	e := emb{project: "idoris-vpn-r4c-" + hex.EncodeToString(suffix[:])}
	_, _ = e.composeOK("down", "-v", "--remove-orphans")
	e.compose(t, "up", "-d", "--wait", "--wait-timeout", "180")
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := e.composeOK("logs", "--no-color", "--tail=80")
			t.Logf("compose logs:\n%s", logs)
			vpndLog, _ := e.composeOK("exec", "-T", "member", "cat", "/tmp/vpnd.log")
			t.Logf("vpnd log:\n%s", vpndLog)
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

	staticKey, err := our.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		UserID:     acme.ID,
		Expiration: time.Now().Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	const staticState = "/var/lib/idoris/r4c-static.json"
	e.startVPND(t, fmt.Sprintf(
		"/opt/idoris-vpnd run --mode embedded --auth-key %s --control-url https://headscale --hostname it-r4c-static --state-dir /var/lib/idoris/r4c-static-node --state-file %s --listen tcp:127.0.0.1:7845 --interval 2s --log-level info --forward %s=%s > /tmp/vpnd.log 2>&1",
		staticKey.Key, staticState, forwardListen, magicShortTarget,
	))
	e.waitPhase(t, "static key connected", 120*time.Second, func(m map[string]any) (bool, string) {
		return m["phase"] == "connected" && m["mode"] == "embedded",
			fmt.Sprintf("phase=%v mode=%v err=%v", m["phase"], m["mode"], m["last_error"])
	})
	waitFor(t, "static forward accepts", 90*time.Second, func() (bool, string) {
		out, err := e.composeOK("exec", "-T", "member", "/opt/echosrv", "dial", forwardListen, fmt.Sprint(echoBytes))
		if err != nil {
			return false, strings.TrimSpace(out)
		}
		return true, ""
	})
	staticSaved := e.readState(t, staticState)
	if !staticSaved.Static || staticSaved.NodeID == "" || staticSaved.Tenant != "" {
		t.Fatalf("static binding %+v", staticSaved)
	}
	// A fresh tsnet state is NeedsLogin, so the static key is used once.
	// That is the login, not an enrollment mint, and it must not repeat.
	if m, err := e.daemonStatus(); err != nil || m["login_attempts"] != float64(1) {
		t.Fatalf("static key login attempts: %+v err=%v", m, err)
	}
	e.stopVPND(t)

	token, err := enroll.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	memberMints := &countingMinter{inner: our}
	memberURL := e.serveEnroll(t, acme.ID, token, "member", memberMints)
	const (
		swapState = "/var/lib/idoris/r4c-swap.json"
		swapDir   = "/var/lib/idoris/r4c-swap-node"
	)
	e.startVPND(t, fmt.Sprintf(
		"/opt/idoris-vpnd run --mode embedded --enroll-url %s --enroll-token %s --enroll-allow-insecure --hostname it-r4c-swap --state-dir %s --state-file %s --listen tcp:127.0.0.1:7845 --interval 2s --log-level info > /tmp/vpnd.log 2>&1",
		memberURL, token, swapDir, swapState,
	))
	e.waitPhase(t, "member enroll connected", 120*time.Second, func(m map[string]any) (bool, string) {
		return m["phase"] == "connected" && m["role"] == "member",
			fmt.Sprintf("phase=%v role=%v err=%v attempts=%v", m["phase"], m["role"], m["last_error"], m["login_attempts"])
	})
	if memberMints.n.Load() != 1 {
		t.Fatalf("member enroll minted %d keys", memberMints.n.Load())
	}
	memberSaved := e.readState(t, swapState)
	if memberSaved.NodeID == "" || memberSaved.Role != "member" {
		t.Fatalf("member binding %+v", memberSaved)
	}
	var hsNode headscale.Node
	waitFor(t, "swap node online", 45*time.Second, func() (bool, string) {
		nodes, err := our.ListNodes(ctx, "acme")
		if err != nil {
			return false, err.Error()
		}
		for _, n := range nodes {
			if n.GivenName == "it-r4c-swap" || strings.HasPrefix(n.Name, "it-r4c-swap") {
				hsNode = n
				if n.Online {
					return true, ""
				}
			}
		}
		return false, fmt.Sprintf("%d nodes", len(nodes))
	})
	e.stopVPND(t)

	adminMints := &countingMinter{inner: our}
	adminURL := e.serveEnroll(t, acme.ID, token, "admin", adminMints)
	e.startVPND(t, fmt.Sprintf(
		"/opt/idoris-vpnd run --mode embedded --enroll-url %s --enroll-token %s --enroll-allow-insecure --hostname it-r4c-swap --state-dir %s --state-file %s --listen tcp:127.0.0.1:7845 --interval 2s --log-level info > /tmp/vpnd.log 2>&1",
		adminURL, token, swapDir, swapState,
	))
	e.waitPhase(t, "admin reauth connected", 150*time.Second, func(m map[string]any) (bool, string) {
		return m["phase"] == "connected" && m["role"] == "admin",
			fmt.Sprintf("phase=%v role=%v err=%v attempts=%v", m["phase"], m["role"], m["last_error"], m["login_attempts"])
	})
	if got := adminMints.n.Load(); got != 1 {
		t.Fatalf("role swap minted %d keys, want 1", got)
	}
	adminSaved := e.readState(t, swapState)
	if adminSaved.NodeID != memberSaved.NodeID || adminSaved.Role != "admin" {
		t.Fatalf("binding before %+v after %+v", memberSaved, adminSaved)
	}
	waitFor(t, "same headscale node after role swap", 60*time.Second, func() (bool, string) {
		nodes, err := our.ListNodes(ctx, "acme")
		if err != nil {
			return false, err.Error()
		}
		for _, n := range nodes {
			if n.ID == hsNode.ID && n.Online {
				return true, ""
			}
		}
		return false, "node id changed or offline"
	})
}

func (e emb) startVPND(t *testing.T, script string) {
	t.Helper()
	e.compose(t, "exec", "-d", "member", "sh", "-c", script)
}

func (e emb) stopVPND(t *testing.T) {
	t.Helper()
	_, _ = e.composeOK("exec", "-T", "member", "pkill", "idoris-vpnd")
	time.Sleep(2 * time.Second)
}

func (e emb) waitPhase(t *testing.T, what string, timeout time.Duration, cond func(map[string]any) (bool, string)) {
	t.Helper()
	waitFor(t, what, timeout, func() (bool, string) {
		m, err := e.daemonStatus()
		if err != nil {
			return false, err.Error()
		}
		return cond(m)
	})
}

func (e emb) readState(t *testing.T, path string) vpnd.DaemonState {
	t.Helper()
	raw := e.compose(t, "exec", "-T", "member", "cat", path)
	var st vpnd.DaemonState
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &st); err != nil {
		t.Fatalf("state %s: %v\n%s", path, err, raw)
	}
	return st
}

func (e emb) serveEnroll(t *testing.T, userID, token, role string, mints *countingMinter) string {
	t.Helper()
	srv, err := enroll.NewServer(enroll.Config{
		ControlURL: "https://headscale",
		Tenants: []enroll.Tenant{{
			Name: "acme", HeadscaleUserID: userID, Role: role,
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
	return fmt.Sprintf("http://host.docker.internal:%d", ln.Addr().(*net.TCPAddr).Port)
}
