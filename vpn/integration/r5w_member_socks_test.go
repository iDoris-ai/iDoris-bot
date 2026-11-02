//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

// r5wMemberStateDir is seeded into the config before Apply so AccessInfo names
// a path that exists inside the member container. Without it, Apply would name
// the host home directory.
const r5wMemberStateDir = "/var/lib/idoris/vpn-state"

// r5wDiskHost is the real filesystem Apply uses. The integration package cannot
// see the gateway package's test host, and the command package is main.
type r5wDiskHost struct{}

func (r5wDiskHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	return fsutil.WriteFileAtomic(path, data, mode)
}
func (r5wDiskHost) MkdirAll(path string, mode os.FileMode) error {
	if mode.Perm()&0o077 == 0 {
		return fsutil.EnsurePrivateDir(path)
	}
	return os.MkdirAll(path, mode)
}
func (r5wDiskHost) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }
func (r5wDiskHost) Chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}
func (r5wDiskHost) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (r5wDiskHost) IsRoot() bool                         { return false }
func (r5wDiskHost) GOOS() string                         { return runtime.GOOS }
func (r5wDiskHost) EnableIPForward(string, string) error { return nil }
func (r5wDiskHost) InstallService(string) error          { return nil }

// TestR5WWizardMemberSOCKS applies a member plan the way the wizard does, with
// a token minted by the real idoris-vpn-enroll binary, then starts idoris-vpnd
// from that config inside the embedded fixture. The authenticated SOCKS5
// listener must reach the Local AI echo using the credential file named in
// AccessInfo.
//
// SimplePlan writes mode auto. This container's userspace tailscaled is up and
// logged out, and auto would then select system mode ("not logged in") and
// drive that daemon. A desktop with no running tailscaled selects embedded.
// The plan is pinned to embedded so this fixture does not change the choice.
// Listen is pinned to the harness status port; an empty listen becomes a unix
// socket when HOME is set, which the status probe cannot read.
func TestR5WWizardMemberSOCKS(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	buildLinuxBin(t, "../cmd/idoris-vpnd", filepath.Join("..", "bin", "idoris-vpnd-linux"))
	buildLinuxBin(t, "./echosrv", filepath.Join("..", "bin", "echosrv-linux"))
	buildLinuxBin(t, "./wireclient", filepath.Join("..", "bin", "wireclient-linux"))
	enrollBin := filepath.Join("..", "bin", "idoris-vpn-enroll")
	buildHostBin(t, "../cmd/idoris-vpn-enroll", enrollBin)

	roots := writeTestPKI(t, embeddedPKIDir,
		[]string{"headscale", "headscale-foreign"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatal(err)
	}
	e := emb{project: fmt.Sprintf("idoris-vpn-r5w-%x", rnd)}
	t.Logf("project %s", e.project)

	var secrets []string
	credPath := ""
	_, _ = e.composeOK("down", "-v", "--remove-orphans")
	e.compose(t, "up", "-d", "--wait", "--wait-timeout", "180")
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := e.composeOK("logs", "--no-color", "--tail=80")
			vpnd, _ := e.composeOK("exec", "-T", "member", "cat", "/tmp/vpnd.log")
			pass := ""
			if credPath != "" {
				pass = r5wSockPass(e, credPath)
			}
			t.Logf("compose logs:\n%s", r5wRedact(logs, append(secrets, pass)))
			t.Logf("vpnd log:\n%s", r5wRedact(vpnd, append(secrets, pass)))
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
	secrets = append(secrets, aiKey.Key)
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

	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	enrollPort := ln.Addr().(*net.TCPAddr).Port
	enrollURL := fmt.Sprintf("http://host.docker.internal:%d", enrollPort)
	localEnroll := fmt.Sprintf("http://127.0.0.1:%d", enrollPort)

	seed, err := enroll.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "enroll.json")
	rawCfg, err := json.MarshalIndent(enroll.Config{
		ControlURL: "https://headscale",
		Tenants: []enroll.Tenant{{
			Name:            "acme",
			HeadscaleUserID: acme.ID,
			TokenHashes:     []string{enroll.HashToken(seed)},
			Role:            join.RoleMember,
			PreAuthTTL:      enroll.Duration(10 * time.Minute),
		}},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, append(rawCfg, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	code, payload := r5wInvite(t, enrollBin, cfgPath, "r5w-member", enrollURL)
	secrets = append(secrets, code, payload.Token, seed)
	if payload.Role != join.RoleMember || payload.Tenant != "acme" || payload.HostnameHint != "r5w-member" || payload.Token == "" {
		t.Fatalf("invite role %s tenant %s hint %s token empty=%v", payload.Role, payload.Tenant, payload.HostnameHint, payload.Token == "")
	}

	loaded, err := enroll.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var enrollLog strings.Builder
	srv, err := enroll.NewServer(*loaded, our, slog.New(slog.NewTextHandler(&enrollLog, nil)))
	if err != nil {
		t.Fatal(err)
	}
	hsrv := &http.Server{Handler: srv.Handler()}
	go func() { _ = hsrv.Serve(ln) }()
	t.Cleanup(func() {
		_ = hsrv.Close()
		if t.Failed() {
			t.Logf("enroll log:\n%s", r5wRedact(enrollLog.String(), secrets))
		}
	})

	discCtx, discCancel := context.WithTimeout(ctx, 20*time.Second)
	disc, err := (&enroll.Client{URL: localEnroll, Token: payload.Token, AllowInsecure: true}).Discover(discCtx)
	discCancel()
	if err != nil {
		t.Fatal(err)
	}
	if disc.ControlURL != "https://headscale" || disc.Tenant != "acme" || disc.Role != join.RoleMember {
		t.Fatalf("discover control %s tenant %s role %s", disc.ControlURL, disc.Tenant, disc.Role)
	}

	plan, err := gateway.SimplePlan(payload.Role, payload.Tenant, payload.HostnameHint)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(home, ".idoris")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	memberCfg := filepath.Join(configDir, gateway.DefaultConfigName)
	if err := os.WriteFile(memberCfg, []byte("{\n  \"state_dir\": \"/var/lib/idoris/vpn-state\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := gateway.PathsFor("", memberCfg)
	plan.Mode = "embedded"
	plan.Listen = "tcp:127.0.0.1:7845"
	plan.EnrollURL = payload.EnrollURL
	plan.AllowInsecure = true
	plan.ConfigPath = paths.Config
	plan.TokenFile = paths.Token
	plan.DiscoveryControlURL = disc.ControlURL
	res, err := gateway.Apply(plan, r5wDiskHost{}, gateway.ApplyOptions{
		Token: payload.Token, NoService: true, PlanPath: paths.Plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.TokenFile != paths.Token || res.DiscoveryControlURL != "https://headscale" || res.Tenant != "acme" {
		t.Fatalf("apply token file %s discovery %s tenant %s", res.TokenFile, res.DiscoveryControlURL, res.Tenant)
	}
	cfgBody, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfgBody), payload.Token) || !strings.Contains(string(cfgBody), `"mode": "embedded"`) || !strings.Contains(string(cfgBody), r5wMemberStateDir) {
		t.Fatal("generated config is missing embedded mode or state_dir, or it contains the token")
	}
	socksAddr := r5wAccessLine(res.AccessInfo, "SOCKS5 ")
	credPath = r5wAccessLine(res.AccessInfo, "SOCKS5 credential file ")
	if socksAddr == "" || credPath != r5wMemberStateDir+"/socks5.auth" {
		t.Fatalf("access info socks %q credential %q", socksAddr, credPath)
	}

	e.compose(t, "exec", "-T", "member", "mkdir", "-p", configDir)
	e.compose(t, "exec", "-T", "member", "chmod", "0700", configDir)
	e.compose(t, "cp", res.ConfigPath, "member:"+res.ConfigPath)
	e.compose(t, "cp", res.TokenFile, "member:"+res.TokenFile)
	e.compose(t, "cp", filepath.Join("..", "bin", "wireclient-linux"), "member:/opt/wireclient")
	// docker cp keeps the host uid. The daemon runs as root and rejects a
	// secret it does not own.
	e.compose(t, "exec", "-T", "member", "chown", "0:0", res.ConfigPath, res.TokenFile)
	e.compose(t, "exec", "-T", "member", "chmod", "0600", res.ConfigPath, res.TokenFile)
	e.compose(t, "exec", "-T", "member", "chmod", "0755", "/opt/wireclient")
	script := "/opt/idoris-vpnd run --config " + r5wShellQuote(res.ConfigPath) + " > /tmp/vpnd.log 2>&1"
	e.compose(t, "exec", "-d", "member", "sh", "-c", script)

	waitFor(t, "wizard member connected", 120*time.Second, func() (bool, string) {
		m, err := e.daemonStatus()
		if err != nil {
			return false, r5wRedact(err.Error(), secrets)
		}
		s5, _ := m["socks5"].(map[string]any)
		ok := m["phase"] == "connected" && m["mode"] == "embedded" && s5["state"] == "listening"
		note := fmt.Sprintf("phase=%v mode=%v socks=%v err=%v control=%v", m["phase"], m["mode"], s5["state"], m["last_error"], m["control_url"])
		return ok, r5wRedact(note, secrets)
	})
	st, err := e.daemonStatus()
	if err != nil {
		t.Fatal(err)
	}
	s5, _ := st["socks5"].(map[string]any)
	if s5["auth_file"] != credPath {
		t.Fatalf("socks5 auth file %v, access info says %s", s5["auth_file"], credPath)
	}

	none := e.compose(t, "exec", "-T", "member", "/opt/wireclient", "none", socksAddr, wireEchoTarget)
	if !strings.Contains(none, "rejected") {
		t.Fatalf("anonymous SOCKS5 was not rejected:\n%s", r5wRedact(none, secrets))
	}
	waitFor(t, "authenticated SOCKS5 echo", 90*time.Second, func() (bool, string) {
		out, err := e.composeOK("exec", "-T", "member", "/opt/wireclient", "auth", socksAddr, wireEchoTarget, credPath, strconv.Itoa(wireEchoBytes))
		note := r5wRedact(strings.TrimSpace(out), append(secrets, r5wSockPass(e, credPath)))
		if err != nil {
			return false, note
		}
		return strings.Contains(out, "echoed"), note
	})
	t.Logf("wizard member SOCKS5 ok via %s credential %s", socksAddr, credPath)
}

func r5wInvite(t *testing.T, bin, cfgPath, hint, enrollURL string) (string, join.Payload) {
	t.Helper()
	cmd := exec.Command(bin, "invite",
		"--config", cfgPath,
		"--entry", "acme",
		"--hostname-hint", hint,
		"--enroll-url", enrollURL,
		"--allow-insecure")
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("invite: %v\n%s", err, wizSecretRE.ReplaceAllString(stderr.String(), "[redacted]"))
	}
	code := strings.TrimSpace(stdout.String())
	if code == "" || strings.Contains(code, "\n") {
		t.Fatal("invite stdout must be exactly one join code line")
	}
	payload, err := join.Decode(code, join.Options{AllowInsecure: true})
	if err != nil {
		t.Fatalf("invite decode: %v", err)
	}
	return code, payload
}

func r5wAccessLine(lines []string, prefix string) string {
	for _, line := range lines {
		if strings.HasPrefix(line, "SOCKS5 credential file ") && prefix == "SOCKS5 " {
			continue
		}
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func r5wShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func r5wSockPass(e emb, path string) string {
	out, err := e.composeOK("exec", "-T", "member", "cat", path)
	if err != nil {
		return ""
	}
	_, pass, ok := strings.Cut(strings.TrimSpace(out), ":")
	if !ok {
		return ""
	}
	return pass
}

func r5wRedact(text string, secrets []string) string {
	text = wizSecretRE.ReplaceAllString(text, "[redacted]")
	for _, secret := range secrets {
		if secret == "" || len(secret) < 8 {
			continue
		}
		text = strings.ReplaceAll(text, secret, "[redacted]")
	}
	return text
}
