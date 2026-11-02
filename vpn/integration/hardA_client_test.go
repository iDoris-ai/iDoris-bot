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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
)

const hardAPKIDir = ".pki-hardA"

// hardA runs docker compose against integration/hardA/compose.yaml.
// The project name is unique per process so it does not collide with the
// other agents' compose projects.
type hardA struct{ project string }

func (h hardA) compose(t *testing.T, args ...string) string {
	t.Helper()
	out, err := h.composeOK(args...)
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", hardARedact(strings.Join(args, " ")), err, hardARedact(out))
	}
	return out
}

func (h hardA) composeOK(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"compose", "-p", h.project, "-f", "hardA/compose.yaml"}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (h hardA) headscaleClient(t *testing.T, roots *x509.CertPool, service string) *headscale.Client {
	t.Helper()
	apiKey := strings.TrimSpace(h.compose(t, "exec", "-T", service, "headscale", "apikeys", "create", "--expiration", "1h"))
	hostPort := strings.TrimSpace(h.compose(t, "port", service, "443"))
	return &headscale.Client{
		BaseURL: "https://" + hostPort,
		APIKey:  apiKey,
		HTTP: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		},
	}
}

func (h hardA) waitSock(t *testing.T, service string) {
	t.Helper()
	waitFor(t, service+" tailscaled socket", 60*time.Second, func() (bool, string) {
		out, err := h.composeOK("exec", "-T", service, "/usr/local/bin/tailscale", "--socket", tsSock, "status", "--json")
		if strings.Contains(out, "BackendState") {
			return true, ""
		}
		if err != nil {
			return false, strings.TrimSpace(out + " " + err.Error())
		}
		return false, strings.TrimSpace(out)
	})
}

func (h hardA) tailscale(t *testing.T, service string, args ...string) string {
	t.Helper()
	all := append([]string{"exec", "-T", service, "/usr/local/bin/tailscale", "--socket", tsSock}, args...)
	out, err := h.composeOK(all...)
	if err != nil {
		t.Fatalf("tailscale %s: %v\n%s", hardARedact(strings.Join(args, " ")), err, hardARedact(out))
	}
	return out
}

var hardASecret = regexp.MustCompile(`hskey-auth-[A-Za-z0-9_-]+|idv1_[0-9a-f]+`)

func hardARedact(s string) string {
	return hardASecret.ReplaceAllString(s, "REDACTED")
}

// hardAProfile is one row of `tailscale switch --list --json`.
type hardAProfile struct {
	ID       string `json:"id"`
	Tailnet  string `json:"tailnet"`
	Account  string `json:"account"`
	Selected bool   `json:"selected"`
}

func (h hardA) profilesOK(service string) ([]hardAProfile, error) {
	raw, err := h.composeOK("exec", "-T", service, "/usr/local/bin/tailscale", "--socket", tsSock, "switch", "--list", "--json")
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(hardARedact(raw)))
	}
	var list []hardAProfile
	if err := json.Unmarshal([]byte(hardAJSONArray(raw)), &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (h hardA) profiles(t *testing.T, service string) []hardAProfile {
	t.Helper()
	list, err := h.profilesOK(service)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func hardAJSONArray(s string) string {
	i := strings.IndexByte(s, '[')
	j := strings.LastIndexByte(s, ']')
	if i < 0 || j < i {
		return s
	}
	return s[i : j+1]
}

// controlURLsInState returns the distinct control URLs stored in tailscaled's
// state file. Values in that file are base64, so the URLs are decoded here
// and nothing else from the file is returned or logged.
func (h hardA) controlURLsInState(t *testing.T, service string) []string {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "tailscaled.state")
	if out, err := h.composeOK("cp", service+":/var/lib/tailscale/tailscaled.state", dest); err != nil {
		t.Fatalf("copy tailscaled state: %v\n%s", err, out)
	}
	b, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	blob := append([]byte(nil), b...)
	var cache map[string][]byte
	if err := json.Unmarshal(b, &cache); err == nil {
		for _, v := range cache {
			blob = append(blob, v...)
			blob = append(blob, '\n')
		}
	}
	seen := map[string]bool{}
	var urls []string
	for _, m := range hardAControlURL.FindAll(blob, -1) {
		u := string(m)
		if seen[u] {
			continue
		}
		seen[u] = true
		urls = append(urls, u)
	}
	return urls
}

var hardAControlURL = regexp.MustCompile(`https://headscale(?:-foreign)?`)

type hardAIdentity struct {
	BackendState string
	SelfID       string
	ControlURL   string
	Hostname     string
	RunSSH       bool
	Routes       []string
}

func (h hardA) identityOK(service string) (hardAIdentity, error) {
	raw, err := h.composeOK("exec", "-T", service, "/usr/local/bin/tailscale", "--socket", tsSock, "status", "--json")
	if err != nil && !strings.Contains(raw, "BackendState") {
		return hardAIdentity{}, fmt.Errorf("%w: %s", err, strings.TrimSpace(raw))
	}
	var st struct {
		BackendState string `json:"BackendState"`
		Self         *struct {
			ID       string `json:"ID"`
			HostName string `json:"HostName"`
		} `json:"Self"`
	}
	if err := json.Unmarshal([]byte(jsonObject(raw)), &st); err != nil {
		return hardAIdentity{}, err
	}
	prefsRaw, err := h.composeOK("exec", "-T", service, "/usr/local/bin/tailscale", "--socket", tsSock, "debug", "prefs")
	if err != nil {
		return hardAIdentity{}, fmt.Errorf("%w: %s", err, strings.TrimSpace(prefsRaw))
	}
	var prefs struct {
		ControlURL      string   `json:"ControlURL"`
		Hostname        string   `json:"Hostname"`
		RunSSH          bool     `json:"RunSSH"`
		AdvertiseRoutes []string `json:"AdvertiseRoutes"`
	}
	if err := json.Unmarshal([]byte(jsonObject(prefsRaw)), &prefs); err != nil {
		return hardAIdentity{}, err
	}
	id := hardAIdentity{
		BackendState: st.BackendState,
		ControlURL:   prefs.ControlURL,
		Hostname:     prefs.Hostname,
		RunSSH:       prefs.RunSSH,
		Routes:       append([]string(nil), prefs.AdvertiseRoutes...),
	}
	if st.Self != nil {
		id.SelfID = st.Self.ID
		if id.Hostname == "" {
			id.Hostname = st.Self.HostName
		}
	}
	return id, nil
}

func (h hardA) identity(t *testing.T, service string) hardAIdentity {
	t.Helper()
	id, err := h.identityOK(service)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (h hardA) status(t *testing.T, service, url string) (map[string]any, error) {
	t.Helper()
	out, err := h.composeOK("exec", "-T", service, "wget", "-qO-", url)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return nil, fmt.Errorf("%w: %s", err, out)
	}
	return m, nil
}

func (h hardA) startDaemon(t *testing.T, service, script, logPath string) {
	t.Helper()
	h.compose(t, "exec", "-d", service, "sh", "-c", script+" > "+logPath+" 2>&1")
}

func (h hardA) waitGone(t *testing.T, service string) {
	t.Helper()
	_, _ = h.composeOK("exec", "-T", service, "pkill", "idoris-vpnd")
	waitFor(t, service+" idoris-vpnd stopped", 20*time.Second, func() (bool, string) {
		out, err := h.composeOK("exec", "-T", service, "sh", "-c", "ps | grep idoris-vpnd | grep -v grep || true")
		if err != nil {
			return false, strings.TrimSpace(out + " " + err.Error())
		}
		return strings.TrimSpace(out) == "", strings.TrimSpace(out)
	})
}

func hardAWarningsHave(m map[string]any, sub string) bool {
	list, _ := m["warnings"].([]any)
	for _, item := range list {
		s, _ := item.(string)
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func hardAHasRoute(routes []string, want string) bool {
	for _, got := range routes {
		if got == want {
			return true
		}
	}
	return false
}

func hardASelected(list []hardAProfile) string {
	for _, p := range list {
		if p.Selected {
			return p.ID
		}
	}
	return ""
}

// TestHardAAwaitTailscaled is case (b): role local-ai with auto mode must not
// start an embedded node when the system tailscaled socket is missing.
func TestHardAAwaitTailscaled(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	buildLinuxBin(t, "../cmd/idoris-vpnd", filepath.Join("..", "bin", "idoris-vpnd-linux"))
	bin, err := filepath.Abs(filepath.Join("..", "bin", "idoris-vpnd-linux"))
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("idoris-vpn-harda-wait-%d", os.Getpid())
	rm := func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	}
	rm()
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "80", name).CombinedOutput()
			t.Logf("wait container logs:\n%s", out)
		}
		rm()
	})

	run := exec.Command("docker", "run", "-d", "--name", name,
		"-v", bin+":/opt/idoris-vpnd:ro",
		"--entrypoint", "/opt/idoris-vpnd",
		"tailscale/tailscale:v1.104.2",
		"run",
		"--role", "local-ai",
		"--mode", "auto",
		"--auth-key", "hardA-unused-key",
		"--control-url", "https://headscale.example",
		"--tailscale-socket", "/tmp/missing.sock",
		"--listen", "tcp:127.0.0.1:7845",
		"--state-dir", "/var/lib/idoris/hardA-embedded",
		"--state-file", "/var/lib/idoris/hardA-state.json",
		"--interval", "2s",
		"--log-level", "info",
	)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}

	var body map[string]any
	waitFor(t, "waiting-for-tailscaled", 45*time.Second, func() (bool, string) {
		out, err := exec.Command("docker", "exec", name, "wget", "-qO-", "http://127.0.0.1:7845/v1/status").CombinedOutput()
		if err != nil {
			return false, strings.TrimSpace(string(out) + " " + err.Error())
		}
		if err := json.Unmarshal(out, &body); err != nil {
			return false, err.Error()
		}
		return body["phase"] == "waiting-for-tailscaled" && body["role"] == "local-ai" && body["mode"] == "system",
			fmt.Sprintf("phase=%v role=%v mode=%v err=%v", body["phase"], body["role"], body["mode"], body["last_error"])
	})
	last, _ := body["last_error"].(string)
	if !strings.Contains(last, "official tailscaled") {
		t.Fatalf("last_error %q does not tell the operator to install tailscaled", last)
	}
	found, err := exec.Command("docker", "exec", name, "sh", "-c",
		`find /tmp /root /home /var/lib -name tailscaled.state -o -name registration-complete 2>/dev/null || true`).CombinedOutput()
	if err != nil {
		t.Fatalf("find embedded state: %v\n%s", err, found)
	}
	if strings.TrimSpace(string(found)) != "" {
		t.Fatalf("local-ai started an embedded node while tailscaled was down:\n%s", found)
	}
	t.Logf("local-ai waiting: phase=%v mode=%v role=%v err=%s", body["phase"], body["mode"], body["role"], last)
}

// TestHardAClientCore covers the docker cases that need a real Headscale:
//
//	(a) system mode, takeover off, foreign login active, saved iDoris profile
//	(c) re-enroll keeps unmanaged ssh and advertise-routes
//	(d) embedded restart while the enrollment service is stopped
func TestHardAClientCore(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	buildLinuxBin(t, "../cmd/idoris-vpnd", filepath.Join("..", "bin", "idoris-vpnd-linux"))
	roots := writeTestPKI(t, hardAPKIDir,
		[]string{"headscale", "headscale-foreign"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)
	h := hardA{project: fmt.Sprintf("idoris-vpn-harda-%d", os.Getpid())}
	_, _ = h.composeOK("down", "-v", "--remove-orphans")
	h.compose(t, "up", "-d", "--wait", "--wait-timeout", "180")
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := h.composeOK("logs", "--no-color", "--tail=80")
			t.Logf("compose logs:\n%s", logs)
			for _, spec := range []struct{ svc, path string }{
				{"member", "/tmp/vpnd-a.log"},
				{"node", "/tmp/vpnd-c.log"},
				{"node", "/tmp/vpnd-d.log"},
			} {
				out, _ := h.composeOK("exec", "-T", spec.svc, "cat", spec.path)
				if strings.TrimSpace(out) != "" {
					t.Logf("%s %s:\n%s", spec.svc, spec.path, out)
				}
			}
		}
		_, _ = h.composeOK("down", "-v", "--remove-orphans")
	})

	ctx := context.Background()
	our := h.headscaleClient(t, roots, "headscale")
	foreign := h.headscaleClient(t, roots, "headscale-foreign")
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

	h.waitSock(t, "member")
	h.waitSock(t, "node")

	t.Run("foreign-stays", func(t *testing.T) {
		hardAForeignStays(t, ctx, h, our, foreign, acme.ID, foreignUser.ID)
	})

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

	preserveOK := false
	t.Run("unmanaged-prefs", func(t *testing.T) {
		hardAUnmanagedPrefs(t, ctx, h, our, mints, enrollURL, token)
		preserveOK = !t.Failed()
	})
	t.Run("enroll-down", func(t *testing.T) {
		if !preserveOK {
			t.Skip("unmanaged-prefs did not finish")
		}
		hardAEnrollDown(t, h, mints, enrollURL, token, hsrv)
	})
}

func hardAForeignStays(t *testing.T, ctx context.Context, h hardA, our, foreign *headscale.Client, ourUser, foreignUser string) {
	t.Helper()
	// Foreign first. A client that has already used the iDoris DERP (region 999)
	// then logs into this placeholder map never reaches Running: magicsock
	// keeps asking for region 999, which the foreign map does not have.
	// `tailscale login` keeps the previous profile, so the iDoris login below
	// is the saved one. Switch back so the foreign login is active.
	frKey, err := foreign.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		UserID: foreignUser, Expiration: time.Now().Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.tailscale(t, "member", "up",
		"--login-server", "https://headscale-foreign", "--auth-key", frKey.Key,
		"--hostname", "harda-foreign", "--accept-dns=false", "--timeout", "90s")

	ourKey, err := our.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		UserID: ourUser, Expiration: time.Now().Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.tailscale(t, "member", "login",
		"--login-server", "https://headscale", "--auth-key", ourKey.Key,
		"--hostname", "harda-saved", "--accept-dns=false", "--timeout", "90s")

	profiles := h.profiles(t, "member")
	if len(profiles) < 2 {
		t.Fatalf("switch --list has %d profiles, want a saved iDoris profile and the active foreign one: %+v", len(profiles), profiles)
	}
	var foreignID string
	for _, p := range profiles {
		if !p.Selected {
			foreignID = p.ID
			break
		}
	}
	if foreignID == "" {
		t.Fatalf("no saved profile to switch back to: %+v", profiles)
	}
	// switch blocks until Running. After the iDoris session, magicsock still
	// wants DERP region 999, which this foreign map does not have, so the
	// CLI would wait forever. Start the switch, then restart tailscaled so
	// the saved foreign profile comes up in a fresh process.
	h.compose(t, "exec", "-d", "member", "/usr/local/bin/tailscale", "--socket", tsSock, "switch", foreignID)
	waitFor(t, "current profile is the foreign one", 20*time.Second, func() (bool, string) {
		list, err := h.profilesOK("member")
		if err != nil {
			return false, err.Error()
		}
		return hardASelected(list) == foreignID, fmt.Sprintf("%+v", list)
	})
	if id, err := h.identityOK("member"); err != nil || id.BackendState != "Running" || !strings.Contains(id.ControlURL, "headscale-foreign") {
		h.compose(t, "restart", "member")
		h.waitSock(t, "member")
	}
	waitFor(t, "foreign profile running again", 60*time.Second, func() (bool, string) {
		id, err := h.identityOK("member")
		if err != nil {
			return false, err.Error()
		}
		return id.BackendState == "Running" && strings.Contains(id.ControlURL, "headscale-foreign"),
			fmt.Sprintf("%+v", id)
	})
	profiles = h.profiles(t, "member")
	if hardASelected(profiles) != foreignID {
		t.Fatalf("switch did not return to %s: %+v", foreignID, profiles)
	}
	urls := h.controlURLsInState(t, "member")
	if !hardAURLSet(urls, "https://headscale") || !hardAURLSet(urls, "https://headscale-foreign") {
		t.Fatalf("state control URLs = %v, want both https://headscale and https://headscale-foreign", urls)
	}
	before := h.identity(t, "member")
	if before.BackendState != "Running" || before.SelfID == "" || !strings.Contains(before.ControlURL, "headscale-foreign") {
		t.Fatalf("foreign tailscale not ready: %+v", before)
	}
	selected := hardASelected(profiles)
	t.Logf("profiles=%d selected=%s foreign id=%s control=%s urls=%v", len(profiles), selected, before.SelfID, before.ControlURL, urls)

	const script = `/opt/idoris-vpnd run --mode system --control-url https://headscale --auth-key hardA-unused-key --listen tcp:127.0.0.1:7845 --state-file /var/lib/idoris/hardA-a-state.json --tailscale-socket /var/run/tailscale/tailscaled.sock --interval 2s --log-level info`
	h.startDaemon(t, "member", script, "/tmp/vpnd-a.log")

	var got map[string]any
	waitFor(t, "blocked-foreign-tailnet", 60*time.Second, func() (bool, string) {
		m, err := h.status(t, "member", "http://127.0.0.1:7845/v1/status")
		if err != nil {
			return false, err.Error()
		}
		got = m
		return m["phase"] == "blocked-foreign-tailnet" && m["login_attempts"] == float64(0),
			fmt.Sprintf("phase=%v attempts=%v err=%v", m["phase"], m["login_attempts"], m["last_error"])
	})
	after := h.identity(t, "member")
	afterProfiles := h.profiles(t, "member")
	if after.SelfID != before.SelfID || after.BackendState != "Running" || after.ControlURL != before.ControlURL || after.Hostname != before.Hostname {
		t.Fatalf("foreign login changed: before %+v after %+v", before, after)
	}
	if hardASelected(afterProfiles) != selected || len(afterProfiles) != len(profiles) {
		t.Fatalf("profiles changed: before %+v after %+v", profiles, afterProfiles)
	}
	t.Logf("foreign untouched: phase=%v attempts=%v self=%s control=%s", got["phase"], got["login_attempts"], after.SelfID, after.ControlURL)
}

func hardAURLSet(urls []string, want string) bool {
	for _, got := range urls {
		if got == want {
			return true
		}
	}
	return false
}

func hardAUnmanagedPrefs(t *testing.T, ctx context.Context, h hardA, our *headscale.Client, mints *countingMinter, enrollURL, token string) {
	t.Helper()
	script := fmt.Sprintf(
		`/opt/idoris-vpnd run --mode system --enroll-url %s --enroll-token %s --enroll-allow-insecure --control-url https://headscale --hostname hardA-sys --listen tcp:127.0.0.1:7846 --state-file /var/lib/idoris/hardA-sys-state.json --tailscale-socket /var/run/tailscale/tailscaled.sock --interval 2s --log-level info`,
		enrollURL, token,
	)
	h.startDaemon(t, "node", script, "/tmp/vpnd-c.log")

	waitFor(t, "system node connected", 120*time.Second, func() (bool, string) {
		m, err := h.status(t, "node", "http://127.0.0.1:7846/v1/status")
		if err != nil {
			return false, err.Error()
		}
		return m["phase"] == "connected" && m["mode"] == "system",
			fmt.Sprintf("phase=%v mode=%v attempts=%v err=%v", m["phase"], m["mode"], m["login_attempts"], m["last_error"])
	})
	var node headscale.Node
	waitFor(t, "hardA-sys online", 45*time.Second, func() (bool, string) {
		nodes, err := our.ListNodes(ctx, "acme")
		if err != nil {
			return false, err.Error()
		}
		for _, n := range nodes {
			if strings.EqualFold(n.GivenName, "hardA-sys") || strings.HasPrefix(strings.ToLower(n.Name), "harda-sys") {
				node = n
				if n.Online {
					return true, ""
				}
				return false, fmt.Sprintf("online=%v", n.Online)
			}
		}
		return false, fmt.Sprintf("%d nodes", len(nodes))
	})
	t.Logf("system node online: id=%s ips=%v keys=%d", node.ID, node.IPAddresses, mints.n.Load())

	h.tailscale(t, "node", "set", "--ssh=true")
	h.tailscale(t, "node", "set", "--advertise-routes=192.168.88.0/24")
	manual := h.identity(t, "node")
	if !manual.RunSSH || !hardAHasRoute(manual.Routes, "192.168.88.0/24") {
		t.Fatalf("manual prefs did not stick before expiry: ssh=%v routes=%v", manual.RunSSH, manual.Routes)
	}
	t.Logf("manual prefs: ssh=%v routes=%v", manual.RunSSH, manual.Routes)

	if err := our.ExpireNode(ctx, node.ID); err != nil {
		t.Fatal(err)
	}
	minted := mints.n.Load()
	waitFor(t, "re-enrolled after expiry", 120*time.Second, func() (bool, string) {
		m, err := h.status(t, "node", "http://127.0.0.1:7846/v1/status")
		if err != nil {
			return false, err.Error()
		}
		attempts, _ := m["login_attempts"].(float64)
		id := h.identity(t, "node")
		return m["phase"] == "connected" && attempts >= 2 && id.RunSSH && hardAHasRoute(id.Routes, "192.168.88.0/24"),
			fmt.Sprintf("phase=%v attempts=%v ssh=%v routes=%v err=%v", m["phase"], attempts, id.RunSSH, id.Routes, m["last_error"])
	})
	if got := mints.n.Load(); got != minted+1 {
		t.Fatalf("re-enroll minted %d keys, want 1 (before %d after %d)", got-minted, minted, got)
	}
	kept := h.identity(t, "node")
	t.Logf("prefs kept after re-enroll: ssh=%v routes=%v keys=%d", kept.RunSSH, kept.Routes, mints.n.Load())
}

func hardAEnrollDown(t *testing.T, h hardA, mints *countingMinter, enrollURL, token string, hsrv *http.Server) {
	t.Helper()
	h.waitGone(t, "node")
	script := fmt.Sprintf(
		`/opt/idoris-vpnd run --mode embedded --enroll-url %s --enroll-token %s --enroll-allow-insecure --control-url https://headscale --hostname hardA-emb --state-dir /var/lib/idoris/hardA-embedded --state-file /var/lib/idoris/hardA-state.json --listen tcp:127.0.0.1:7847 --interval 2s --log-level info`,
		enrollURL, token,
	)
	h.startDaemon(t, "node", script, "/tmp/vpnd-d.log")
	waitFor(t, "embedded connected", 120*time.Second, func() (bool, string) {
		m, err := h.status(t, "node", "http://127.0.0.1:7847/v1/status")
		if err != nil {
			return false, err.Error()
		}
		return m["phase"] == "connected" && m["mode"] == "embedded",
			fmt.Sprintf("phase=%v mode=%v attempts=%v err=%v", m["phase"], m["mode"], m["login_attempts"], m["last_error"])
	})
	minted := mints.n.Load()
	t.Logf("embedded connected before enroll stop: keys=%d", minted)

	if err := hsrv.Close(); err != nil {
		t.Fatal(err)
	}
	h.waitGone(t, "node")
	h.startDaemon(t, "node", script, "/tmp/vpnd-d.log")
	var got map[string]any
	waitFor(t, "embedded resumed with enroll down", 90*time.Second, func() (bool, string) {
		m, err := h.status(t, "node", "http://127.0.0.1:7847/v1/status")
		if err != nil {
			return false, err.Error()
		}
		got = m
		attempts, _ := m["login_attempts"].(float64)
		return m["phase"] == "connected" && m["mode"] == "embedded" && m["enroll_reachable"] == false && attempts == 0 &&
				hardAWarningsHave(m, "enrollment service is unreachable"),
			fmt.Sprintf("phase=%v mode=%v reachable=%v attempts=%v warnings=%v err=%v",
				m["phase"], m["mode"], m["enroll_reachable"], attempts, m["warnings"], m["last_error"])
	})
	if extra := mints.n.Load() - minted; extra != 0 {
		t.Fatalf("restart with enroll down minted %d keys", extra)
	}
	t.Logf("enroll down resume: phase=%v reachable=%v attempts=%v warnings=%v keys=%d",
		got["phase"], got["enroll_reachable"], got["login_attempts"], got["warnings"], mints.n.Load())
}
