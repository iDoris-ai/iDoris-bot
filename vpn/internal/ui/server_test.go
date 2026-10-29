package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
)

const uiToken = "idv1_secretsecretsecretsecretsecretse"

func office() netdetect.Report {
	rec := netdetect.Candidate{Name: "eth0", Addr: "10.251.73.4", Bits: 24, Network: "10.251.73.0/24", Gateway: "10.251.73.1", Default: true}
	return netdetect.Report{Platform: "linux", GatewaySupported: true, Candidates: []netdetect.Candidate{rec}, Recommended: &rec,
		Checks: []netdetect.Check{{ID: "tun", OK: true, Detail: "present"}, {ID: "root", OK: false, Detail: "not root", Fix: "re-run the printed sudo command"}}}
}

type applied struct {
	plan gateway.Plan
	opt  gateway.ApplyOptions
}

func testServer(t *testing.T, idle time.Duration) (*Server, *http.Client, *applied) {
	t.Helper()
	got := &applied{}
	srv, err := New(Options{
		EUID: 1, LoginUID: 1, Secret: "secretsecretsecretsecretsecretse", CSRF: "csrfcsrfcsrfcsrfcsrfcsrfcsrfcsrf",
		Idle: idle,
		Services: Services{
			Detect: func() (netdetect.Report, error) { return office(), nil },
			Probe: func(context.Context, string) (netdetect.ProbeResult, error) {
				return netdetect.ProbeResult{IP: "10.251.73.10", Reachable: true, Port: 8740}, nil
			},
			Discover: func(context.Context, string, string, bool) (*enroll.Discovery, error) {
				return &enroll.Discovery{ControlURL: "https://vpn.example", Tenant: "acme", LANCIDRs: []string{"10.251.73.10/32"}}, nil
			},
			Apply: func(plan gateway.Plan, opt gateway.ApplyOptions) (gateway.ApplyResult, error) {
				got.plan = plan
				got.opt = opt
				return gateway.ApplyResult{ConfigPath: plan.ConfigPath, SudoCommand: "sudo idoris-vpnd gateway apply --plan " + plan.ConfigPath}, nil
			},
			Status: func(context.Context) (map[string]any, error) {
				return map[string]any{"phase": "routes-pending-approval", "admin_hint": "headscale nodes approve-routes --identifier office-gw --routes 10.251.73.10/32"}, nil
			},
			Home:     func() (string, error) { return "/home/acme", nil },
			Hostname: func() (string, error) { return "office-gw", nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return srv, &http.Client{Jar: jar, Timeout: 2 * time.Second}, got
}

func (s *Server) url() string { return "http://" + s.bound }

func TestPageRequiresHostSecretAndCSRF(t *testing.T) {
	srv, client, _ := testServer(t, time.Minute)
	base := srv.url()

	res, err := client.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no secret: %d %s", res.StatusCode, body)
	}

	req, _ := http.NewRequest(http.MethodGet, base+"/?k="+srv.secret, nil)
	req.Host = "evil.example"
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("bad host: %d", res.StatusCode)
	}

	res, err = client.Get(base + "/?k=" + srv.secret)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("page %d", res.StatusCode)
	}
	if res.Header.Get("Cache-Control") != "no-store" || !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("headers %#v", res.Header)
	}
	if res.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal(res.Header.Get("Referrer-Policy"))
	}
	html := string(page)
	for _, want := range []string{"这台机器就是 Local AI 吗？", "识别网络", "使用建议", "启用", "csrf-token", srv.csrf} {
		if !strings.Contains(html, want) {
			t.Fatalf("page missing %q", want)
		}
	}
	if strings.Contains(html, "http://") || strings.Contains(html, "https://") || strings.Contains(html, srv.secret) {
		t.Fatal("page has an external URL or the secret")
	}
	cookie := res.Header.Get("Set-Cookie")
	if !strings.Contains(cookie, "idoris_ui=") || !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Strict") {
		t.Fatalf("cookie %q", cookie)
	}

	res, err = client.Get(base + "/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || strings.Contains(string(js), "http://") || strings.Contains(string(js), "https://") {
		t.Fatalf("js %d external?", res.StatusCode)
	}
	res, err = client.Get(base + "/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || strings.Contains(string(css), "http://") || strings.Contains(string(css), "https://") {
		t.Fatal("css")
	}

	post := func(origin, site, csrf string, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, base+"/api/detect", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	res = post("", "", srv.csrf, "{}")
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("missing origin: %d", res.StatusCode)
	}
	res = post("http://evil.example", "", srv.csrf, "{}")
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("evil origin: %d", res.StatusCode)
	}
	res = post("", "cross-site", srv.csrf, "{}")
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site: %d", res.StatusCode)
	}
	res = post("http://"+srv.bound, "same-origin", "", "{}")
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("missing csrf: %d", res.StatusCode)
	}
	res = post("http://"+srv.bound, "same-origin", srv.csrf, "{}")
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte("10.251.73.0/24")) {
		t.Fatalf("detect %d %s", res.StatusCode, raw)
	}

	big := `{"code":"` + strings.Repeat("a", maxBody) + `"}`
	res = post("http://"+srv.bound, "same-origin", srv.csrf, big)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("body limit %d", res.StatusCode)
	}
}

func TestJoinPlanAndApplyHideTheToken(t *testing.T) {
	srv, client, got := testServer(t, time.Minute)
	base := srv.url()
	res, err := client.Get(base + "/?k=" + srv.secret)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()

	code, err := join.Encode(join.Payload{
		V: 1, EnrollURL: "https://enroll.example.org", Token: uiToken, Role: join.RoleGateway, Tenant: "acme", HostnameHint: "office-gw",
	}, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	call := func(path string, body any) (int, []byte) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://"+srv.bound)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("X-CSRF-Token", srv.csrf)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, b
	}
	status, body := call("/api/join", map[string]any{"code": code})
	if status != http.StatusOK || bytes.Contains(body, []byte(uiToken)) || bytes.Contains(body, []byte(code)) {
		t.Fatalf("join %d %s", status, body)
	}
	status, body = call("/api/detect", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("detect %d %s", status, body)
	}
	status, body = call("/api/plan", map[string]any{"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}})
	var plan gateway.Plan
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatalf("plan %d %s", status, body)
	}
	if status != http.StatusOK || bytes.Contains(body, []byte(uiToken)) || len(plan.Routes) != 1 || plan.Routes[0] != "10.251.73.10/32" || !plan.WillAutoApprove {
		t.Fatalf("plan %d %+v %s", status, plan.Routes, body)
	}
	status, body = call("/api/apply", map[string]any{})
	if status != http.StatusOK || bytes.Contains(body, []byte(uiToken)) || !bytes.Contains(body, []byte("sudo idoris-vpnd gateway apply")) {
		t.Fatalf("apply %d %s", status, body)
	}
	if got.opt.Token != uiToken || len(got.plan.Routes) != 1 {
		t.Fatalf("apply saw %+v routes %v", got.opt.Token == uiToken, got.plan.Routes)
	}
	req, _ := http.NewRequest(http.MethodGet, base+"/api/status", nil)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !bytes.Contains(b, []byte("routes-pending-approval")) {
		t.Fatalf("status %d %s", res.StatusCode, b)
	}

	// Header secret works without the cookie.
	bare := &http.Client{Timeout: 2 * time.Second}
	req, _ = http.NewRequest(http.MethodGet, base+"/app.js", nil)
	req.Header.Set(secretHeader, srv.secret)
	res, err = bare.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("header secret %d", res.StatusCode)
	}
}

func TestLocalAIPlanHasNoRoute(t *testing.T) {
	srv, client, _ := testServer(t, time.Minute)
	base := srv.url()
	res, err := client.Get(base + "/?k=" + srv.secret)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	code, err := join.Encode(join.Payload{
		V: 1, EnrollURL: "https://enroll.example.org", Token: uiToken, Role: join.RoleMember, Tenant: "acme",
	}, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"code": code})
	req, _ := http.NewRequest(http.MethodPost, base+"/api/join", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+srv.bound)
	req.Header.Set("X-CSRF-Token", srv.csrf)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	raw, _ = json.Marshal(map[string]any{"this_machine_is_local_ai": true})
	req, _ = http.NewRequest(http.MethodPost, base+"/api/plan", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+srv.bound)
	req.Header.Set("X-CSRF-Token", srv.csrf)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"role":"local-ai"`)) || bytes.Contains(body, []byte("advertise")) {
		t.Fatalf("plan %d %s", res.StatusCode, body)
	}
}

func TestSessionUserAndIdleShutdown(t *testing.T) {
	if err := CheckSessionUser(0, 1000); err == nil {
		t.Fatal("different session user was allowed")
	}
	if err := CheckSessionUser(1000, 1000); err != nil {
		t.Fatal(err)
	}
	if err := CheckSessionUser(0, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{EUID: 0, LoginUID: 1000}); err == nil {
		t.Fatal("New accepted a mismatched session")
	}

	srv, err := New(Options{EUID: 1, LoginUID: -1, Secret: "abcabcabcabcabcabcabcabcabcabcab", CSRF: "csrfcsrfcsrfcsrfcsrfcsrfcsrfcsrf", Idle: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle server did not shut down")
	}
}
