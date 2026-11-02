package ui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

// TestR5WSameRoleReplacementDoesNotReportTheOldDaemon applies a member join
// over a config that still pins the previous control server. The written pin
// is dropped. The daemon status stays on that previous server, same role,
// already connected. Completion is the discovery URL from the apply result,
// so that status is not done.
func TestR5WSameRoleReplacementDoesNotReportTheOldDaemon(t *testing.T) {
	const (
		oldControl = "https://hs-a.example"
		newControl = "https://hs-b.example"
		oldEnroll  = "https://enroll-a.example"
		newEnroll  = "https://enroll-b.example"
		tenant     = "beta"
		token      = "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := gateway.PathsFor(home, "")
	if err := os.MkdirAll(filepath.Dir(paths.Config), 0o700); err != nil {
		t.Fatal(err)
	}
	oldRaw, err := json.Marshal(map[string]string{
		"enroll_url":        oldEnroll,
		"control_url":       oldControl,
		"role":              join.RoleMember,
		"hostname":          "laptop",
		"enroll_token_file": paths.Token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Config, append(oldRaw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	srv, client, _ := testServer(t, time.Minute)
	srv.svc.Home = func() (string, error) { return home, nil }
	srv.svc.Discover = func(context.Context, string, string, bool) (*enroll.Discovery, error) {
		return &enroll.Discovery{ControlURL: newControl, Tenant: tenant, Role: join.RoleMember}, nil
	}
	srv.svc.Status = func(context.Context) (map[string]any, error) {
		return map[string]any{
			"phase": "connected", "role": join.RoleMember, "control_url": oldControl,
		}, nil
	}
	srv.svc.Apply = func(plan gateway.Plan, opt gateway.ApplyOptions) (gateway.ApplyResult, error) {
		return gateway.Apply(plan, r5wDiskHost{}, opt)
	}

	cap, csrf := r3w1Bootstrap(t, srv, client)
	code, err := join.Encode(join.Payload{
		V: 1, EnrollURL: newEnroll, Token: token, Role: join.RoleMember, Tenant: tenant, HostnameHint: "laptop",
	}, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw := mustJoin(t, client, srv, cap, csrf, code)
	joined := r3w1ReadJoin(t, raw)
	// /api/plan rejects unknown fields. replace_existing belongs on apply.
	planReq := joined.body(nil)
	status, planBody := r3w1Post(t, client, srv, cap, csrf, "/api/plan", planReq)
	if status != http.StatusOK {
		t.Fatalf("plan %d %s", status, planBody)
	}
	status, applyBody := r3w1Post(t, client, srv, cap, csrf, "/api/apply", joined.body(map[string]any{"replace_existing": true}))
	if status != http.StatusOK {
		t.Fatalf("apply %d %s", status, applyBody)
	}
	var applied gateway.ApplyResult
	if err := json.Unmarshal(applyBody, &applied); err != nil {
		t.Fatal(err)
	}
	if applied.ControlURL != "" || !applied.ControlPinDropped {
		t.Fatalf("pin was kept: %+v", applied)
	}
	if applied.DiscoveryControlURL != newControl || applied.Tenant != tenant || applied.TokenFingerprint == "" || strings.Contains(applied.TokenFingerprint, token) {
		t.Fatalf("apply did not name the new identity: %+v", applied)
	}

	req, err := http.NewRequest(http.MethodGet, srv.url()+"/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(SessionHeader, cap)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	statusBody, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", res.StatusCode, statusBody)
	}
	var st map[string]any
	if err := json.Unmarshal(statusBody, &st); err != nil {
		t.Fatal(err)
	}
	if st["phase"] != "connected" || st["role"] != join.RoleMember || st["control_url"] != oldControl {
		t.Fatalf("status is not the old daemon: %s", statusBody)
	}
	if r5wIdentityDone(applied, st) {
		t.Fatal("old same-role daemon was treated as the applied identity")
	}
}

// r5wIdentityDone is the raw string check used by the HTTP test above.
// The page itself canonicalises control URLs and treats
// identity_unconfirmed as not done; TestR6WAppJSCanonicalControlURL and
// TestR6WAppJSUnconfirmedIdentityIsNotDone drive app.js for that.
func r5wIdentityDone(res gateway.ApplyResult, st map[string]any) bool {
	if res.Role != "" {
		role, _ := st["role"].(string)
		if role != res.Role {
			return false
		}
	}
	want := strings.TrimSpace(res.DiscoveryControlURL)
	if want == "" {
		want = strings.TrimSpace(res.ControlURL)
	}
	if want != "" {
		got, _ := st["control_url"].(string)
		if got != want {
			return false
		}
	}
	if res.Tenant != "" {
		if v, ok := st["tenant"].(string); ok && v != "" && v != res.Tenant {
			return false
		}
	}
	if res.TokenFingerprint != "" {
		if v, ok := st["token_fingerprint"].(string); ok && v != "" && v != res.TokenFingerprint {
			return false
		}
	}
	return true
}

// r5wDiskHost is the real filesystem, matching the host Apply uses.
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
func (r5wDiskHost) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) } //nolint:gosec // test path
func (r5wDiskHost) IsRoot() bool                         { return false }
func (r5wDiskHost) GOOS() string                         { return "darwin" }
func (r5wDiskHost) EnableIPForward(string, string) error { return nil }
func (r5wDiskHost) InstallService(string) error          { return nil }
