package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
)

// TestR4WPageOnboardsMemberAndAdmin posts a plan for a member code and an
// admin code through the real HTTP server. Neither call detects the LAN.
func TestR4WPageOnboardsMemberAndAdmin(t *testing.T) {
	var detects atomic.Int32
	srv, client, got := testServer(t, time.Minute)
	srv.svc.Detect = func() (netdetect.Report, error) {
		detects.Add(1)
		return office(), nil
	}
	srv.svc.Discover = func(context.Context, string, string, bool) (*enroll.Discovery, error) {
		return &enroll.Discovery{ControlURL: "https://vpn.example", Tenant: "acme"}, nil
	}
	srv.svc.Apply = func(plan gateway.Plan, opt gateway.ApplyOptions) (gateway.ApplyResult, error) {
		got.plan = plan
		got.opt = opt
		return gateway.ApplyResult{
			ConfigPath: plan.ConfigPath, Role: plan.Role, Hostname: plan.Hostname, EnrollURL: plan.EnrollURL,
		}, nil
	}
	cap, csrf := r3w1Bootstrap(t, srv, client)
	for _, role := range []string{join.RoleMember, join.RoleAdmin} {
		code := r3w1CodeRole(t, role, "https://enroll.example", "token-"+role+"-aaaaaaaaaaaaaaaa", role+"-host")
		raw := mustJoin(t, client, srv, cap, csrf, code)
		joined := r3w1ReadJoin(t, raw)
		var view struct {
			Role string `json:"role"`
		}
		if err := json.Unmarshal(raw, &view); err != nil || view.Role != role {
			t.Fatalf("join view %s", raw)
		}
		body := joined.body(map[string]any{
			"this_machine_is_local_ai": true,
			"whole_subnet":             true,
			"device_ips":               []string{"10.251.73.10"},
		})
		status, planBody := r3w1Post(t, client, srv, cap, csrf, "/api/plan", body)
		var plan struct {
			Role         string   `json:"role"`
			Mode         string   `json:"mode"`
			AcceptRoutes bool     `json:"accept_routes"`
			Routes       []string `json:"routes"`
			Hostname     string   `json:"hostname"`
		}
		if status != http.StatusOK || json.Unmarshal(planBody, &plan) != nil ||
			plan.Role != role || plan.Mode != "auto" || !plan.AcceptRoutes || len(plan.Routes) != 0 ||
			plan.Hostname != role+"-host" {
			t.Fatalf("%s plan %d %s", role, status, planBody)
		}
		status, applyBody := r3w1Post(t, client, srv, cap, csrf, "/api/apply", body)
		var applied struct {
			Role string `json:"role"`
		}
		if status != http.StatusOK || json.Unmarshal(applyBody, &applied) != nil || applied.Role != role || got.plan.Role != role || len(got.plan.Routes) != 0 {
			t.Fatalf("%s apply %d plan=%+v %s", role, status, got.plan, applyBody)
		}
	}
	if detects.Load() != 0 {
		t.Fatalf("member and admin onboarding detected the LAN %d times", detects.Load())
	}
}
