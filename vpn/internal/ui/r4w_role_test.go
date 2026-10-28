package ui

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

func TestR4WPageRejectsDiscoveredRoleDisagreement(t *testing.T) {
	var discovered []string
	srv, client, _ := testServer(t, time.Minute)
	srv.svc.Discover = func(_ context.Context, enrollURL, token string, _ bool) (*enroll.Discovery, error) {
		discovered = append(discovered, enrollURL+" "+token)
		return &enroll.Discovery{ControlURL: "https://vpn.example", Tenant: "acme", Role: join.RoleLocalAI, LANCIDRs: []string{"10.251.73.10/32"}}, nil
	}
	cap, csrf := r3w1Bootstrap(t, srv, client)
	code := r3w1Code(t, "https://enroll.example", "token-gw", "office-gw")
	body := mustJoin(t, client, srv, cap, csrf, code)
	joined := r3w1ReadJoin(t, body)
	if status, detectBody := r3w1Post(t, client, srv, cap, csrf, "/api/detect", map[string]any{}); status != http.StatusOK {
		t.Fatalf("detect %d %s", status, detectBody)
	}
	status, planBody := r3w1Post(t, client, srv, cap, csrf, "/api/plan", joined.body(map[string]any{
		"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"},
	}))
	if status != http.StatusBadRequest || !strings.Contains(string(planBody), join.RoleLocalAI) || !strings.Contains(string(planBody), join.RoleGateway) {
		t.Fatalf("plan %d %s", status, planBody)
	}
	if len(discovered) != 1 {
		t.Fatalf("discover calls %v", discovered)
	}
	// A second plan still refuses and does not build a gateway plan.
	status, planBody = r3w1Post(t, client, srv, cap, csrf, "/api/plan", joined.body(map[string]any{
		"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"},
	}))
	if status != http.StatusBadRequest {
		t.Fatalf("second plan %d %s", status, planBody)
	}
}

func TestR4WReconcileRoleAgrees(t *testing.T) {
	srv, client, _ := testServer(t, time.Minute)
	srv.svc.Discover = func(context.Context, string, string, bool) (*enroll.Discovery, error) {
		return &enroll.Discovery{ControlURL: "https://vpn.example", Tenant: "acme", Role: join.RoleGateway, LANCIDRs: []string{"10.251.73.10/32"}}, nil
	}
	cap, csrf := r3w1Bootstrap(t, srv, client)
	joined := r3w1ReadyPlan(t, client, srv, cap, csrf, r3w1Code(t, "https://enroll.example", "token-gw", "office-gw"))
	if joined.Authority == "" {
		t.Fatal("missing authority")
	}
	role, err := gateway.ReconcileRole(join.RoleGateway, "", "")
	if err != nil || role != join.RoleGateway {
		t.Fatalf("empty discovery %q %v", role, err)
	}
}
