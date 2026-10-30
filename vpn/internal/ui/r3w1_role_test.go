package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

func r3w1Err(t *testing.T, body []byte) string {
	t.Helper()
	var got struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("error json %s", body)
	}
	return got.Error
}

func TestR3W1RoleChoiceRejected(t *testing.T) {
	var discover atomic.Int32
	var applyCalls atomic.Int32
	srv, client := r3w1PlanServer(t, func(plan gateway.Plan, _ gateway.ApplyOptions) (gateway.ApplyResult, error) {
		applyCalls.Add(1)
		return gateway.ApplyResult{ConfigPath: plan.ConfigPath}, nil
	})
	srv.svc.Discover = func(context.Context, string, string, bool) (*enroll.Discovery, error) {
		discover.Add(1)
		return &enroll.Discovery{LANCIDRs: []string{"10.251.73.10/32"}}, nil
	}
	cap, csrf := r3w1Bootstrap(t, srv, client)
	gatewayCode := r3w1Code(t, "https://enroll.example.org", "token-gw-aaaaaaaaaaaaaaaaaaaa", "office-a")
	r3w1ReadyPlan(t, client, srv, cap, csrf, gatewayCode)
	discovered := discover.Load()

	localAI := map[string]any{"this_machine_is_local_ai": true, "confirm_authority": true}
	status, body := r3w1Post(t, client, srv, cap, csrf, "/api/plan", localAI)
	want := `gateway: this join code is for a "gateway" machine, not a "local-ai" one: ask your administrator for a local-ai code`
	if status != http.StatusBadRequest || r3w1Err(t, body) != want || discover.Load() != discovered {
		t.Fatalf("gateway code as local AI %d discover %d->%d %s", status, discovered, discover.Load(), body)
	}
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/apply", map[string]any{
		"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}, "confirm_authority": true,
	})
	if status == http.StatusOK || applyCalls.Load() != 0 {
		t.Fatalf("stale plan remained applicable %d calls %d %s", status, applyCalls.Load(), body)
	}

	localCode := r3w1CodeRole(t, join.RoleLocalAI, "https://enroll.example.org", "token-ai-aaaaaaaaaaaaaaaaaaaa", "office-ai")
	if status, body = r3w1Post(t, client, srv, cap, csrf, "/api/join", map[string]any{"code": localCode}); status != http.StatusOK {
		t.Fatalf("join local-ai %d %s", status, body)
	}
	if status, body = r3w1Post(t, client, srv, cap, csrf, "/api/detect", map[string]any{}); status != http.StatusOK {
		t.Fatalf("detect %d %s", status, body)
	}
	before := discover.Load()
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/plan", map[string]any{
		"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}, "confirm_authority": true,
	})
	want = `gateway: this join code is for a "local-ai" machine, not a "gateway" one: ask your administrator for a gateway code`
	if status != http.StatusBadRequest || r3w1Err(t, body) != want || discover.Load() != before || applyCalls.Load() != 0 {
		t.Fatalf("local-ai code as gateway %d discover %d->%d %s", status, before, discover.Load(), body)
	}
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/plan", localAI)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"role":"local-ai"`)) || bytes.Contains(body, []byte("advertise")) {
		t.Fatalf("matching local-ai plan %d %s", status, body)
	}
}

func r3w1CodeRole(t *testing.T, role, enrollURL, token, host string) string {
	t.Helper()
	code, err := join.Encode(join.Payload{
		V: 1, EnrollURL: enrollURL, Token: token, Role: role, Tenant: "acme", HostnameHint: host,
	}, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return code
}
