package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

func TestR3W1StaleJoinIsNotApplied(t *testing.T) {
	var mu sync.Mutex
	var calls []applied
	srv, client := r3w1PlanServer(t, func(plan gateway.Plan, opt gateway.ApplyOptions) (gateway.ApplyResult, error) {
		mu.Lock()
		calls = append(calls, applied{plan: plan, opt: opt})
		mu.Unlock()
		return gateway.ApplyResult{ConfigPath: plan.ConfigPath}, nil
	})
	cap, csrf := r3w1Bootstrap(t, srv, client)
	codeA := r3w1Code(t, "https://a.example", "token-a-aaaaaaaaaaaaaaaaaaaa", "office-a")
	codeB := r3w1Code(t, "https://b.example", "token-b-bbbbbbbbbbbbbbbbbbbb", "office-b")

	if status, body := r3w1Post(t, client, srv, cap, csrf, "/api/join", map[string]any{"code": codeA}); status != http.StatusOK {
		t.Fatalf("join A %d %s", status, body)
	}
	if status, body := r3w1Post(t, client, srv, cap, csrf, "/api/detect", map[string]any{}); status != http.StatusOK {
		t.Fatalf("detect %d %s", status, body)
	}
	planBody := map[string]any{"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}, "confirm_authority": true}
	if status, body := r3w1Post(t, client, srv, cap, csrf, "/api/plan", planBody); status != http.StatusOK || !bytes.Contains(body, []byte("https://a.example")) {
		t.Fatalf("plan A %d %s", status, body)
	}
	if status, body := r3w1Post(t, client, srv, cap, csrf, "/api/join", map[string]any{"code": codeB}); status != http.StatusOK {
		t.Fatalf("join B %d %s", status, body)
	}
	status, body := r3w1Post(t, client, srv, cap, csrf, "/api/apply", planBody)
	mu.Lock()
	seen := append([]applied(nil), calls...)
	mu.Unlock()
	if status == http.StatusOK {
		for _, c := range seen {
			t.Fatalf("stale apply accepted: url %s token %s", c.plan.EnrollURL, c.opt.Token)
		}
		t.Fatalf("stale apply accepted with no recorded call: %s", body)
	}
	if status != http.StatusConflict || !bytes.Contains(body, []byte("the plan is stale")) {
		t.Fatalf("stale apply %d %s", status, body)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, c := range calls {
		if c.plan.EnrollURL == "https://a.example" && c.opt.Token == "token-b-bbbbbbbbbbbbbbbbbbbb" {
			t.Fatalf("mixed plan A URL with token B: %+v token %s", c.plan.EnrollURL, c.opt.Token)
		}
		t.Fatalf("apply ran for a stale plan: url %s token %s", c.plan.EnrollURL, c.opt.Token)
	}
}

func TestR3W1FailedReplanDropsTheOldPlan(t *testing.T) {
	var calls int
	srv, client := r3w1PlanServer(t, func(gateway.Plan, gateway.ApplyOptions) (gateway.ApplyResult, error) {
		calls++
		return gateway.ApplyResult{}, nil
	})
	cap, csrf := r3w1Bootstrap(t, srv, client)
	r3w1ReadyPlan(t, client, srv, cap, csrf, r3w1Code(t, "https://a.example", "token-a-aaaaaaaaaaaaaaaaaaaa", "office-a"))
	status, body := r3w1Post(t, client, srv, cap, csrf, "/api/plan", map[string]any{
		"this_machine_is_local_ai": false, "whole_subnet": true, "device_ips": []string{"10.251.73.10"}, "confirm_authority": true,
	})
	if status != http.StatusBadRequest {
		t.Fatalf("bad replan %d %s", status, body)
	}
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/apply", map[string]any{
		"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}, "confirm_authority": true,
	})
	if status != http.StatusConflict || calls != 0 {
		t.Fatalf("apply after failed replan %d calls %d %s", status, calls, body)
	}
}

func TestR3W1DetectOrAnswersDropThePlan(t *testing.T) {
	var calls int
	srv, client := r3w1PlanServer(t, func(gateway.Plan, gateway.ApplyOptions) (gateway.ApplyResult, error) {
		calls++
		return gateway.ApplyResult{}, nil
	})
	cap, csrf := r3w1Bootstrap(t, srv, client)
	r3w1ReadyPlan(t, client, srv, cap, csrf, r3w1Code(t, "https://a.example", "token-a-aaaaaaaaaaaaaaaaaaaa", "office-a"))
	if status, body := r3w1Post(t, client, srv, cap, csrf, "/api/detect", map[string]any{}); status != http.StatusOK {
		t.Fatalf("detect %d %s", status, body)
	}
	status, body := r3w1Post(t, client, srv, cap, csrf, "/api/apply", map[string]any{
		"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}, "confirm_authority": true,
	})
	if status != http.StatusConflict || calls != 0 {
		t.Fatalf("apply after detect %d calls %d %s", status, calls, body)
	}

	r3w1ReadyPlan(t, client, srv, cap, csrf, r3w1Code(t, "https://a.example", "token-a-aaaaaaaaaaaaaaaaaaaa", "office-a"))
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/apply", map[string]any{
		"this_machine_is_local_ai": true, "confirm_authority": true,
	})
	if status != http.StatusConflict || !bytes.Contains(body, []byte("does not match the answers")) || calls != 0 {
		t.Fatalf("answer mismatch %d calls %d %s", status, calls, body)
	}
}

func TestR3W1ConcurrentApplyIsRefused(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	srv, client := r3w1PlanServer(t, func(plan gateway.Plan, opt gateway.ApplyOptions) (gateway.ApplyResult, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return gateway.ApplyResult{ConfigPath: plan.ConfigPath}, nil
	})
	client.Timeout = 5 * time.Second
	cap, csrf := r3w1Bootstrap(t, srv, client)
	r3w1ReadyPlan(t, client, srv, cap, csrf, r3w1Code(t, "https://a.example", "token-a-aaaaaaaaaaaaaaaaaaaa", "office-a"))
	applyBody := map[string]any{"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}, "confirm_authority": true}
	var firstCode int
	var firstBody []byte
	done := make(chan struct{})
	go func() {
		firstCode, firstBody = r3w1Post(t, client, srv, cap, csrf, "/api/apply", applyBody)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first apply did not enter")
	}
	status, body := r3w1Post(t, client, srv, cap, csrf, "/api/apply", applyBody)
	close(release)
	<-done
	if status != http.StatusConflict || !bytes.Contains(body, []byte("already running")) {
		t.Fatalf("second apply %d %s", status, body)
	}
	if firstCode != http.StatusOK {
		t.Fatalf("first apply %d %s", firstCode, firstBody)
	}
	if calls.Load() != 1 {
		t.Fatalf("apply calls %d", calls.Load())
	}
}

func r3w1ReadyPlan(t *testing.T, client *http.Client, srv *Server, cap, csrf, code string) {
	t.Helper()
	if status, body := r3w1Post(t, client, srv, cap, csrf, "/api/join", map[string]any{"code": code}); status != http.StatusOK {
		t.Fatalf("join %d %s", status, body)
	}
	if status, body := r3w1Post(t, client, srv, cap, csrf, "/api/detect", map[string]any{}); status != http.StatusOK {
		t.Fatalf("detect %d %s", status, body)
	}
	status, body := r3w1Post(t, client, srv, cap, csrf, "/api/plan", map[string]any{
		"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}, "confirm_authority": true,
	})
	if status != http.StatusOK {
		t.Fatalf("plan %d %s", status, body)
	}
}

func r3w1Code(t *testing.T, enrollURL, token, host string) string {
	t.Helper()
	code, err := join.Encode(join.Payload{
		V: 1, EnrollURL: enrollURL, Token: token, Role: join.RoleGateway, Tenant: "acme", HostnameHint: host,
	}, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func r3w1PlanServer(t *testing.T, apply func(gateway.Plan, gateway.ApplyOptions) (gateway.ApplyResult, error)) (*Server, *http.Client) {
	t.Helper()
	srv, client, _ := testServer(t, time.Minute)
	srv.svc.Apply = apply
	srv.opt.Services.Apply = apply
	return srv, client
}

func r3w1Post(t *testing.T, client *http.Client, srv *Server, capability, csrf, path string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.url()+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+srv.bound)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set(SessionHeader, capability)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}
