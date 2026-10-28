package ui

import (
	"bytes"
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
)

func TestR3W1ApplyRequiresAuthorityConfirmation(t *testing.T) {
	var discover atomic.Int32
	var applyCalls atomic.Int32
	var appliedURL, appliedToken string
	srv, client := r3w1PlanServer(t, func(plan gateway.Plan, opt gateway.ApplyOptions) (gateway.ApplyResult, error) {
		applyCalls.Add(1)
		appliedURL = plan.EnrollURL
		appliedToken = opt.Token
		return gateway.ApplyResult{ConfigPath: plan.ConfigPath}, nil
	})
	srv.svc.Discover = func(context.Context, string, string, bool) (*enroll.Discovery, error) {
		discover.Add(1)
		return &enroll.Discovery{ControlURL: "https://vpn.example", Tenant: "acme", LANCIDRs: []string{"10.251.73.10/32"}}, nil
	}
	cap, csrf := r3w1Bootstrap(t, srv, client)
	const token = "token-auth-aaaaaaaaaaaaaaaaaa"
	const enrollURL = "https://enroll.example.org:8443/vpn"
	code := r3w1Code(t, enrollURL, token, "office-a")

	status, body := r3w1Post(t, client, srv, cap, csrf, "/api/join", map[string]any{"code": code})
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"authority":"enroll.example.org:8443"`)) {
		t.Fatalf("join authority %d %s", status, body)
	}
	joined := r3w1ReadJoin(t, body)
	if bytes.Contains(body, []byte(token)) || discover.Load() != 0 {
		t.Fatalf("join sent the credential or echoed the token: discover %d %s", discover.Load(), body)
	}
	if status, body = r3w1Post(t, client, srv, cap, csrf, "/api/detect", map[string]any{}); status != http.StatusOK {
		t.Fatalf("detect %d %s", status, body)
	}

	no := map[string]any{"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}}
	yes := joined.body(map[string]any{"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}})

	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/plan", no)
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("confirm this is your organization")) || discover.Load() != 0 {
		t.Fatalf("plan without confirmation %d discover %d %s", status, discover.Load(), body)
	}
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/apply", no)
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("confirm this is your organization")) || applyCalls.Load() != 0 {
		t.Fatalf("apply without confirmation %d calls %d %s", status, applyCalls.Load(), body)
	}

	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/plan", yes)
	if status != http.StatusOK || !bytes.Contains(body, []byte(enrollURL)) || discover.Load() != 1 {
		t.Fatalf("confirmed plan %d discover %d %s", status, discover.Load(), body)
	}
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/plan", no)
	if status != http.StatusBadRequest || discover.Load() != 1 {
		t.Fatalf("second unconfirmed plan %d discover %d %s", status, discover.Load(), body)
	}
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/apply", no)
	if status != http.StatusBadRequest || applyCalls.Load() != 0 {
		t.Fatalf("unconfirmed apply dropped or called apply %d calls %d %s", status, applyCalls.Load(), body)
	}
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/apply", yes)
	if status != http.StatusOK || applyCalls.Load() != 1 || appliedURL != enrollURL || appliedToken != token {
		t.Fatalf("confirmed apply %d calls %d url %s token-match %v %s", status, applyCalls.Load(), appliedURL, appliedToken == token, body)
	}
}

func TestR3W1UnconfirmedPlanDoesNotDiscover(t *testing.T) {
	// A Discover that blocks must not be entered before confirmation.
	srv, client, _ := testServer(t, time.Minute)
	started := make(chan struct{})
	srv.svc.Discover = func(ctx context.Context, _, _ string, _ bool) (*enroll.Discovery, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	cap, csrf := r3w1Bootstrap(t, srv, client)
	code := r3w1Code(t, "https://enroll.example.org:8443/vpn", "token-auth-aaaaaaaaaaaaaaaaaa", "office-a")
	if status, body := r3w1Post(t, client, srv, cap, csrf, "/api/join", map[string]any{"code": code}); status != http.StatusOK {
		t.Fatalf("join %d %s", status, body)
	}
	status, body := r3w1Post(t, client, srv, cap, csrf, "/api/plan", map[string]any{
		"this_machine_is_local_ai": true,
	})
	select {
	case <-started:
		t.Fatal("discover started before confirmation")
	default:
	}
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("confirm this is your organization")) {
		t.Fatalf("plan %d %s", status, body)
	}
}
