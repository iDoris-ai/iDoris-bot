package ui

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
)

func TestR4WConfirmationIsBoundToAuthorityAndRevision(t *testing.T) {
	var mu sync.Mutex
	var urls []string
	var tokens []string
	block := make(chan struct{})
	entered := make(chan struct{})
	srv, client := r3w1PlanServer(t, func(gateway.Plan, gateway.ApplyOptions) (gateway.ApplyResult, error) {
		return gateway.ApplyResult{}, nil
	})
	client.Timeout = 5 * time.Second
	srv.svc.Discover = func(ctx context.Context, enrollURL, token string, _ bool) (*enroll.Discovery, error) {
		mu.Lock()
		urls = append(urls, enrollURL)
		tokens = append(tokens, token)
		n := len(urls)
		mu.Unlock()
		if n == 1 {
			close(entered)
			select {
			case <-block:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return &enroll.Discovery{ControlURL: "https://vpn.example", Tenant: "acme", LANCIDRs: []string{"10.251.73.10/32"}, Role: "gateway"}, nil
	}
	cap, csrf := r3w1Bootstrap(t, srv, client)
	codeA := r3w1Code(t, "https://a.example", "token-a-aaaaaaaaaaaaaaaaaaaa", "office-a")
	codeB := r3w1Code(t, "https://b.example", "token-b-bbbbbbbbbbbbbbbbbbbb", "office-b")

	joinedA := r3w1ReadJoin(t, mustJoin(t, client, srv, cap, csrf, codeA))
	if status, body := r3w1Post(t, client, srv, cap, csrf, "/api/detect", map[string]any{}); status != http.StatusOK {
		t.Fatalf("detect %d %s", status, body)
	}
	planA := joinedA.body(map[string]any{"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}})

	var planStatus int
	var planBody []byte
	done := make(chan struct{})
	go func() {
		planStatus, planBody = r3w1Post(t, client, srv, cap, csrf, "/api/plan", planA)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("discover did not start")
	}
	joinedB := r3w1ReadJoin(t, mustJoin(t, client, srv, cap, csrf, codeB))
	close(block)
	<-done
	if planStatus != http.StatusConflict || !bytes.Contains(planBody, []byte("the plan is stale")) {
		t.Fatalf("overlapping plan %d %s", planStatus, planBody)
	}
	mu.Lock()
	if len(urls) != 1 || urls[0] != "https://a.example" || tokens[0] != "token-a-aaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("in-flight discover %v %v", urls, tokens)
	}
	mu.Unlock()

	// Saving B cleared the server-side plan. A's confirmation must not discover B.
	before := 1
	status, body := r3w1Post(t, client, srv, cap, csrf, "/api/plan", planA)
	mu.Lock()
	after := len(urls)
	mu.Unlock()
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("does not match the displayed enrollment authority")) || after != before {
		t.Fatalf("plan with A's confirmation after B %d discover %d->%d %s", status, before, after, body)
	}

	if status, body = r3w1Post(t, client, srv, cap, csrf, "/api/detect", map[string]any{}); status != http.StatusOK {
		t.Fatalf("detect B %d %s", status, body)
	}
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/plan", joinedB.body(map[string]any{
		"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"},
	}))
	mu.Lock()
	defer mu.Unlock()
	if status != http.StatusOK || len(urls) != 2 || urls[1] != "https://b.example" || tokens[1] != "token-b-bbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("plan B %d urls %v tokens %v %s", status, urls, tokens, body)
	}
}
