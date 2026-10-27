package ui

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
)

func TestR3W1ReplaceExistingAndAccessInfo(t *testing.T) {
	const foreign = "gateway: existing config belongs to another organization"
	var mu sync.Mutex
	var opts []gateway.ApplyOptions
	srv, client := r3w1PlanServer(t, func(plan gateway.Plan, opt gateway.ApplyOptions) (gateway.ApplyResult, error) {
		mu.Lock()
		opts = append(opts, opt)
		mu.Unlock()
		if !opt.ReplaceExisting {
			return gateway.ApplyResult{}, errors.New(foreign)
		}
		return gateway.ApplyResult{
			ConfigPath: plan.ConfigPath,
			AccessInfo: []string{"SOCKS5 127.0.0.1:1055", "token file is mode 0600"},
		}, nil
	})
	cap, csrf := r3w1Bootstrap(t, srv, client)
	code := r3w1Code(t, "https://enroll.example.org", "token-gw-aaaaaaaaaaaaaaaaaaaa", "office-a")
	if status, body := r3w1Post(t, client, srv, cap, csrf, "/api/join", map[string]any{"code": code}); status != http.StatusOK {
		t.Fatalf("join %d %s", status, body)
	}
	if status, body := r3w1Post(t, client, srv, cap, csrf, "/api/detect", map[string]any{}); status != http.StatusOK {
		t.Fatalf("detect %d %s", status, body)
	}
	status, body := r3w1Post(t, client, srv, cap, csrf, "/api/plan", map[string]any{
		"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}, "confirm_authority": true,
	})
	wantPaths := gateway.PathsFor("/home/acme", "")
	if status != http.StatusOK || !bytes.Contains(body, []byte(wantPaths.Config)) || !bytes.Contains(body, []byte(wantPaths.Token)) {
		t.Fatalf("plan paths %d %s", status, body)
	}

	same := map[string]any{
		"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"}, "confirm_authority": true,
	}
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/apply", same)
	if status != http.StatusBadGateway || r3w1Err(t, body) != foreign {
		t.Fatalf("foreign config %d %s", status, body)
	}
	status, body = r3w1Post(t, client, srv, cap, csrf, "/api/apply", map[string]any{
		"this_machine_is_local_ai": false, "device_ips": []string{"10.251.73.10"},
		"confirm_authority": true, "replace_existing": true,
	})
	if status != http.StatusOK || !bytes.Contains(body, []byte("SOCKS5 127.0.0.1:1055")) || !bytes.Contains(body, []byte("token file is mode 0600")) {
		t.Fatalf("access info %d %s", status, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(opts) != 2 || opts[0].ReplaceExisting || !opts[1].ReplaceExisting || opts[1].PlanPath != wantPaths.Plan {
		t.Fatalf("apply options %+v", opts)
	}

	res, err := client.Get(srv.url() + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	html := string(page)
	if !bytes.Contains(page, []byte("replace the existing configuration for another organisation")) {
		t.Fatal("page missing replace checkbox")
	}
	if bytes.Contains(page, []byte(`id="replace-existing" type="checkbox" checked`)) || bytes.Contains(page, []byte(`id="replace-existing" checked`)) {
		t.Fatalf("replace checkbox defaults on: %s", html)
	}
}
