package vpnd

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type stubStatus struct{ snap Snapshot }

func (s stubStatus) Snapshot() Snapshot { return s.snap }

func TestStatusViewAddsModeAndForwards(t *testing.T) {
	access, err := StartLocalAccess(&net.Dialer{}, []Forward{{Listen: "127.0.0.1:0", Target: "acme-local-ai:11434"}}, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = access.Close() })

	src := View{
		Source: stubStatus{snap: Snapshot{
			Phase:      PhaseConnected,
			ControlURL: "https://vpn.example",
			Attempts:   1,
			UpdatedAt:  time.Unix(1, 0).UTC(),
		}},
		Mode:       ModeEmbedded,
		ModeReason: "tailscaled unreachable",
		Access:     access,
	}
	rr := httptest.NewRecorder()
	StatusHandler(src, "v-test").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["phase"] != string(PhaseConnected) || body["mode"] != ModeEmbedded || body["mode_reason"] != "tailscaled unreachable" {
		t.Fatalf("overlay missing: %s", rr.Body.String())
	}
	if body["daemon_version"] != "v-test" || body["login_attempts"] != float64(1) {
		t.Fatalf("existing fields changed: %s", rr.Body.String())
	}
	fw, _ := body["forwards"].([]any)
	if len(fw) != 1 {
		t.Fatalf("forwards: %s", rr.Body.String())
	}
	row, _ := fw[0].(map[string]any)
	if row["target"] != "acme-local-ai:11434" || row["state"] != "listening" || !strings.HasPrefix(row["listen"].(string), "127.0.0.1:") {
		t.Fatalf("forward row %+v", row)
	}
	s5, _ := body["socks5"].(map[string]any)
	if s5["state"] != "listening" || !strings.HasPrefix(s5["listen"].(string), "127.0.0.1:") {
		t.Fatalf("socks5 %+v", s5)
	}
	text := FormatStatus(body)
	for _, want := range []string{"mode:", "embedded", "mode_reason:", "tailscaled unreachable", "forward:", "socks5:", "acme-local-ai:11434"} {
		if !strings.Contains(text, want) {
			t.Fatalf("text missing %q:\n%s", want, text)
		}
	}

	health := httptest.NewRecorder()
	StatusHandler(src, "v-test").ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	b, _ := io.ReadAll(health.Body)
	if health.Code != http.StatusOK || string(b) != "ok\n" {
		t.Fatalf("health %d %q", health.Code, b)
	}
}

func TestEmbeddedMemberWithoutPathWarns(t *testing.T) {
	v := View{Source: stubStatus{snap: Snapshot{Phase: PhaseConnected, Role: "member"}}, Mode: ModeEmbedded}
	snap := v.Snapshot()
	if len(snap.Warnings) != 1 || snap.Warnings[0] != EmbeddedNoPathWarning {
		t.Fatalf("warnings %+v", snap.Warnings)
	}
	withFwd := View{Source: stubStatus{snap: Snapshot{
		Role:     "member",
		Forwards: []ForwardStatus{{Listen: "127.0.0.1:9", Target: "h:1", State: "listening"}},
	}}, Mode: ModeEmbedded}
	if w := withFwd.Snapshot().Warnings; len(w) != 0 {
		t.Fatalf("forward is a path: %v", w)
	}
	withSOCKS := View{Source: stubStatus{snap: Snapshot{
		Role:   "member",
		SOCKS5: &SOCKS5Status{Listen: "127.0.0.1:1055", State: "listening"},
	}}, Mode: ModeEmbedded}
	if w := withSOCKS.Snapshot().Warnings; len(w) != 0 {
		t.Fatalf("socks5 is a path: %v", w)
	}
	admin := View{Source: stubStatus{snap: Snapshot{Role: "admin"}}, Mode: ModeEmbedded}
	if w := admin.Snapshot().Warnings; len(w) != 0 {
		t.Fatalf("admin is not the member warning: %v", w)
	}
	system := View{Source: stubStatus{snap: Snapshot{Role: "member"}}, Mode: ModeSystem}
	if w := system.Snapshot().Warnings; len(w) != 0 {
		t.Fatalf("system mode: %v", w)
	}

	h := httptest.NewRecorder()
	StatusHandler(FixedSnapshot(Snapshot{Phase: PhaseWaitingTailscaled, Role: "local-ai"}), "v").ServeHTTP(h, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if h.Code != http.StatusServiceUnavailable || !strings.Contains(h.Body.String(), string(PhaseWaitingTailscaled)) {
		t.Fatalf("health %d %s", h.Code, h.Body.String())
	}
}

func TestStatusPrintsPendingRoutes(t *testing.T) {
	src := stubStatus{snap: Snapshot{
		Phase: PhaseRoutesPending,
		Routes: []RouteReport{
			{CIDR: "10.251.73.10/32", Advertised: true, Approved: false},
		},
		AdminHint: "headscale nodes approve-routes --identifier office-gw --routes 10.251.73.10/32",
	}}
	rr := httptest.NewRecorder()
	StatusHandler(src, "v-test").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	text := FormatStatus(body)
	for _, want := range []string{"routes-pending-approval", "10.251.73.10/32", "pending", "admin_hint:", "office-gw"} {
		if !strings.Contains(text, want) {
			t.Fatalf("text missing %q:\n%s", want, text)
		}
	}
	health := httptest.NewRecorder()
	StatusHandler(src, "v-test").ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	b, _ := io.ReadAll(health.Body)
	if health.Code != http.StatusServiceUnavailable || string(b) != "routes-pending-approval\n" {
		t.Fatalf("health %d %q", health.Code, b)
	}
}
