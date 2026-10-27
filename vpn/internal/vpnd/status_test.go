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
