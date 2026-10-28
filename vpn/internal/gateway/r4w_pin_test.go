package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

func TestR4WReplaceDropsControlPin(t *testing.T) {
	const hsA = "https://hs-a.example"
	const hsB = "https://hs-b.example"
	p, err := SimplePlan(join.RoleMember, "acme", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = "https://b.example"
	p.ConfigPath = "/home/acme/.idoris/vpn.json"
	p.TokenFile = "/home/acme/.idoris/enroll.token"
	h := newMemHost(false, "darwin")
	h.files[p.ConfigPath] = []byte("{\n  \"enroll_url\": \"https://a.example\",\n  \"control_url\": \"" + hsA + "\",\n  \"hostname\": \"old\"\n}\n")
	res, err := Apply(p, h, ApplyOptions{Token: "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", NoService: true, ReplaceExisting: true})
	if err != nil {
		t.Fatal(err)
	}
	body := h.files[p.ConfigPath]
	if !res.ControlPinDropped || res.ControlURL != "" || strings.Contains(string(body), "control_url") || strings.Contains(string(body), hsA) {
		t.Fatalf("pin kept: dropped=%v control=%q\n%s", res.ControlPinDropped, res.ControlURL, body)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vpn.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := vpnd.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControlURL != "" {
		t.Fatalf("loader still has pin %q", cfg.ControlURL)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/discover" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"control_url":"` + hsB + `","tenant":"acme","role":"member"}`))
	}))
	t.Cleanup(srv.Close)
	disc, err := (&enroll.Client{URL: srv.URL, Token: "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", AllowInsecure: true}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if disc.ControlURL != hsB {
		t.Fatalf("discovery %q", disc.ControlURL)
	}
	got, degraded, err := vpnd.ResolveStartupControl(cfg.ControlURL, disc.ControlURL, hsA, true)
	if err != nil || degraded || got != hsB {
		t.Fatalf("startup control got=%q degraded=%v err=%v", got, degraded, err)
	}
	if _, _, err := vpnd.ResolveStartupControl(hsA, disc.ControlURL, hsA, true); err == nil {
		t.Fatal("keeping the old pin would accept a different discovered server")
	}

	same := p
	same.EnrollURL = "https://a.example"
	h.files[p.ConfigPath] = []byte("{\n  \"enroll_url\": \"https://a.example\",\n  \"control_url\": \"" + hsA + "\"\n}\n")
	res, err = Apply(same, h, ApplyOptions{Token: "idv1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", NoService: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.ControlPinDropped || res.ControlURL != hsA || !strings.Contains(string(h.files[p.ConfigPath]), hsA) {
		t.Fatalf("same authority dropped the pin: %+v\n%s", res, h.files[p.ConfigPath])
	}
	noted := same
	noted.Warnings = nil
	NoteControlPinDrop(&noted, "https://a.example")
	if len(noted.Warnings) != 0 {
		t.Fatal("same authority was warned")
	}
	NoteControlPinDrop(&noted, "https://old.example")
	if len(noted.Warnings) != 1 || noted.Warnings[0].Text != DropControlPinText {
		t.Fatalf("warning %+v", noted.Warnings)
	}
}
