package enroll

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// gateReader blocks the first Read until release is closed, after signalling
// that the server has started to read the body.
type gateReader struct {
	once    sync.Once
	started chan struct{}
	release <-chan struct{}
	rest    io.Reader
}

func (g *gateReader) Read(p []byte) (int, error) {
	g.once.Do(func() { close(g.started) })
	<-g.release
	return g.rest.Read(p)
}

func TestR2GEnrollRechecksCredentialAfterBody(t *testing.T) {
	m := &fakeMinter{}
	tokA, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	tokB, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ControlURL:          "https://vpn.example.org",
		GlobalRatePerMinute: 100,
		PerIPRatePerMinute:  100,
		Tenants: []Tenant{{
			Name:            "acme",
			HeadscaleUserID: "1",
			TokenHashes:     []string{HashToken(tokA), HashToken(tokB)},
			RatePerMinute:   1,
		}},
	}
	s, err := NewServer(cfg, m, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	frozen := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return frozen }

	release := make(chan struct{})
	started := make(chan struct{})
	body := &gateReader{
		started: started,
		release: release,
		rest:    strings.NewReader(`{"hostname":"slow","os":"linux"}`),
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", body)
	req.RemoteAddr = "203.0.113.9:4000"
	req.Header.Set("Authorization", "Bearer "+tokA)
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.Handler().ServeHTTP(rr, req)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not read the body")
	}
	revoked := cfg
	revoked.Tenants = []Tenant{{
		Name:            "acme",
		HeadscaleUserID: "1",
		TokenHashes:     []string{HashToken(tokB)},
		RatePerMinute:   1,
	}}
	if err := s.Reload(revoked); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid token") {
		t.Fatalf("revoked slow body: %d %s", rr.Code, rr.Body.String())
	}
	if len(m.calls) != 0 {
		t.Fatalf("revoked credential minted %d keys", len(m.calls))
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{"hostname":"ok","os":"linux"}`))
	req2.RemoteAddr = "203.0.113.10:4001"
	req2.Header.Set("Authorization", "Bearer "+tokB)
	rr2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("remaining credential: %d %s", rr2.Code, rr2.Body.String())
	}
	if len(m.calls) != 1 {
		t.Fatalf("minted %d", len(m.calls))
	}
}
