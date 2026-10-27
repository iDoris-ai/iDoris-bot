package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
)

type fakeProber struct {
	probe ControlProbe
	err   error
	calls int
}

func (f *fakeProber) ProbeControl(context.Context) (ControlProbe, error) {
	f.calls++
	return f.probe, f.err
}

func readyServer(t *testing.T, p ControlProber) *Server {
	t.Helper()
	s, tok := newTestServer(t, &fakeMinter{})
	_ = tok
	s.now = func() time.Time { return time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC) }
	s.SetControlProber(p)
	return s
}

func TestHealthzIgnoresTheReadinessProbe(t *testing.T) {
	p := &fakeProber{err: errors.New("should not be called")}
	s := readyServer(t, p)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "ok\n" || !strings.Contains(rr.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("healthz %d %q %s", rr.Code, rr.Body.String(), rr.Header().Get("Content-Type"))
	}
	if p.calls != 0 {
		t.Fatal("healthz called the prober")
	}
}

func TestReadyz(t *testing.T) {
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	secret := "super-secret-key"
	cases := []struct {
		name   string
		prober ControlProber
		status int
		state  string
		warn   bool
		hasExp bool
		head   string
		exp    time.Time
	}{
		{name: "unconfigured", status: http.StatusServiceUnavailable, state: "unavailable", head: "readiness probe is not configured"},
		{name: "unreachable", prober: &fakeProber{err: errors.New("dial " + secret)}, status: http.StatusServiceUnavailable, state: "unavailable", head: "unreachable"},
		{name: "rejected", prober: &fakeProber{err: &headscale.APIError{Status: http.StatusUnauthorized, Body: secret}}, status: http.StatusServiceUnavailable, state: "unavailable", head: "api key rejected"},
		{name: "past", prober: &fakeProber{probe: ControlProbe{ExpiresAt: now.Add(-time.Second), Known: true}}, status: http.StatusServiceUnavailable, state: "unavailable", head: "api key expired", hasExp: true, exp: now.Add(-time.Second)},
		{name: "ten-days", prober: &fakeProber{probe: ControlProbe{ExpiresAt: now.Add(10 * day), Known: true}}, status: http.StatusOK, state: "warning", head: "ok", warn: true, hasExp: true, exp: now.Add(10 * day)},
		{name: "exactly-thirty", prober: &fakeProber{probe: ControlProbe{ExpiresAt: now.Add(30 * day), Known: true}}, status: http.StatusOK, state: "ok", head: "ok", hasExp: true, exp: now.Add(30 * day)},
		{name: "ninety-days", prober: &fakeProber{probe: ControlProbe{ExpiresAt: now.Add(90 * day), Known: true}}, status: http.StatusOK, state: "ok", head: "ok", hasExp: true, exp: now.Add(90 * day)},
		{name: "unknown", prober: &fakeProber{probe: ControlProbe{}}, status: http.StatusOK, state: "ok", head: "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer(t, &fakeMinter{})
			s.now = func() time.Time { return now }
			if tc.prober != nil {
				s.SetControlProber(tc.prober)
			}
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rr.Code != tc.status {
				t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), secret) {
				t.Fatalf("body leaked the key: %s", rr.Body.String())
			}
			var body readyBody
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Status != tc.state || body.Headscale != tc.head {
				t.Fatalf("body %+v", body)
			}
			if tc.warn {
				if !strings.Contains(body.Warning, "30 days") {
					t.Fatalf("warning %q", body.Warning)
				}
			} else if body.Warning != "" {
				t.Fatalf("unexpected warning %q", body.Warning)
			}
			if tc.hasExp {
				if body.APIKeyExpiresAt == nil || !body.APIKeyExpiresAt.Equal(tc.exp.UTC()) {
					t.Fatalf("expiry %v", body.APIKeyExpiresAt)
				}
			} else if body.APIKeyExpiresAt != nil {
				t.Fatalf("expiry present %v", body.APIKeyExpiresAt)
			}
		})
	}
}

func TestReadyzAgainstHeadscale(t *testing.T) {
	secret := "hskey-ready.secret"
	exp := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiKeys": []map[string]any{{
				"id":         "9",
				"prefix":     "hskey-ready",
				"expiration": exp.Format(time.RFC3339),
			}},
		})
	}))
	t.Cleanup(hs.Close)
	s, _ := newTestServer(t, &fakeMinter{})
	s.now = func() time.Time { return time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC) }
	s.SetControlProber(clientProber{&headscale.Client{BaseURL: hs.URL, APIKey: secret}})
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"status":"warning"`) || strings.Contains(rr.Body.String(), secret) {
		t.Fatalf("readyz %d %s", rr.Code, rr.Body.String())
	}
}

// clientProber is the same adapter cmd/idoris-vpn-enroll installs. It keeps
// the Headscale client from having to implement the enroll interface.
type clientProber struct{ c *headscale.Client }

func (p clientProber) ProbeControl(ctx context.Context) (ControlProbe, error) {
	st, err := p.c.ProbeControl(ctx)
	if err != nil {
		return ControlProbe{}, err
	}
	return ControlProbe{ExpiresAt: st.ExpiresAt, Known: st.Known}, nil
}
