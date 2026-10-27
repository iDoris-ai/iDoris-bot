package enroll

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type logBuf struct {
	mu    sync.Mutex
	lines []string
}

func (l *logBuf) Enabled(context.Context, slog.Level) bool { return true }

func (l *logBuf) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteByte(' ')
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.String())
		return true
	})
	l.mu.Lock()
	l.lines = append(l.lines, b.String())
	l.mu.Unlock()
	return nil
}

func (l *logBuf) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logBuf) WithGroup(string) slog.Handler      { return l }

func (l *logBuf) joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *logBuf) count(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

func TestPreAuthLimitRunsBeforeHashScan(t *testing.T) {
	m := &fakeMinter{}
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ControlURL:          "https://vpn.example.org",
		GlobalRatePerMinute: 1,
		PerIPRatePerMinute:  100,
		Tenants: []Tenant{{
			Name:            "acme",
			HeadscaleUserID: "1",
			TokenHashes:     []string{HashToken(tok)},
			RatePerMinute:   100,
		}},
	}
	s, err := NewServer(cfg, m, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC) }
	h := s.Handler()
	call := func() int {
		req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{"hostname":"mbp"}`))
		req.RemoteAddr = "198.51.100.9:40000"
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if call() != http.StatusOK {
		t.Fatal("first enroll should pass the global bucket")
	}
	scans := s.authScans
	if scans != 1 {
		t.Fatalf("scans %d", scans)
	}
	if call() != http.StatusTooManyRequests {
		t.Fatal("second enroll should be limited")
	}
	if s.authScans != scans {
		t.Fatalf("limited request scanned hashes: before %d after %d", scans, s.authScans)
	}
	if len(m.calls) != 1 {
		t.Fatalf("minter calls %d", len(m.calls))
	}
}

func TestSpoofedForwardedForFromUntrustedPeer(t *testing.T) {
	m := &fakeMinter{}
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ControlURL:         "https://vpn.example.org",
		PerIPRatePerMinute: 1,
		Tenants: []Tenant{{
			Name: "acme", HeadscaleUserID: "1", TokenHashes: []string{HashToken(tok)}, RatePerMinute: 100,
		}},
	}
	s, err := NewServer(cfg, m, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC) }
	h := s.Handler()
	status := func(remote, xff string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/discover", nil)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+tok)
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if status("198.51.100.9:9", "203.0.113.5") != http.StatusOK {
		t.Fatal("first request from the untrusted peer should pass")
	}
	if status("198.51.100.9:9", "203.0.113.50") != http.StatusTooManyRequests {
		t.Fatal("spoofed X-Forwarded-For must not select a fresh bucket")
	}
	if status("203.0.113.5:9", "") != http.StatusOK {
		t.Fatal("the address named in the spoofed header still has its own bucket")
	}
}

func TestTrustedProxyUsesRightmostUntrusted(t *testing.T) {
	m := &fakeMinter{}
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ControlURL:         "https://vpn.example.org",
		PerIPRatePerMinute: 1,
		TrustedProxies:     []string{"10.0.0.0/8"},
		Tenants: []Tenant{{
			Name: "acme", HeadscaleUserID: "1", TokenHashes: []string{HashToken(tok)}, RatePerMinute: 100,
		}},
	}
	s, err := NewServer(cfg, m, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC) }
	h := s.Handler()
	status := func(remote, xff string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/discover", nil)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+tok)
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	// Rightmost untrusted hop is 203.0.113.8; 10.9.9.9 is another trusted proxy.
	if status("10.1.2.3:443", "6.6.6.6, 203.0.113.8, 10.9.9.9") != http.StatusOK {
		t.Fatal("trusted peer should be admitted")
	}
	if status("10.1.2.3:443", "203.0.113.8") != http.StatusTooManyRequests {
		t.Fatal("same client via the proxy should share the bucket")
	}
	if status("10.1.2.3:443", "198.51.100.7") != http.StatusOK {
		t.Fatal("a different client behind the proxy should have its own bucket")
	}
}

func TestResolveClientIP(t *testing.T) {
	trusted := mustParseTrusted(t, "10.0.0.0/8")
	cases := []struct {
		remote, xff, want string
	}{
		{"198.51.100.9:9", "203.0.113.5", "198.51.100.9"},
		{"10.1.2.3:443", "203.0.113.8", "203.0.113.8"},
		{"10.1.2.3:443", "6.6.6.6, 203.0.113.8, 10.9.9.9", "203.0.113.8"},
		{"10.1.2.3:443", "10.2.2.2, 10.3.3.3", "10.2.2.2"},
		{"10.1.2.3:443", "", "10.1.2.3"},
		{"[2001:db8::5]:443", "203.0.113.1", "2001:db8::5"},
	}
	for _, tc := range cases {
		if got := resolveClientIP(tc.remote, tc.xff, trusted); got != tc.want {
			t.Errorf("remote %s xff %q: got %s want %s", tc.remote, tc.xff, got, tc.want)
		}
	}
}

func mustParseTrusted(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	ps, err := parseTrusted(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func TestDiscoverIsLimitedSeparatelyFromEnroll(t *testing.T) {
	m := &fakeMinter{}
	s, tok := newTestServer(t, m)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.mu.Lock()
	s.cfg.Tenants[0].RatePerMinute = 1
	s.mu.Unlock()
	h := s.Handler()
	discover := func() int {
		req := httptest.NewRequest(http.MethodGet, "/v1/discover", nil)
		req.RemoteAddr = "203.0.113.9:1"
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if discover() != http.StatusOK || discover() != http.StatusTooManyRequests {
		t.Fatal("discover should allow one call then 429")
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{}`))
	req.RemoteAddr = "203.0.113.9:1"
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enroll bucket should be independent, got %d %s", rr.Code, rr.Body.String())
	}
	if len(m.calls) != 1 {
		t.Fatalf("minter calls %d", len(m.calls))
	}
}

func TestFailedAuthLogIsSampled(t *testing.T) {
	buf := &logBuf{}
	m := &fakeMinter{}
	s, _ := newTestServer(t, m)
	s.log = slog.New(buf)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	h := s.Handler()
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/discover", nil)
		req.RemoteAddr = "198.51.100.20:1"
		req.Header.Set("Authorization", "Bearer idv1_nope")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if buf.count("rejected: unknown token") != 1 {
		t.Fatalf("logs:\n%s", buf.joined())
	}
	now = now.Add(authLogInterval)
	req := httptest.NewRequest(http.MethodGet, "/v1/discover", nil)
	req.RemoteAddr = "198.51.100.20:1"
	req.Header.Set("Authorization", "Bearer idv1_nope")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if buf.count("rejected: unknown token") != 2 || !strings.Contains(buf.joined(), "suppressed=4") {
		t.Fatalf("logs:\n%s", buf.joined())
	}
	if strings.Contains(buf.joined(), "idv1_nope") {
		t.Fatal("failed-auth log included the token")
	}
}

func TestEnrollAuditIncludesRemote(t *testing.T) {
	buf := &logBuf{}
	m := &fakeMinter{}
	s, tok := newTestServer(t, m)
	s.log = slog.New(buf)
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{"hostname":"mbp","os":"darwin"}`))
	req.RemoteAddr = "203.0.113.40:51515"
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	line := buf.joined()
	if !strings.Contains(line, "enrolled") || !strings.Contains(line, "remote=203.0.113.40") {
		t.Fatalf("audit line %q", line)
	}
	if strings.Contains(line, tok) {
		t.Fatal("audit line included the enrollment token")
	}
}

func TestReloadKeepsOldConfigWhenTrustedProxyIsInvalid(t *testing.T) {
	m := &fakeMinter{}
	s, tok := newTestServer(t, m)
	frozen := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return frozen }
	bad := s.cfg
	bad.TrustedProxies = []string{"10.1.2.3/8"}
	if err := s.Reload(bad); err == nil || !strings.Contains(err.Error(), "host bits") {
		t.Fatalf("reload err %v", err)
	}
	if got := resolveClientIP("198.51.100.9:1", "203.0.113.5", s.trusted); got != "198.51.100.9" {
		t.Fatalf("trusted list changed to %v (%s)", s.trusted, got)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/discover", nil)
	req.RemoteAddr = "198.51.100.9:1"
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Forwarded-For", "203.0.113.5")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("old config dropped: %d %s", rr.Code, rr.Body.String())
	}

	// A server that has not spent its global bucket yet picks up the new rate.
	s2, tok2 := newTestServer(t, m)
	s2.now = func() time.Time { return frozen }
	next := s2.cfg
	next.GlobalRatePerMinute = 1
	next.TrustedProxies = []string{"10.0.0.0/8"}
	if err := s2.Reload(next); err != nil {
		t.Fatal(err)
	}
	status := func() int {
		r := httptest.NewRequest(http.MethodGet, "/v1/discover", nil)
		r.RemoteAddr = "10.8.8.8:1"
		r.Header.Set("Authorization", "Bearer "+tok2)
		r.Header.Set("X-Forwarded-For", "203.0.113.70")
		w := httptest.NewRecorder()
		s2.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if status() != http.StatusOK || status() != http.StatusTooManyRequests {
		t.Fatal("reloaded global rate was not applied")
	}
	if len(s2.trusted) != 1 || s2.trusted[0].String() != "10.0.0.0/8" {
		t.Fatalf("trusted %+v", s2.trusted)
	}
	// The second call was limited as the forwarded client, not the proxy.
	// A different client behind the same proxy still has to pass the global
	// bucket, which is empty, so the prefix check above is the assertion.
}

func TestConfigRejectsBadLimitFields(t *testing.T) {
	good := Config{ControlURL: "https://x", Tenants: []Tenant{{Name: "a", HeadscaleUserID: "1", TokenHashes: []string{HashToken("t")}}}}
	bad := good
	bad.GlobalRatePerMinute = -1
	if err := bad.Validate(); err == nil {
		t.Fatal("negative global rate")
	}
	bad = good
	bad.TrustedProxies = []string{"not-a-cidr"}
	if err := bad.Validate(); err == nil {
		t.Fatal("bad cidr")
	}
	ok := good
	ok.GlobalRatePerMinute = 10
	ok.PerIPRatePerMinute = 2
	ok.TrustedProxies = []string{"192.0.2.0/24"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}
