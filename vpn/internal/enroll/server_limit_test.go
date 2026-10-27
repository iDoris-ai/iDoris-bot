package enroll

import (
	"context"
	"fmt"
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
	if !strings.Contains(line, "enrolled") || !strings.Contains(line, "remote=203.0.113.40") || !strings.Contains(line, "label=-") {
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

func TestR2GNoisySourceDoesNotStarve(t *testing.T) {
	s, tok := limitedServer(t, 3, 1)
	h := s.Handler()
	call := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/discover", nil)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if call("198.51.100.1:1") != http.StatusOK {
		t.Fatal("first request from the noisy source")
	}
	firstReject := call("198.51.100.1:1")
	secondReject := call("198.51.100.1:1")
	if firstReject != http.StatusTooManyRequests || secondReject != http.StatusTooManyRequests {
		t.Fatal("noisy source should be rejected by its own bucket")
	}
	if call("198.51.100.2:1") != http.StatusOK {
		t.Fatal("a second source was starved by the noisy source")
	}
	if call("198.51.100.3:1") != http.StatusOK {
		t.Fatal("global capacity was consumed by rejected requests")
	}
	if call("198.51.100.4:1") != http.StatusTooManyRequests {
		t.Fatal("global bucket should be empty after three admissions")
	}
	before := sourceBucketCount(s)
	if call("198.51.100.5:1") != http.StatusTooManyRequests {
		t.Fatal("new source should be rejected once the global bucket is empty")
	}
	if got := sourceBucketCount(s); got != before {
		t.Fatalf("global rejection created a source bucket: before %d after %d", before, got)
	}
}

func TestR2GSourceBucketsBounded(t *testing.T) {
	s, tok := limitedServer(t, 100000, 1)
	base := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	now := base
	s.now = func() time.Time { return now }
	call := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/discover", nil)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		return rr.Code
	}
	if call("[2001:db8:1:2::1]:9") != http.StatusOK {
		t.Fatal("first address in the /64")
	}
	if call("[2001:db8:1:2::abcd]:9") != http.StatusTooManyRequests {
		t.Fatal("second address in the same /64 got its own bucket")
	}
	if call("[2001:db8:1:3::1]:9") != http.StatusOK {
		t.Fatal("a different /64 was aggregated with the first")
	}
	if sourceBucketCount(s) != 2 {
		t.Fatalf("ipv6 buckets %d", sourceBucketCount(s))
	}

	if call("198.51.100.9:9") != http.StatusOK {
		t.Fatal("idle source was not admitted")
	}
	idleKey := "pre:ip:" + sourceKey("198.51.100.9")
	now = now.Add(sourceBucketIdle - time.Nanosecond)
	if call("198.51.100.10:9") != http.StatusOK {
		t.Fatal("neighbour before idle expiry")
	}
	if _, ok := lockedBucket(s, idleKey); !ok {
		t.Fatal("source expired before it was idle")
	}
	now = now.Add(time.Nanosecond)
	if call("198.51.100.11:9") != http.StatusOK {
		t.Fatal("request that should expire the idle source")
	}
	if _, ok := lockedBucket(s, idleKey); ok {
		t.Fatal("idle source bucket was kept")
	}
	if _, ok := lockedBucket(s, "pre:global"); !ok {
		t.Fatal("idle sweep removed the global bucket")
	}
	if _, ok := lockedBucket(s, "discover:acme"); !ok {
		t.Fatal("idle sweep removed the tenant bucket")
	}

	s2, tok2 := limitedServer(t, 100000, 1)
	now2 := base
	s2.now = func() time.Time { return now2 }
	call2 := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/discover", nil)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+tok2)
		rr := httptest.NewRecorder()
		s2.Handler().ServeHTTP(rr, req)
		return rr.Code
	}
	for i := 0; i < maxSourceBuckets; i++ {
		remote := fmt.Sprintf("198.18.%d.%d:9", i/256, i%256)
		if call2(remote) != http.StatusOK {
			t.Fatalf("source %d status", i)
		}
	}
	if got := sourceBucketCount(s2); got != maxSourceBuckets {
		t.Fatalf("filled buckets %d", got)
	}
	now2 = now2.Add(time.Second)
	if call2("198.18.0.0:9") != http.StatusTooManyRequests {
		t.Fatal("oldest source should still be over its own limit")
	}
	if call2("198.19.0.1:9") != http.StatusOK {
		t.Fatal("new source past the cap was rejected")
	}
	if got := sourceBucketCount(s2); got != maxSourceBuckets {
		t.Fatalf("buckets after cap %d", got)
	}
	if _, ok := lockedBucket(s2, "pre:ip:"+sourceKey("198.18.0.0")); !ok {
		t.Fatal("recently used source was evicted ahead of an older one")
	}
	if _, ok := lockedBucket(s2, "discover:acme"); !ok {
		t.Fatal("cap eviction removed the tenant bucket")
	}
}

func limitedServer(t *testing.T, global, perIP int) (*Server, string) {
	t.Helper()
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ControlURL:          "https://vpn.example.org",
		GlobalRatePerMinute: global,
		PerIPRatePerMinute:  perIP,
		Tenants: []Tenant{{
			Name:            "acme",
			HeadscaleUserID: "1",
			TokenHashes:     []string{HashToken(tok)},
			RatePerMinute:   100000,
		}},
	}
	s, err := NewServer(cfg, &fakeMinter{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	frozen := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return frozen }
	return s, tok
}

func sourceBucketCount(s *Server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for key := range s.buckets {
		if strings.HasPrefix(key, "pre:ip:") {
			n++
		}
	}
	return n
}

func lockedBucket(s *Server, key string) (*bucket, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	return b, ok
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
