package enroll

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	// defaultGlobalRatePerMinute is the pre-authentication budget for the
	// whole process. It is intentionally above the per-tenant enroll bucket
	// so one organisation cannot be starved by the global cap during a
	// normal join, and low enough that an internet scan cannot walk every
	// token hash without bound.
	defaultGlobalRatePerMinute = 600
	// defaultPerIPRatePerMinute is the same budget for one resolved client.
	defaultPerIPRatePerMinute = 60
	defaultTenantRate         = 30
	// authLogInterval is the minimum gap between failed-auth warnings.
	authLogInterval = 10 * time.Second
	// maxSourceBuckets is the most per-source pre-auth buckets kept in memory.
	maxSourceBuckets = 4096
	// sourceBucketIdle is how long an unused per-source bucket stays.
	sourceBucketIdle = 10 * time.Minute
)

func tenantRate(t Tenant) float64 {
	if t.RatePerMinute > 0 {
		return float64(t.RatePerMinute)
	}
	return defaultTenantRate
}

func parseTrusted(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, fmt.Errorf("trusted_proxies contains an empty entry")
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies %q: %w", s, err)
		}
		if p.Masked() != p {
			return nil, fmt.Errorf("trusted_proxies %q has host bits set", s)
		}
		out = append(out, p)
	}
	return out, nil
}

// admit spends one global token and one per-source token, or neither.
// A source that has used its own allowance must not burn the shared budget.
// It runs before the bearer token is hashed. A closed bucket writes 429 and
// returns ok=false. The per-source map drops idle entries and stays at
// maxSourceBuckets.
func (s *Server) admit(w http.ResponseWriter, r *http.Request) (string, bool) {
	remote := s.clientIP(r)
	key := "pre:ip:" + sourceKey(remote)
	globalRate := s.rate(func(c Config) int { return c.GlobalRatePerMinute }, defaultGlobalRatePerMinute)
	sourceRate := s.rate(func(c Config) int { return c.PerIPRatePerMinute }, defaultPerIPRatePerMinute)
	s.mu.Lock()
	now := s.now()
	s.evictIdleSources(now)
	global := s.refillBucket("pre:global", globalRate, now)
	if global.tokens < 1 {
		s.mu.Unlock()
		s.sampleWarn("rate limited", "scope", "global", "path", r.URL.Path, "remote", remote)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return remote, false
	}
	source := s.sourceBucket(key, sourceRate, now)
	if source.tokens < 1 {
		s.mu.Unlock()
		s.sampleWarn("rate limited", "scope", "ip", "path", r.URL.Path, "remote", remote)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return remote, false
	}
	global.tokens--
	source.tokens--
	s.mu.Unlock()
	return remote, true
}

// sourceKey aggregates IPv6 clients to /64. IPv4 stays one address. Unparsed
// values are kept whole so two different garbage strings do not share a bucket.
func sourceKey(remote string) string {
	ip, err := netip.ParseAddr(remote)
	if err != nil {
		return remote
	}
	ip = ip.Unmap()
	if !ip.Is6() {
		return ip.String()
	}
	p, err := ip.Prefix(64)
	if err != nil {
		return ip.String()
	}
	return p.String()
}

// refillBucket updates a token bucket and creates it full when missing.
// Caller holds s.mu.
func (s *Server) refillBucket(key string, rate float64, now time.Time) *bucket {
	if rate <= 0 {
		rate = defaultTenantRate
	}
	b := s.buckets[key]
	if b == nil {
		b = &bucket{tokens: rate, last: now}
		s.buckets[key] = b
		return b
	}
	elapsed := now.Sub(b.last).Minutes() * rate
	b.tokens += elapsed
	if b.tokens > rate {
		b.tokens = rate
	}
	b.last = now
	return b
}

// sourceBucket returns the per-source bucket, creating it when absent.
// A new key evicts the least recently used source first so the map cannot
// grow past maxSourceBuckets. Caller holds s.mu. Idle entries are already gone.
func (s *Server) sourceBucket(key string, rate float64, now time.Time) *bucket {
	if b := s.buckets[key]; b != nil {
		return s.refillBucket(key, rate, now)
	}
	s.evictOldestSource()
	return s.refillBucket(key, rate, now)
}

func (s *Server) evictIdleSources(now time.Time) {
	for key, b := range s.buckets {
		if strings.HasPrefix(key, "pre:ip:") && now.Sub(b.last) >= sourceBucketIdle {
			delete(s.buckets, key)
		}
	}
}

func (s *Server) evictOldestSource() {
	n := 0
	oldestKey := ""
	var oldest time.Time
	for key, b := range s.buckets {
		if !strings.HasPrefix(key, "pre:ip:") {
			continue
		}
		n++
		if oldestKey == "" || b.last.Before(oldest) {
			oldestKey = key
			oldest = b.last
		}
	}
	if n >= maxSourceBuckets && oldestKey != "" {
		delete(s.buckets, oldestKey)
	}
}

func (s *Server) rate(pick func(Config) int, fallback int) float64 {
	s.mu.Lock()
	n := pick(s.cfg)
	s.mu.Unlock()
	if n <= 0 {
		n = fallback
	}
	return float64(n)
}

func (s *Server) allowKeyed(key string, rate float64) bool {
	if rate <= 0 {
		rate = defaultTenantRate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.refillBucket(key, rate, s.now())
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sampleWarn logs at most one failed-auth line per authLogInterval and
// reports how many were dropped. The token itself is never included.
func (s *Server) sampleWarn(msg string, args ...any) {
	s.mu.Lock()
	now := s.now()
	if !s.authLogNext.IsZero() && now.Before(s.authLogNext) {
		s.authLogSkipped++
		s.mu.Unlock()
		return
	}
	skipped := s.authLogSkipped
	s.authLogSkipped = 0
	s.authLogNext = now.Add(authLogInterval)
	s.mu.Unlock()
	if skipped > 0 {
		args = append(args, "suppressed", skipped)
	}
	s.log.Warn(msg, args...)
}

func (s *Server) clientIP(r *http.Request) string {
	s.mu.Lock()
	trusted := s.trusted
	s.mu.Unlock()
	return resolveClientIP(r.RemoteAddr, forwardedFor(r), trusted)
}

func forwardedFor(r *http.Request) string {
	return strings.Join(r.Header.Values("X-Forwarded-For"), ",")
}

// resolveClientIP uses the rightmost-untrusted algorithm. The header is
// ignored unless the TCP peer is inside trusted, so a client that can
// connect directly cannot pick its own bucket key.
func resolveClientIP(remoteAddr, xff string, trusted []netip.Prefix) string {
	if remoteAddr == "" {
		return "unknown"
	}
	peer, ok := addrFromRemote(remoteAddr)
	if !ok || !prefixContains(trusted, peer) {
		if ok {
			return peer.Unmap().String()
		}
		return remoteAddr
	}
	parts := splitXFF(xff)
	for i := len(parts) - 1; i >= 0; i-- {
		ip, parsed := parseIPToken(parts[i])
		if !parsed {
			return parts[i]
		}
		if prefixContains(trusted, ip) {
			continue
		}
		return ip.Unmap().String()
	}
	if len(parts) > 0 {
		return parts[0]
	}
	return peer.Unmap().String()
}

func addrFromRemote(remote string) (netip.Addr, bool) {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func parseIPToken(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func splitXFF(xff string) []string {
	if strings.TrimSpace(xff) == "" {
		return nil
	}
	raw := strings.Split(xff, ",")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func prefixContains(ps []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
