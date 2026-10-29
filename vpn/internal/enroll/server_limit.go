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

// admit spends one global token and one per-IP token. It runs before the
// bearer token is hashed. A closed bucket writes 429 and returns ok=false.
func (s *Server) admit(w http.ResponseWriter, r *http.Request) (string, bool) {
	remote := s.clientIP(r)
	if !s.allowKeyed("pre:global", s.rate(func(c Config) int { return c.GlobalRatePerMinute }, defaultGlobalRatePerMinute)) {
		s.sampleWarn("rate limited", "scope", "global", "path", r.URL.Path, "remote", remote)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return remote, false
	}
	if !s.allowKeyed("pre:ip:"+remote, s.rate(func(c Config) int { return c.PerIPRatePerMinute }, defaultPerIPRatePerMinute)) {
		s.sampleWarn("rate limited", "scope", "ip", "path", r.URL.Path, "remote", remote)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return remote, false
	}
	return remote, true
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
	now := s.now()
	b := s.buckets[key]
	if b == nil {
		b = &bucket{tokens: rate, last: now}
		s.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Minutes() * rate
	b.tokens += elapsed
	if b.tokens > rate {
		b.tokens = rate
	}
	b.last = now
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
