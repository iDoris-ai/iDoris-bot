// Package enroll implements the iDoris enrollment service: the only component
// that holds a Headscale API key. Client daemons present a per-tenant
// enrollment token and receive a short-lived, single-use Headscale
// pre-authenticated key plus the control URL to use. The Headscale API key
// never leaves the operator's side.
package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

// Tenant is one organisation served by the Headscale instance. It maps to a
// Headscale user; every node enrolled through it belongs to that user.
type Tenant struct {
	Name string `json:"name"`
	// HeadscaleUserID is the numeric id (decimal string) of the Headscale user.
	HeadscaleUserID string `json:"headscale_user_id"`
	// TokenHashes are hex-encoded SHA-256 digests of accepted enrollment tokens.
	TokenHashes []string `json:"token_hashes"`
	// ACLTags are applied to nodes enrolled with this tenant (optional).
	ACLTags []string `json:"acl_tags,omitempty"`
	// Role is the join-code role minted for this entry: member, local-ai,
	// gateway, or admin. Empty means member when an invite is issued.
	Role string `json:"role,omitempty"`
	// LANCIDRs is the list of prefixes the organisation has pre-approved for
	// subnet routers. It must match autoApprovers.routes on the Headscale
	// policy. Discover returns it; this service never approves a route itself.
	LANCIDRs []string `json:"lan_cidrs,omitempty"`
	// PreAuthTTL bounds the validity of each minted key. Zero means 10 minutes.
	PreAuthTTL Duration `json:"preauth_ttl,omitempty"`
	// Ephemeral marks enrolled nodes as ephemeral (removed when offline).
	Ephemeral bool `json:"ephemeral,omitempty"`
	// RatePerMinute caps successful enrollments per minute. Zero means 30.
	RatePerMinute int `json:"rate_per_minute,omitempty"`
}

// Config is the on-disk configuration of the enrollment service.
type Config struct {
	// ControlURL is what clients are told to use as Tailscale login server.
	ControlURL string `json:"control_url"`
	// HeadscaleURL is where the service reaches the Headscale API. Defaults to ControlURL.
	HeadscaleURL string `json:"headscale_url,omitempty"`
	// HeadscaleAPIKeyFile holds the API key (one line). Can also be given via env.
	HeadscaleAPIKeyFile string   `json:"headscale_api_key_file,omitempty"`
	Tenants             []Tenant `json:"tenants"`
}

// Duration is a time.Duration that JSON-encodes as "10m".
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Validate checks the configuration for obvious mistakes.
func (c *Config) Validate() error {
	if !strings.HasPrefix(c.ControlURL, "https://") && !strings.HasPrefix(c.ControlURL, "http://") {
		return errors.New("control_url must be an http(s) URL")
	}
	if len(c.Tenants) == 0 {
		return errors.New("at least one tenant is required")
	}
	seen := map[string]bool{}
	for i, t := range c.Tenants {
		if t.Name == "" {
			return fmt.Errorf("tenant[%d]: name is required", i)
		}
		if seen[t.Name] {
			return fmt.Errorf("tenant %q: duplicate name", t.Name)
		}
		seen[t.Name] = true
		if t.HeadscaleUserID == "" {
			return fmt.Errorf("tenant %q: headscale_user_id is required", t.Name)
		}
		if len(t.TokenHashes) == 0 {
			return fmt.Errorf("tenant %q: at least one token hash is required", t.Name)
		}
		for _, h := range t.TokenHashes {
			if b, err := hex.DecodeString(h); err != nil || len(b) != sha256.Size {
				return fmt.Errorf("tenant %q: token hash %q is not a hex SHA-256", t.Name, h)
			}
		}
		if time.Duration(t.PreAuthTTL) > time.Hour {
			return fmt.Errorf("tenant %q: preauth_ttl must be <= 1h", t.Name)
		}
		if t.Role != "" && !join.ValidRole(t.Role) {
			return fmt.Errorf("tenant %q: role %q is not member, local-ai, gateway, or admin", t.Name, t.Role)
		}
		for _, cidr := range t.LANCIDRs {
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				return fmt.Errorf("tenant %q: lan_cidrs %q: %w", t.Name, cidr, err)
			}
			if p.Masked() != p {
				return fmt.Errorf("tenant %q: lan_cidrs %q has host bits set", t.Name, cidr)
			}
		}
	}
	return nil
}

// Request is the body sent by a daemon.
type Request struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	DaemonVersion string `json:"daemon_version,omitempty"`
}

// Response is what the daemon receives.
type Response struct {
	ControlURL string    `json:"control_url"`
	AuthKey    string    `json:"auth_key"`
	ExpiresAt  time.Time `json:"expires_at"`
	Tenant     string    `json:"tenant"`
	ACLTags    []string  `json:"acl_tags,omitempty"`
}

// Discovery tells a daemon which control server its tenant uses, without
// minting a key. Daemons call it at startup when control_url is not pinned.
// Role and LANCIDRs describe the pre-approved gateway plan. They are empty
// when the operator has not set them. Discover never mints a key.
type Discovery struct {
	ControlURL string   `json:"control_url"`
	Tenant     string   `json:"tenant"`
	Role       string   `json:"role,omitempty"`
	LANCIDRs   []string `json:"lan_cidrs,omitempty"`
}

// Minter is the subset of the Headscale client the server needs.
type Minter interface {
	CreatePreAuthKey(ctx context.Context, req headscale.CreatePreAuthKeyRequest) (*headscale.PreAuthKey, error)
}

// Server is the HTTP enrollment endpoint.
type Server struct {
	cfg    Config
	minter Minter
	log    *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewServer validates cfg and returns a server.
func NewServer(cfg Config, minter Minter, log *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if minter == nil {
		return nil, errors.New("enroll: minter is nil")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, minter: minter, log: log, now: time.Now, buckets: map[string]*bucket{}}, nil
}

// Handler returns the HTTP mux for the service.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /v1/discover", s.handleDiscover)
	return mux
}

// HashToken returns the hex SHA-256 of a token, the format stored in Config.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewToken generates a random enrollment token (URL-safe, 256 bits).
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "idv1_" + hex.EncodeToString(b), nil
}

// Reload swaps in cfg after Validate. A failed validation leaves the previous
// config serving. Rate-limit buckets are kept so a reload cannot reset them.
func (s *Server) Reload(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	return nil
}

// lookupLocked finds the tenant owning token. The caller holds s.mu. It always
// walks every hash so the match does not leak which entry succeeded.
func (s *Server) lookupLocked(token string) (Tenant, bool) {
	want := sha256.Sum256([]byte(token))
	found := -1
	for i := range s.cfg.Tenants {
		t := &s.cfg.Tenants[i]
		for _, h := range t.TokenHashes {
			b, err := hex.DecodeString(h)
			if err != nil || len(b) != sha256.Size {
				continue
			}
			if subtle.ConstantTimeCompare(b, want[:]) == 1 && found < 0 {
				found = i
			}
		}
	}
	if found < 0 {
		return Tenant{}, false
	}
	return cloneTenant(s.cfg.Tenants[found]), true
}

func cloneTenant(t Tenant) Tenant {
	t.TokenHashes = append([]string(nil), t.TokenHashes...)
	t.ACLTags = append([]string(nil), t.ACLTags...)
	t.LANCIDRs = append([]string(nil), t.LANCIDRs...)
	return t
}

func (s *Server) controlURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.ControlURL
}

func (s *Server) allow(t *Tenant) bool {
	rate := float64(t.RatePerMinute)
	if rate <= 0 {
		rate = 30
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	b := s.buckets[t.Name]
	if b == nil {
		b = &bucket{tokens: rate, last: now}
		s.buckets[t.Name] = b
	}
	b.tokens += now.Sub(b.last).Minutes() * rate
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// authenticate resolves the bearer token to a tenant or writes a 401.
// The returned tenant is a copy, safe to use after a concurrent Reload.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (Tenant, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) || len(auth) <= len(prefix) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
		return Tenant{}, false
	}
	s.mu.Lock()
	tenant, ok := s.lookupLocked(strings.TrimSpace(auth[len(prefix):]))
	s.mu.Unlock()
	if !ok {
		s.log.Warn("rejected: unknown token", "path", r.URL.Path, "remote", r.RemoteAddr)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return Tenant{}, false
	}
	return tenant, true
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, Discovery{
		ControlURL: s.controlURL(),
		Tenant:     tenant.Name,
		Role:       tenant.Role,
		LANCIDRs:   tenant.LANCIDRs,
	})
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var req Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}
	if !s.allow(&tenant) {
		s.log.Warn("enroll rate limited", "tenant", tenant.Name, "remote", r.RemoteAddr)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return
	}
	ttl := time.Duration(tenant.PreAuthTTL)
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	exp := s.now().Add(ttl)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	key, err := s.minter.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		UserID:     tenant.HeadscaleUserID,
		Reusable:   false,
		Ephemeral:  tenant.Ephemeral,
		Expiration: exp,
		ACLTags:    tenant.ACLTags,
	})
	if err != nil {
		s.log.Error("enroll: headscale preauthkey failed", "tenant", tenant.Name, "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "control server unavailable"})
		return
	}
	s.log.Info("enrolled", "tenant", tenant.Name, "hostname", req.Hostname, "os", req.OS, "key_id", key.ID, "expires_at", exp.UTC().Format(time.RFC3339))
	writeJSON(w, http.StatusOK, Response{
		ControlURL: s.controlURL(),
		AuthKey:    key.Key,
		ExpiresAt:  exp.UTC(),
		Tenant:     tenant.Name,
		ACLTags:    tenant.ACLTags,
	})
}
