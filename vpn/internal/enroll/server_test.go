package enroll

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
)

type fakeMinter struct {
	calls []headscale.CreatePreAuthKeyRequest
	err   error
}

func (f *fakeMinter) CreatePreAuthKey(_ context.Context, req headscale.CreatePreAuthKeyRequest) (*headscale.PreAuthKey, error) {
	f.calls = append(f.calls, req)
	if f.err != nil {
		return nil, f.err
	}
	return &headscale.PreAuthKey{ID: "42", Key: "hskey-" + req.UserID, Expiration: req.Expiration}, nil
}

func newTestServer(t *testing.T, m Minter) (*Server, string) {
	t.Helper()
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ControlURL: "https://vpn.example.org",
		Tenants: []Tenant{{
			Name:            "acme",
			HeadscaleUserID: "1",
			TokenHashes:     []string{HashToken(tok)},
			ACLTags:         []string{"tag:member"},
			PreAuthTTL:      Duration(5 * time.Minute),
			RatePerMinute:   2,
		}},
	}
	s, err := NewServer(cfg, m, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s, tok
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

func TestEnrollHappyPath(t *testing.T) {
	m := &fakeMinter{}
	s, tok := newTestServer(t, m)
	base := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	c := &Client{URL: ts.URL, Token: tok, AllowInsecure: true}
	resp, err := c.Fetch(context.Background(), Request{Hostname: "mbp", OS: "darwin"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.AuthKey != "hskey-1" || resp.ControlURL != "https://vpn.example.org" || resp.Tenant != "acme" {
		t.Fatalf("bad response %+v", resp)
	}
	if !resp.ExpiresAt.Equal(base.Add(5 * time.Minute)) {
		t.Fatalf("expires_at %v", resp.ExpiresAt)
	}
	if len(m.calls) != 1 || m.calls[0].Reusable || m.calls[0].UserID != "1" || len(m.calls[0].ACLTags) != 1 {
		t.Fatalf("minter calls %+v", m.calls)
	}
}

func TestEnrollRejectsBadToken(t *testing.T) {
	m := &fakeMinter{}
	s, _ := newTestServer(t, m)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	c := &Client{URL: ts.URL, Token: "idv1_wrong", AllowInsecure: true}
	_, err := c.Fetch(context.Background(), Request{})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
	if len(m.calls) != 0 {
		t.Fatal("minter must not be called for a rejected token")
	}
	// No Authorization header at all.
	r, _ := http.Post(ts.URL+"/v1/enroll", "application/json", strings.NewReader("{}"))
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", r.StatusCode)
	}
}

func TestEnrollRateLimitAndUpstreamFailure(t *testing.T) {
	m := &fakeMinter{}
	s, tok := newTestServer(t, m)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	c := &Client{URL: ts.URL, Token: tok, AllowInsecure: true}
	for i := 0; i < 2; i++ {
		if _, err := c.Fetch(context.Background(), Request{}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	_, err := c.Fetch(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("expected 429, got %v", err)
	}
	now = now.Add(time.Minute) // bucket refills
	m.err = errors.New("boom")
	_, err = c.Fetch(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("expected 502 on upstream failure, got %v", err)
	}
}

func TestDiscoverDoesNotMint(t *testing.T) {
	m := &fakeMinter{}
	s, tok := newTestServer(t, m)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	d, err := (&Client{URL: ts.URL, Token: tok, AllowInsecure: true}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.ControlURL != "https://vpn.example.org" || d.Tenant != "acme" || d.Role != "" || len(d.LANCIDRs) != 0 {
		t.Fatalf("bad discovery %+v", d)
	}
	if len(m.calls) != 0 {
		t.Fatalf("discover must not mint keys, got %d calls", len(m.calls))
	}
	_, err = (&Client{URL: ts.URL, Token: "idv1_wrong", AllowInsecure: true}).Discover(context.Background())
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("expected ErrRejected for bad token, got %v", err)
	}
}

func TestClientRefusesPlainHTTPByDefault(t *testing.T) {
	c := &Client{URL: "http://enroll.example.org", Token: "x"}
	if _, err := c.Fetch(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("expected non-https refusal, got %v", err)
	}
}

func TestDiscoverReturnsRoleAndApprovedCIDRs(t *testing.T) {
	m := &fakeMinter{}
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ControlURL: "https://vpn.example.org",
		Tenants: []Tenant{{
			Name:            "acme",
			HeadscaleUserID: "1",
			TokenHashes:     []string{HashToken(tok)},
			Role:            "gateway",
			LANCIDRs:        []string{"10.251.73.10/32", "10.20.0.0/16"},
		}},
	}
	s, err := NewServer(cfg, m, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	d, err := (&Client{URL: ts.URL, Token: tok, AllowInsecure: true}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Role != "gateway" || len(d.LANCIDRs) != 2 || d.LANCIDRs[0] != "10.251.73.10/32" {
		t.Fatalf("discovery %+v", d)
	}
	if len(m.calls) != 0 {
		t.Fatal("discover minted a key")
	}
}

func TestReloadKeepsOldConfigWhenNewOneIsInvalid(t *testing.T) {
	m := &fakeMinter{}
	s, tok := newTestServer(t, m)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	bad := Config{
		ControlURL: "https://vpn.example.org",
		Tenants:    []Tenant{{Name: "acme", HeadscaleUserID: "1", TokenHashes: []string{"nope"}, LANCIDRs: []string{"192.168.1.1/24"}}},
	}
	if err := s.Reload(bad); err == nil {
		t.Fatal("invalid config was accepted")
	}
	d, err := (&Client{URL: ts.URL, Token: tok, AllowInsecure: true}).Discover(context.Background())
	if err != nil || d.Tenant != "acme" {
		t.Fatalf("old config dropped: %v %+v", err, d)
	}

	nextTok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	good := Config{
		ControlURL: "https://vpn.example.org",
		Tenants: []Tenant{{
			Name:            "acme",
			HeadscaleUserID: "9",
			TokenHashes:     []string{HashToken(nextTok)},
			Role:            "local-ai",
			LANCIDRs:        []string{"192.168.50.9/32"},
		}},
	}
	if err := s.Reload(good); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Client{URL: ts.URL, Token: tok, AllowInsecure: true}).Discover(context.Background()); !errors.Is(err, ErrRejected) {
		t.Fatalf("old token still accepted: %v", err)
	}
	d, err = (&Client{URL: ts.URL, Token: nextTok, AllowInsecure: true}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Role != "local-ai" || len(d.LANCIDRs) != 1 || d.LANCIDRs[0] != "192.168.50.9/32" {
		t.Fatalf("reloaded discovery %+v", d)
	}
	if len(m.calls) != 0 {
		t.Fatal("reload path minted a key")
	}
}

func TestConfigValidate(t *testing.T) {
	good := Config{ControlURL: "https://x", Tenants: []Tenant{{Name: "a", HeadscaleUserID: "1", TokenHashes: []string{HashToken("t")}}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.Tenants = []Tenant{{Name: "a", HeadscaleUserID: "1", TokenHashes: []string{"zz"}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected invalid hash error")
	}
	bad = good
	bad.Tenants = []Tenant{{Name: "a", HeadscaleUserID: "1", TokenHashes: []string{HashToken("t")}, PreAuthTTL: Duration(2 * time.Hour)}}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected ttl error")
	}
	bad = good
	bad.Tenants = append(bad.Tenants, bad.Tenants[0])
	if err := bad.Validate(); err == nil {
		t.Fatal("expected duplicate tenant error")
	}
	bad = good
	bad.Tenants = []Tenant{{Name: "a", HeadscaleUserID: "1", TokenHashes: []string{HashToken("t")}, Role: "boss"}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("role: %v", err)
	}
	bad = good
	bad.Tenants = []Tenant{{Name: "a", HeadscaleUserID: "1", TokenHashes: []string{HashToken("t")}, LANCIDRs: []string{"192.168.1.1/24"}}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "host bits") {
		t.Fatalf("cidr: %v", err)
	}
	bad = good
	bad.Tenants = []Tenant{{Name: "a", HeadscaleUserID: "1", TokenHashes: []string{HashToken("t")}, LANCIDRs: []string{"not-a-cidr"}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected cidr parse error")
	}
	ok := good
	ok.Tenants = []Tenant{{Name: "a", HeadscaleUserID: "1", TokenHashes: []string{HashToken("t")}, Role: "gateway", LANCIDRs: []string{"192.168.1.0/24"}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}
