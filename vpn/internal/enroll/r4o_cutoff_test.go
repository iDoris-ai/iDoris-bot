package enroll

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
)

// r4oGateMinter blocks inside CreatePreAuthKey until release is closed.
// The test reloads the server while the mint is in flight.
type r4oGateMinter struct {
	mu      sync.Mutex
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
	calls   []headscale.CreatePreAuthKeyRequest
	expired []string
	errExp  error
}

func (m *r4oGateMinter) CreatePreAuthKey(_ context.Context, req headscale.CreatePreAuthKeyRequest) (*headscale.PreAuthKey, error) {
	m.mu.Lock()
	m.calls = append(m.calls, req)
	m.mu.Unlock()
	m.once.Do(func() { close(m.entered) })
	<-m.release
	return &headscale.PreAuthKey{ID: "77", Key: "hskey-auth-r4o-secret", Expiration: req.Expiration}, nil
}

func (m *r4oGateMinter) ExpirePreAuthKey(_ context.Context, id string) error {
	m.mu.Lock()
	m.expired = append(m.expired, id)
	m.mu.Unlock()
	return m.errExp
}

func r4oCutoffServer(t *testing.T, m Minter, tok string) *Server {
	t.Helper()
	cfg := Config{
		ControlURL:          "https://vpn.example.org",
		GlobalRatePerMinute: 100,
		PerIPRatePerMinute:  100,
		Tenants: []Tenant{{
			Name:            "acme",
			HeadscaleUserID: "1",
			TokenHashes:     []string{HashToken(tok)},
			ACLTags:         []string{"tag:member"},
			PreAuthTTL:      Duration(5 * time.Minute),
			RatePerMinute:   10,
		}},
	}
	s, err := NewServer(cfg, m, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func r4oEnrollDuringMint(t *testing.T, s *Server, m *r4oGateMinter, tok string, reload func(Config) Config) *httptest.ResponseRecorder {
	t.Helper()
	release := make(chan struct{})
	m.release = release
	m.entered = make(chan struct{})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{"hostname":"slow","os":"linux"}`))
	req.RemoteAddr = "203.0.113.40:4000"
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.Handler().ServeHTTP(rr, req)
		close(done)
	}()
	select {
	case <-m.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("mint did not start")
	}
	s.mu.Lock()
	cur := s.cfg
	s.mu.Unlock()
	next := reload(cur)
	if err := s.Reload(next); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	return rr
}

func TestR4OMintCutoffRevoke(t *testing.T) {
	m := &r4oGateMinter{}
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	s := r4oCutoffServer(t, m, tok)
	rr := r4oEnrollDuringMint(t, s, m, tok, func(cfg Config) Config {
		cfg.Tenants[0].TokenHashes = nil
		cfg.Tenants[0].Credentials = nil
		return cfg
	})
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid token") {
		t.Fatalf("revoked during mint: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "hskey-auth-r4o-secret") || strings.Contains(rr.Body.String(), "auth_key") {
		t.Fatalf("revoked mint returned the key: %s", rr.Body.String())
	}
	if len(m.expired) != 1 || m.expired[0] != "77" {
		t.Fatalf("expire calls %+v", m.expired)
	}
	if len(m.calls) != 1 || m.calls[0].UserID != "1" {
		t.Fatalf("mint calls %+v", m.calls)
	}
}

func TestR4OMintCutoffTagsUser(t *testing.T) {
	m := &r4oGateMinter{}
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	s := r4oCutoffServer(t, m, tok)
	rr := r4oEnrollDuringMint(t, s, m, tok, func(cfg Config) Config {
		cfg.Tenants[0].HeadscaleUserID = "9"
		cfg.Tenants[0].ACLTags = []string{"tag:other"}
		return cfg
	})
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid token") {
		t.Fatalf("tags changed during mint: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "hskey-auth-r4o-secret") {
		t.Fatalf("changed auth returned the key: %s", rr.Body.String())
	}
	if len(m.expired) != 1 || m.expired[0] != "77" {
		t.Fatalf("expire calls %+v", m.expired)
	}
	if len(m.calls) != 1 || m.calls[0].UserID != "1" || len(m.calls[0].ACLTags) != 1 || m.calls[0].ACLTags[0] != "tag:member" {
		t.Fatalf("mint used current instead of captured auth: %+v", m.calls)
	}
}

func TestR4OMintCutoffSameAuthReturnsKey(t *testing.T) {
	m := &r4oGateMinter{}
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	s := r4oCutoffServer(t, m, tok)
	rr := r4oEnrollDuringMint(t, s, m, tok, func(cfg Config) Config {
		cfg.GlobalRatePerMinute = 50
		return cfg
	})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "hskey-auth-r4o-secret") {
		t.Fatalf("unchanged authorization: %d %s", rr.Code, rr.Body.String())
	}
	if len(m.expired) != 0 {
		t.Fatalf("expire calls %+v", m.expired)
	}
}
