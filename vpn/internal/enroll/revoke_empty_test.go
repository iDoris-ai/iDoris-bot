package enroll

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR2GRevokeAllowEmpty(t *testing.T) {
	path := writeTenantFile(t, 0o600)
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := cfg.Tenants[0].TokenHashes[0]
	if _, err := RemoveCredential(path, "acme", CredentialMatch{HashPrefix: hash[:8]}); err == nil || err.Error() != "enroll: refusing to remove the last token hash" {
		t.Fatalf("without allow-empty: %v", err)
	}
	removed, err := RemoveCredential(path, "acme", CredentialMatch{HashPrefix: hash[:8], AllowEmpty: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(removed.Hash, hash) {
		t.Fatalf("removed %s", removed.Hash)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(loaded.Tenants) != 1 || len(loaded.Tenants[0].TokenHashes) != 0 || len(loaded.Tenants[0].Credentials) != 0 {
		t.Fatalf("entry %+v", loaded.Tenants[0])
	}
	m := &fakeMinter{}
	s, err := NewServer(*loaded, m, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(*loaded); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	reject := func(method, target, body, token string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, target, rdr)
		req.RemoteAddr = "198.51.100.20:9"
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized || strings.TrimSpace(rr.Body.String()) != `{"error":"invalid token"}` {
			t.Fatalf("%s %s: %d %s", method, target, rr.Code, rr.Body.String())
		}
	}
	reject(http.MethodGet, "/v1/discover", "", "seed-token")
	reject(http.MethodGet, "/v1/discover", "", "someone-else")
	reject(http.MethodPost, "/v1/enroll", `{"hostname":"mbp"}`, "seed-token")
	if len(m.calls) != 0 {
		t.Fatalf("minted %d", len(m.calls))
	}

	missingPath := filepath.Join(t.TempDir(), "missing.json")
	missing := []byte(`{"control_url":"https://vpn.example.org","tenants":[{"name":"acme","headscale_user_id":"1"}]}`)
	if err := os.WriteFile(missingPath, missing, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(missingPath); err == nil || !strings.Contains(err.Error(), "token_hashes is required") {
		t.Fatalf("missing field: %v", err)
	}
}
