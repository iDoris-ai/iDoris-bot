package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

func TestR4CPrepareKeysStaticSkipsDiscovery(t *testing.T) {
	cfg := &vpnd.Config{
		ControlURL: "https://vpn.idoris.example",
		AuthKey:    "tskey-auth-example",
		StateFile:  filepath.Join(t.TempDir(), "state.json"),
	}
	_, url, ident, _, confirmed, err := prepareKeys(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if !ident.Static || ident.Known || ident.Tenant != "" || ident.Role != "" {
		t.Fatalf("identity %+v", ident)
	}
	if url != cfg.ControlURL || !confirmed {
		t.Fatalf("url %q confirmed %v", url, confirmed)
	}
}

func TestR4CPrepareKeysDiscoveryFailureKeepsFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	const token = "idv1_example-token"
	cfg := &vpnd.Config{
		ControlURL:          "https://vpn.idoris.example",
		EnrollURL:           srv.URL,
		EnrollToken:         token,
		EnrollAllowInsecure: true,
		StateFile:           filepath.Join(t.TempDir(), "state.json"),
	}
	_, _, ident, _, confirmed, err := prepareKeys(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if ident.Known || ident.Static || ident.TokenFingerprint != vpnd.TokenFingerprint(token) {
		t.Fatalf("identity %+v", ident)
	}
	if confirmed {
		t.Fatal("discovery failure was treated as confirmed")
	}
}
