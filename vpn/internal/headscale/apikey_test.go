package headscale

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeControlReadsMatchingKeyExpiry(t *testing.T) {
	secret := "hskey-longer.secret-value"
	exp := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	shorterExp := exp.Add(24 * time.Hour)
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/v1/apikey" {
			t.Errorf("path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiKeys": []map[string]any{
				{"id": "1", "prefix": "hs", "expiration": shorterExp.Format(time.RFC3339)},
				{"id": "2", "prefix": "hskey-longer", "expiration": exp.Format(time.RFC3339)},
				{"id": "3", "prefix": "other", "expiration": exp.Add(time.Hour).Format(time.RFC3339)},
			},
		})
	}))
	t.Cleanup(srv.Close)

	st, err := (&Client{BaseURL: srv.URL, APIKey: secret}).ProbeControl(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Known || !st.ExpiresAt.Equal(exp) {
		t.Fatalf("status %+v", st)
	}
	if sawAuth != "Bearer "+secret {
		t.Fatal("probe did not authenticate")
	}
}

func TestProbeControlFallsBackWhenKeyListIsMissing(t *testing.T) {
	secret := "hskey-fallback.secret"
	var userHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/apikey":
			http.NotFound(w, r)
		case "/api/v1/user":
			userHits++
			_, _ = w.Write([]byte(`{"users":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	st, err := (&Client{BaseURL: srv.URL, APIKey: secret}).ProbeControl(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Known || !st.ExpiresAt.IsZero() || userHits != 1 {
		t.Fatalf("status %+v userHits %d", st, userHits)
	}
}

func TestProbeControlRejectsUnauthorizedWithoutListingUsers(t *testing.T) {
	secret := "hskey-denied.secret"
	var userHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/user" {
			userHits++
		}
		http.Error(w, "denied "+secret, http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	_, err := (&Client{BaseURL: srv.URL, APIKey: secret}).ProbeControl(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		t.Fatalf("err %v", err)
	}
	if userHits != 0 {
		t.Fatal("401 fell through to the user list")
	}
}

func TestProbeControlUnknownWhenPrefixDoesNotMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"apiKeys":[{"id":"1","prefix":"other","expiration":"2026-12-01T00:00:00Z"}]}`))
	}))
	t.Cleanup(srv.Close)
	st, err := (&Client{BaseURL: srv.URL, APIKey: "hskey-mine.secret"}).ProbeControl(context.Background())
	if err != nil || st.Known {
		t.Fatalf("status %+v err %v", st, err)
	}
}
