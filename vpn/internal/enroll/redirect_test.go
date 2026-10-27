package enroll

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClientRefusesRedirectToHTTPAndOtherHost(t *testing.T) {
	var httpHits, otherHits atomic.Int32
	record := func(n *atomic.Int32) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n.Add(1)
			if r.Header.Get("Authorization") != "" {
				t.Errorf("bearer token reached %s", r.URL)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"control_url":"https://vpn.example","auth_key":"leaked"}`)
		})
	}
	plain := httptest.NewServer(record(&httpHits))
	t.Cleanup(plain.Close)
	other := httptest.NewTLSServer(record(&otherHits))
	t.Cleanup(other.Close)

	for _, tc := range []struct {
		name string
		dest string
	}{
		{name: "http", dest: plain.URL + "/v1/enroll"},
		{name: "other-host", dest: other.URL + "/v1/enroll"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
					t.Errorf("origin missing bearer: %q", r.Header.Get("Authorization"))
				}
				http.Redirect(w, r, tc.dest, http.StatusFound)
			}))
			t.Cleanup(origin.Close)
			c := &Client{
				URL:   origin.URL,
				Token: "idv1_secret",
				HTTP:  origin.Client(),
			}
			_, err := c.Fetch(context.Background(), Request{Hostname: "mbp"})
			if err == nil || !errors.Is(err, ErrRedirect) || !strings.Contains(err.Error(), tc.dest) {
				t.Fatalf("expected redirect refusal naming %s, got %v", tc.dest, err)
			}
			_, err = c.Discover(context.Background())
			if err == nil || !errors.Is(err, ErrRedirect) {
				t.Fatalf("discover followed a redirect: %v", err)
			}
		})
	}
	if httpHits.Load() != 0 || otherHits.Load() != 0 {
		t.Fatalf("redirect targets were contacted: http=%d other=%d", httpHits.Load(), otherHits.Load())
	}
}

func TestClientRefusesRedirectWithoutLocation(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)
	c := &Client{URL: origin.URL, Token: "idv1_secret", HTTP: origin.Client()}
	_, err := c.Discover(context.Background())
	if err == nil || !errors.Is(err, ErrRedirect) || !strings.Contains(err.Error(), "no Location") {
		t.Fatalf("got %v", err)
	}
}
