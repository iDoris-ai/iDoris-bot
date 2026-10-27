package headscale

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
				t.Errorf("api key reached %s", r.URL)
			}
			_, _ = io.WriteString(w, `{"users":[]}`)
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
		{name: "http", dest: plain.URL + "/api/v1/user"},
		{name: "other-host", dest: other.URL + "/api/v1/user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer hskey-test" {
					t.Errorf("origin auth %q", r.Header.Get("Authorization"))
				}
				http.Redirect(w, r, tc.dest, http.StatusFound)
			}))
			t.Cleanup(origin.Close)
			c := &Client{BaseURL: origin.URL, APIKey: "hskey-test", HTTP: origin.Client()}
			_, err := c.ListUsers(context.Background(), "")
			if err == nil || !errors.Is(err, ErrRedirect) || !strings.Contains(err.Error(), tc.dest) {
				t.Fatalf("expected redirect refusal naming %s, got %v", tc.dest, err)
			}
		})
	}
	if httpHits.Load() != 0 || otherHits.Load() != 0 {
		t.Fatalf("redirect targets were contacted: http=%d other=%d", httpHits.Load(), otherHits.Load())
	}
}
