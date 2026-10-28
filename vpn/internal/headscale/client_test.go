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

func TestCreatePreAuthKey(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/preauthkey" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		b, _ := json.Marshal(m)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"preAuthKey":{"id":"7","key":"abc123","reusable":false,"ephemeral":false,"used":false,"expiration":"2026-10-27T10:00:00Z","createdAt":"2026-10-27T09:50:00Z","aclTags":["tag:member"],"user":{"id":"1","name":"acme"}}}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL + "/", APIKey: "k"}
	exp := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	k, err := c.CreatePreAuthKey(context.Background(), CreatePreAuthKeyRequest{UserID: "1", Expiration: exp, ACLTags: []string{"tag:member"}})
	if err != nil {
		t.Fatal(err)
	}
	if k.Key != "abc123" || k.ID != "7" || k.User == nil || k.User.Name != "acme" {
		t.Fatalf("bad key: %+v", k)
	}
	if gotAuth != "Bearer k" {
		t.Fatalf("auth header %q", gotAuth)
	}
	if gotBody != `{"aclTags":["tag:member"],"ephemeral":false,"expiration":"2026-10-27T10:00:00Z","reusable":false,"user":"1"}` {
		t.Fatalf("body %s", gotBody)
	}
}

func TestCreatePreAuthKeyValidation(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1"}
	if _, err := c.CreatePreAuthKey(context.Background(), CreatePreAuthKeyRequest{Expiration: time.Now()}); err == nil {
		t.Fatal("expected error for missing user")
	}
	if _, err := c.CreatePreAuthKey(context.Background(), CreatePreAuthKeyRequest{UserID: "1"}); err == nil {
		t.Fatal("expected error for missing expiration")
	}
}

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, APIKey: "bad"}
	_, err := c.ListUsers(context.Background(), "")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 401 {
		t.Fatalf("expected APIError 401, got %v", err)
	}
}

func TestEnsureUser(t *testing.T) {
	created := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user":
			if r.URL.Query().Get("name") == "acme" && created > 0 {
				_, _ = w.Write([]byte(`{"users":[{"id":"3","name":"acme"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"users":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/user":
			created++
			_, _ = w.Write([]byte(`{"user":{"id":"3","name":"acme"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, APIKey: "k"}
	u, err := c.EnsureUser(context.Background(), "acme")
	if err != nil || u.ID != "3" {
		t.Fatalf("first ensure: %v %+v", err, u)
	}
	u, err = c.EnsureUser(context.Background(), "acme")
	if err != nil || u.ID != "3" || created != 1 {
		t.Fatalf("second ensure: %v %+v created=%d", err, u, created)
	}
	if _, err := c.CreateUser(context.Background(), "bad@"); err == nil {
		t.Fatal("name ending in @ must be rejected")
	}
}
