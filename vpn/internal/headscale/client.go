// Package headscale is a minimal, dependency-free client for the Headscale
// REST API (/api/v1). It covers only what the iDoris VPN layer needs: users,
// pre-authenticated keys and node inspection. The surface mirrors the
// grpc-gateway JSON produced by headscale v0.29.x; uint64 identifiers are
// transported as decimal strings, exactly as the gateway emits them.
package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one Headscale server with one API key.
type Client struct {
	// BaseURL is the public URL of the Headscale server, e.g.
	// https://vpn.example.org. The /api/v1 prefix is appended by the client.
	BaseURL string
	// APIKey is a key produced by `headscale apikeys create`.
	APIKey string
	// HTTP is the transport. A nil value uses a client with a 15s timeout.
	HTTP *http.Client
}

// APIError is returned for any non-2xx response.
type APIError struct {
	Status int
	Method string
	Path   string
	Body   string
}

func (e *APIError) Error() string {
	body := e.Body
	if len(body) > 300 {
		body = body[:300] + "…"
	}
	return fmt.Sprintf("headscale %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, strings.TrimSpace(body))
}

// User is a Headscale user (a tenant namespace in iDoris terms).
type User struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName,omitempty"`
	Email       string    `json:"email,omitempty"`
	CreatedAt   time.Time `json:"createdAt,omitempty"`
}

// PreAuthKey is a node registration key.
type PreAuthKey struct {
	ID         string    `json:"id"`
	Key        string    `json:"key"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration"`
	CreatedAt  time.Time `json:"createdAt"`
	ACLTags    []string  `json:"aclTags"`
	User       *User     `json:"user,omitempty"`
}

// Node is a registered machine.
type Node struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	GivenName   string    `json:"givenName"`
	IPAddresses []string  `json:"ipAddresses"`
	Online      bool      `json:"online"`
	LastSeen    time.Time `json:"lastSeen"`
	Expiry      time.Time `json:"expiry"`
	Tags        []string  `json:"tags"`
	User        *User     `json:"user,omitempty"`
}

// CreatePreAuthKeyRequest mirrors v1CreatePreAuthKeyRequest.
type CreatePreAuthKeyRequest struct {
	// UserID is the numeric Headscale user id as a decimal string.
	UserID     string
	Reusable   bool
	Ephemeral  bool
	Expiration time.Time
	ACLTags    []string
}

// ErrRedirect is wrapped when an authenticated call receives a 3xx.
// The Location value is in the error text. The API key was not sent there.
var ErrRedirect = errors.New("refusing redirect")

// httpClient returns a client that never follows redirects. A caller-supplied
// client is copied so its CheckRedirect is not mutated; its Transport is kept
// so tests can trust an httptest certificate. The default client follows
// redirects and would resend the bearer token, including to an http:// origin.
func (c *Client) httpClient() *http.Client {
	hc := &http.Client{Timeout: 15 * time.Second}
	if c.HTTP != nil {
		cp := *c.HTTP
		hc = &cp
		if hc.Timeout == 0 {
			hc.Timeout = 15 * time.Second
		}
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return hc
}

func errRefusingRedirect(resp *http.Response) error {
	loc := ""
	code := 0
	if resp != nil {
		code = resp.StatusCode
		loc = strings.TrimSpace(resp.Header.Get("Location"))
	}
	if loc == "" {
		return fmt.Errorf("%w: HTTP %d with no Location", ErrRedirect, code)
	}
	return fmt.Errorf("%w to %q", ErrRedirect, loc)
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	if c.BaseURL == "" {
		return errors.New("headscale: BaseURL is empty")
	}
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/") + path)
	if err != nil {
		return fmt.Errorf("headscale: bad url: %w", err)
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("headscale: encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("headscale %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return fmt.Errorf("headscale %s %s: %w", method, path, errRefusingRedirect(resp))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("headscale %s %s: read body: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Status: resp.StatusCode, Method: method, Path: path, Body: string(raw)}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("headscale %s %s: decode response: %w", method, path, err)
	}
	return nil
}

// Health checks the unauthenticated /health endpoint.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/health", nil, nil, nil)
}

// ListUsers returns all users, optionally filtered by exact name.
func (c *Client) ListUsers(ctx context.Context, name string) ([]User, error) {
	var q url.Values
	if name != "" {
		q = url.Values{"name": {name}}
	}
	var out struct {
		Users []User `json:"users"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/user", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

// CreateUser creates a user. Headscale rejects names ending in "@".
func (c *Client) CreateUser(ctx context.Context, name string) (*User, error) {
	if name == "" || strings.HasSuffix(name, "@") {
		return nil, fmt.Errorf("headscale: invalid user name %q", name)
	}
	var out struct {
		User *User `json:"user"`
	}
	in := map[string]string{"name": name}
	if err := c.do(ctx, http.MethodPost, "/api/v1/user", nil, in, &out); err != nil {
		return nil, err
	}
	if out.User == nil {
		return nil, errors.New("headscale: CreateUser returned no user")
	}
	return out.User, nil
}

// EnsureUser returns the user with the given name, creating it when absent.
func (c *Client) EnsureUser(ctx context.Context, name string) (*User, error) {
	users, err := c.ListUsers(ctx, name)
	if err != nil {
		var ae *APIError
		// Older gateways answer 404/500 for an unknown name filter; fall through to create.
		if !errors.As(err, &ae) {
			return nil, err
		}
	}
	for i := range users {
		if users[i].Name == name {
			return &users[i], nil
		}
	}
	return c.CreateUser(ctx, name)
}

// CreatePreAuthKey mints a registration key.
func (c *Client) CreatePreAuthKey(ctx context.Context, req CreatePreAuthKeyRequest) (*PreAuthKey, error) {
	if req.UserID == "" {
		return nil, errors.New("headscale: CreatePreAuthKey requires UserID")
	}
	if req.Expiration.IsZero() {
		return nil, errors.New("headscale: CreatePreAuthKey requires Expiration")
	}
	in := struct {
		User       string    `json:"user"`
		Reusable   bool      `json:"reusable"`
		Ephemeral  bool      `json:"ephemeral"`
		Expiration time.Time `json:"expiration"`
		ACLTags    []string  `json:"aclTags,omitempty"`
	}{req.UserID, req.Reusable, req.Ephemeral, req.Expiration.UTC(), req.ACLTags}
	var out struct {
		PreAuthKey *PreAuthKey `json:"preAuthKey"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/preauthkey", nil, in, &out); err != nil {
		return nil, err
	}
	if out.PreAuthKey == nil || out.PreAuthKey.Key == "" {
		return nil, errors.New("headscale: CreatePreAuthKey returned no key")
	}
	return out.PreAuthKey, nil
}

// ExpirePreAuthKey invalidates one pre-auth key by id. Headscale v0.29
// accepts POST /api/v1/preauthkey/expire with {"id":"<decimal>"}. The key
// string itself is not sent. Callers use this when a key was minted under
// an authorization that is no longer current and must not be handed out.
func (c *Client) ExpirePreAuthKey(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("headscale: ExpirePreAuthKey requires id")
	}
	in := struct {
		ID string `json:"id"`
	}{ID: id}
	return c.do(ctx, http.MethodPost, "/api/v1/preauthkey/expire", nil, in, nil)
}

// ListNodes lists nodes, optionally restricted to a user (by name, as the
// gateway expects for this endpoint).
func (c *Client) ListNodes(ctx context.Context, userName string) ([]Node, error) {
	var q url.Values
	if userName != "" {
		q = url.Values{"user": {userName}}
	}
	var out struct {
		Nodes []Node `json:"nodes"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/node", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Nodes, nil
}

// ExpireNode forces a node to re-authenticate.
func (c *Client) ExpireNode(ctx context.Context, nodeID string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/node/"+url.PathEscape(nodeID)+"/expire", nil, nil, nil)
}

// DeleteNode removes a node.
func (c *Client) DeleteNode(ctx context.Context, nodeID string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/node/"+url.PathEscape(nodeID), nil, nil, nil)
}
