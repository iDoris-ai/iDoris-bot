package enroll

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

// Client is the daemon-side caller of the enrollment service.
type Client struct {
	// URL is the base URL of the enrollment service (no path).
	URL string
	// Token is the tenant enrollment token.
	Token string
	// AllowInsecure permits plain http:// (tests, lab networks).
	AllowInsecure bool
	HTTP          *http.Client
}

// ErrRejected is wrapped when the service answers 401/403.
var ErrRejected = errors.New("enrollment token rejected")

// do performs an authenticated call to the enrollment service and decodes a
// 200 response into out.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("enroll: invalid service url %q", c.URL)
	}
	if u.Scheme != "https" && (!c.AllowInsecure || u.Scheme != "http") {
		return fmt.Errorf("enroll: refusing non-https service url %q (set allow_insecure for labs)", c.URL)
	}
	if c.Token == "" {
		return errors.New("enroll: token is empty")
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	hr, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	hr.Header.Set("Authorization", "Bearer "+c.Token)
	if in != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(hr)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("enroll: HTTP %d: %w", resp.StatusCode, ErrRejected)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("enroll: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("enroll: decode: %w", err)
	}
	return nil
}

// Fetch obtains a fresh single-use pre-authenticated key.
func (c *Client) Fetch(ctx context.Context, req Request) (*Response, error) {
	var out Response
	if err := c.do(ctx, http.MethodPost, "/v1/enroll", req, &out); err != nil {
		return nil, err
	}
	if out.AuthKey == "" || out.ControlURL == "" {
		return nil, errors.New("enroll: response missing auth_key or control_url")
	}
	return &out, nil
}

// Discover returns the tenant's control URL without minting a key.
func (c *Client) Discover(ctx context.Context) (*Discovery, error) {
	var out Discovery
	if err := c.do(ctx, http.MethodGet, "/v1/discover", nil, &out); err != nil {
		return nil, err
	}
	if out.ControlURL == "" {
		return nil, errors.New("enroll: discover response missing control_url")
	}
	return &out, nil
}
