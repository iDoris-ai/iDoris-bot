package headscale

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// APIKey is one entry from GET /api/v1/apikey. Headscale returns the prefix
// only; the secret half of the key is not in this payload.
type APIKey struct {
	ID         string     `json:"id"`
	Prefix     string     `json:"prefix"`
	Expiration *time.Time `json:"expiration,omitempty"`
	CreatedAt  time.Time  `json:"createdAt,omitempty"`
	LastSeen   time.Time  `json:"lastSeen,omitempty"`
}

// KeyStatus is what ProbeControl could learn about the caller's own API key.
// Known is false when the server accepted the key but did not say when it
// expires (no matching prefix, a null expiration, or a build without the
// key-list route).
type KeyStatus struct {
	ExpiresAt time.Time
	Known     bool
}

// ListAPIKeys lists API keys. It is the cheap authenticated call used to
// prove the configured key is still accepted.
func (c *Client) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	var out struct {
		APIKeys []APIKey `json:"apiKeys"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/apikey", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.APIKeys, nil
}

// ProbeControl checks that the API key is accepted and, when the key list
// exposes it, when that key expires. A 404 on the key list falls back to
// listing users: the key is valid and the expiry is unknown. The key is not
// written into the error.
func (c *Client) ProbeControl(ctx context.Context) (KeyStatus, error) {
	if strings.TrimSpace(c.APIKey) == "" {
		return KeyStatus{}, errors.New("headscale: api key is empty")
	}
	keys, err := c.ListAPIKeys(ctx)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			if _, uerr := c.ListUsers(ctx, ""); uerr != nil {
				return KeyStatus{}, uerr
			}
			return KeyStatus{}, nil
		}
		return KeyStatus{}, err
	}
	match, ok := matchOwnKey(c.APIKey, keys)
	if !ok || match.Expiration == nil || match.Expiration.IsZero() {
		return KeyStatus{}, nil
	}
	return KeyStatus{ExpiresAt: match.Expiration.UTC(), Known: true}, nil
}

// matchOwnKey picks the listed key whose prefix is the longest prefix of secret.
// The list never contains the secret, so this does not compare the secret to a
// stored hash; it only identifies which row belongs to the configured key.
func matchOwnKey(secret string, keys []APIKey) (APIKey, bool) {
	secret = strings.TrimSpace(secret)
	var best APIKey
	bestLen := 0
	found := false
	for _, k := range keys {
		p := strings.TrimSpace(k.Prefix)
		if p == "" || len(p) <= bestLen {
			continue
		}
		if strings.HasPrefix(secret, p) {
			best = k
			bestLen = len(p)
			found = true
		}
	}
	return best, found
}
