// Package vpnd is the client-side daemon that keeps the official Tailscale
// client of a machine logged into the iDoris-operated Headscale control
// server. It never replaces or patches Tailscale; it drives tailscaled through
// the same LocalAPI the `tailscale` CLI uses.
package vpnd

import (
	"context"
	"net/url"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

// Backend is the subset of the Tailscale LocalAPI the daemon depends on.
// *local.Client satisfies it; tests supply a fake.
type Backend interface {
	Status(ctx context.Context) (*ipnstate.Status, error)
	GetPrefs(ctx context.Context) (*ipn.Prefs, error)
	EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error)
	CheckPrefs(ctx context.Context, p *ipn.Prefs) error
	ProfileStatus(ctx context.Context) (current ipn.LoginProfile, all []ipn.LoginProfile, err error)
	SwitchProfile(ctx context.Context, profile ipn.ProfileID) error
	SwitchToEmptyProfile(ctx context.Context) error
	Start(ctx context.Context, opts ipn.Options) error
	// StartLoginInteractive makes tailscaled actually contact control. With an
	// auth key supplied to Start it registers non-interactively (no browser);
	// Start alone only logs in when a node key already exists.
	StartLoginInteractive(ctx context.Context) error
}

var _ Backend = (*local.Client)(nil)

// NewLocalBackend returns a LocalAPI client. An empty socket uses the
// platform default, which on macOS also finds the GUI app's LocalAPI port.
func NewLocalBackend(socket string) *local.Client {
	c := &local.Client{}
	if socket != "" {
		c.Socket = socket
		c.UseSocketOnly = true
	}
	return c
}

// NormalizeControlURL canonicalises a control URL for comparison: lower-case
// scheme and host, no trailing slash, no default port.
func NormalizeControlURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.TrimRight(strings.ToLower(s), "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	switch {
	case u.Scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case u.Scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}
	u.Host = host
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// SameControlURL reports whether a and b denote the same control server.
// Tailscale's own synonyms for its SaaS control plane are treated as equal.
func SameControlURL(a, b string) bool {
	if ipn.IsLoginServerSynonym(a) && ipn.IsLoginServerSynonym(b) {
		return true
	}
	return NormalizeControlURL(a) == NormalizeControlURL(b)
}
