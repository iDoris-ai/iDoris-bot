package vpnd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Config is the daemon configuration (JSON file + env overrides).
type Config struct {
	// ControlURL of the iDoris Headscale server. Required unless the
	// enrollment service supplies it.
	ControlURL string `json:"control_url"`

	// EnrollURL is the iDoris enrollment service. Either EnrollURL+token or
	// AuthKey must be configured.
	EnrollURL           string `json:"enroll_url,omitempty"`
	EnrollToken         string `json:"enroll_token,omitempty"`
	EnrollTokenFile     string `json:"enroll_token_file,omitempty"`
	EnrollAllowInsecure bool   `json:"enroll_allow_insecure,omitempty"`

	// AuthKey / AuthKeyFile: a pre-provisioned Headscale key (lab use).
	AuthKey     string `json:"auth_key,omitempty"`
	AuthKeyFile string `json:"auth_key_file,omitempty"`

	Hostname     string `json:"hostname,omitempty"`
	AcceptRoutes bool `json:"accept_routes,omitempty"`
	AcceptDNS    *bool `json:"accept_dns,omitempty"`
	// SSH is Tailscale SSH (RunSSH). Nil means the daemon does not touch it.
	// An ACL that allows tcp/22 does not turn this on.
	SSH *bool `json:"ssh,omitempty"`
	// AdvertiseTags is the tag the operator expects on this node. The daemon
	// does not send it at login: Headscale v0.29.6 rejects a pre-auth-key
	// registration that also requests tags. Put the same tag in the
	// enrollment entry's acl_tags; that key is what tags the node.
	AdvertiseTags []string `json:"advertise_tags,omitempty"`
	// Takeover, when true, allows system mode to switch a tailscaled that is
	// logged into some other control server. The default (nil or false) is to
	// leave that login alone. Pointer so an explicit false is distinct from
	// "unset" in older configs; both mean off.
	Takeover *bool `json:"takeover,omitempty"`

	// Mode is auto (default), system, or embedded.
	Mode string `json:"mode,omitempty"`
	// Role is the join role this config was written for: member, local-ai,
	// gateway, or admin. The daemon does not enforce it; the wizard does.
	Role string `json:"role,omitempty"`
	// StateDir is the embedded node's private state directory (0700). Empty
	// uses ~/.idoris/vpn-state.
	StateDir string `json:"state_dir,omitempty"`
	// StateFile is the identity binding (control URL, tenant, role, token
	// fingerprint). Empty uses DefaultStateFile. Never stores the token.
	StateFile string `json:"state_file,omitempty"`
	// Forwards are loopback TCP listeners dialed through the tailnet. In
	// embedded mode that is the only way other processes on the machine can
	// reach tailnet addresses.
	Forwards []Forward `json:"forwards,omitempty"`
	// SOCKS5Listen, if set, is a loopback address for a SOCKS5 proxy into the
	// tailnet (embedded: via tsnet; system: via the kernel route).
	SOCKS5Listen string `json:"socks5_listen,omitempty"`
	// AdvertiseRoutes are CIDRs this node advertises (subnet router). Valid
	// only in system mode; embedded mode has no TUN and rejects them.
	AdvertiseRoutes []string `json:"advertise_routes,omitempty"`

	// TailscaleSocket overrides the LocalAPI socket (Linux containers, tests).
	TailscaleSocket string `json:"tailscale_socket,omitempty"`
	// Listen is the status API: unix:<path> or tcp:127.0.0.1:<port>.
	Listen   string `json:"listen,omitempty"`
	Interval string `json:"interval,omitempty"`
	LogLevel string `json:"log_level,omitempty"`
}

// DefaultListen is the per-user status socket location.
func DefaultListen() string {
	if runtime.GOOS == "windows" {
		return "tcp:127.0.0.1:7845"
	}
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			base = os.TempDir()
		} else {
			base = filepath.Join(home, ".idoris")
		}
	}
	return "unix:" + filepath.Join(base, "vpnd.sock")
}

// Forward is one loopback TCP listener and the tailnet target it dials.
type Forward struct {
	Listen string `json:"listen"`
	Target string `json:"target"`
}

// DefaultStateDir is the embedded node's state directory, under the user's
// ~/.idoris and created mode 0700 by the daemon.
func DefaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("state_dir: home directory: %w", err)
	}
	return filepath.Join(home, ".idoris", "vpn-state"), nil
}

// LoadConfig reads a JSON file (optional) then applies IDORIS_VPN_* env vars.
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	if path != "" {
		b, err := os.ReadFile(path) //nolint:gosec // path is the operator-chosen config file
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	env := func(k string, dst *string) {
		if v, ok := os.LookupEnv("IDORIS_VPN_" + k); ok {
			*dst = v
		}
	}
	env("CONTROL_URL", &cfg.ControlURL)
	env("ENROLL_URL", &cfg.EnrollURL)
	env("ENROLL_TOKEN", &cfg.EnrollToken)
	env("ENROLL_TOKEN_FILE", &cfg.EnrollTokenFile)
	env("AUTH_KEY", &cfg.AuthKey)
	env("AUTH_KEY_FILE", &cfg.AuthKeyFile)
	env("HOSTNAME", &cfg.Hostname)
	env("TAILSCALE_SOCKET", &cfg.TailscaleSocket)
	env("LISTEN", &cfg.Listen)
	env("LOG_LEVEL", &cfg.LogLevel)
	env("MODE", &cfg.Mode)
	env("ROLE", &cfg.Role)
	env("STATE_DIR", &cfg.StateDir)
	env("STATE_FILE", &cfg.StateFile)
	env("SOCKS5_LISTEN", &cfg.SOCKS5Listen)
	if v, ok := os.LookupEnv("IDORIS_VPN_ENROLL_ALLOW_INSECURE"); ok {
		cfg.EnrollAllowInsecure = v == "1" || strings.EqualFold(v, "true")
	}
	if v, ok := os.LookupEnv("IDORIS_VPN_TAKEOVER"); ok {
		b, err := ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("IDORIS_VPN_TAKEOVER: %w", err)
		}
		cfg.Takeover = &b
	}
	if v, ok := os.LookupEnv("IDORIS_VPN_ACCEPT_ROUTES"); ok {
		b, err := ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("IDORIS_VPN_ACCEPT_ROUTES: %w", err)
		}
		cfg.AcceptRoutes = b
	}
	if v, ok := os.LookupEnv("IDORIS_VPN_ACCEPT_DNS"); ok {
		b, err := ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("IDORIS_VPN_ACCEPT_DNS: %w", err)
		}
		cfg.AcceptDNS = &b
	}
	if v, ok := os.LookupEnv("IDORIS_VPN_SSH"); ok {
		b, err := ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("IDORIS_VPN_SSH: %w", err)
		}
		cfg.SSH = &b
	}
	if v, ok := os.LookupEnv("IDORIS_VPN_ADVERTISE_ROUTES"); ok {
		cfg.AdvertiseRoutes = splitList(v)
	}
	if v, ok := os.LookupEnv("IDORIS_VPN_FORWARDS"); ok {
		if strings.TrimSpace(v) == "" {
			cfg.Forwards = nil
		} else if err := json.Unmarshal([]byte(v), &cfg.Forwards); err != nil {
			return nil, fmt.Errorf("IDORIS_VPN_FORWARDS: %w", err)
		}
	}
	return cfg, nil
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // secret file path comes from the operator config
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Resolve fills defaults, reads *_file secrets and validates.
func (c *Config) Resolve() error {
	if c.EnrollToken == "" && c.EnrollTokenFile != "" {
		t, err := readSecretFile(c.EnrollTokenFile)
		if err != nil {
			return fmt.Errorf("enroll_token_file: %w", err)
		}
		c.EnrollToken = t
	}
	if c.AuthKey == "" && c.AuthKeyFile != "" {
		k, err := readSecretFile(c.AuthKeyFile)
		if err != nil {
			return fmt.Errorf("auth_key_file: %w", err)
		}
		c.AuthKey = k
	}
	hasEnroll := c.EnrollURL != "" && c.EnrollToken != ""
	if !hasEnroll && c.AuthKey == "" {
		return errors.New("configure enroll_url + enroll_token (recommended) or auth_key")
	}
	if c.EnrollURL != "" && c.EnrollToken == "" {
		return errors.New("enroll_url set but no enroll_token / enroll_token_file")
	}
	if c.ControlURL == "" && !hasEnroll {
		return errors.New("control_url is required when using a static auth_key")
	}
	if c.Listen == "" {
		c.Listen = DefaultListen()
	}
	if _, _, err := ParseListen(c.Listen); err != nil {
		return err
	}
	if c.Interval != "" {
		if _, err := time.ParseDuration(c.Interval); err != nil {
			return fmt.Errorf("interval: %w", err)
		}
	}
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = ModeAuto
	}
	switch c.Mode {
	case ModeAuto, ModeSystem, ModeEmbedded:
	default:
		return fmt.Errorf("mode %q: want auto, system, or embedded", c.Mode)
	}
	if err := c.validateForwards(); err != nil {
		return err
	}
	if _, err := c.RoutePrefixes(); err != nil {
		return err
	}
	if err := c.RejectEmbeddedRoutes(c.Mode); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateForwards() error {
	for i, f := range c.Forwards {
		if err := ValidateLoopback(f.Listen); err != nil {
			return fmt.Errorf("forwards[%d].listen: %w", i, err)
		}
		if _, _, err := net.SplitHostPort(f.Target); err != nil {
			return fmt.Errorf("forwards[%d].target %q: %w", i, f.Target, err)
		}
	}
	if c.SOCKS5Listen != "" {
		if err := ValidateLoopback(c.SOCKS5Listen); err != nil {
			return fmt.Errorf("socks5_listen: %w", err)
		}
	}
	return nil
}

// RoutePrefixes parses advertise_routes. An empty list returns nil.
func (c *Config) RoutePrefixes() ([]netip.Prefix, error) {
	if len(c.AdvertiseRoutes) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(c.AdvertiseRoutes))
	seen := map[netip.Prefix]struct{}{}
	for _, s := range c.AdvertiseRoutes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("advertise_routes %q: %w", s, err)
		}
		if masked := p.Masked(); !masked.IsValid() || masked != p {
			return nil, fmt.Errorf("advertise_routes %q: has host bits set", s)
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out, nil
}

// RejectEmbeddedRoutes reports an error when mode is embedded and the config
// asks this node to advertise subnet routes. Embedded mode has no TUN, so it
// cannot route a LAN. mode "auto" is not rejected here; the daemon checks
// again after it has decided.
func (c *Config) RejectEmbeddedRoutes(mode string) error {
	if mode == ModeEmbedded && len(c.AdvertiseRoutes) > 0 {
		return errors.New("advertise_routes is not supported in embedded mode (no TUN): set mode to system to advertise LAN routes; on Linux also set net.ipv4.ip_forward=1 and approve the routes in Headscale")
	}
	return nil
}

// ValidateLoopback accepts host:port where host is a loopback IP.
func ValidateLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q: %w", addr, err)
	}
	if _, err := strconv.Atoi(port); err != nil || port == "" {
		return fmt.Errorf("%q: invalid port", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%q: must bind a loopback address", addr)
	}
	return nil
}

// IntervalDuration returns the parsed interval or zero.
func (c *Config) IntervalDuration() time.Duration {
	d, _ := time.ParseDuration(c.Interval)
	return d
}

// AcceptDNSValue defaults to true (MagicDNS is how members find the Local AI host).
func (c *Config) AcceptDNSValue() bool { return c.AcceptDNS == nil || *c.AcceptDNS }

// ParseBool accepts 1/0, true/false, yes/no. Empty is an error so an unset
// variable (which is not looked up) stays distinct from an explicit value.
func ParseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y":
		return true, nil
	case "0", "false", "no", "n":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", s)
	}
}

// TakeoverValue is true only when the operator explicitly enabled takeover.
// The default is false: never switch a system tailscaled that is logged into
// some other control server unless asked.
func (c *Config) TakeoverValue() bool { return c.Takeover != nil && *c.Takeover }
