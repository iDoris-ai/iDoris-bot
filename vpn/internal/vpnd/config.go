package vpnd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

	Hostname      string   `json:"hostname,omitempty"`
	AcceptRoutes  bool     `json:"accept_routes,omitempty"`
	AcceptDNS     *bool    `json:"accept_dns,omitempty"`
	AdvertiseTags []string `json:"advertise_tags,omitempty"`
	Takeover      *bool    `json:"takeover,omitempty"`

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
	if v, ok := os.LookupEnv("IDORIS_VPN_ENROLL_ALLOW_INSECURE"); ok {
		cfg.EnrollAllowInsecure = v == "1" || strings.EqualFold(v, "true")
	}
	return cfg, nil
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
	return nil
}

// IntervalDuration returns the parsed interval or zero.
func (c *Config) IntervalDuration() time.Duration {
	d, _ := time.ParseDuration(c.Interval)
	return d
}

// AcceptDNSValue defaults to true (MagicDNS is how members find the Local AI host).
func (c *Config) AcceptDNSValue() bool { return c.AcceptDNS == nil || *c.AcceptDNS }

// TakeoverValue defaults to true: the daemon's job is to make this machine a
// member of the iDoris tailnet.
func (c *Config) TakeoverValue() bool { return c.Takeover == nil || *c.Takeover }
