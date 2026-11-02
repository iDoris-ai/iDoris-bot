package vpnd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
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
	AcceptRoutes bool   `json:"accept_routes,omitempty"`
	AcceptDNS    *bool  `json:"accept_dns,omitempty"`
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
	// Role is member (default), local-ai, gateway, or admin. local-ai and
	// gateway cannot use embedded mode. Discovery overwrites this when it
	// returns a role.
	Role string `json:"role,omitempty"`
	// StateDir is the embedded node's private state directory (0700). Empty
	// uses $STATE_DIRECTORY/node when that variable is set, otherwise
	// ~/.idoris/vpn-state.
	StateDir string `json:"state_dir,omitempty"`
	// StateFile is the identity binding (control URL, tenant, role, token
	// fingerprint). Empty uses DefaultStateFile. Never stores the token.
	StateFile string `json:"state_file,omitempty"`
	// Forwards are loopback TCP listeners dialed through the tailnet. In
	// embedded mode that is the only way other processes on the machine can
	// reach tailnet addresses.
	Forwards []Forward `json:"forwards,omitempty"`
	// SOCKS5Listen, if set, is a loopback address or unix:<absolute path> for a
	// SOCKS5 proxy into the tailnet (embedded: via tsnet; system: via the kernel route).
	SOCKS5Listen string `json:"socks5_listen,omitempty"`
	// SOCKS5AuthFile is a 0600 file with one "user:password" line.
	// Empty, with SOCKS5Listen set, generates <state_dir>/socks5.auth.
	SOCKS5AuthFile string `json:"socks5_auth_file,omitempty"`
	// SOCKS5AllowAnonymous turns off SOCKS5 authentication. It cannot be
	// combined with SOCKS5AuthFile. The default is authenticated.
	SOCKS5AllowAnonymous bool `json:"socks5_allow_anonymous,omitempty"`
	// MaxConnections is the per-listener cap. Zero means 64.
	MaxConnections int `json:"max_connections,omitempty"`
	// DialTimeout is how long a tailnet dial may take. Empty means 10s.
	DialTimeout string `json:"dial_timeout,omitempty"`
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

// DefaultListen is the status socket location.
// Windows stays on a loopback TCP port. Elsewhere $XDG_RUNTIME_DIR/vpnd.sock
// wins (the system unit sets XDG_RUNTIME_DIR=/run/idoris, which does not need
// HOME). Then $STATE_DIRECTORY/vpnd.sock for a machine service that has no
// runtime directory. Then the per-user socket under ~/.idoris.
func DefaultListen() string {
	if runtime.GOOS == "windows" {
		return "tcp:127.0.0.1:7845"
	}
	if base := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); base != "" {
		return "unix:" + filepath.Join(base, "vpnd.sock")
	}
	if dir, err := serviceStateDir(); err == nil && dir != "" {
		return "unix:" + filepath.Join(dir, "vpnd.sock")
	}
	var base string
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		base = os.TempDir()
	} else {
		base = filepath.Join(home, ".idoris")
	}
	return "unix:" + filepath.Join(base, "vpnd.sock")
}

// Forward is one loopback listener and the tailnet target it dials.
// Listen is host:port or unix:<absolute path>.
type Forward struct {
	Listen string `json:"listen"`
	Target string `json:"target"`
	// OwnerOnly, on Linux, drops TCP connections whose peer uid is not the
	// daemon's uid. On other operating systems a TCP OwnerOnly is a
	// configuration error: the peer uid cannot be read reliably. A unix:
	// listener is created mode 0600, so OwnerOnly changes nothing there.
	OwnerOnly bool `json:"owner_only,omitempty"`
}

// DefaultStateDir is the embedded node's state directory, created mode 0700
// by the daemon. $STATE_DIRECTORY/node wins. Otherwise ~/.idoris/vpn-state.
func DefaultStateDir() (string, error) {
	if dir, err := serviceStateDir(); err != nil {
		return "", err
	} else if dir != "" {
		return filepath.Join(dir, "node"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		if err == nil {
			err = errors.New("HOME is not defined")
		}
		return "", fmt.Errorf("state_dir: set STATE_DIRECTORY or HOME: %w", err)
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
		if cfg.EnrollToken != "" || cfg.AuthKey != "" {
			if err := CheckSecretFile(path); err != nil {
				return nil, fmt.Errorf("config %s holds an inline secret: %w", path, err)
			}
		}
	}
	if err := applyEnv(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// EnvName is IDORIS_VPN_ plus the JSON key in upper snake case.
func EnvName(jsonKey string) string {
	return "IDORIS_VPN_" + strings.ToUpper(jsonKey)
}

// applyEnv sets every Config field from IDORIS_VPN_<JSON KEY>. A variable
// with that prefix that does not match a field is an error, so a typo is
// not silently ignored.
func applyEnv(cfg *Config) error {
	known := map[string]struct{}{}
	present := map[string]string{}
	for _, entry := range os.Environ() {
		key, val, ok := strings.Cut(entry, "=")
		if !ok || !strings.HasPrefix(key, "IDORIS_VPN_") {
			continue
		}
		present[key] = val
	}
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		name := jsonFieldName(t.Field(i))
		if name == "" {
			continue
		}
		envKey := EnvName(name)
		known[envKey] = struct{}{}
		raw, ok := present[envKey]
		if !ok {
			continue
		}
		// A blank credential variable is not set. Treating it as set would
		// wipe the config-file value and still leave the other side in place.
		if secretCredential(name) && strings.TrimSpace(raw) == "" {
			continue
		}
		if err := assignEnv(v.Field(i), raw); err != nil {
			return fmt.Errorf("%s: %w", envKey, err)
		}
	}
	var unknown []string
	for key := range present {
		if _, ok := known[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("unknown environment variable %s", strings.Join(unknown, ", "))
	}
	return applyCredentialEnv(cfg, present)
}

// secretCredential is one side of the enrollment token or the auth key.
func secretCredential(jsonKey string) bool {
	switch jsonKey {
	case "enroll_token", "enroll_token_file", "auth_key", "auth_key_file":
		return true
	default:
		return false
	}
}

// applyCredentialEnv makes a higher layer replace the whole credential.
// Env wins over the config file. Setting both sides in the env, or leaving
// both sides set in the file when the env sets neither, is an error.
// A blank variable is not set.
func applyCredentialEnv(cfg *Config, present map[string]string) error {
	pairs := []struct {
		inline, file       string
		inlineDst, fileDst *string
	}{
		{"enroll_token", "enroll_token_file", &cfg.EnrollToken, &cfg.EnrollTokenFile},
		{"auth_key", "auth_key_file", &cfg.AuthKey, &cfg.AuthKeyFile},
	}
	for _, p := range pairs {
		inlineSet := credentialEnvSet(present, p.inline)
		fileSet := credentialEnvSet(present, p.file)
		switch {
		case inlineSet && fileSet:
			return fmt.Errorf("%s and %s are both set; set only one", EnvName(p.inline), EnvName(p.file))
		case inlineSet:
			*p.fileDst = ""
		case fileSet:
			*p.inlineDst = ""
		default:
			if strings.TrimSpace(*p.inlineDst) != "" && strings.TrimSpace(*p.fileDst) != "" {
				return fmt.Errorf("config file sets both %s and %s; set only one", p.inline, p.file)
			}
		}
	}
	return nil
}

func credentialEnvSet(present map[string]string, jsonKey string) bool {
	raw, ok := present[EnvName(jsonKey)]
	return ok && strings.TrimSpace(raw) != ""
}

func jsonFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" || tag == "-" {
		return ""
	}
	return strings.Split(tag, ",")[0]
}

func assignEnv(dst reflect.Value, raw string) error {
	switch dst.Kind() {
	case reflect.String:
		dst.SetString(raw)
		return nil
	case reflect.Bool:
		b, err := ParseBool(raw)
		if err != nil {
			return err
		}
		dst.SetBool(b)
		return nil
	case reflect.Int:
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return err
		}
		dst.SetInt(int64(n))
		return nil
	case reflect.Pointer:
		if dst.Type().Elem().Kind() != reflect.Bool {
			return fmt.Errorf("unsupported type %s", dst.Type())
		}
		b, err := ParseBool(raw)
		if err != nil {
			return err
		}
		dst.Set(reflect.ValueOf(&b))
		return nil
	case reflect.Slice:
		if dst.Type().Elem().Kind() == reflect.String {
			dst.Set(reflect.ValueOf(splitList(raw)))
			return nil
		}
		if dst.Type() == reflect.TypeOf([]Forward(nil)) {
			if strings.TrimSpace(raw) == "" {
				dst.Set(reflect.Zero(dst.Type()))
				return nil
			}
			var fw []Forward
			if err := json.Unmarshal([]byte(raw), &fw); err != nil {
				return err
			}
			dst.Set(reflect.ValueOf(fw))
			return nil
		}
		return fmt.Errorf("unsupported type %s", dst.Type())
	default:
		return fmt.Errorf("unsupported type %s", dst.Type())
	}
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
	if err := CheckSecretFile(path); err != nil {
		return "", err
	}
	b, err := os.ReadFile(path) //nolint:gosec // secret file path comes from the operator config and passed CheckSecretFile
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Resolve fills defaults, reads *_file secrets and validates.
func (c *Config) Resolve() error {
	// A broken STATE_DIRECTORY must fail here, before a home directory is
	// used for the socket or for any path Resolve does not itself fill in.
	if _, err := serviceStateDir(); err != nil {
		return err
	}
	if err := c.rejectDualCredentials(); err != nil {
		return err
	}
	if strings.TrimSpace(c.EnrollToken) == "" && c.EnrollTokenFile != "" {
		t, err := readSecretFile(c.EnrollTokenFile)
		if err != nil {
			return fmt.Errorf("enroll_token_file: %w", err)
		}
		c.EnrollToken = t
	}
	if strings.TrimSpace(c.AuthKey) == "" && c.AuthKeyFile != "" {
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
	c.Role = strings.ToLower(strings.TrimSpace(c.Role))
	if c.Role == "" {
		c.Role = "member"
	}
	if !ValidRole(c.Role) {
		return fmt.Errorf("role %q: want member, local-ai, gateway, or admin", c.Role)
	}
	if err := c.RejectEmbeddedRole(); err != nil {
		return err
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

// rejectDualCredentials refuses one source leaving both the inline value and
// the file path set. Apply layers clear the other side before this runs.
func (c *Config) rejectDualCredentials() error {
	if strings.TrimSpace(c.EnrollToken) != "" && strings.TrimSpace(c.EnrollTokenFile) != "" {
		return errors.New("enroll_token and enroll_token_file are both set; set only one")
	}
	if strings.TrimSpace(c.AuthKey) != "" && strings.TrimSpace(c.AuthKeyFile) != "" {
		return errors.New("auth_key and auth_key_file are both set; set only one")
	}
	return nil
}

func (c *Config) validateForwards() error {
	var ownerOnly []string
	for i, f := range c.Forwards {
		if err := ValidateForwardListen(f.Listen); err != nil {
			return fmt.Errorf("forwards[%d].listen: %w", i, err)
		}
		if _, _, err := net.SplitHostPort(f.Target); err != nil {
			return fmt.Errorf("forwards[%d].target %q: %w", i, f.Target, err)
		}
		if !f.OwnerOnly {
			continue
		}
		network, address, err := splitListen(f.Listen)
		if err != nil {
			return fmt.Errorf("forwards[%d].listen: %w", i, err)
		}
		// unix: is already mode 0600. OwnerOnly does not need a peer-uid check.
		if network != "tcp" {
			continue
		}
		if !ownerOnlySupported {
			return fmt.Errorf("forwards[%d].owner_only: refusing TCP owner checks on %s because the peer uid cannot be read reliably (Linux reads /proc/net/tcp; this OS does not). Use a unix: listener, which is created mode 0600", i, runtime.GOOS)
		}
		ownerOnly = append(ownerOnly, address)
	}
	if c.SOCKS5Listen != "" {
		if err := ValidateForwardListen(c.SOCKS5Listen); err != nil {
			return fmt.Errorf("socks5_listen: %w", err)
		}
	}
	if c.MaxConnections < 0 {
		return errors.New("max_connections must be >= 0")
	}
	if c.SOCKS5AllowAnonymous && strings.TrimSpace(c.SOCKS5AuthFile) != "" {
		return errors.New("socks5_allow_anonymous cannot be combined with socks5_auth_file")
	}
	if strings.TrimSpace(c.DialTimeout) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(c.DialTimeout))
		if err != nil {
			return fmt.Errorf("dial_timeout: %w", err)
		}
		if d <= 0 {
			return errors.New("dial_timeout must be > 0")
		}
	}
	// Publish only after the config is valid, so a rejected file does not
	// arm or clear the listener policy. StartAccess calls listenLocal and
	// cannot see Forward.OwnerOnly directly.
	setOwnerOnlyListens(ownerOnly)
	return nil
}

// DialTimeoutDuration returns the parsed dial timeout, or zero when unset.
// StartAccess treats zero as its 10s default. Resolve rejects a value that
// does not parse or is not positive.
func (c *Config) DialTimeoutDuration() time.Duration {
	d, _ := time.ParseDuration(strings.TrimSpace(c.DialTimeout))
	if d < 0 {
		return 0
	}
	return d
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

// ValidRole reports whether role is one the daemon knows.
func ValidRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "member", "local-ai", "gateway", "admin":
		return true
	default:
		return false
	}
}

// RejectEmbeddedRole reports an error when a role that serves inbound traffic
// is pinned to embedded mode. auto is allowed: startup waits for tailscaled
// instead of falling back to embedded.
func (c *Config) RejectEmbeddedRole() error {
	if c.Mode == ModeEmbedded && RequiresSystem(c.Role) {
		return fmt.Errorf("role %s cannot use embedded mode: embedded mode is outbound-only and cannot serve inbound traffic; set mode to system or auto and run the official tailscaled", c.Role)
	}
	return nil
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
