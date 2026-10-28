package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

// Host is the sliver of the OS Apply needs. Tests use a fake. The command
// layer supplies the real one, including the existing service installer.
type Host interface {
	WriteFile(path string, data []byte, mode os.FileMode) error
	MkdirAll(path string, mode os.FileMode) error
	Stat(path string) (os.FileInfo, error)
	Chmod(path string, mode os.FileMode) error
	ReadFile(path string) ([]byte, error)
	IsRoot() bool
	GOOS() string
	EnableIPForward(path, content string) error
	InstallService(configPath string) error
}

// ApplyOptions carries the secret and the flags that are not part of the plan.
// Token is written to plan.TokenFile and nowhere else.
type ApplyOptions struct {
	Token     string
	NoService bool
	PlanPath  string
	// ReplaceExisting allows Apply to overwrite a config (and its token) that
	// belongs to a different enrollment URL. Without it that case is an error,
	// so one organisation's credential is never replaced by another's by accident.
	ReplaceExisting bool
}

// ApplyResult is what the CLI and the local page show after Apply.
type ApplyResult struct {
	ConfigPath       string `json:"config_path"`
	PlanPath         string `json:"plan_path,omitempty"`
	TokenFile        string `json:"token_file,omitempty"`
	IPForwardApplied bool   `json:"ip_forward_applied"`
	SudoCommand      string `json:"sudo_command,omitempty"`
	ServiceInstalled bool   `json:"service_installed"`
	// Role, Hostname, EnrollURL and ControlURL name the identity that was
	// written. ControlURL is empty when the config does not pin one. Callers
	// use this to tell a new identity from the daemon that is still running.
	Role       string `json:"role,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	EnrollURL  string `json:"enroll_url,omitempty"`
	ControlURL string `json:"control_url,omitempty"`
	// ControlPinDropped is true when a new enrollment authority replaced the
	// previous one and the old control server pin was removed.
	ControlPinDropped bool `json:"control_pin_dropped,omitempty"`
	// AccessInfo is human-readable text telling the member how applications reach
	// the Local AI (for example the loopback SOCKS5 address). It never holds a
	// secret, only the path of the file that does.
	AccessInfo []string `json:"access_info,omitempty"`
}

// SudoApplyCommand is the exact command a non-root gateway prints.
// It never includes the enrollment token. The path is POSIX single-quoted
// so `$()`, backticks and other expansions stay literal.
func SudoApplyCommand(planPath string) string {
	return "sudo idoris-vpnd gateway apply --plan " + shellSingleQuote(planPath)
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Apply writes the daemon config and, on a Linux gateway running as root,
// enables forwarding. Without root it still writes the user-level files and
// returns SudoCommand instead of failing. A second call with the same inputs
// rewrites the same bytes.
func Apply(plan Plan, host Host, opt ApplyOptions) (ApplyResult, error) {
	if host == nil {
		return ApplyResult{}, errors.New("gateway: host is nil")
	}
	if plan.Blocked {
		return ApplyResult{}, fmt.Errorf("gateway: %s", plan.BlockReason)
	}
	if plan.ConfigPath == "" || plan.TokenFile == "" {
		return ApplyResult{}, errors.New("gateway: plan is missing config_path or token_file")
	}
	existing, haveConfig, err := readExistingConfig(host, plan.ConfigPath)
	if err != nil {
		return ApplyResult{}, err
	}
	if haveConfig {
		// A config that still points at another file (the historical shared
		// enroll.token, or a previous sidecar) keeps that file's bytes. The new
		// token is written to this config's own sidecar and the config is updated
		// to point there.
		if pointer, ok := jsonStringField(existing, "enroll_token_file"); ok && strings.TrimSpace(pointer) != "" {
			own := PathsFor("", plan.ConfigPath).Token
			if filepath.Clean(pointer) != filepath.Clean(own) {
				plan.TokenFile = own
			}
		}
		oldURL, hasURL := jsonStringField(existing, "enroll_url")
		if hasURL && oldURL != "" && oldURL != plan.EnrollURL && !opt.ReplaceExisting {
			return ApplyResult{}, fmt.Errorf("gateway: %s is already enrolled with %s; pass --replace to switch it to %s", plan.ConfigPath, oldURL, plan.EnrollURL)
		}
	}
	raw, access, err := mergeConfig(existing, haveConfig, plan)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := validateConfigBytes(raw); err != nil {
		return ApplyResult{}, err
	}
	if err := host.MkdirAll(filepath.Dir(plan.ConfigPath), 0o700); err != nil {
		return ApplyResult{}, err
	}
	if err := host.MkdirAll(filepath.Dir(plan.TokenFile), 0o700); err != nil {
		return ApplyResult{}, err
	}
	if opt.Token != "" {
		if err := host.WriteFile(plan.TokenFile, []byte(opt.Token+"\n"), 0o600); err != nil {
			return ApplyResult{}, err
		}
	} else if _, err := host.Stat(plan.TokenFile); err != nil {
		return ApplyResult{}, fmt.Errorf("gateway: enrollment token file: %w", err)
	}
	if err := host.WriteFile(plan.ConfigPath, raw, 0o600); err != nil {
		return ApplyResult{}, err
	}
	controlURL, _ := jsonStringField(raw, "control_url")
	_, pinDropped := jsonStringField(existing, "control_url")
	if !haveConfig || controlURL != "" || PreviousEnrollURL(existing) == "" || PreviousEnrollURL(existing) == plan.EnrollURL {
		pinDropped = false
	}
	res := ApplyResult{
		ConfigPath: plan.ConfigPath, TokenFile: plan.TokenFile, AccessInfo: access,
		Role: plan.Role, Hostname: plan.Hostname, EnrollURL: plan.EnrollURL, ControlURL: controlURL,
		ControlPinDropped: pinDropped,
	}
	if wantsForward(plan) {
		if host.GOOS() != "linux" {
			return res, errors.New("gateway: refusing to enable forwarding on a non-Linux host")
		}
		if host.IsRoot() {
			if err := host.EnableIPForward(IPForwardConf, IPForwardBody); err != nil {
				return res, err
			}
			res.IPForwardApplied = true
		} else if opt.PlanPath == "" {
			return res, errors.New("gateway: a non-root apply needs a plan path so it can print the sudo command")
		} else {
			res.SudoCommand = SudoApplyCommand(opt.PlanPath)
		}
	}
	if opt.PlanPath != "" {
		body, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return res, err
		}
		body = append(body, '\n')
		if opt.Token != "" && bytes.Contains(body, []byte(opt.Token)) {
			return res, errors.New("gateway: refusing to write a plan that contains the enrollment token")
		}
		if err := host.MkdirAll(filepath.Dir(opt.PlanPath), 0o700); err != nil {
			return res, err
		}
		if err := host.WriteFile(opt.PlanPath, body, 0o600); err != nil {
			return res, err
		}
		res.PlanPath = opt.PlanPath
	}
	if !opt.NoService {
		if err := host.InstallService(plan.ConfigPath); err != nil {
			return res, err
		}
		res.ServiceInstalled = true
	}
	return res, nil
}

func wantsForward(plan Plan) bool {
	return plan.Role == join.RoleGateway && len(plan.Routes) > 0
}

// PlanEnablesForward reports whether applying this plan needs ip_forward.
// The root continuation enables that and does not rewrite the user's files.
func PlanEnablesForward(plan Plan) bool { return wantsForward(plan) }

// defaultSOCKSListen is the authenticated loopback proxy a member or admin
// prefers when the config is embedded, or auto (which becomes embedded when
// the system tailnet is foreign or down). If that port is taken, ChooseLoopbackSOCKS
// walks the next ports through socksLastPort. The daemon writes the credential
// to <state_dir>/socks5.auth. local-ai and gateway stay on system mode and do
// not get this listener. socks5_allow_anonymous stays unset.
const (
	defaultSOCKSListen = "127.0.0.1:1080"
	socksLastPort      = 1096
)

// ChooseLoopbackSOCKS returns the first free 127.0.0.1 port from 1080 through
// 1096. It listens and closes, so the port can be taken again before the
// daemon binds it. An existing socks5_listen value is left alone by the caller.
func ChooseLoopbackSOCKS() (string, error) {
	host, portText, err := net.SplitHostPort(defaultSOCKSListen)
	if err != nil {
		return "", err
	}
	first, err := strconv.Atoi(portText)
	if err != nil {
		return "", err
	}
	var lastErr error
	for port := first; port <= socksLastPort; port++ {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		ln, listenErr := net.Listen("tcp", addr)
		if listenErr != nil {
			lastErr = listenErr
			continue
		}
		if err := ln.Close(); err != nil {
			return "", fmt.Errorf("gateway: close SOCKS probe %s: %w", addr, err)
		}
		return addr, nil
	}
	return "", fmt.Errorf("gateway: no free loopback port for the member SOCKS5 listener in %s-%d: %v; set socks5_listen before joining", defaultSOCKSListen, socksLastPort, lastErr)
}

func mergeConfig(existing []byte, have bool, plan Plan) ([]byte, []string, error) {
	var keys []string
	vals := map[string]json.RawMessage{}
	if have {
		var err error
		keys, vals, err = parseObject(existing)
		if err != nil {
			return nil, nil, err
		}
	}
	var err error
	keys, err = assignOwned(keys, vals, plan)
	if err != nil {
		return nil, nil, err
	}
	if memberEmbeddedAccess(plan) {
		if _, ok := vals["socks5_listen"]; !ok {
			addr, err := ChooseLoopbackSOCKS()
			if err != nil {
				return nil, nil, err
			}
			keys, err = assignRaw(keys, vals, "socks5_listen", addr, true)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	access := accessLines(plan, vals)
	return emitObject(keys, vals), access, nil
}

func assignOwned(keys []string, vals map[string]json.RawMessage, plan Plan) ([]string, error) {
	var err error
	oldURL, hasOld := jsonString(vals, "enroll_url")
	if hasOld && oldURL != "" && oldURL != plan.EnrollURL {
		if _, pinned := vals["control_url"]; pinned {
			delete(vals, "control_url")
			next := make([]string, 0, len(keys))
			for _, k := range keys {
				if k != "control_url" {
					next = append(next, k)
				}
			}
			keys = next
		}
	}
	keys, err = assignRaw(keys, vals, "enroll_url", plan.EnrollURL, plan.EnrollURL != "")
	if err != nil {
		return nil, err
	}
	keys, err = assignRaw(keys, vals, "enroll_token_file", plan.TokenFile, plan.TokenFile != "")
	if err != nil {
		return nil, err
	}
	// enroll_token and enroll_token_file are one setting. Installing the file
	// removes the inline value, which the daemon would reject at start.
	if plan.TokenFile != "" {
		keys = dropJSONKey(keys, vals, "enroll_token")
	}
	if path, ok := jsonString(vals, "auth_key_file"); ok && strings.TrimSpace(path) != "" {
		keys = dropJSONKey(keys, vals, "auth_key")
	}
	keys, err = assignRaw(keys, vals, "enroll_allow_insecure", true, plan.AllowInsecure)
	if err != nil {
		return nil, err
	}
	keys, err = assignRaw(keys, vals, "hostname", plan.Hostname, plan.Hostname != "")
	if err != nil {
		return nil, err
	}
	keys, err = assignRaw(keys, vals, "accept_routes", true, plan.AcceptRoutes)
	if err != nil {
		return nil, err
	}
	var tags []string
	if plan.Tag != "" {
		tags = []string{plan.Tag}
	}
	keys, err = assignRaw(keys, vals, "advertise_tags", tags, len(tags) > 0)
	if err != nil {
		return nil, err
	}
	keys, err = assignRaw(keys, vals, "mode", plan.Mode, plan.Mode != "")
	if err != nil {
		return nil, err
	}
	keys, err = assignRaw(keys, vals, "role", plan.Role, plan.Role != "")
	if err != nil {
		return nil, err
	}
	keys, err = assignRaw(keys, vals, "listen", plan.Listen, plan.Listen != "")
	if err != nil {
		return nil, err
	}
	routes := append([]string(nil), plan.Routes...)
	return assignRaw(keys, vals, "advertise_routes", routes, len(routes) > 0)
}

func dropJSONKey(keys []string, vals map[string]json.RawMessage, key string) []string {
	if _, ok := vals[key]; !ok {
		return keys
	}
	delete(vals, key)
	next := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != key {
			next = append(next, k)
		}
	}
	return next
}

func assignRaw(keys []string, vals map[string]json.RawMessage, key string, v any, include bool) ([]string, error) {
	if !include {
		if _, ok := vals[key]; !ok {
			return keys, nil
		}
		delete(vals, key)
		next := make([]string, 0, len(keys))
		for _, k := range keys {
			if k != key {
				next = append(next, k)
			}
		}
		return next, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	vals[key] = raw
	for _, k := range keys {
		if k == key {
			return keys, nil
		}
	}
	return append(keys, key), nil
}

func memberEmbeddedAccess(plan Plan) bool {
	switch plan.Role {
	case join.RoleMember, join.RoleAdmin:
	default:
		return false
	}
	switch strings.ToLower(strings.TrimSpace(plan.Mode)) {
	case "", "auto", "embedded":
		return true
	default:
		return false
	}
}

func accessLines(plan Plan, vals map[string]json.RawMessage) []string {
	if plan.Role != join.RoleMember && plan.Role != join.RoleAdmin {
		return nil
	}
	addr, ok := jsonString(vals, "socks5_listen")
	if !ok || addr == "" {
		return nil
	}
	// plan.Hostname is THIS machine's name. The wizard does not know the Local AI
	// host, so it only shows the shape of the name; the administrator supplies it.
	return []string{
		"SOCKS5 " + addr,
		"SOCKS5 credential file " + socksAuthPath(plan.ConfigPath, vals),
		"Reach the Local AI through this proxy by its MagicDNS name <local-ai-hostname>.idoris.internal (your administrator gives you the exact name)",
	}
}

func socksAuthPath(configPath string, vals map[string]json.RawMessage) string {
	if path, ok := jsonString(vals, "socks5_auth_file"); ok && path != "" {
		return path
	}
	dir, ok := jsonString(vals, "state_dir")
	if !ok || dir == "" {
		parent := filepath.Dir(configPath)
		if filepath.Base(parent) == ".idoris" {
			dir = filepath.Join(parent, "vpn-state")
		} else if d, err := vpnd.DefaultStateDir(); err == nil {
			dir = d
		} else {
			dir = filepath.Join(parent, "vpn-state")
		}
	}
	return filepath.Join(dir, "socks5.auth")
}

func emitObject(keys []string, vals map[string]json.RawMessage) []byte {
	var buf bytes.Buffer
	buf.WriteString("{\n")
	n := 0
	for _, key := range keys {
		raw, ok := vals[key]
		if !ok {
			continue
		}
		if n > 0 {
			buf.WriteString(",\n")
		}
		buf.WriteString("  ")
		buf.WriteString(strconvQuote(key))
		buf.WriteString(": ")
		buf.Write(raw)
		n++
	}
	buf.WriteString("\n}\n")
	return buf.Bytes()
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func parseObject(data []byte) ([]string, map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("gateway: existing config: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil, errors.New("gateway: existing config is not a JSON object")
	}
	var keys []string
	vals := map[string]json.RawMessage{}
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return nil, nil, fmt.Errorf("gateway: existing config: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, nil, errors.New("gateway: existing config key is not a string")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, nil, fmt.Errorf("gateway: existing config: %w", err)
		}
		if _, seen := vals[key]; !seen {
			keys = append(keys, key)
		}
		vals[key] = bytes.TrimSpace(raw)
	}
	tok, err = dec.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("gateway: existing config: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '}' {
		return nil, nil, errors.New("gateway: existing config is not a JSON object")
	}
	return keys, vals, nil
}

// PreviousEnrollURL reads enroll_url from a config document. Unknown keys are
// ignored so the warning can be printed before the strict decoder runs.
func PreviousEnrollURL(data []byte) string {
	got, ok := jsonStringField(data, "enroll_url")
	if !ok {
		return ""
	}
	return strings.TrimSpace(got)
}

func jsonStringField(data []byte, key string) (string, bool) {
	_, vals, err := parseObject(data)
	if err != nil {
		return "", false
	}
	return jsonString(vals, key)
}

func jsonString(vals map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := vals[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func readExistingConfig(host Host, path string) ([]byte, bool, error) {
	b, err := host.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, false, nil
	}
	return b, true, nil
}

// validateConfigBytes runs the exact document through the daemon's strict
// decoder (DisallowUnknownFields via LoadConfig). Unsupported keys are named
// and rejected before Apply writes anything. Resolve then checks mode, role,
// forwards and routes. A placeholder token avoids reading the real token
// file, which may not have been written yet.
func validateConfigBytes(data []byte) error {
	bad, err := unknownConfigKeys(data)
	if err != nil {
		return err
	}
	if len(bad) > 0 {
		return fmt.Errorf("gateway: config has unsupported keys: %s; remove them before joining, the daemon would refuse this file at start", strings.Join(bad, ", "))
	}
	dir, err := os.MkdirTemp("", "idoris-vpn-cfg-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "vpn.json")
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // G703: path is under MkdirTemp
		return err
	}
	cfg, err := vpnd.LoadConfig(path)
	if err != nil {
		return fmt.Errorf("gateway: config: %w", err)
	}
	if cfg.EnrollToken == "" && cfg.AuthKey == "" {
		// Only the shape is validated here. The token file may not exist yet, and
		// Resolve rejects an inline value next to a file, so swap one for the other.
		cfg.EnrollTokenFile = ""
		cfg.AuthKeyFile = ""
		cfg.EnrollToken = "validation-placeholder"
	}
	if err := cfg.Resolve(); err != nil {
		return fmt.Errorf("gateway: config: %w", err)
	}
	return nil
}

func unknownConfigKeys(data []byte) ([]string, error) {
	keys, _, err := parseObject(data)
	if err != nil {
		return nil, err
	}
	known := knownConfigKeys()
	var bad []string
	for _, key := range keys {
		if _, ok := known[key]; !ok {
			bad = append(bad, key)
		}
	}
	return bad, nil
}

func knownConfigKeys() map[string]struct{} {
	t := reflect.TypeOf(vpnd.Config{})
	out := make(map[string]struct{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}
