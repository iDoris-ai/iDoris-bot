package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

// Host is the sliver of the OS Apply needs. Tests use a fake. The command
// layer supplies the real one, including the existing service installer.
type Host interface {
	WriteFile(path string, data []byte, mode os.FileMode) error
	MkdirAll(path string, mode os.FileMode) error
	Stat(path string) (os.FileInfo, error)
	Chmod(path string, mode os.FileMode) error
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
	// AccessInfo is human-readable text telling the member how applications reach
	// the Local AI (for example the loopback SOCKS5 address). It never holds a
	// secret, only the path of the file that does.
	AccessInfo []string `json:"access_info,omitempty"`
}

// SudoApplyCommand is the exact command a non-root gateway prints.
// It never includes the enrollment token.
func SudoApplyCommand(planPath string) string {
	return "sudo idoris-vpnd gateway apply --plan " + strconv.Quote(planPath)
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
	if err := host.Chmod(plan.TokenFile, 0o600); err != nil {
		return ApplyResult{}, err
	}
	raw, err := marshalConfig(plan)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := host.WriteFile(plan.ConfigPath, raw, 0o600); err != nil {
		return ApplyResult{}, err
	}
	res := ApplyResult{ConfigPath: plan.ConfigPath, TokenFile: plan.TokenFile}
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

// fileConfig is the JSON written for idoris-vpnd. It is a subset of
// vpnd.Config so the file cannot carry an auth key or a plaintext token.
// Field names match vpnd.Config so LoadConfig accepts the file.
type fileConfig struct {
	EnrollURL           string   `json:"enroll_url,omitempty"`
	EnrollTokenFile     string   `json:"enroll_token_file,omitempty"`
	EnrollAllowInsecure bool     `json:"enroll_allow_insecure,omitempty"`
	Hostname            string   `json:"hostname,omitempty"`
	AcceptRoutes        bool     `json:"accept_routes,omitempty"`
	AdvertiseTags       []string `json:"advertise_tags,omitempty"`
	Mode                string   `json:"mode,omitempty"`
	Role                string   `json:"role,omitempty"`
	Listen              string   `json:"listen,omitempty"`
	AdvertiseRoutes     []string `json:"advertise_routes,omitempty"`
}

func marshalConfig(plan Plan) ([]byte, error) {
	cfg := fileConfig{
		EnrollURL:           plan.EnrollURL,
		EnrollTokenFile:     plan.TokenFile,
		EnrollAllowInsecure: plan.AllowInsecure,
		Hostname:            plan.Hostname,
		AcceptRoutes:        plan.AcceptRoutes,
		Mode:                plan.Mode,
		Role:                plan.Role,
		Listen:              plan.Listen,
	}
	if plan.Tag != "" {
		cfg.AdvertiseTags = []string{plan.Tag}
	}
	if len(plan.Routes) > 0 {
		cfg.AdvertiseRoutes = append([]string(nil), plan.Routes...)
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
