package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/vpnd"
)

const launchdLabel = "ai.idoris.vpnd"

func serviceCmd(args []string) error {
	if len(args) < 1 {
		return errors.New("service: expected install or uninstall")
	}
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	configPath := fs.String("config", "", "JSON config file the service should load")
	system := fs.Bool("system", false, "install a machine service that runs before login (requires root or SYSTEM)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "install":
		if *configPath == "" {
			return errors.New("service install: --config is required")
		}
		abs, err := filepath.Abs(*configPath)
		if err != nil {
			return err
		}
		if _, err := os.Stat(abs); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		// Both the user service and --system stop here. CheckSecretFile warns
		// and returns nil on Windows; on Unix a failure contains "chmod 600".
		if err := checkInstallSecrets(abs); err != nil {
			return err
		}
		if *system {
			return installSystemService(abs)
		}
		if err := installService(abs); err != nil {
			return err
		}
		fmt.Println(userServiceNotice(runtime.GOOS))
		return nil
	case "uninstall":
		if *system {
			return uninstallSystemService()
		}
		return uninstallService()
	default:
		return fmt.Errorf("service: unknown action %q", args[0])
	}
}

// userServiceNotice tells the operator that a per-user service stays stopped
// until they log in. Linux additionally needs lingering.
func userServiceNotice(goos string) string {
	msg := "a user service does not run before this user logs in"
	if goos == "linux" {
		msg += "; enable it with: loginctl enable-linger"
	}
	return msg
}

// checkInstallSecrets calls CheckSecretFile for the enrollment token file,
// the auth key file, the SOCKS5 auth file, and the config itself when it
// holds an inline enroll_token or auth_key. A config that only names those
// files may stay 0644.
func checkInstallSecrets(configPath string) error {
	b, err := os.ReadFile(configPath) //nolint:gosec // operator-chosen config, checked before install
	if err != nil {
		return err
	}
	var probe struct {
		EnrollToken     string `json:"enroll_token"`
		EnrollTokenFile string `json:"enroll_token_file"`
		AuthKey         string `json:"auth_key"`
		AuthKeyFile     string `json:"auth_key_file"`
		SOCKS5AuthFile  string `json:"socks5_auth_file"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if probe.EnrollToken != "" || probe.AuthKey != "" {
		if err := vpnd.CheckSecretFile(configPath); err != nil {
			return fmt.Errorf("config holds an inline secret: %w", err)
		}
	}
	files := []struct{ name, path string }{
		{"enroll_token_file", probe.EnrollTokenFile},
		{"auth_key_file", probe.AuthKeyFile},
		{"socks5_auth_file", probe.SOCKS5AuthFile},
	}
	for _, f := range files {
		if strings.TrimSpace(f.path) == "" {
			continue
		}
		if err := vpnd.CheckSecretFile(f.path); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
	}
	return nil
}

func selfPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

func installService(configPath string) error {
	exe, err := selfPath()
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat(systemLaunchdPath); err == nil {
			return errors.New("a system LaunchDaemon is installed; remove it with: idoris-vpnd service uninstall --system")
		}
		return installLaunchd(exe, configPath)
	case "linux":
		if err := rejectEnabledSystemUnit(); err != nil {
			return err
		}
		return installSystemdUser(exe, configPath)
	default:
		return fmt.Errorf("service install is not supported on %s; run `idoris-vpnd run` under your service manager", runtime.GOOS)
	}
}

func rejectEnabledSystemUnit() error {
	out, err := exec.Command("systemctl", "is-enabled", systemUnitName).CombinedOutput()
	if err == nil && strings.TrimSpace(string(out)) == "enabled" {
		return errors.New("the system unit is enabled; remove it with: idoris-vpnd service uninstall --system")
	}
	return nil
}

func uninstallService() error {
	switch runtime.GOOS {
	case "darwin":
		p, err := launchdPlistPath()
		if err != nil {
			return err
		}
		_ = exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), launchdLabel)).Run()
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		fmt.Println("removed", p)
		return nil
	case "linux":
		_ = exec.Command("systemctl", "--user", "disable", "--now", "idoris-vpnd.service").Run()
		p, err := systemdUnitPath()
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		fmt.Println("removed", p)
		return nil
	default:
		return fmt.Errorf("service uninstall is not supported on %s", runtime.GOOS)
	}
}

func launchdPlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist"), nil
}

func plistEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func renderLaunchdPlist(exe, configPath, logDir string) string {
	return renderLaunchdPlistEnv(exe, configPath, logDir, nil)
}

// renderSystemLaunchdPlist is the machine LaunchDaemon. STATE_DIRECTORY
// matches the Linux StateDirectory=idoris convention so the daemon does not
// consult HOME. The user LaunchAgent must not set it.
func renderSystemLaunchdPlist(exe, configPath, logDir string) string {
	return renderLaunchdPlistEnv(exe, configPath, logDir, [][2]string{
		{"STATE_DIRECTORY", systemStateDir},
	})
}

func renderLaunchdPlistEnv(exe, configPath, logDir string, env [][2]string) string {
	var envXML string
	if len(env) > 0 {
		var b strings.Builder
		b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
		for _, kv := range env {
			fmt.Fprintf(&b, "    <key>%s</key><string>%s</string>\n", plistEscape(kv[0]), plistEscape(kv[1]))
		}
		b.WriteString("  </dict>\n")
		envXML = b.String()
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>run</string>
    <string>--config</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
%s  <key>StandardOutPath</key><string>%s/vpnd.log</string>
  <key>StandardErrorPath</key><string>%s/vpnd.log</string>
</dict>
</plist>
`, launchdLabel, plistEscape(exe), plistEscape(configPath), envXML, plistEscape(logDir), plistEscape(logDir))
}

func installLaunchd(exe, configPath string) error {
	p, err := launchdPlistPath()
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	logDir := filepath.Join(home, "Library", "Logs", "iDoris")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return err
	}
	plist := renderLaunchdPlist(exe, configPath, logDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(plist), 0o600); err != nil { //nolint:gosec // G703: user LaunchAgent path under the current home, not a request path
		return err
	}
	target := fmt.Sprintf("gui/%d", os.Getuid())
	_ = exec.Command("launchctl", "bootout", target+"/"+launchdLabel).Run()
	if out, err := exec.Command("launchctl", "bootstrap", target, p).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("installed and started", launchdLabel, "from", p)
	fmt.Println("logs:", filepath.Join(logDir, "vpnd.log"))
	return nil
}

func systemdUnitPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "systemd", "user", "idoris-vpnd.service"), nil
}

func renderSystemdUserUnit(exe, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=iDoris VPN membership daemon (Tailscale client -> iDoris Headscale)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s
Restart=always
RestartSec=3
NoNewPrivileges=yes

[Install]
WantedBy=default.target
`, renderExecStart(exe, configPath))
}

func installSystemdUser(exe, configPath string) error {
	p, err := systemdUnitPath()
	if err != nil {
		return err
	}
	unit := renderSystemdUserUnit(exe, configPath)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(unit), 0o600); err != nil {
		return err
	}
	for _, a := range [][]string{{"daemon-reload"}, {"enable", "--now", "idoris-vpnd.service"}} {
		if out, err := exec.Command("systemctl", append([]string{"--user"}, a...)...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl --user %s: %w: %s", strings.Join(a, " "), err, strings.TrimSpace(string(out)))
		}
	}
	fmt.Println("installed and started idoris-vpnd.service from", p)
	return nil
}
