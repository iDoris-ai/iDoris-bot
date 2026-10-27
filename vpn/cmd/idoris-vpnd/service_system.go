package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	systemUnitName    = "idoris-vpnd.service"
	systemUnitPath    = "/etc/systemd/system/idoris-vpnd.service"
	systemConfigDir   = "/etc/idoris"
	systemConfigPath  = "/etc/idoris/vpn.json"
	systemStateDir    = "/var/lib/idoris"
	systemRuntimeDir  = "/run/idoris"
	systemLogDir      = "/var/log/idoris"
	systemLaunchdPath = "/Library/LaunchDaemons/ai.idoris.vpnd.plist"
	windowsConfigDir  = `C:\ProgramData\idoris`
	windowsConfigPath = `C:\ProgramData\idoris\vpn.json`
	windowsTaskName   = "idoris-vpnd"
)

func installSystemService(configPath string) error {
	switch runtime.GOOS {
	case "linux":
		return installSystemdSystem(configPath)
	case "darwin":
		return installLaunchDaemon(configPath)
	case "windows":
		return installWindowsTask(configPath)
	default:
		return fmt.Errorf("service install --system is not supported on %s", runtime.GOOS)
	}
}

func uninstallSystemService() error {
	switch runtime.GOOS {
	case "linux":
		return uninstallSystemdSystem()
	case "darwin":
		return uninstallLaunchDaemon()
	case "windows":
		return uninstallWindowsTask()
	default:
		return fmt.Errorf("service uninstall --system is not supported on %s", runtime.GOOS)
	}
}

// renderExecStart quotes paths the way systemd's command line expects.
// Paths without spaces stay bare so the unit is readable.
func renderExecStart(exe, configPath string) string {
	return strings.Join([]string{systemdQuote(exe), "run", "--config", systemdQuote(configPath)}, " ")
}

func systemdQuote(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\"'\\") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}

// renderSystemdSystemUnit builds the machine unit. cfgJSON is read only for
// state_dir and unix listen paths; it is not validated as a full daemon config.
func renderSystemdSystemUnit(exe, configPath string, cfgJSON []byte) (string, error) {
	paths, err := systemReadWritePaths(cfgJSON)
	if err != nil {
		return "", err
	}
	stateNames, runtimeNames := systemdManagedDirs(paths)
	var rw strings.Builder
	fmt.Fprintf(&rw, "StateDirectory=%s\n", strings.Join(stateNames, " "))
	rw.WriteString("StateDirectoryMode=0750\n")
	fmt.Fprintf(&rw, "RuntimeDirectory=%s\n", strings.Join(runtimeNames, " "))
	rw.WriteString("RuntimeDirectoryMode=0750\n")
	// DefaultListen follows XDG_RUNTIME_DIR. Pin it so an empty listen lands
	// on /run/idoris/vpnd.sock, which RuntimeDirectory creates on every boot.
	// Do not set IDORIS_VPN_STATE_DIR here: that env var overrides the file.
	rw.WriteString("Environment=XDG_RUNTIME_DIR=/run/idoris\n")
	for _, p := range paths {
		fmt.Fprintf(&rw, "ReadWritePaths=%s\n", systemdQuote(p))
	}
	unit := fmt.Sprintf(`[Unit]
Description=iDoris VPN membership daemon (Tailscale client -> iDoris Headscale)
After=network-online.target
Wants=network-online.target

[Service]
# Runs as root so it can open the tailscaled socket and edit prefs.
# To run as an unprivileged user set User=idoris Group=idoris and on the host run: tailscale set --operator=idoris
ExecStart=%s
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
%s
[Install]
WantedBy=multi-user.target
`, renderExecStart(exe, configPath), rw.String())
	return unit, nil
}

// systemdManagedDirs returns StateDirectory and RuntimeDirectory names that
// systemd itself creates before setting up the namespace. Only a single path
// component under /var/lib or /run fits those settings.
func systemdManagedDirs(paths []string) (state, runtime []string) {
	state = []string{"idoris"}
	runtime = []string{"idoris"}
	for _, p := range paths {
		if name, ok := strings.CutPrefix(p, "/var/lib/"); ok && systemdDirToken(name) && name != "idoris" {
			state = append(state, name)
		}
		if name, ok := strings.CutPrefix(p, "/run/"); ok && systemdDirToken(name) && name != "idoris" {
			runtime = append(runtime, name)
		}
	}
	return state, runtime
}

func systemdDirToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}

func systemReadWritePaths(cfgJSON []byte) ([]string, error) {
	// /var/lib/idoris is the default state parent. /run/idoris is the status
	// socket directory created by RuntimeDirectory= on every boot.
	paths := []string{systemStateDir, systemRuntimeDir}
	if len(bytes.TrimSpace(cfgJSON)) == 0 {
		return paths, nil
	}
	var probe struct {
		Listen       string `json:"listen"`
		StateDir     string `json:"state_dir"`
		SOCKS5Listen string `json:"socks5_listen"`
		Forwards     []struct {
			Listen string `json:"listen"`
		} `json:"forwards"`
	}
	if err := json.Unmarshal(cfgJSON, &probe); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	add := func(p string) error {
		if p == "" {
			return nil
		}
		if err := rejectUnsafePath(p); err != nil {
			return err
		}
		if !path.IsAbs(p) {
			return nil
		}
		p = path.Clean(p)
		if p == "/" {
			return errors.New("config: refusing ReadWritePaths=/")
		}
		// A path under /run disappears on reboot. List only /run/<name>, which
		// RuntimeDirectory recreates. The parent is writable, so the daemon
		// can create anything nested below it. Listing the nested path would
		// make systemd fail the namespace once /run is empty again.
		// Nested and exact runtime paths both collapse to /run/<name>.
		if top, _ := runtimeDir(p); top != "" {
			return appendReadWrite(&paths, "/run/"+top)
		}
		return appendReadWrite(&paths, p)
	}
	if err := add(probe.StateDir); err != nil {
		return nil, err
	}
	addUnix := func(listen string) error {
		sock, ok := strings.CutPrefix(listen, "unix:")
		if !ok || sock == "" {
			return nil
		}
		// path.Dir cleans ".." away, so reject traversal on the raw socket path.
		if err := rejectUnsafePath(sock); err != nil {
			return err
		}
		return add(path.Dir(sock))
	}
	if err := addUnix(probe.Listen); err != nil {
		return nil, err
	}
	if err := addUnix(probe.SOCKS5Listen); err != nil {
		return nil, err
	}
	for _, f := range probe.Forwards {
		if err := addUnix(f.Listen); err != nil {
			return nil, err
		}
	}
	return paths, nil
}

func appendReadWrite(paths *[]string, p string) error {
	for _, have := range *paths {
		if have == p {
			return nil
		}
	}
	*paths = append(*paths, p)
	return nil
}

// runtimeDir reports the single directory name under /run. nested is true
// when p is deeper than /run/<name> (or /var/run/<name>, the usual symlink).
func runtimeDir(p string) (top string, nested bool) {
	rest := ""
	switch {
	case strings.HasPrefix(p, "/run/"):
		rest = strings.TrimPrefix(p, "/run/")
	case strings.HasPrefix(p, "/var/run/"):
		rest = strings.TrimPrefix(p, "/var/run/")
	default:
		return "", false
	}
	name, sub, ok := strings.Cut(rest, "/")
	if name == "" || name == "." {
		return "", false
	}
	return name, ok && sub != ""
}

// provisionSystemPaths creates every ReadWritePaths entry. root is empty on
// a real install. Tests pass a temp directory; the absolute path's leading
// slash is stripped before joining, because filepath.Join drops the parent
// when the child is absolute.
func provisionSystemPaths(root string, cfgJSON []byte) error {
	paths, err := systemReadWritePaths(cfgJSON)
	if err != nil {
		return err
	}
	for _, p := range paths {
		dest := p
		if root != "" {
			dest = filepath.Join(root, strings.TrimPrefix(p, "/"))
		}
		if err := os.MkdirAll(dest, 0o750); err != nil {
			return err
		}
		if err := os.Chmod(dest, 0o750); err != nil { //nolint:gosec // directory must stay traversable; 0750 is the required mode
			return err
		}
		if err := chownSystemRoot(dest); err != nil {
			return err
		}
	}
	return nil
}

func rejectUnsafePath(p string) error {
	if strings.ContainsAny(p, "\r\n\x00") {
		return fmt.Errorf("config: path %q contains a control character", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("config: path %q must not contain a parent-directory segment", p)
		}
	}
	return nil
}

func renderSchtasksCreate(exe, configPath string) []string {
	// schtasks has no environment field. cmd /c sets STATE_DIRECTORY for this
	// process only. Under SYSTEM, os.UserConfigDir is the system profile;
	// state, the embedded node, and locks must stay in ProgramData, which
	// the installer creates and locks down with icacls. No space before &&:
	// cmd would otherwise include it in the value.
	tr := fmt.Sprintf("cmd /c set STATE_DIRECTORY=%s&& %s run --config %s", quoteTask(windowsConfigDir), quoteTask(exe), quoteTask(configPath))
	return []string{"/Create", "/TN", windowsTaskName, "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F", "/TR", tr}
}

func renderSchtasksDelete() []string {
	return []string{"/Delete", "/TN", windowsTaskName, "/F"}
}

func quoteTask(s string) string {
	if strings.ContainsAny(s, " \t\"") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}

func installSystemdSystem(configPath string) error {
	if runtime.GOOS != "linux" {
		return errors.New("systemd system units are only installed on Linux")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	src, err := selfPath()
	if err != nil {
		return err
	}
	exeDir, exe := systemExecutable(runtime.GOOS, os.Getenv("ProgramFiles"))
	if err := copyProtectedExecutable(src, exeDir, exe); err != nil {
		return err
	}
	cfg, err := os.ReadFile(configPath) //nolint:gosec // operator-chosen config copied into /etc
	if err != nil {
		return err
	}
	unit, err := renderSystemdSystemUnit(exe, systemConfigPath, cfg)
	if err != nil {
		return err
	}
	if err := writeRootFile(systemConfigDir, systemConfigPath, cfg, 0o600); err != nil {
		return err
	}
	// Every ReadWritePaths entry has to exist before systemd builds the
	// namespace. StateDirectory and RuntimeDirectory recreate /var/lib/idoris
	// and /run/idoris on boot; nested state directories are created here.
	if err := provisionSystemPaths("", cfg); err != nil {
		return err
	}
	if err := os.WriteFile(systemUnitPath, []byte(unit), 0o600); err != nil { //nolint:gosec // fixed unit path under /etc/systemd/system
		return err
	}
	// Best effort: a user unit and this system unit must not both be running.
	_, _ = exec.Command("systemctl", "--user", "disable", "--now", systemUnitName).CombinedOutput()
	for _, a := range [][]string{{"daemon-reload"}, {"enable", "--now", systemUnitName}} {
		if out, err := exec.Command("systemctl", a...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(a, " "), err, strings.TrimSpace(string(out)))
		}
	}
	fmt.Println("installed and started", systemUnitName, "from", systemUnitPath)
	fmt.Println("config:", systemConfigPath)
	fmt.Println("logs: journalctl -u", systemUnitName)
	fmt.Println("if a user unit is still enabled for another account, disable it with: systemctl --user disable --now", systemUnitName)
	return nil
}

func uninstallSystemdSystem() error {
	if runtime.GOOS != "linux" {
		return errors.New("systemd system units are only removed on Linux")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if _, err := os.Stat(systemUnitPath); err == nil {
		if out, err := exec.Command("systemctl", "disable", "--now", systemUnitName).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl disable --now: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if err := os.Remove(systemUnitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("removed", systemUnitPath)
	_, exe := systemExecutable(runtime.GOOS, os.Getenv("ProgramFiles"))
	if err := removeProtectedExecutable(exe); err != nil {
		return err
	}
	fmt.Println("removed", exe)
	fmt.Println("left", systemConfigPath, "in place")
	return nil
}

func installLaunchDaemon(configPath string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("LaunchDaemons are only installed on macOS")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	src, err := selfPath()
	if err != nil {
		return err
	}
	exeDir, exe := systemExecutable(runtime.GOOS, os.Getenv("ProgramFiles"))
	if err := copyProtectedExecutable(src, exeDir, exe); err != nil {
		return err
	}
	cfg, err := os.ReadFile(configPath) //nolint:gosec // operator-chosen config copied into /etc
	if err != nil {
		return err
	}
	if err := writeRootFile(systemConfigDir, systemConfigPath, cfg, 0o600); err != nil {
		return err
	}
	// STATE_DIRECTORY and the log paths in the plist. 0700 root: a LaunchDaemon
	// has no HOME, and these directories must not be group-writable.
	if err := provisionLaunchDaemonDirs(""); err != nil {
		return err
	}
	plist := renderSystemLaunchdPlist(exe, systemConfigPath, systemLogDir)
	if err := os.WriteFile(systemLaunchdPath, []byte(plist), 0o600); err != nil {
		return err
	}
	_ = exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), launchdLabel)).Run()
	_ = exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run()
	if out, err := exec.Command("launchctl", "bootstrap", "system", systemLaunchdPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap system: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("installed and started", launchdLabel, "from", systemLaunchdPath)
	fmt.Println("config:", systemConfigPath)
	fmt.Println("logs:", systemLogDir+"/vpnd.log")
	return nil
}

func uninstallLaunchDaemon() error {
	if runtime.GOOS != "darwin" {
		return errors.New("LaunchDaemons are only removed on macOS")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	_ = exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run()
	if err := os.Remove(systemLaunchdPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Println("removed", systemLaunchdPath)
	_, exe := systemExecutable(runtime.GOOS, os.Getenv("ProgramFiles"))
	if err := removeProtectedExecutable(exe); err != nil {
		return err
	}
	fmt.Println("removed", exe)
	fmt.Println("left", systemConfigPath, "in place")
	return nil
}

// provisionLaunchDaemonDirs creates every directory the machine plist writes.
// root is empty on a real install. Tests pass a temp directory; the absolute
// path's leading slash is stripped before joining, because filepath.Join
// drops the parent when the child is absolute.
func provisionLaunchDaemonDirs(root string) error {
	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{systemStateDir, 0o700},
		{systemLogDir, 0o700},
	}
	for _, d := range dirs {
		dest := d.path
		if root != "" {
			dest = filepath.Join(root, strings.TrimPrefix(d.path, "/"))
		}
		if err := os.MkdirAll(dest, d.mode); err != nil {
			return err
		}
		if err := os.Chmod(dest, d.mode); err != nil { //nolint:gosec // 0700 is the required mode; the directory is not left group-writable
			return err
		}
		if err := chownSystemRoot(dest); err != nil {
			return err
		}
	}
	return nil
}

func installWindowsTask(configPath string) error {
	if runtime.GOOS != "windows" {
		return errors.New("scheduled tasks are only installed on Windows")
	}
	src, err := selfPath()
	if err != nil {
		return err
	}
	exeDir, exe := systemExecutable(runtime.GOOS, os.Getenv("ProgramFiles"))
	if err := copyProtectedExecutable(src, exeDir, exe); err != nil {
		return err
	}
	cfg, err := os.ReadFile(configPath) //nolint:gosec // operator-chosen config copied into ProgramData
	if err != nil {
		return err
	}
	if err := os.MkdirAll(windowsConfigDir, 0o750); err != nil {
		return err
	}
	body, creds, err := stageWindowsConfig(cfg, windowsConfigDir)
	if err != nil {
		return err
	}
	if err := writeRootFile(windowsConfigDir, windowsConfigPath, body, 0o600); err != nil {
		return err
	}
	// Unix modes do not set a DACL. icacls removes inheritance and grants
	// only SYSTEM and Administrators on the directory, the config, copied
	// credential files, and the protected executable.
	if err := protectWindowsInstall(windowsConfigDir, windowsConfigPath, exeDir, exe, creds); err != nil {
		return err
	}
	args := renderSchtasksCreate(exe, windowsConfigPath)
	if out, err := exec.Command("schtasks", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("installed scheduled task", windowsTaskName)
	fmt.Println("config:", windowsConfigPath)
	return nil
}

func uninstallWindowsTask() error {
	if runtime.GOOS != "windows" {
		return errors.New("scheduled tasks are only removed on Windows")
	}
	args := renderSchtasksDelete()
	if out, err := exec.Command("schtasks", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("removed scheduled task", windowsTaskName)
	_, exe := systemExecutable(runtime.GOOS, os.Getenv("ProgramFiles"))
	if err := removeProtectedExecutable(exe); err != nil {
		return err
	}
	fmt.Println("removed", exe)
	fmt.Println("left", windowsConfigPath, "in place")
	return nil
}

func writeRootFile(dir, path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // directory must stay traversable; 0750 is the required mode
		return err
	}
	return os.WriteFile(path, data, mode) //nolint:gosec // callers pass a fixed install path, not a request path
}
