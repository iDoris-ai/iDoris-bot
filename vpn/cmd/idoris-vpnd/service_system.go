package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err != nil { //nolint:gosec // G703: operator-chosen config path, made absolute
		return fmt.Errorf("config: %w", err)
	}
	configPath = abs
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
		if name, ok := strings.CutPrefix(p, "/run/"); ok && systemdDirToken(name) && name != "idoris" && name != "user" {
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
		StateFile    string `json:"state_file"`
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
		// Never claim /run, /var/run, or /run/user. A nested path under
		// /run/user collapses to /run/user, which is the same shared directory.
		if err := rejectSharedRuntime(p); err != nil {
			return err
		}
		// A path under /run disappears on reboot. List only /run/<name>, which
		// RuntimeDirectory recreates. The parent is writable, so the daemon
		// can create anything nested below it. Listing the nested path would
		// make systemd fail the namespace once /run is empty again.
		// Nested and exact runtime paths both collapse to /run/<name>.
		if top, _ := runtimeDir(p); top != "" {
			collapsed := "/run/" + top
			if err := rejectSharedRuntime(collapsed); err != nil {
				return err
			}
			return appendReadWrite(&paths, collapsed)
		}
		return appendReadWrite(&paths, p)
	}
	if err := add(probe.StateDir); err != nil {
		return nil, err
	}
	if err := addStateFile(&paths, probe.StateFile); err != nil {
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
		dir := path.Dir(path.Clean(sock))
		if err := rejectSharedRuntime(dir); err != nil {
			return err
		}
		return add(dir)
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

// addStateFile lists the parent of state_file so an atomic rename has a
// writable directory. Paths under /run still collapse to /run/<name>. A
// shared runtime directory is rejected instead of being chmod'd.
func addStateFile(paths *[]string, p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil
	}
	if err := rejectUnsafePath(p); err != nil {
		return err
	}
	if !path.IsAbs(p) {
		return nil
	}
	parent := path.Clean(path.Dir(path.Clean(p)))
	if parent == "/" {
		return errors.New("config: refusing state_file in /")
	}
	if err := rejectSharedRuntime(parent); err != nil {
		return fmt.Errorf("config: state_file parent %s is a shared runtime directory. Put state_file under /var/lib/idoris", parent)
	}
	if top, _ := runtimeDir(parent); top != "" {
		if top == "user" {
			return fmt.Errorf("config: state_file parent %s is a shared runtime directory. Put state_file under /var/lib/idoris", parent)
		}
		return appendReadWrite(paths, "/run/"+top)
	}
	return appendReadWrite(paths, parent)
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

// rejectSharedRuntime refuses an ancestor the service does not own. The
// installer must not chmod it or list it as RuntimeDirectory.
func rejectSharedRuntime(p string) error {
	p = path.Clean(p)
	switch p {
	case "/run", "/var/run", "/run/user", "/var/run/user":
		return fmt.Errorf("config: %s is a shared runtime directory (/run, /var/run, or /run/user). The system service will not change it. Listen on unix:/run/idoris/ instead", p)
	}
	if strings.HasPrefix(p, "/run/user/") || strings.HasPrefix(p, "/var/run/user/") {
		return fmt.Errorf("config: %s is under the shared directory /run/user. The system service will not change it. Listen on unix:/run/idoris/ instead", p)
	}
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
		if err := rejectSharedRuntime(p); err != nil {
			return err
		}
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
	return renderSchtasksCreateIn(exe, configPath, windowsConfigDir)
}

func renderSchtasksCreateIn(exe, configPath, stateDir string) []string {
	// schtasks has no environment field. cmd /c sets STATE_DIRECTORY for this
	// process only. Under SYSTEM, os.UserConfigDir is the system profile;
	// state, the embedded node, and locks must stay in ProgramData, which
	// the installer creates and locks down with icacls. No space before &&:
	// cmd would otherwise include it in the value.
	tr := fmt.Sprintf("cmd /c set STATE_DIRECTORY=%s&& %s run --config %s", quoteTask(stateDir), quoteTask(exe), quoteTask(configPath))
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
	if err := validateExecutableAncestors(exe); err != nil {
		return err
	}
	cfg, err := os.ReadFile(configPath) //nolint:gosec // operator-chosen config copied into /etc
	if err != nil {
		return err
	}
	// Validate the unit and stage secrets before the installed binary or any
	// live file is replaced. A rejected listener or a missing credential
	// leaves the previous installation in place.
	unit, stage, installed, err := prepareSystemInstall(exe, systemConfigPath, systemStateDir, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }() //nolint:gosec // G703: stage is the directory prepareSystemInstall just created
	if err := copyProtectedExecutable(src, exeDir, exe); err != nil {
		return err
	}
	if err := finishSystemInstall(stage, systemStateDir, systemConfigPath, installed); err != nil {
		return err
	}
	// Every ReadWritePaths entry has to exist before systemd builds the
	// namespace. StateDirectory and RuntimeDirectory recreate /var/lib/idoris
	// and /run/idoris on boot; nested state directories are created here.
	if err := provisionSystemPaths("", installed); err != nil {
		return err
	}
	if err := os.WriteFile(systemUnitPath, []byte(unit), 0o600); err != nil { //nolint:gosec // fixed unit path under /etc/systemd/system
		return err
	}
	// Best effort: a user unit and this system unit must not both be running.
	_, _ = runServiceCommand("systemctl", "--user", "disable", "--now", systemUnitName)
	if err := activateSystemService("linux", systemServiceActive("linux")); err != nil {
		return err
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
		if out, err := runServiceCommand("systemctl", "disable", "--now", systemUnitName); err != nil {
			return fmt.Errorf("systemctl disable --now: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if err := os.Remove(systemUnitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if out, err := runServiceCommand("systemctl", "daemon-reload"); err != nil {
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
	if err := validateExecutableAncestors(exe); err != nil {
		return err
	}
	cfg, err := os.ReadFile(configPath) //nolint:gosec // operator-chosen config copied into /etc
	if err != nil {
		return err
	}
	// Same order as the systemd installer: a bad listener path or a missing
	// credential must not overwrite the live token or config. The plist is
	// rendered after that commit. The systemd unit text is what rejects
	// /run/user; it is not installed on macOS.
	_, stage, installed, err := prepareSystemInstall(exe, systemConfigPath, systemStateDir, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }() //nolint:gosec // G703: stage is the directory prepareSystemInstall just created
	if err := copyProtectedExecutable(src, exeDir, exe); err != nil {
		return err
	}
	if err := finishSystemInstall(stage, systemStateDir, systemConfigPath, installed); err != nil {
		return err
	}
	// STATE_DIRECTORY and the log paths in the plist. 0700 root: a LaunchDaemon
	// has no HOME, and these directories must not be group-writable.
	if err := provisionLaunchDaemonDirs(""); err != nil {
		return err
	}
	plist := renderSystemLaunchdPlist(exe, systemConfigPath, systemLogDir)
	if err := os.WriteFile(systemLaunchdPath, []byte(plist), 0o600); err != nil { //nolint:gosec // G703: fixed LaunchDaemon path under /Library/LaunchDaemons
		return err
	}
	_, _ = runServiceCommand("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), launchdLabel))
	if err := activateSystemService("darwin", systemServiceActive("darwin")); err != nil {
		return err
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
	_, _ = runServiceCommand("launchctl", "bootout", "system/"+launchdLabel)
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
		if err := os.MkdirAll(dest, d.mode); err != nil { //nolint:gosec // G703: dest is /var/lib/idoris or /var/log/idoris, or those paths under a test root
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
	staging, err := windowsStagingPath()
	if err != nil {
		return err
	}
	spec := windowsReplaceSpec{
		SrcExe:     src,
		LiveExe:    exe,
		ExeDir:     exeDir,
		ConfigSrc:  configPath,
		LiveDir:    windowsConfigDir,
		LiveConfig: windowsConfigPath,
		StagingDir: staging,
		Active:     systemServiceActive("windows"),
	}
	// tasklist matches the image name. This process is listed whether or not
	// it is the file the task runs, so the wait always ignores it. SelfPID
	// is only the signal to leave that mapped file alone.
	spec.ExcludePID = os.Getpid()
	if sameInstallExe(src, exe) {
		spec.SelfPID = os.Getpid()
	}
	if err := replaceWindowsTask(spec); err != nil {
		return err
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
	if out, err := runServiceCommand("schtasks", args...); err != nil {
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

func systemServiceActive(goos string) bool {
	switch goos {
	case "linux":
		out, err := runServiceCommand("systemctl", "is-active", systemUnitName)
		return err == nil && strings.TrimSpace(string(out)) == "active"
	case "darwin":
		_, err := runServiceCommand("launchctl", "print", "system/"+launchdLabel)
		return err == nil
	case "windows":
		_, err := runServiceCommand("schtasks", "/Query", "/TN", windowsTaskName)
		return err == nil
	default:
		return false
	}
}

// activateSystemService restarts a unit that is already running so a
// reinstall picks up the new config. A first install enables or bootstraps
// it. already is the result of systemServiceActive before this call.
func activateSystemService(goos string, already bool) error {
	switch goos {
	case "linux":
		if out, err := runServiceCommand("systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
		}
		if already {
			out, err := runServiceCommand("systemctl", "restart", systemUnitName)
			if err != nil {
				return fmt.Errorf("systemctl restart: %w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
		out, err := runServiceCommand("systemctl", "enable", "--now", systemUnitName)
		if err != nil {
			return fmt.Errorf("systemctl enable --now: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	case "darwin":
		target := "system/" + launchdLabel
		if already {
			_, _ = runServiceCommand("launchctl", "bootout", target)
			if out, err := runServiceCommand("launchctl", "bootstrap", "system", systemLaunchdPath); err != nil {
				return fmt.Errorf("launchctl bootstrap system: %w: %s", err, strings.TrimSpace(string(out)))
			}
			out, err := runServiceCommand("launchctl", "kickstart", "-k", target)
			if err != nil {
				return fmt.Errorf("launchctl kickstart: %w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
		out, err := runServiceCommand("launchctl", "bootstrap", "system", systemLaunchdPath)
		if err != nil {
			return fmt.Errorf("launchctl bootstrap system: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	case "windows":
		if !already {
			return nil
		}
		if out, err := runServiceCommand("schtasks", "/End", "/TN", windowsTaskName); err != nil {
			return fmt.Errorf("schtasks /End: %w: %s", err, strings.TrimSpace(string(out)))
		}
		out, err := runServiceCommand("schtasks", "/Run", "/TN", windowsTaskName)
		if err != nil {
			return fmt.Errorf("schtasks /Run: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	default:
		return fmt.Errorf("service activation is not supported on %s", goos)
	}
}

// prepareSystemInstall renders the machine unit, which rejects a shared
// runtime listener or state path, then copies credential files into a
// sibling of liveState. It does not write liveState or liveConfig. On
// failure the staging directory is removed. The caller removes it after a
// successful finishSystemInstall.
func prepareSystemInstall(exe, liveConfig, liveState string, cfg []byte) (string, string, []byte, error) {
	unit, err := renderSystemdSystemUnit(exe, liveConfig, cfg)
	if err != nil {
		return "", "", nil, err
	}
	parent := filepath.Dir(liveState)
	if parent == "" || parent == "." || parent == string(filepath.Separator) {
		return "", "", nil, errors.New("system install: state directory has no parent")
	}
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return "", "", nil, err
	}
	stage, err := os.MkdirTemp(parent, ".idoris-stage-*")
	if err != nil {
		return "", "", nil, err
	}
	body, err := stageSystemSecrets(cfg, stage)
	if err != nil {
		_ = os.RemoveAll(stage) //nolint:gosec // G703: stage is the directory just created above
		return "", "", nil, err
	}
	body, err = retargetStagedConfig(body, stage, liveState)
	if err != nil {
		_ = os.RemoveAll(stage) //nolint:gosec // G703: stage is the directory just created above
		return "", "", nil, err
	}
	return unit, stage, body, nil
}

// finishSystemInstall moves staged credential files onto liveState and writes
// the retargeted config. Call it only after prepareSystemInstall has succeeded.
func finishSystemInstall(stage, liveState, liveConfig string, body []byte) error {
	for _, name := range []string{"enroll_token", "auth_key", "socks5.auth"} {
		src := filepath.Join(stage, name)
		if _, err := os.Lstat(src); err != nil { //nolint:gosec // G703: src is a credential file inside the staging directory
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if err := os.MkdirAll(liveState, 0o750); err != nil { //nolint:gosec // G301: state directory mode matches the install tree
			return err
		}
		dest := filepath.Join(liveState, name)
		if err := replaceFile(src, dest); err != nil {
			return err
		}
		if err := chownSystemRoot(dest); err != nil {
			return err
		}
	}
	return writeRootFile(filepath.Dir(liveConfig), liveConfig, body, 0o600)
}

// stageSystemSecrets copies credential files into destDir as root-owned
// 0600 files and rewrites the installed config to those paths.
func stageSystemSecrets(cfg []byte, destDir string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(cfg))
	dec.UseNumber()
	var probe map[string]any
	if err := dec.Decode(&probe); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if dec.More() {
		return nil, errors.New("config: trailing data")
	}
	var written []string
	rollback := func() {
		for _, f := range written {
			_ = os.Remove(f)
		}
	}
	changed := false
	for _, it := range stagedCredentialFiles {
		raw, ok := probe[it.key]
		if !ok || raw == nil {
			continue
		}
		src, ok := raw.(string)
		if !ok {
			rollback()
			return nil, fmt.Errorf("config: %s is not a string", it.key)
		}
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		if err := acceptInstallSecret(src); err != nil {
			rollback()
			return nil, fmt.Errorf("%s: %w", it.key, err)
		}
		if err := os.MkdirAll(destDir, 0o750); err != nil {
			rollback()
			return nil, err
		}
		dest := filepath.Join(destDir, it.name)
		if err := copyCredentialFile(src, dest); err != nil {
			rollback()
			return nil, fmt.Errorf("%s: %w", it.key, err)
		}
		if err := chownSystemRoot(dest); err != nil {
			rollback()
			return nil, err
		}
		probe[it.key] = dest
		written = append(written, dest)
		changed = true
	}
	if !changed {
		return append([]byte(nil), cfg...), nil
	}
	body, err := json.MarshalIndent(probe, "", "  ")
	if err != nil {
		rollback()
		return nil, err
	}
	return append(body, '\n'), nil
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
