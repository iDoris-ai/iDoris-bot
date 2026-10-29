package vpnd

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
)

// serviceStateDir is the machine-service state directory.
//
// systemd sets STATE_DIRECTORY from StateDirectory= (the first entry when
// several directories are listed, separated by colons). A LaunchDaemon and
// the Windows SYSTEM task set the same variable. Callers consult it before
// any home, config, or cache directory, so a service without HOME still has
// a place to write.
//
// An unset or blank value returns "", nil and the caller keeps its per-user
// default. A set value that is not absolute is an error: falling through to
// a home directory would hide a broken service environment.
func serviceStateDir() (string, error) {
	return parseStateDirectory(os.Getenv("STATE_DIRECTORY"), runtime.GOOS)
}

// parseStateDirectory applies the STATE_DIRECTORY rules for goos.
// Windows paths are not split on colon: the drive letter is a colon.
func parseStateDirectory(raw, goos string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	first := raw
	if goos != "windows" {
		cut, _, _ := strings.Cut(raw, ":")
		first = strings.TrimSpace(cut)
	}
	if first == "" || !statePathAbs(first, goos) {
		return "", fmt.Errorf("STATE_DIRECTORY must be an absolute path, got %q", raw)
	}
	if goos == "windows" {
		return cleanWindowsPath(first), nil
	}
	return path.Clean(first), nil
}

func statePathAbs(p, goos string) bool {
	if goos == "windows" {
		if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `//`) {
			return len(p) > 2
		}
		if len(p) < 3 || p[1] != ':' {
			return false
		}
		letter := p[0]
		if (letter < 'A' || letter > 'Z') && (letter < 'a' || letter > 'z') {
			return false
		}
		return p[2] == '\\' || p[2] == '/'
	}
	return strings.HasPrefix(p, "/")
}

func cleanWindowsPath(p string) string {
	slashed := strings.ReplaceAll(p, `\`, `/`)
	cleaned := path.Clean(slashed)
	// path.Clean collapses a UNC prefix to a single slash. Put it back.
	if (strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `//`)) && !strings.HasPrefix(cleaned, "//") {
		cleaned = "/" + cleaned
	}
	return strings.ReplaceAll(cleaned, `/`, `\`)
}

// ResolveStateFile applies the daemon state-file order: an explicit config,
// flag, or IDORIS_VPN_STATE_FILE value, then STATE_DIRECTORY/vpnd-state.json,
// then the per-user default.
func ResolveStateFile(explicit string) (string, error) {
	if p := strings.TrimSpace(explicit); p != "" {
		return p, nil
	}
	return DefaultStateFile()
}

// ResolveStateDir applies the embedded-node state-dir order: an explicit
// config, flag, or IDORIS_VPN_STATE_DIR value, then STATE_DIRECTORY/node,
// then the per-user default.
func ResolveStateDir(explicit string) (string, error) {
	if p := strings.TrimSpace(explicit); p != "" {
		return p, nil
	}
	return DefaultStateDir()
}
