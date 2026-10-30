package vpnd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
	"tailscale.com/paths"
)

// ControllerLock is an exclusive hold on one backend. The process keeps the
// file open for its whole life; closing it releases the lock. A second
// idoris-vpnd that targets the same backend fails immediately.
type ControllerLock struct {
	f     *os.File
	path  string
	extra any // keeps the Windows OVERLAPPED alive for the life of the lock
}

// Path is the lock file.
func (l *ControllerLock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Release drops the exclusive hold. It is safe to call more than once.
func (l *ControllerLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := unlockFile(l.f, l.extra)
	cerr := l.f.Close()
	l.f = nil
	l.extra = nil
	if err != nil {
		return err
	}
	return cerr
}

// LockSystem locks the system tailscaled this daemon will drive.
// The lock file is named by the canonical LocalAPI socket and lives in
// os.UserCacheDir()/idoris/locks, so XDG_STATE_HOME and an explicit spelling
// of the default socket do not create a second lock. Two OS users still have
// two cache directories: a root system service and a user daemon do not
// exclude each other.
func LockSystem(socketPath string) (*ControllerLock, error) {
	path, err := systemLockPath(socketPath)
	if err != nil {
		return nil, err
	}
	return acquireLock(path, "system")
}

// LockEmbedded locks the embedded state directory before tsnet is started.
// The directory is canonicalised, so a symlink and its target share one lock.
func LockEmbedded(stateDir string) (*ControllerLock, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return nil, fmt.Errorf("embedded controller lock: state dir is empty")
	}
	if !filepath.IsAbs(stateDir) {
		abs, err := filepath.Abs(stateDir)
		if err != nil {
			return nil, err
		}
		stateDir = abs
	}
	stateDir = canonicalizePath(stateDir)
	if err := fsutil.EnsurePrivateDir(stateDir); err != nil {
		return nil, err
	}
	return acquireLock(filepath.Join(stateDir, "controller.lock"), "embedded")
}

func systemLockDir() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil || cache == "" {
		return "", fmt.Errorf("controller lock directory: %w", err)
	}
	dir := filepath.Join(cache, "idoris", "locks")
	if err := fsutil.EnsurePrivateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func systemLockPath(socketPath string) (string, error) {
	dir, err := systemLockDir()
	if err != nil {
		return "", err
	}
	key, err := systemLockKey(socketPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, key+".lock"), nil
}

func lockSystemIn(dir, socketPath string) (*ControllerLock, error) {
	key, err := systemLockKey(socketPath)
	if err != nil {
		return nil, err
	}
	if err := fsutil.EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	return acquireLock(filepath.Join(dir, key+".lock"), "system")
}

func systemLockKey(socketPath string) (string, error) {
	canon, err := canonicalSocket(socketPath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:]), nil
}

// canonicalSocket is the LocalAPI identity. An empty path is the platform
// default (the same path tailscale.com/paths uses), then symlinks are
// resolved so "/var/..." and "/private/var/..." share a lock when /var is
// a symlink. A socket that does not exist yet still contributes its
// resolved parent, so the file not being there yet does not split the key.
func canonicalSocket(socketPath string) (string, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		socketPath = paths.DefaultTailscaledSocket()
	}
	if strings.TrimSpace(socketPath) == "" {
		return "", fmt.Errorf("system controller lock: no default LocalAPI socket")
	}
	if isPipePath(socketPath) {
		return socketPath, nil
	}
	if !filepath.IsAbs(socketPath) {
		abs, err := filepath.Abs(socketPath)
		if err != nil {
			return "", err
		}
		socketPath = abs
	}
	return canonicalizePath(socketPath), nil
}

func isPipePath(path string) bool {
	return strings.HasPrefix(path, `\\`) || strings.HasPrefix(strings.ToLower(path), `//./pipe/`)
}
