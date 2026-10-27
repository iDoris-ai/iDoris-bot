package vpnd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ControllerLock is an exclusive hold on one backend. The process keeps the
// file open for its whole life; closing it releases the lock. A second
// idoris-vpnd that targets the same backend fails immediately.
type ControllerLock struct {
	f    *os.File
	path string
}

// Path is the lock file. Tests use it to see that two sockets do not share one.
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
	err := unlockFile(l.f)
	cerr := l.f.Close()
	l.f = nil
	if err != nil {
		return err
	}
	return cerr
}

// LockSystem locks the system tailscaled this daemon will drive. An empty
// socket path uses one stable key, so two daemons on the default socket
// still exclude each other. The lock directory is the directory of the
// identity state file (~/.idoris, or the XDG / Windows equivalent).
func LockSystem(socketPath string) (*ControllerLock, error) {
	dir, err := defaultLockDir()
	if err != nil {
		return nil, err
	}
	return lockSystemIn(dir, socketPath)
}

// LockEmbedded locks the embedded state directory before tsnet is started.
func LockEmbedded(stateDir string) (*ControllerLock, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return nil, fmt.Errorf("embedded controller lock: state dir is empty")
	}
	return acquireLock(filepath.Join(stateDir, "controller.lock"), "embedded")
}

func defaultLockDir() (string, error) {
	state, err := DefaultStateFile()
	if err != nil {
		return "", err
	}
	return filepath.Dir(state), nil
}

func lockSystemIn(dir, socketPath string) (*ControllerLock, error) {
	return acquireLock(filepath.Join(dir, "system-"+systemLockKey(socketPath)+".lock"), "system")
}

func systemLockKey(socketPath string) string {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		return "default"
	}
	sum := sha256.Sum256([]byte(filepath.Clean(socketPath)))
	return hex.EncodeToString(sum[:])
}
