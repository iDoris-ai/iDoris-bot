//go:build windows

package vpnd

import (
	"log/slog"
	"os"
)

// Windows has no flock in the standard library. The service manager is what
// keeps a second user service from starting. This hold is best-effort: it
// creates the lock file and does not fail when another process has it.
func acquireLock(path, kind string) (*ControllerLock, error) {
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // lock file path is derived from the state dir or socket hash
	if err != nil {
		return nil, err
	}
	slog.Warn("controller lock is best-effort on Windows; a second idoris-vpnd is not excluded by the OS", "backend", kind, "path", path)
	return &ControllerLock{f: f, path: path}, nil
}

func unlockFile(*os.File) error { return nil }
