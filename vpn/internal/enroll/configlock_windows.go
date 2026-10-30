//go:build windows

package enroll

import "os"

// acquireConfigLock is best-effort on Windows. The standard library has no
// flock, and this process does not call LockFileEx. The lock file is created
// mode 0600 next to the config so callers have a stable path, but another
// process is not excluded. Do not run overlapping invite and revoke on Windows.
func acquireConfigLock(path string) (func(), error) {
	resolved, err := configPath(path)
	if err != nil {
		return nil, err
	}
	lockPath := resolved + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // lock sits beside the operator-chosen config
	if err != nil {
		return nil, lockUnavailable(lockPath, err)
	}
	return func() { _ = f.Close() }, nil
}
