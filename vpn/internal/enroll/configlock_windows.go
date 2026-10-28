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

// acquireConfigLockRead opens an existing lock without creating it. Windows
// still does not exclude another process; the split only matches Unix, where
// a credential listing must not leave a root-owned lock behind.
func acquireConfigLockRead(path string) (func(), error) {
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_RDWR, 0) //nolint:gosec // lock sits beside the operator-chosen config
	if err != nil {
		return nil, lockUnavailable(lockPath, err)
	}
	return func() { _ = f.Close() }, nil
}
