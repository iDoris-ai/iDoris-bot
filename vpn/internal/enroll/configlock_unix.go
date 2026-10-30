//go:build unix

package enroll

import (
	"fmt"
	"os"
	"syscall"
)

// acquireConfigLock takes an exclusive flock on <config>.lock in the same
// directory as the config. The file mode is 0600. The lock is held until
// release returns, and the kernel drops it if this process dies. A second
// process blocks in flock until the first finishes the whole transaction.
// Writers create the file. Readers use acquireConfigLockRead and must not.
func acquireConfigLock(path string) (func(), error) {
	resolved, err := configPath(path)
	if err != nil {
		return nil, err
	}
	lockPath := resolved + ".lock"
	f, created, err := openConfigLock(lockPath)
	if err != nil {
		return nil, lockOpenError(path, lockPath, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		if created {
			_ = os.Remove(lockPath) //nolint:gosec // lock sits beside the operator-chosen config
		}
		return nil, err
	}
	if created {
		if err := chownNewLock(resolved, f); err != nil {
			_ = f.Close()
			_ = os.Remove(lockPath) //nolint:gosec // lock sits beside the operator-chosen config
			return nil, err
		}
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		if created {
			_ = os.Remove(lockPath) //nolint:gosec // lock sits beside the operator-chosen config
		}
		return nil, fmt.Errorf("enroll: lock %s: %w", lockPath, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// openConfigLock creates the lock only when it is absent, and reports that
// fact so the caller can chown a lock this process just created.
func openConfigLock(lockPath string) (*os.File, bool, error) {
	f, err := os.OpenFile(lockPath, os.O_RDWR, 0) //nolint:gosec // lock sits beside the operator-chosen config
	if err == nil {
		return f, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, err
	}
	f, err = os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) //nolint:gosec // lock sits beside the operator-chosen config
	if err == nil {
		return f, true, nil
	}
	if !os.IsExist(err) {
		return nil, false, err
	}
	f, err = os.OpenFile(lockPath, os.O_RDWR, 0) //nolint:gosec // lock sits beside the operator-chosen config
	if err != nil {
		return nil, false, err
	}
	return f, false, nil
}

// acquireConfigLockRead flocks an existing lock file. A missing file is not
// created: no writer has run, so there is nothing to exclude. Permission
// errors use the same unavailable error as a read-only mount.
func acquireConfigLockRead(path string) (func(), error) {
	resolved, err := configPath(path)
	if err != nil {
		return nil, err
	}
	lockPath := resolved + ".lock"
	f, err := os.OpenFile(lockPath, os.O_RDWR, 0) //nolint:gosec // lock sits beside the operator-chosen config
	if err != nil {
		return nil, lockUnavailable(lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("enroll: lock %s: %w", lockPath, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
