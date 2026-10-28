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
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // lock sits beside the operator-chosen config
	if err != nil {
		return nil, lockUnavailable(lockPath, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
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

// acquireConfigLockRead flocks an existing lock file. A missing file is not
// created: no writer has run, so there is nothing to exclude. Permission
// errors use the same unavailable error as a read-only mount.
func acquireConfigLockRead(path string) (func(), error) {
	lockPath := path + ".lock"
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
