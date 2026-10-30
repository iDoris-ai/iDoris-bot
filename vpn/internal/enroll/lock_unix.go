//go:build unix

package enroll

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// withFileLock serializes readers and writers of the enroll config across processes.
func withFileLock(path string, fn func() error) error {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // lock beside the operator-chosen config
	if err != nil {
		return fmt.Errorf("enroll: lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("enroll: lock: %w", err)
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	return fn()
}
