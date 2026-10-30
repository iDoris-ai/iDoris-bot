//go:build unix

package enroll

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// withFileLock locks the canonical config path. A symlink and its target share
// one lock file, and that lock file is the same one writeInPlace truncates under.
func withFileLock(path string, fn func() error) error {
	resolved, err := configPath(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(resolved+".lock", os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // lock beside the canonical config
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
