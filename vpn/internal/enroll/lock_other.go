//go:build !unix

package enroll

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// withFileLock is the non-unix fallback. A crash can leave the O_EXCL file behind.
// The wait is 100×5ms, which is shorter than a slow fsync, so this is not the
// Linux deliverable.
func withFileLock(path string, fn func() error) error {
	resolved, err := configPath(path)
	if err != nil {
		return err
	}
	lockPath := resolved + ".lock"
	var f *os.File
	for range 100 {
		f, err = os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) //nolint:gosec // lock beside the canonical config
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return fmt.Errorf("enroll: lock: %w", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if f == nil {
		return errors.New("enroll: lock timeout")
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(lockPath)
	}()
	return fn()
}
