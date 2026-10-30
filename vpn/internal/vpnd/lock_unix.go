//go:build unix

package vpnd

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func acquireLock(path, kind string) (*ControllerLock, error) {
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // lock file path is derived from the state dir or socket hash
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("another idoris-vpnd already controls this %s backend (%s)", kind, path)
		}
		return nil, fmt.Errorf("lock %s backend (%s): %w", kind, path, err)
	}
	return &ControllerLock{f: f, path: path}, nil
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
