//go:build unix

package vpnd

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
)

func acquireLock(path, kind string) (*ControllerLock, error) {
	if err := fsutil.EnsurePrivateDir(dirOf(path)); err != nil {
		return nil, err
	}
	if err := refuseLockSymlink(path); err != nil {
		return nil, err
	}
	// O_NOFOLLOW fails with ELOOP when the last component is a symlink,
	// so a planted lock path cannot truncate or flock the link target.
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("lock file %s is a symlink", path)
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err := f.Chmod(0o600); err != nil {
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

func unlockFile(f *os.File, _ any) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

func refuseLockSymlink(path string) error {
	st, err := os.Lstat(path) //nolint:gosec // G703: path is the controller lock under the user cache or state dir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("lock file %s is a symlink", path)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("lock file %s is not a regular file", path)
	}
	return nil
}
