//go:build unix

package vpnd

import (
	"fmt"
	"os"
	"syscall"
)

func checkSecretFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("secret file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("secret file %s is a symlink; replace it with a regular owner-only file: chmod 600 %s", path, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("secret file %s is not a regular file: chmod 600 %s", path, path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return fmt.Errorf("secret file %s: owner is unknown: chmod 600 %s", path, path)
	}
	uid := os.Getuid()
	if uid < 0 || uint64(st.Uid) != uint64(uid) {
		return fmt.Errorf("secret file %s is owned by uid %d, not uid %d: chmod 600 %s", path, st.Uid, uid, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("secret file %s is mode %o and must be owner-only: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	return nil
}
