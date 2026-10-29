//go:build unix

package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// acceptInstallSecret allows a 0600 regular file owned by the current user,
// or, when this process is root and SUDO_UID is set, owned by that uid.
// SUDO_UID is ignored unless the process is root. The owner comes from stat.
func acceptInstallSecret(path string) error {
	info, err := os.Lstat(path) //nolint:gosec // G703: operator-chosen secret path, not a request path
	if err != nil {
		return fmt.Errorf("secret file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("secret file %s is a symlink; replace it with a regular owner-only file: chmod 600 %s", path, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("secret file %s is not a regular file: chmod 600 %s", path, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("secret file %s is mode %o and must be owner-only: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return fmt.Errorf("secret file %s: owner is unknown: chmod 600 %s", path, path)
	}
	euid := os.Geteuid()
	if euid >= 0 && uint64(st.Uid) == uint64(euid) {
		return nil
	}
	if euid != 0 {
		return fmt.Errorf("secret file %s is owned by uid %d, not uid %d: chmod 600 %s", path, st.Uid, euid, path)
	}
	sudo := os.Getenv("SUDO_UID")
	if sudo == "" {
		return fmt.Errorf("secret file %s is owned by uid %d, not root, and SUDO_UID is unset. Re-run with sudo so the invoking user can be checked", path, st.Uid)
	}
	n, err := strconv.ParseUint(sudo, 10, 32)
	if err != nil || uint32(n) != st.Uid {
		return fmt.Errorf("secret file %s is owned by uid %d, which is not SUDO_UID %q", path, st.Uid, sudo)
	}
	return nil
}
