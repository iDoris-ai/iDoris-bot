//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// validateExecutableAncestors fails closed unless every existing ancestor of
// exe is a directory owned by root, not group/other-writable, and not a
// symlink. A missing leaf is allowed; the installer creates it.
func validateExecutableAncestors(exe string) error {
	dir := filepath.Clean(exe)
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("service: %s does not exist", exe)
		}
		st, err := os.Lstat(parent) //nolint:gosec // G703: install path ancestors, not a request path
		if err != nil {
			if os.IsNotExist(err) {
				dir = parent
				continue
			}
			return fmt.Errorf("service: cannot inspect %s: %w", parent, err)
		}
		return checkAncestorChain(parent, st)
	}
}

func checkAncestorChain(dir string, st os.FileInfo) error {
	for {
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("service: %s is a symlink; refusing to install under a path with a symlink component", dir)
		}
		if !st.IsDir() {
			return fmt.Errorf("service: %s is not a directory", dir)
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys == nil {
			return fmt.Errorf("service: %s owner is unknown", dir)
		}
		if sys.Uid != 0 {
			return fmt.Errorf("service: %s is owned by uid %d, not root. On macOS the machine service installs under /Library/PrivilegedHelperTools/idoris. On Linux every ancestor of /usr/local/lib/idoris must be owned by root", dir, sys.Uid)
		}
		if st.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("service: %s is writable by group or others (mode %o). Remove that write bit before installing", dir, st.Mode().Perm())
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		next, err := os.Lstat(parent) //nolint:gosec // G703: install path ancestors, not a request path
		if err != nil {
			return fmt.Errorf("service: cannot inspect %s: %w", parent, err)
		}
		dir, st = parent, next
	}
}
