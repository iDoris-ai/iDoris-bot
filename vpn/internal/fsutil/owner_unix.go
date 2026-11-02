//go:build unix

package fsutil

import (
	"fmt"
	"os"
	"syscall"
)

func supportsUnixModes() bool { return true }

func protectSecretBeforeWrite(string) error { return nil }

func protectPrivateDir(string, bool) error { return nil }

func checkDirOwner(st os.FileInfo, dir string) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("fsutil: %s is owned by uid %d, not the current user", dir, sys.Uid)
	}
	return nil
}
