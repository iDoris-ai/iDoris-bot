//go:build unix

package enroll

import (
	"fmt"
	"os"
	"syscall"
)

func callerIDs() (uid, gid int, ok bool) {
	return os.Geteuid(), os.Getegid(), true
}

func ownerOf(st os.FileInfo) (uid, gid int, ok bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return 0, 0, false
	}
	return int(sys.Uid), int(sys.Gid), true
}

// refuseForeignConfig stops a non-root caller from replacing a config owned
// by someone else. Root can chown the replacement. The check runs before the
// lock file is created.
func refuseForeignConfig(path string) error {
	euid, egid, ok := callerIDs()
	if !ok || euid == 0 {
		return nil
	}
	st, err := os.Stat(path) //nolint:gosec // path is the operator-chosen enroll config
	if err != nil {
		return err
	}
	ou, og, ook := ownerOf(st)
	if !ook || (ou == euid && og == egid) {
		return nil
	}
	return mismatchedOwnerError(path, st, euid, egid)
}

func mismatchedOwnerError(path string, st os.FileInfo, euid, egid int) error {
	ou, og, _ := ownerOf(st)
	return fmt.Errorf("enroll: config %s is owned by uid %d gid %d (mode %o); caller is uid %d gid %d. Refusing to replace it before any change. Re-run as that user: sudo -u \\#%d -g \\#%d -- idoris-vpn-enroll invite --config %s",
		path, ou, og, st.Mode().Perm(), euid, egid, ou, og, path)
}

// preserveOwner chowns the temp file to the config's owner before rename.
// A non-root caller never calls chown: that returns EPERM, and a mismatched
// owner was already refused with the invocation above.
func preserveOwner(path string, f *os.File, st os.FileInfo) error {
	euid, egid, ok := callerIDs()
	if !ok {
		return nil
	}
	ou, og, ook := ownerOf(st)
	if !ook || (ou == euid && og == egid) {
		return nil
	}
	if euid != 0 {
		return mismatchedOwnerError(path, st, euid, egid)
	}
	if err := syscall.Fchown(int(f.Fd()), ou, og); err != nil {
		return fmt.Errorf("enroll: chown replacement to uid %d gid %d: %w", ou, og, err)
	}
	return nil
}

// chownNewLock gives a lock this process just created to the config owner.
// The caller removes the lock when this returns an error.
func chownNewLock(configPath string, f *os.File) error {
	euid, _, ok := callerIDs()
	if !ok || euid != 0 {
		return nil
	}
	st, err := os.Stat(configPath) //nolint:gosec // path is the operator-chosen enroll config
	if err != nil {
		return err
	}
	ou, og, ook := ownerOf(st)
	if !ook || (ou == 0 && og == 0) {
		return nil
	}
	if err := syscall.Fchown(int(f.Fd()), ou, og); err != nil {
		return fmt.Errorf("enroll: chown lock %s to uid %d gid %d: %w", f.Name(), ou, og, err)
	}
	return nil
}

// lockOpenError keeps errConfigLockUnavailable for callers that branch on it.
// A non-root caller who does not own the config gets the re-run invocation
// instead of a bare permission error.
func lockOpenError(configPath, lockPath string, err error) error {
	base := lockUnavailable(lockPath, err)
	if !os.IsPermission(err) {
		return base
	}
	euid, egid, ok := callerIDs()
	if !ok || euid == 0 {
		return base
	}
	st, statErr := os.Stat(configPath) //nolint:gosec // path is the operator-chosen enroll config
	if statErr != nil {
		return base
	}
	ou, og, ook := ownerOf(st)
	if !ook || (ou == euid && og == egid) {
		return base
	}
	return fmt.Errorf("%w. %w", base, mismatchedOwnerError(configPath, st, euid, egid))
}
