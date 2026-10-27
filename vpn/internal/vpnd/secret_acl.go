package vpnd

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// socksACLRunner, when set, runs icacls. Production sets it on Windows.
// Tests pass a runner into applyOwnerACL and do not execute icacls.
var socksACLRunner func(name string, args ...string) ([]byte, error)

// socksRejectsLooseMode reports whether this OS must refuse a SOCKS auth
// file whose permission bits are not 0600. Windows does not: Go reports
// ordinary files as 0666.
func socksRejectsLooseMode(mode os.FileMode) bool {
	return socksRejectsLooseModeOn(mode, socksChecksUnixMode)
}

// socksRejectsLooseModeOn is the policy with the platform bit injected so
// the Windows decision can be tested on a Unix host.
func socksRejectsLooseModeOn(mode os.FileMode, checkUnix bool) bool {
	if !checkUnix {
		return false
	}
	return mode.Perm() != 0o600
}

// validOwnerSID accepts a Windows SID and nothing that icacls would treat
// as another argument or another principal.
func validOwnerSID(sid string) bool {
	if !strings.HasPrefix(sid, "S-1-") {
		return false
	}
	return !strings.ContainsAny(sid, " \t:*")
}

// ownerOnlyICACLS is the service installer's three-step shape
// (/reset, /inheritance:r, /grant:r) with one change: the ACE is the
// current user's SID, not SYSTEM and Administrators. Those two principals
// are correct for a machine service directory. This file is a per-user
// SOCKS credential, and granting them would lock the user out of it.
func ownerOnlyICACLS(path, sid string) [][]string {
	return [][]string{
		{"icacls", path, "/reset"},
		{"icacls", path, "/inheritance:r"},
		{"icacls", path, "/grant:r", "*" + sid + ":F"},
	}
}

// applyOwnerACL runs the three icacls commands and stops at the first
// failure, so a denied /inheritance:r does not continue to /grant.
func applyOwnerACL(path, sid string, run func(string, ...string) ([]byte, error)) error {
	if !validOwnerSID(sid) {
		return fmt.Errorf("owner SID %q is not usable", sid)
	}
	if run == nil {
		run = socksACLRunner
	}
	if run == nil {
		return errors.New("owner ACL runner is not set")
	}
	for _, argv := range ownerOnlyICACLS(path, sid) {
		out, err := run(argv[0], argv[1:]...)
		if err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
