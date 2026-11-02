//go:build windows

package vpnd

import (
	"fmt"
	"log/slog"
	"os/exec"
	"os/user"
	"strings"
)

// socksChecksUnixMode is false on Windows. os.FileMode for an ordinary file
// is 0666 even after we create it owner-only, so a 0600 comparison rejects
// the credential on every restart.
const socksChecksUnixMode = false

func checkSecretFile(path string) error {
	slog.Default().Warn("secret file permissions were not verified on Windows; keep the file owner-only (chmod 600)", "path", path)
	return nil
}

// protectGeneratedSecret restricts a file this process just created to the
// current user's SID. The service installer grants SYSTEM and Administrators
// because that tree is a machine install. A SOCKS credential lives in the
// user profile, so the ACE is *<sid>:F for os/user.Current, not those two
// principals. An operator-supplied socks5_auth_file is not rewritten; it
// keeps the profile directory's ACL.
func protectGeneratedSecret(path string) error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("socks5 auth file owner: %w", err)
	}
	sid := strings.TrimSpace(u.Uid)
	if !validOwnerSID(sid) {
		return fmt.Errorf("socks5 auth file owner SID %q is not usable", sid)
	}
	return applyOwnerACL(path, sid, socksACLRunner)
}

// The Windows build is the one that executes icacls. Tests inject a runner
// into applyOwnerACL and do not take this path.
func init() {
	if socksACLRunner == nil {
		socksACLRunner = func(name string, args ...string) ([]byte, error) {
			out, err := exec.Command(name, args...).CombinedOutput() //nolint:gosec // G204: argv is the fixed icacls sequence, path is the generated auth file
			return out, err
		}
	}
}
