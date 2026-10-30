package vpnd

import (
	"path/filepath"
	"strings"
)

// SOCKSAuthPath is the credential file a member SOCKS5 listener uses.
// An explicit socks5_auth_file wins. Otherwise the file is socks5.auth
// inside ResolveStateDir: an explicit state_dir, then STATE_DIRECTORY/node,
// then ~/.idoris/vpn-state. That is the same order the daemon uses when it
// starts the listener.
func SOCKSAuthPath(explicitAuth, explicitState string) (string, error) {
	if p := strings.TrimSpace(explicitAuth); p != "" {
		return p, nil
	}
	dir, err := ResolveStateDir(explicitState)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "socks5.auth"), nil
}
