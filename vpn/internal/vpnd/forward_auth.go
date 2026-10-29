package vpnd

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveSOCKSAuth decides how a SOCKS5 listener authenticates.
// An explicit user/password wins. Otherwise a 0600 file is loaded, or
// created under StateDir. Anonymous is only the explicit opt-in.
func resolveSOCKSAuth(opt AccessOptions) (user, pass string, anon bool, err error) {
	switch {
	case opt.SOCKS5User != "" || opt.SOCKS5Password != "":
		if opt.SOCKS5User == "" || opt.SOCKS5Password == "" {
			return "", "", false, errors.New("vpnd: SOCKS5 username and password are both required")
		}
		return opt.SOCKS5User, opt.SOCKS5Password, false, nil
	case opt.SOCKS5AuthFile != "":
		user, pass, err = loadOrCreateSOCKSAuth(opt.SOCKS5AuthFile, false)
		return user, pass, false, err
	case opt.StateDir != "":
		user, pass, err = loadOrCreateSOCKSAuth(filepath.Join(opt.StateDir, "socks5.auth"), true)
		return user, pass, false, err
	case opt.AllowAnonymous:
		return "", "", true, nil
	default:
		return "", "", false, errors.New("vpnd: SOCKS5 requires socks5_auth_file, a state dir, or socks5_allow_anonymous")
	}
}

// loadOrCreateSOCKSAuth reads one "user:password" line. create is set for the
// state-dir file, which is generated when it is absent. An operator-supplied
// path is never created, so a typo does not invent a credential.
func loadOrCreateSOCKSAuth(path string, create bool) (string, string, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return "", "", fmt.Errorf("vpnd: socks5 auth file %q: %w", path, err)
		}
		return writeSOCKSAuth(path)
	}
	if err != nil {
		return "", "", err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return "", "", fmt.Errorf("vpnd: socks5 auth file %q: refusing a symlink", path)
	}
	if st.Mode().Perm() != 0o600 {
		return "", "", fmt.Errorf("vpnd: socks5 auth file %q must be mode 0600", path)
	}
	return readSOCKSAuth(path)
}

func writeSOCKSAuth(path string) (string, string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", err
	}
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", "", err
	}
	user, pass := "idoris", hex.EncodeToString(buf[:])
	// O_EXCL plus 0600: umask cannot add group or world bits to this mode,
	// and a second daemon will not overwrite the credential.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // path is the daemon state dir, mode is 0600
	if err != nil {
		return "", "", err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.WriteString(user + ":" + pass + "\n"); err != nil {
		return "", "", err
	}
	if err := f.Chmod(0o600); err != nil {
		return "", "", err
	}
	ok = true
	return user, pass, nil
}

func readSOCKSAuth(path string) (string, string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // mode was checked; path is the operator auth file or the state dir
	if err != nil {
		return "", "", err
	}
	if len(b) > 1024 {
		return "", "", fmt.Errorf("vpnd: socks5 auth file %q is too large", path)
	}
	line := strings.TrimRight(string(b), "\r\n")
	if strings.ContainsAny(line, "\r\n") {
		return "", "", fmt.Errorf("vpnd: socks5 auth file %q must be a single line", path)
	}
	user, pass, ok := strings.Cut(line, ":")
	if !ok || user == "" || pass == "" {
		return "", "", fmt.Errorf("vpnd: socks5 auth file %q must contain user:password", path)
	}
	return user, pass, nil
}

// credEqual compares SOCKS5 credentials without leaking which side or which
// byte differed, and without returning early on the length.
func credEqual(gotUser, gotPass, wantUser, wantPass string) bool {
	sum := func(user, pass string) [sha256.Size]byte {
		h := sha256.New()
		_, _ = h.Write([]byte(user))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(pass))
		var out [sha256.Size]byte
		copy(out[:], h.Sum(nil))
		return out
	}
	got := sum(gotUser, gotPass)
	want := sum(wantUser, wantPass)
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

func init() {
	_ = resolveSOCKSAuth
	_ = credEqual
}
