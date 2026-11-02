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
// resolveSOCKSAuth returns the credential, whether anonymous access was
// requested, the auth-file path when one is used, and whether that file was
// created on this call. created is false when an existing file is loaded.
func resolveSOCKSAuth(opt AccessOptions) (user, pass string, anon bool, authPath string, created bool, err error) {
	switch {
	case opt.SOCKS5User != "" || opt.SOCKS5Password != "":
		if opt.SOCKS5User == "" || opt.SOCKS5Password == "" {
			return "", "", false, "", false, errors.New("vpnd: SOCKS5 username and password are both required")
		}
		if err = validateSOCKSCred(opt.SOCKS5User, opt.SOCKS5Password); err != nil {
			return "", "", false, "", false, err
		}
		return opt.SOCKS5User, opt.SOCKS5Password, false, "", false, nil
	case opt.SOCKS5AuthFile != "":
		user, pass, created, err = loadOrCreateSOCKSAuth(opt.SOCKS5AuthFile, false)
		if err != nil {
			return "", "", false, "", false, err
		}
		if err = validateSOCKSCred(user, pass); err != nil {
			return "", "", false, "", false, err
		}
		return user, pass, false, opt.SOCKS5AuthFile, created, nil
	case opt.StateDir != "":
		authPath = filepath.Join(opt.StateDir, "socks5.auth")
		user, pass, created, err = loadOrCreateSOCKSAuth(authPath, true)
		if err != nil {
			return "", "", false, "", false, err
		}
		if err = validateSOCKSCred(user, pass); err != nil {
			return "", "", false, "", false, err
		}
		return user, pass, false, authPath, created, nil
	case opt.AllowAnonymous:
		return "", "", true, "", false, nil
	default:
		return "", "", false, "", false, errors.New("vpnd: SOCKS5 requires socks5_auth_file, a state dir, or socks5_allow_anonymous")
	}
}

// loadOrCreateSOCKSAuth reads one "user:password" line. create is set for the
// state-dir file, which is generated when it is absent. An operator-supplied
// path is never created, so a typo does not invent a credential.
func loadOrCreateSOCKSAuth(path string, create bool) (user, pass string, created bool, err error) {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return "", "", false, fmt.Errorf("vpnd: socks5 auth file %q: %w", path, err)
		}
		user, pass, err = writeSOCKSAuth(path)
		return user, pass, err == nil, err
	}
	if err != nil {
		return "", "", false, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return "", "", false, fmt.Errorf("vpnd: socks5 auth file %q: refusing a symlink", path)
	}
	// Windows reports ordinary files as 0666, so a 0600 comparison rejects the
	// credential this process generated on the previous start. That OS uses
	// the file's ACL instead of the Unix mode bits.
	if socksRejectsLooseMode(st.Mode()) {
		return "", "", false, fmt.Errorf("vpnd: socks5 auth file %q must be mode 0600", path)
	}
	user, pass, err = readSOCKSAuth(path)
	return user, pass, false, err
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
	// Close before the Windows ACL edit. On Unix protectGeneratedSecret is a
	// no-op and the 0600 mode above is the control. Failure removes the file.
	if err := f.Close(); err != nil {
		return "", "", err
	}
	if err := protectGeneratedSecret(path); err != nil {
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

// validateSOCKSCred enforces the RFC 1929 field length. The length is bytes,
// not runes. A value outside 1..255 is accepted by the config parser but no
// client can send it, so the listener must not open.
func validateSOCKSCred(user, pass string) error {
	if n := len(user); n < 1 || n > 255 {
		return fmt.Errorf("vpnd: SOCKS5 username must be 1 to 255 bytes")
	}
	if n := len(pass); n < 1 || n > 255 {
		return fmt.Errorf("vpnd: SOCKS5 password must be 1 to 255 bytes")
	}
	return nil
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
