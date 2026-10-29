package vpnd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ValidateForwardListen accepts a loopback host:port or unix:<absolute path>.
// It does not create or remove anything. StartAccess removes a stale socket
// and rejects one that another process is still serving.
func ValidateForwardListen(addr string) error {
	_, _, err := splitListen(addr)
	return err
}

func splitListen(addr string) (network, address string, err error) {
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		if err := validateUnixPath(path); err != nil {
			return "", "", err
		}
		return "unix", path, nil
	}
	if err := ValidateLoopback(addr); err != nil {
		return "", "", err
	}
	return "tcp", addr, nil
}

func validateUnixPath(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("vpnd: unix listen %q must be an absolute path", path)
	}
	parent := filepath.Dir(path)
	st, err := os.Stat(parent)
	if err == nil {
		if st.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("vpnd: unix listen %q: parent directory is world-writable", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	st, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("vpnd: unix listen %q: refusing a symlink", path)
	}
	if st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("vpnd: unix listen %q: path exists and is not a socket", path)
	}
	return nil
}

// prepareUnixSocket creates a private parent when needed and clears a socket
// file that no longer has a listener. A socket another process accepts on is
// left in place and reported as an error.
func prepareUnixSocket(path string) error {
	if err := validateUnixPath(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	st, err := os.Stat(parent)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("vpnd: unix listen %q: parent directory is world-writable", path)
	}
	st, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("vpnd: unix listen %q: path is not a socket we can replace", path)
	}
	d := net.Dialer{Timeout: 200 * time.Millisecond}
	c, dialErr := d.Dial("unix", path)
	if dialErr == nil {
		_ = c.Close()
		return fmt.Errorf("vpnd: unix listen %q: another process is serving this socket", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func listenLocal(network, address string) (net.Listener, error) {
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		if err := os.Chmod(address, 0o600); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}
	return ln, nil
}
