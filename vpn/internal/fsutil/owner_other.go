//go:build !unix

package fsutil

import (
	"os"
	"os/exec"
)

func defaultCommandRunner(name string, args ...string) ([]byte, error) {
	// G204: name is whoami or icacls. The arguments are the fixed sequence
	// from OwnerDACLCommands, or a single path for the read-back query.
	out, err := exec.Command(name, args...).CombinedOutput() //nolint:gosec
	return out, err
}

// Windows reports synthetic modes and has no uid. Directory and secret-file
// protection is a DACL applied before any secret byte is written.
func supportsUnixModes() bool { return false }

func checkDirOwner(os.FileInfo, string) error { return nil }

func protectSecretBeforeWrite(path string) error {
	sid, err := LookupOwnerSID(defaultCommandRunner)
	if err != nil {
		return err
	}
	return ApplyOwnerDACL(path, false, sid, defaultCommandRunner)
}

func protectPrivateDir(dir string, created bool) error {
	sid, err := LookupOwnerSID(defaultCommandRunner)
	if err != nil {
		return err
	}
	return ProtectPrivateDir(dir, created, sid, defaultCommandRunner)
}
