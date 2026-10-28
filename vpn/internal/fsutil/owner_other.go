//go:build !unix

package fsutil

import "os"

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
