//go:build !unix

package fsutil

import "os"

// Windows reports synthetic modes and has no uid; directory protection there is
// an ACL concern handled by the installer.
func supportsUnixModes() bool { return false }

func checkDirOwner(os.FileInfo, string) error { return nil }
