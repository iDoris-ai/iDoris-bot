// Package fsutil holds the small file helpers that secrets and state files go
// through: an exclusive temporary file, owner-only permissions from the first
// byte, and an atomic rename.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic replaces path with data. The bytes go to a temporary file
// that is created exclusively next to path (random name, never an existing
// file or a link), its mode is set before any data is written, and it is then
// renamed over path. A symlink already at path is replaced, never followed, so
// the file the link pointed to is not touched.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name) //nolint:gosec // G703: name was just created by CreateTemp
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil { //nolint:gosec // G703: both names are inside the validated directory
		return err
	}
	ok = true
	return nil
}

// EnsurePrivateDir creates dir (and parents) with mode 0700 when it is missing
// and refuses a directory that is a symlink, is not owned by the current user
// (Unix), or is writable by anyone else. It does not silently chmod somebody
// else's directory: a pre-populated shared directory is an error.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("fsutil: %s is a symlink", dir)
	}
	if !st.IsDir() {
		return fmt.Errorf("fsutil: %s is not a directory", dir)
	}
	if err := checkDirOwner(st, dir); err != nil {
		return err
	}
	if perm := st.Mode().Perm(); perm&0o022 != 0 && supportsUnixModes() {
		return fmt.Errorf("fsutil: %s is writable by group or others (mode %o)", dir, perm)
	}
	return nil
}
