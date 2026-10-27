package main

import (
	"fmt"
	"io"
	"os"
)

const (
	systemLibDir = "/usr/local/lib/idoris"
	systemLibExe = "/usr/local/lib/idoris/idoris-vpnd"
)

// chownSystemRoot sets the owner of an installed file to root. Tests replace it.
// The Unix and Windows implementations live in the service_root_* files.
var chownSystemRoot = chownSystemRootImpl

// systemExecutable is the protected path a machine service runs.
// Linux and macOS use /usr/local/lib/idoris/idoris-vpnd. Windows uses
// %ProgramFiles%\iDoris\idoris-vpnd.exe. An empty programFiles means
// the usual "C:\Program Files".
func systemExecutable(goos, programFiles string) (dir, exe string) {
	if goos == "windows" {
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		dir = programFiles + `\iDoris`
		return dir, dir + `\idoris-vpnd.exe`
	}
	return systemLibDir, systemLibExe
}

// copyProtectedExecutable installs src at dest, mode 0755, owned by root.
// dest's directory is created the same way. The bytes are written to a temp
// file in that directory and renamed into place, so a symlink at dest is
// replaced rather than followed.
func copyProtectedExecutable(src, destDir, dest string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("service: executable %s is not a regular file", src)
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	// The directory is a standard library location. 0755 lets the service
	// manager traverse it; the root owner is what keeps a user from replacing
	// the binary.
	if err := os.Chmod(destDir, 0o755); err != nil { //nolint:gosec // G302: installed library directory is mode 0755
		return err
	}
	if err := chownSystemRoot(destDir); err != nil {
		return err
	}
	in, err := os.Open(src) //nolint:gosec // G304: src is this process's own executable, not a request path
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	tmp, err := os.CreateTemp(destDir, ".idoris-vpnd-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil { //nolint:gosec // G302: installed executable is mode 0755
		_ = tmp.Close()
		return err
	}
	if err := chownSystemRoot(tmpName); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return err
	}
	ok = true
	return chownSystemRoot(dest)
}

func removeProtectedExecutable(dest string) error {
	err := os.Remove(dest)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}
