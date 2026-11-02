//go:build windows

package vpnd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
	"golang.org/x/sys/windows"
)

// winLockState keeps the OVERLAPPED block alive. LockFileEx requires it for
// the whole time the byte range stays locked.
type winLockState struct {
	h  windows.Handle
	ol windows.Overlapped
}

func machineLockDir() (string, error) {
	if !windowsMachineController() {
		return "", nil
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "idoris", "locks"), nil
}

func currentIsMachineController() bool {
	return windowsMachineController()
}

// windowsMachineController is true for an elevated token and for LOCAL SYSTEM.
// A user who can change ProgramData can point this directory elsewhere; that
// process is already an administrator.
func windowsMachineController() bool {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return true
	}
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false
	}
	return user.User.Sid.String() == "S-1-5-18"
}

func acquireLock(path, kind string) (*ControllerLock, error) {
	if err := fsutil.EnsurePrivateDir(dirOf(path)); err != nil {
		return nil, err
	}
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// FILE_FLAG_OPEN_REPARSE_POINT does not follow a symlink planted at path.
	h, err := windows.CreateFile(
		p16,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("lock file %s is a symlink", path)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("lock file %s is a directory", path)
	}
	st := &winLockState{h: h}
	err = windows.LockFileEx(
		h,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&st.ol,
	)
	if err != nil {
		_ = windows.CloseHandle(h)
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, fmt.Errorf("another idoris-vpnd already controls this %s backend (%s)", kind, path)
		}
		return nil, fmt.Errorf("lock %s backend (%s): %w", kind, path, err)
	}
	f := os.NewFile(uintptr(h), path)
	return &ControllerLock{f: f, path: path, extra: st}, nil
}

func unlockFile(f *os.File, extra any) error {
	st, _ := extra.(*winLockState)
	if st == nil {
		return fmt.Errorf("windows lock state missing for %s", f.Name())
	}
	return windows.UnlockFileEx(st.h, 0, 1, 0, &st.ol)
}
