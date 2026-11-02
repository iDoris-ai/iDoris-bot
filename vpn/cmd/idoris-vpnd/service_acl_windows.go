//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
)

// protectWindowsPath runs icacls and refuses to continue unless the resulting
// DACL is exactly SYSTEM and Administrators. The read-back uses
// GetNamedSecurityInfo, not icacls display names. icacls is not available on
// the macOS tree where the unit tests run; those tests lock the argv and the
// SID verifier.
func protectWindowsPath(path string, directory bool) error {
	for _, args := range icaclsProtectCommands(path, directory) {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput() //nolint:gosec // G204: argv is the fixed icacls sequence, path is the install path
		if err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	view, err := fsutil.ReadACL(path)
	if err != nil {
		return fmt.Errorf("read DACL %s: %w", path, err)
	}
	if err := verifyServiceDACL(view); err != nil {
		return fmt.Errorf("DACL %s: %w", path, err)
	}
	return nil
}

func protectWindowsInstall(dir, config, exeDir, exe string, creds []string) error {
	if dir != "" {
		if err := protectWindowsPath(dir, true); err != nil {
			return err
		}
	}
	if config != "" {
		if err := protectWindowsPath(config, false); err != nil {
			return err
		}
	}
	for _, f := range creds {
		if strings.TrimSpace(f) == "" {
			continue
		}
		if err := protectWindowsPath(f, false); err != nil {
			return err
		}
	}
	if exeDir != "" {
		if err := protectWindowsPath(exeDir, true); err != nil {
			return err
		}
	}
	if exe != "" {
		st, err := os.Lstat(exe)
		if err != nil {
			return err
		}
		if err := protectWindowsPath(exe, st.IsDir()); err != nil {
			return err
		}
	}
	return nil
}
