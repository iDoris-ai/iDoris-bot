//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// protectWindowsPath runs icacls and refuses to continue unless the resulting
// DACL lists only SYSTEM and Administrators. icacls is not available on the
// macOS tree where the unit tests run; those tests lock the argv and the parser.
func protectWindowsPath(path string, directory bool) error {
	for _, args := range icaclsProtectCommands(path, directory) {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput() //nolint:gosec // G204: argv is the fixed icacls sequence, path is the install path
		if err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	out, err := exec.Command("icacls", path).CombinedOutput() //nolint:gosec // G204: read-back of the ACL just written
	if err != nil {
		return fmt.Errorf("icacls %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	if err := parseICACLSProtected(string(out)); err != nil {
		return fmt.Errorf("icacls %s: %w\n%s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func protectWindowsInstall(dir, config, exeDir, exe string, creds []string) error {
	if err := protectWindowsPath(dir, true); err != nil {
		return err
	}
	if err := protectWindowsPath(config, false); err != nil {
		return err
	}
	for _, f := range creds {
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
