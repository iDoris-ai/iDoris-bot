package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
)

// icaclsProtectCommands is the exact argv of the icacls sequence that removes
// inherited ACEs and grants only SYSTEM (S-1-5-18) and Administrators
// (S-1-5-32-544). directory selects object-inherit and container-inherit,
// which apply to a directory and not to a file.
func icaclsProtectCommands(path string, directory bool) [][]string {
	rights := "F"
	if directory {
		rights = "(OI)(CI)F"
	}
	return [][]string{
		{"icacls", path, "/reset"},
		{"icacls", path, "/inheritance:r"},
		{"icacls", path, "/grant:r", "*S-1-5-18:" + rights, "*S-1-5-32-544:" + rights},
	}
}

// renderICACLSCommands prints one argument per line and a blank line between
// commands, for the golden file.
func renderICACLSCommands(cmds [][]string) string {
	var b strings.Builder
	for _, args := range cmds {
		for _, a := range args {
			b.WriteString(a)
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// verifyServiceDACL accepts the DACL icaclsProtectCommands writes: explicit
// allow ACEs for SYSTEM and Administrators, and no other SID. The comparison
// is on SIDs from the security descriptor, so a localised account name cannot
// change the result. SYSTEM as owner is accepted.
func verifyServiceDACL(view fsutil.ACLView) error {
	return fsutil.VerifyOwnerDACL(view, []string{fsutil.SIDLocalSystem, fsutil.SIDAdministrators})
}

// stagedCredentialFiles are the credential paths an install copies into the
// destination directory. retargetStagedConfig rewrites these keys from the
// decoded JSON value. A new key here is staged and retargeted together.
var stagedCredentialFiles = []struct{ key, name string }{
	{"enroll_token_file", "enroll_token"},
	{"auth_key_file", "auth_key"},
	{"socks5_auth_file", "socks5.auth"},
}

// stageWindowsConfig copies credential files named by the config into destDir
// and rewrites those paths. The original bytes are kept when nothing is copied.
// Returned paths are the copies, not the config file itself.
func stageWindowsConfig(cfg []byte, destDir string) ([]byte, []string, error) {
	dec := json.NewDecoder(bytes.NewReader(cfg))
	dec.UseNumber()
	var probe map[string]any
	if err := dec.Decode(&probe); err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	if dec.More() {
		return nil, nil, errors.New("config: trailing data")
	}
	var files []string
	changed := false
	rollback := func() {
		for _, f := range files {
			_ = os.Remove(f)
		}
	}
	for _, it := range stagedCredentialFiles {
		raw, ok := probe[it.key]
		if !ok || raw == nil {
			continue
		}
		src, ok := raw.(string)
		if !ok {
			rollback()
			return nil, nil, fmt.Errorf("config: %s is not a string", it.key)
		}
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		dest := filepath.Join(destDir, it.name)
		if err := copyCredentialFile(src, dest); err != nil {
			rollback()
			return nil, nil, fmt.Errorf("%s: %w", it.key, err)
		}
		probe[it.key] = dest
		files = append(files, dest)
		changed = true
	}
	if !changed {
		return append([]byte(nil), cfg...), nil, nil
	}
	body, err := json.MarshalIndent(probe, "", "  ")
	if err != nil {
		rollback()
		return nil, nil, err
	}
	return append(body, '\n'), files, nil
}

func copyCredentialFile(src, dest string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", src)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	b, err := os.ReadFile(src) //nolint:gosec // G304: operator config names this credential file
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, b, 0o600); err != nil { //nolint:gosec // G703: dest is the install copy of an operator credential file
		return err
	}
	return os.Chmod(dest, 0o600) //nolint:gosec // credential copy is mode 0600 before the ACL is applied
}
