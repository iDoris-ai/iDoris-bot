package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// knownACEPrincipals are matched as a suffix of the text before ":(", longest
// first, so a path on the same line is not the principal.
var knownACEPrincipals = []string{
	`NT AUTHORITY\Authenticated Users`,
	`NT AUTHORITY\SYSTEM`,
	`BUILTIN\Administrators`,
	`BUILTIN\Users`,
	`*S-1-5-32-544`,
	`*S-1-5-32-545`,
	`*S-1-5-18`,
	`*S-1-5-11`,
	`*S-1-1-0`,
	`S-1-5-32-544`,
	`S-1-5-32-545`,
	`S-1-5-18`,
	`S-1-5-11`,
	`S-1-1-0`,
	`Administrators`,
	`Everyone`,
	`SYSTEM`,
	`Users`,
}

func principalOfACE(left string) string {
	left = strings.TrimSpace(left)
	upper := strings.ToUpper(left)
	best := ""
	bestLen := 0
	for _, c := range knownACEPrincipals {
		cu := strings.ToUpper(c)
		if strings.HasSuffix(upper, cu) && len(cu) > bestLen {
			best = c
			bestLen = len(cu)
		}
	}
	if best != "" {
		return best
	}
	fields := strings.Fields(left)
	if len(fields) == 0 {
		return left
	}
	return fields[len(fields)-1]
}

func aceClass(principal string) string {
	switch strings.ToUpper(principal) {
	case `NT AUTHORITY\SYSTEM`, `SYSTEM`, `*S-1-5-18`, `S-1-5-18`:
		return "system"
	case `BUILTIN\ADMINISTRATORS`, `ADMINISTRATORS`, `*S-1-5-32-544`, `S-1-5-32-544`:
		return "administrators"
	default:
		return ""
	}
}

// parseICACLSProtected accepts icacls query output only when every ACE is
// SYSTEM or Administrators and both are present. Other lines (the success
// summary, blank lines) are ignored.
func parseICACLSProtected(out string) error {
	sawSystem := false
	sawAdmin := false
	aces := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		i := strings.Index(line, ":(")
		if i < 0 {
			continue
		}
		aces++
		class := aceClass(principalOfACE(line[:i]))
		switch class {
		case "system":
			sawSystem = true
		case "administrators":
			sawAdmin = true
		default:
			return fmt.Errorf("unexpected ACE %q", strings.TrimSpace(line))
		}
	}
	if aces == 0 || !sawSystem || !sawAdmin {
		return errors.New("ACL does not grant only SYSTEM and Administrators")
	}
	return nil
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
	items := []struct{ key, name string }{
		{"enroll_token_file", "enroll_token"},
		{"auth_key_file", "auth_key"},
		{"socks5_auth_file", "socks5.auth"},
	}
	var files []string
	changed := false
	for _, it := range items {
		raw, ok := probe[it.key]
		if !ok || raw == nil {
			continue
		}
		src, ok := raw.(string)
		if !ok {
			return nil, nil, fmt.Errorf("config: %s is not a string", it.key)
		}
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		dest := filepath.Join(destDir, it.name)
		if err := copyCredentialFile(src, dest); err != nil {
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
	if err := os.WriteFile(dest, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(dest, 0o600) //nolint:gosec // credential copy is mode 0600 before the ACL is applied
}
