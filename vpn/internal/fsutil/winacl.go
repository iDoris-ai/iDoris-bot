package fsutil

import (
	"errors"
	"fmt"
	"strings"
)

// CommandRunner runs one command. The Windows ACL path uses it for icacls
// and whoami. Tests pass a runner and do not execute those programs.
type CommandRunner func(name string, args ...string) ([]byte, error)

// OwnerDACLCommands is the icacls sequence for one path. directory selects
// object-inherit and container-inherit. The ACE is the current user's SID.
// SYSTEM and Administrators are the right principals for a machine service
// directory; granting only those here would lock the joining user out of a
// per-user enrollment token. The command shape is the service installer's:
// /reset, then /inheritance:r, then /grant:r.
func OwnerDACLCommands(path string, directory bool, sid string) [][]string {
	rights := "F"
	if directory {
		rights = "(OI)(CI)F"
	}
	return [][]string{
		{"icacls", path, "/reset"},
		{"icacls", path, "/inheritance:r"},
		{"icacls", path, "/grant:r", "*" + sid + ":" + rights},
	}
}

func validSID(sid string) bool {
	if !strings.HasPrefix(sid, "S-1-") || len(sid) < 6 {
		return false
	}
	return !strings.ContainsAny(sid, " \t:*\"\\/")
}

// LookupOwnerSID reads the current user's SID from `whoami /user /fo csv /nh`.
func LookupOwnerSID(run CommandRunner) (string, error) {
	if run == nil {
		return "", errors.New("fsutil: ACL runner is not set")
	}
	out, err := run("whoami", "/user", "/fo", "csv", "/nh")
	if err != nil {
		return "", fmt.Errorf("fsutil: whoami: %w: %s", err, strings.TrimSpace(string(out)))
	}
	sid := sidFromWhoami(string(out))
	if !validSID(sid) {
		return "", fmt.Errorf("fsutil: whoami did not return an owner SID: %s", strings.TrimSpace(string(out)))
	}
	return sid, nil
}

func sidFromWhoami(out string) string {
	out = strings.TrimSpace(out)
	var best string
	for _, field := range strings.Split(out, ",") {
		field = strings.Trim(strings.TrimSpace(field), `"`)
		if strings.HasPrefix(field, "S-1-") && len(field) > len(best) {
			best = field
		}
	}
	if best != "" {
		return best
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[len(fields)-1], `"`)
}

// ApplyOwnerDACL runs /reset, /inheritance:r, /grant:r, then reads the ACL
// back. It stops at the first failure, so a denied /inheritance:r does not
// continue to /grant.
func ApplyOwnerDACL(path string, directory bool, sid string, run CommandRunner) error {
	if !validSID(sid) {
		return fmt.Errorf("fsutil: owner SID %q is not usable", sid)
	}
	if run == nil {
		return errors.New("fsutil: ACL runner is not set")
	}
	for _, argv := range OwnerDACLCommands(path, directory, sid) {
		out, err := run(argv[0], argv[1:]...)
		if err != nil {
			return fmt.Errorf("fsutil: %s: %w: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
		}
	}
	out, err := run("icacls", path)
	if err != nil {
		return fmt.Errorf("fsutil: icacls %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return VerifyWindowsACL(string(out), sid)
}

// VerifyWindowsACL accepts icacls query output when every ACE is the owner
// SID, SYSTEM, or Administrators, and the result is still private to that
// set. Users, Everyone, and Authenticated Users are rejected. The owner SID
// must be present, unless the ACL is exactly SYSTEM and Administrators.
func VerifyWindowsACL(out, ownerSID string) error {
	if !validSID(ownerSID) {
		return fmt.Errorf("fsutil: owner SID %q is not usable", ownerSID)
	}
	sawOwner := false
	sawSystem := false
	sawAdmin := false
	aces := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		i := strings.Index(line, ":(")
		if i < 0 {
			// icacls also prints "SID:F" without parentheses.
			i = strings.Index(line, ":F")
			if i < 0 {
				i = strings.Index(line, ":R")
			}
		}
		if i < 0 {
			continue
		}
		principal := principalOfACE(line[:i])
		if principal == "" {
			continue
		}
		aces++
		switch aceClass(principal, ownerSID) {
		case "owner":
			sawOwner = true
		case "system":
			sawSystem = true
		case "administrators":
			sawAdmin = true
		default:
			return fmt.Errorf("fsutil: directory ACL allows %s", principal)
		}
	}
	if aces == 0 {
		return errors.New("fsutil: directory ACL is empty")
	}
	if sawOwner || (sawSystem && sawAdmin) {
		return nil
	}
	return errors.New("fsutil: directory ACL does not grant the owner")
}

func principalOfACE(left string) string {
	left = strings.TrimSpace(left)
	known := []string{
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
	upper := strings.ToUpper(left)
	best := ""
	for _, c := range known {
		if strings.HasSuffix(upper, strings.ToUpper(c)) && len(c) > len(best) {
			best = c
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

func aceClass(principal, ownerSID string) string {
	p := strings.TrimPrefix(principal, "*")
	switch strings.ToUpper(p) {
	case `NT AUTHORITY\SYSTEM`, `SYSTEM`, `S-1-5-18`:
		return "system"
	case `BUILTIN\ADMINISTRATORS`, `ADMINISTRATORS`, `S-1-5-32-544`:
		return "administrators"
	}
	if strings.EqualFold(p, ownerSID) || strings.EqualFold(principal, "*"+ownerSID) {
		return "owner"
	}
	return ""
}

// ProtectPrivateDir sets a restrictive DACL on a directory this call created.
// An existing directory is only queried: a loose ACL is an error, and this
// function does not rewrite somebody else's directory.
func ProtectPrivateDir(dir string, created bool, sid string, run CommandRunner) error {
	if !validSID(sid) {
		return fmt.Errorf("fsutil: owner SID %q is not usable", sid)
	}
	if run == nil {
		return errors.New("fsutil: ACL runner is not set")
	}
	if !created {
		out, err := run("icacls", dir)
		if err != nil {
			return fmt.Errorf("fsutil: icacls %s: %w: %s", dir, err, strings.TrimSpace(string(out)))
		}
		if err := VerifyWindowsACL(string(out), sid); err != nil {
			return fmt.Errorf("fsutil: %s: %w", dir, err)
		}
		return nil
	}
	return ApplyOwnerDACL(dir, true, sid, run)
}

// WriteSecretAfterDACL applies the file DACL and only then calls write.
// write is not called when icacls fails, so a secret byte is never stored
// under the inherited ACL.
func WriteSecretAfterDACL(path string, data []byte, sid string, run CommandRunner, write func(path string, data []byte) error) error {
	if err := ApplyOwnerDACL(path, false, sid, run); err != nil {
		return err
	}
	if write == nil {
		return errors.New("fsutil: secret write is not set")
	}
	return write(path, data)
}
