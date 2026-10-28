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
func ApplyOwnerDACL(path string, directory bool, sid string, run CommandRunner, read ACLReader) error {
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
	if read == nil {
		return errors.New("fsutil: ACL reader is not set")
	}
	view, err := read.ReadACL(path)
	if err != nil {
		return fmt.Errorf("fsutil: read DACL %s: %w", path, err)
	}
	if err := VerifyOwnerDACL(view, []string{sid}); err != nil {
		return fmt.Errorf("fsutil: %s: %w", path, err)
	}
	return nil
}

// SIDLocalSystem is NT AUTHORITY\SYSTEM. SIDAdministrators is
// BUILTIN\Administrators. Callers compare these strings; account names are
// not part of the check.
const (
	SIDLocalSystem    = "S-1-5-18"
	SIDAdministrators = "S-1-5-32-544"
)

// ACE is one DACL entry. SID is the trustee. Inherited is the INHERITED_ACE
// flag (the entry came from a parent), which is distinct from an inherit-down
// flag such as OBJECT_INHERIT. Deny is an access-denied entry. Unrecognized
// is an ACE type whose SID is not at the standard offset.
type ACE struct {
	SID          string
	Inherited    bool
	Deny         bool
	Unrecognized bool
}

// ACLView is the owner and the DACL of one object, both as SIDs. A resolved
// or localised account name is not stored and cannot affect the comparison.
type ACLView struct {
	OwnerSID string
	ACEs     []ACE
}

// ACLReader reads a DACL as SIDs. The Windows implementation uses
// GetNamedSecurityInfo and GetAce. Tests pass a fake.
type ACLReader interface {
	ReadACL(path string) (ACLView, error)
}

// windowsDACLReader is the production reader. The Windows file sets it.
var windowsDACLReader ACLReader

// ReadACL reads path with the production Windows reader.
func ReadACL(path string) (ACLView, error) {
	if windowsDACLReader == nil {
		return ACLView{}, errors.New("fsutil: Windows ACL reader is not available")
	}
	return windowsDACLReader.ReadACL(path)
}

// VerifyOwnerDACL accepts view when every ACE is an explicit allow for a SID
// in allowed, every allowed SID is present, and the owner is SYSTEM or one of
// the granted SIDs. allowed is the set the writer granted: the current user,
// plus SYSTEM and Administrators only when that writer grants them.
//
// A process running as SYSTEM grants only S-1-5-18. That owner is accepted
// without an Administrators ACE. An owner of S-1-5-32-544 is also accepted:
// Windows assigns the Administrators group as the owner of an object created
// by an elevated administrator, and the DACL is still required to be exactly
// allowed. Any other owner, an inherited ACE, a deny ACE, or a SID outside
// allowed is rejected. Display names are not an input.
func VerifyOwnerDACL(view ACLView, allowed []string) error {
	if len(allowed) == 0 {
		return errors.New("fsutil: allowed SID set is empty")
	}
	seen := make(map[string]bool, len(allowed))
	for _, sid := range allowed {
		if !validSID(sid) {
			return fmt.Errorf("fsutil: allowed SID %q is not usable", sid)
		}
		seen[sid] = false
	}
	if !validSID(view.OwnerSID) {
		return fmt.Errorf("fsutil: owner SID %q is not usable", view.OwnerSID)
	}
	if view.OwnerSID != SIDLocalSystem && view.OwnerSID != SIDAdministrators {
		if _, ok := seen[view.OwnerSID]; !ok {
			return fmt.Errorf("fsutil: owner %s is not in the granted set", view.OwnerSID)
		}
	}
	if len(view.ACEs) == 0 {
		return errors.New("fsutil: DACL is empty")
	}
	for _, ace := range view.ACEs {
		switch {
		case ace.Unrecognized:
			return errors.New("fsutil: DACL has an unrecognized ACE")
		case !validSID(ace.SID):
			return fmt.Errorf("fsutil: ACE SID %q is not usable", ace.SID)
		case ace.Inherited:
			return fmt.Errorf("fsutil: inherited ACE for %s", ace.SID)
		case ace.Deny:
			return fmt.Errorf("fsutil: deny ACE for %s", ace.SID)
		}
		if _, ok := seen[ace.SID]; !ok {
			return fmt.Errorf("fsutil: DACL allows %s", ace.SID)
		}
		seen[ace.SID] = true
	}
	for sid, ok := range seen {
		if !ok {
			return fmt.Errorf("fsutil: DACL is missing %s", sid)
		}
	}
	return nil
}

// ProtectPrivateDir sets a restrictive DACL on a directory this call created.
// An existing directory is only queried: a loose ACL is an error, and this
// function does not rewrite somebody else's directory.
func ProtectPrivateDir(dir string, created bool, sid string, run CommandRunner, read ACLReader) error {
	if !validSID(sid) {
		return fmt.Errorf("fsutil: owner SID %q is not usable", sid)
	}
	if run == nil {
		return errors.New("fsutil: ACL runner is not set")
	}
	if !created {
		if read == nil {
			return errors.New("fsutil: ACL reader is not set")
		}
		view, err := read.ReadACL(dir)
		if err != nil {
			return fmt.Errorf("fsutil: read DACL %s: %w", dir, err)
		}
		if err := VerifyExistingPrivateDir(view, sid); err != nil {
			return fmt.Errorf("fsutil: %s: %w", dir, err)
		}
		return nil
	}
	return ApplyOwnerDACL(dir, true, sid, run, read)
}

// VerifyExistingPrivateDir checks a directory this call did not create.
// When sid is LOCAL SYSTEM, the DACL may be exactly {SYSTEM} or exactly
// {SYSTEM, Administrators}. The installer grants both; a directory created
// by this process as SYSTEM may have only SYSTEM. The owner is SYSTEM or
// Administrators. Every other current SID must be exactly {sid}. An
// inherited ACE, a deny ACE, or an unrecognized ACE fails for both policies.
func VerifyExistingPrivateDir(view ACLView, sid string) error {
	if !validSID(sid) {
		return fmt.Errorf("fsutil: owner SID %q is not usable", sid)
	}
	if sid != SIDLocalSystem {
		return VerifyOwnerDACL(view, []string{sid})
	}
	// The wider set's error names an unexpected SID. The SYSTEM-only check
	// would report Administrators itself as unexpected and hide that SID.
	err := VerifyOwnerDACL(view, []string{SIDLocalSystem, SIDAdministrators})
	if err == nil {
		return nil
	}
	if sysOnly := VerifyOwnerDACL(view, []string{SIDLocalSystem}); sysOnly == nil {
		return nil
	}
	return err
}

// WriteSecretAfterDACL applies the file DACL and only then calls write.
// write is not called when icacls fails, so a secret byte is never stored
// under the inherited ACL.
func WriteSecretAfterDACL(path string, data []byte, sid string, run CommandRunner, read ACLReader, write func(path string, data []byte) error) error {
	if err := ApplyOwnerDACL(path, false, sid, run, read); err != nil {
		return err
	}
	if write == nil {
		return errors.New("fsutil: secret write is not set")
	}
	return write(path, data)
}
