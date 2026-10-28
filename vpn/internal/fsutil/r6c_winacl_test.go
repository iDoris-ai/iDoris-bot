package fsutil

import (
	"strings"
	"testing"
)

// TestR6CExistingPrivateDirPolicy is the runtime check for a directory this
// process did not create. As SYSTEM, the installer's grant (SYSTEM and
// Administrators) and a SYSTEM-only DACL both pass. An extra SID does not.
// Any other current SID stays exact. icacls is not executed.
func TestR6CExistingPrivateDirPolicy(t *testing.T) {
	t.Log("icacls was not executed; ACL views are in-memory. Windows was not run")
	sys := SIDLocalSystem
	adm := SIDAdministrators
	user := "S-1-5-21-100"
	extra := "S-1-5-21-200"
	users := "S-1-5-32-545"

	pass := func(t *testing.T, sid string, view ACLView) {
		t.Helper()
		read := &fakeACL{view: view}
		run := func(name string, args ...string) ([]byte, error) {
			t.Fatalf("existing directory was rewritten: %s %v", name, args)
			return nil, nil
		}
		if err := ProtectPrivateDir(`C:\ProgramData\idoris`, false, sid, run, read); err != nil {
			t.Fatal(err)
		}
		if read.hits != 1 {
			t.Fatalf("reads %d", read.hits)
		}
	}
	reject := func(t *testing.T, sid string, view ACLView, want string) {
		t.Helper()
		read := &fakeACL{view: view}
		run := func(name string, args ...string) ([]byte, error) {
			t.Fatalf("rejected directory was rewritten: %s %v", name, args)
			return nil, nil
		}
		err := ProtectPrivateDir(`C:\ProgramData\idoris`, false, sid, run, read)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("got %v, want substring %q", err, want)
		}
	}

	t.Run("installer grant as SYSTEM", func(t *testing.T) {
		pass(t, sys, ownerView(sys, ACE{SID: sys}, ACE{SID: adm}))
		pass(t, sys, ownerView(adm, ACE{SID: sys}, ACE{SID: adm}))
	})
	t.Run("system only", func(t *testing.T) {
		pass(t, sys, ownerView(sys, ACE{SID: sys}))
		pass(t, sys, ownerView(adm, ACE{SID: sys}))
	})
	t.Run("system plus a user", func(t *testing.T) {
		reject(t, sys, ownerView(sys, ACE{SID: sys}, ACE{SID: adm}, ACE{SID: extra}), "allows "+extra)
	})
	t.Run("per-user exact", func(t *testing.T) {
		pass(t, user, ownerView(user, ACE{SID: user}))
	})
	t.Run("per-user extra", func(t *testing.T) {
		reject(t, user, ownerView(user, ACE{SID: user}, ACE{SID: users}), "allows "+users)
	})
	t.Run("inherited", func(t *testing.T) {
		reject(t, sys, ownerView(sys, ACE{SID: sys, Inherited: true}, ACE{SID: adm}), "inherited ACE")
		reject(t, user, ownerView(user, ACE{SID: user, Inherited: true}), "inherited ACE")
	})
}
