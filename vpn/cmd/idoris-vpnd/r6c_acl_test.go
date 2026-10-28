package main

import (
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
)

// r6cGrantSIDs reads the SIDs icaclsProtectCommands puts on a /grant:r
// argument. The test must not retype that list.
func r6cGrantSIDs(cmds [][]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, cmd := range cmds {
		for _, arg := range cmd {
			if !strings.HasPrefix(arg, "*S-1-") {
				continue
			}
			sid := strings.TrimPrefix(arg, "*")
			if i := strings.IndexByte(sid, ':'); i >= 0 {
				sid = sid[:i]
			}
			if sid == "" || seen[sid] {
				continue
			}
			seen[sid] = true
			out = append(out, sid)
		}
	}
	return out
}

type r6cACLReader struct {
	view fsutil.ACLView
	hits int
}

func (r *r6cACLReader) ReadACL(string) (fsutil.ACLView, error) {
	r.hits++
	return r.view, nil
}

// TestR6CInstallerGrantPassesRuntimeDirCheck feeds the SID list from
// icaclsProtectCommands into the runtime directory check as SYSTEM.
// icacls is not executed.
func TestR6CInstallerGrantPassesRuntimeDirCheck(t *testing.T) {
	t.Log("icacls was not executed; the grant SIDs come from icaclsProtectCommands. Windows was not run")
	cmds := icaclsProtectCommands(`C:\ProgramData\idoris`, true)
	sids := r6cGrantSIDs(cmds)
	if len(sids) == 0 {
		t.Fatal("installer grant has no SIDs")
	}
	hasSystem := false
	aces := make([]fsutil.ACE, len(sids))
	for i, sid := range sids {
		aces[i] = fsutil.ACE{SID: sid}
		if sid == fsutil.SIDLocalSystem {
			hasSystem = true
		}
	}
	if !hasSystem {
		t.Fatalf("installer grant %v does not include the runtime SYSTEM SID", sids)
	}
	view := fsutil.ACLView{OwnerSID: fsutil.SIDLocalSystem, ACEs: aces}
	read := &r6cACLReader{view: view}
	run := func(name string, args ...string) ([]byte, error) {
		t.Fatalf("runtime check rewrote the machine directory: %s %v", name, args)
		return nil, nil
	}
	if err := fsutil.ProtectPrivateDir(`C:\ProgramData\idoris`, false, fsutil.SIDLocalSystem, run, read); err != nil {
		t.Fatalf("installer SIDs %v: %v", sids, err)
	}
	if read.hits != 1 {
		t.Fatalf("reads %d", read.hits)
	}
	view.OwnerSID = fsutil.SIDAdministrators
	read.view = view
	if err := fsutil.ProtectPrivateDir(`C:\ProgramData\idoris`, false, fsutil.SIDLocalSystem, run, read); err != nil {
		t.Fatalf("administrators owner, installer SIDs %v: %v", sids, err)
	}
}
