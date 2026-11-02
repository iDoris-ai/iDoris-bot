package fsutil

import (
	"errors"
	"strings"
	"testing"
)

// fakeACL is a test double for the Windows DACL reader. It never calls icacls.
type fakeACL struct {
	view ACLView
	err  error
	hits int
}

func (f *fakeACL) ReadACL(string) (ACLView, error) {
	f.hits++
	if f.err != nil {
		return ACLView{}, f.err
	}
	return f.view, nil
}

func ownerView(owner string, aces ...ACE) ACLView {
	return ACLView{OwnerSID: owner, ACEs: aces}
}

// TestR5CVerifyOwnerDACL covers the ACLs the writer produces and the ones it
// must refuse. Account names are not inputs: the same SID passes whether
// Windows would display it as HOST\alice, a localised name, or S-1-5-21-....
func TestR5CVerifyOwnerDACL(t *testing.T) {
	const user = "S-1-5-21-100"
	sys := SIDLocalSystem
	adm := SIDAdministrators
	users := "S-1-5-32-545"
	cases := []struct {
		name    string
		view    ACLView
		allowed []string
		want    string
	}{
		{
			name:    "system-only when running as SYSTEM",
			view:    ownerView(sys, ACE{SID: sys}),
			allowed: []string{sys},
		},
		{
			name:    "ordinary user SID, display name is irrelevant",
			view:    ownerView(user, ACE{SID: user}),
			allowed: []string{user},
		},
		{
			name:    "elevated creator is owned by Administrators",
			view:    ownerView(adm, ACE{SID: user}),
			allowed: []string{user},
		},
		{
			name:    "system owner of a user grant",
			view:    ownerView(sys, ACE{SID: user}),
			allowed: []string{user},
		},
		{
			name:    "service grant, system owner",
			view:    ownerView(sys, ACE{SID: sys}, ACE{SID: adm}),
			allowed: []string{sys, adm},
		},
		{
			name:    "extra foreign ACE",
			view:    ownerView(user, ACE{SID: user}, ACE{SID: users}),
			allowed: []string{user},
			want:    "allows " + users,
		},
		{
			name:    "inherited ACE",
			view:    ownerView(user, ACE{SID: user, Inherited: true}),
			allowed: []string{user},
			want:    "inherited ACE",
		},
		{
			name:    "inherited allowed SID beside an explicit one",
			view:    ownerView(sys, ACE{SID: sys}, ACE{SID: adm, Inherited: true}),
			allowed: []string{sys, adm},
			want:    "inherited ACE",
		},
		{
			name:    "deny ACE",
			view:    ownerView(user, ACE{SID: user}, ACE{SID: users, Deny: true}),
			allowed: []string{user},
			want:    "deny ACE",
		},
		{
			name:    "foreign owner",
			view:    ownerView("S-1-5-21-999", ACE{SID: user}),
			allowed: []string{user},
			want:    "owner S-1-5-21-999",
		},
		{
			name:    "missing granted SID",
			view:    ownerView(sys, ACE{SID: sys}),
			allowed: []string{sys, adm},
			want:    "missing " + adm,
		},
		{
			name:    "empty DACL",
			view:    ownerView(user),
			allowed: []string{user},
			want:    "empty",
		},
		{
			name:    "unrecognized ACE",
			view:    ownerView(user, ACE{Unrecognized: true}),
			allowed: []string{user},
			want:    "unrecognized",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyOwnerDACL(tc.view, tc.allowed)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestR4WWindowsDACLBeforeSecretBytes checks the icacls sequence with an
// injected runner and a SID reader. icacls is not executed: this host is not
// Windows, and the reader does not parse display names.
func TestR4WWindowsDACLBeforeSecretBytes(t *testing.T) {
	t.Log("real Windows execution was not possible; the runner and the SID reader are fakes, and icacls is not executed")
	const (
		sid  = "S-1-5-21-100"
		path = `C:\Users\ada\.idoris\enroll.token`
		dir  = `C:\Users\ada\.idoris`
	)
	var calls []string
	run := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "whoami" {
			return []byte(`"ada","` + sid + `"` + "\r\n"), nil
		}
		return []byte("Successfully processed 1 files\r\n"), nil
	}
	read := &fakeACL{view: ownerView(sid, ACE{SID: sid})}

	gotSID, err := LookupOwnerSID(run)
	if err != nil {
		t.Fatal(err)
	}
	if gotSID != sid {
		t.Fatalf("sid %s", gotSID)
	}

	wrote := false
	err = WriteSecretAfterDACL(path, []byte("token-bytes"), sid, run, read, func(target string, data []byte) error {
		wrote = true
		if target != path || string(data) != "token-bytes" {
			t.Fatalf("write %s %q", target, data)
		}
		joined := strings.Join(calls, "\n")
		reset := strings.Index(joined, "icacls "+path+" /reset")
		inherit := strings.Index(joined, "icacls "+path+" /inheritance:r")
		grant := strings.Index(joined, "icacls "+path+" /grant:r *"+sid+":F")
		if reset < 0 || inherit < reset || grant < inherit {
			t.Fatalf("DACL commands out of order before the write:\n%s", joined)
		}
		if read.hits != 1 {
			t.Fatalf("DACL was read %d times before the write", read.hits)
		}
		if strings.Contains(joined, "icacls "+path+"\n") || strings.HasSuffix(joined, "icacls "+path) {
			t.Fatalf("verifier queried icacls display names:\n%s", joined)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("secret was not written after the DACL")
	}

	before := len(calls)
	hits := read.hits
	if err := ProtectPrivateDir(dir, true, sid, run, read); err != nil {
		t.Fatal(err)
	}
	dirCalls := strings.Join(calls[before:], "\n")
	if !strings.Contains(dirCalls, "icacls "+dir+" /reset") ||
		!strings.Contains(dirCalls, "icacls "+dir+" /inheritance:r") ||
		!strings.Contains(dirCalls, "icacls "+dir+" /grant:r *"+sid+":(OI)(CI)F") {
		t.Fatalf("new directory commands:\n%s", dirCalls)
	}
	if read.hits != hits+1 {
		t.Fatalf("new directory was not read back: hits %d", read.hits)
	}

	// An existing directory is only read. A foreign ACE is refused and no
	// icacls command runs, so a caller who does not own the policy cannot
	// tighten it.
	var looseCalls []string
	looseRun := func(name string, args ...string) ([]byte, error) {
		looseCalls = append(looseCalls, name+" "+strings.Join(args, " "))
		t.Fatalf("existing directory must be queried, not modified: %s %v", name, args)
		return nil, nil
	}
	loose := &fakeACL{view: ownerView(sid, ACE{SID: sid}, ACE{SID: "S-1-5-32-545"})}
	err = ProtectPrivateDir(dir, false, sid, looseRun, loose)
	if err == nil || !strings.Contains(err.Error(), "S-1-5-32-545") {
		t.Fatalf("loose existing directory: %v", err)
	}
	if len(looseCalls) != 0 || loose.hits != 1 {
		t.Fatalf("calls %v hits %d", looseCalls, loose.hits)
	}
}

func TestR4WWindowsDACLRejectsBadSID(t *testing.T) {
	run := func(string, ...string) ([]byte, error) {
		t.Fatal("runner must not be called for a bad SID")
		return nil, nil
	}
	read := &fakeACL{}
	if err := ApplyOwnerDACL(`C:\x`, false, "Everyone", run, read); err == nil {
		t.Fatal("bad SID was accepted")
	}
	if read.hits != 0 {
		t.Fatal("reader ran for a bad SID")
	}
	if err := WriteSecretAfterDACL(`C:\x`, []byte("s"), "S-1-5-21-1", func(string, ...string) ([]byte, error) {
		return nil, errors.New("icacls denied")
	}, read, func(string, []byte) error {
		t.Fatal("secret bytes were written after icacls failed")
		return nil
	}); err == nil {
		t.Fatal("failed DACL still wrote the secret")
	}
}
