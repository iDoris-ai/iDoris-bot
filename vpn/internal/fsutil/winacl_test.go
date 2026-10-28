package fsutil

import (
	"errors"
	"strings"
	"testing"
)

// TestR4WWindowsDACLBeforeSecretBytes checks the icacls sequence with an
// injected runner. icacls is not executed: this host is not Windows.
func TestR4WWindowsDACLBeforeSecretBytes(t *testing.T) {
	t.Log("real Windows execution was not possible; the runner is injected and icacls is not executed")
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
		if name == "icacls" && len(args) == 1 {
			return []byte(args[0] + " *" + sid + ":F\r\nSuccessfully processed 1 files\r\n"), nil
		}
		return []byte("Successfully processed 1 files\r\n"), nil
	}

	gotSID, err := LookupOwnerSID(run)
	if err != nil {
		t.Fatal(err)
	}
	if gotSID != sid {
		t.Fatalf("sid %s", gotSID)
	}

	wrote := false
	err = WriteSecretAfterDACL(path, []byte("token-bytes"), sid, run, func(target string, data []byte) error {
		wrote = true
		if target != path || string(data) != "token-bytes" {
			t.Fatalf("write %s %q", target, data)
		}
		joined := strings.Join(calls, "\n")
		reset := strings.Index(joined, "icacls "+path+" /reset")
		inherit := strings.Index(joined, "icacls "+path+" /inheritance:r")
		grant := strings.Index(joined, "icacls "+path+" /grant:r *"+sid+":F")
		query := strings.LastIndex(joined, "icacls "+path)
		if reset < 0 || inherit < reset || grant < inherit || query < grant {
			t.Fatalf("DACL commands out of order before the write:\n%s", joined)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("secret was not written after the DACL")
	}

	// A new directory is locked before it is treated as private.
	before := len(calls)
	if err := ProtectPrivateDir(dir, true, sid, run); err != nil {
		t.Fatal(err)
	}
	dirCalls := strings.Join(calls[before:], "\n")
	if !strings.Contains(dirCalls, "icacls "+dir+" /reset") ||
		!strings.Contains(dirCalls, "icacls "+dir+" /inheritance:r") ||
		!strings.Contains(dirCalls, "icacls "+dir+" /grant:r *"+sid+":(OI)(CI)F") {
		t.Fatalf("new directory commands:\n%s", dirCalls)
	}

	// An existing directory is queried and refused when another principal can read it.
	// No /grant runs, so nothing is tightened under a caller who does not own the policy.
	loose := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, "loose "+name+" "+strings.Join(args, " "))
		if len(args) != 1 {
			t.Fatalf("existing directory must be queried, not modified: %s %v", name, args)
		}
		return []byte(dir + " BUILTIN\\Users:(OI)(CI)(RX)\r\n" + dir + " *" + sid + ":(OI)(CI)(F)\r\n"), nil
	}
	if err := ProtectPrivateDir(dir, false, sid, loose); err == nil || !strings.Contains(err.Error(), "Users") {
		t.Fatalf("loose existing directory: %v", err)
	}
}

func TestR4WWindowsDACLRejectsBadSID(t *testing.T) {
	run := func(string, ...string) ([]byte, error) {
		t.Fatal("runner must not be called for a bad SID")
		return nil, nil
	}
	if err := ApplyOwnerDACL(`C:\x`, false, "Everyone", run); err == nil {
		t.Fatal("bad SID was accepted")
	}
	if err := WriteSecretAfterDACL(`C:\x`, []byte("s"), "S-1-5-21-1", func(string, ...string) ([]byte, error) {
		return nil, errors.New("icacls denied")
	}, func(string, []byte) error {
		t.Fatal("secret bytes were written after icacls failed")
		return nil
	}); err == nil {
		t.Fatal("failed DACL still wrote the secret")
	}
}
