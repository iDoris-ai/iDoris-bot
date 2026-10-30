package vpnd

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestR3c2OwnerACLRunner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Log("icacls itself is not executed by this test; the runner is injected")
	} else {
		t.Log("icacls cannot run on this host; the runner is injected")
	}
	const path = `C:\Users\a\socks5.auth`
	const sid = "S-1-5-21-1"
	want := [][]string{
		{"icacls", path, "/reset"},
		{"icacls", path, "/inheritance:r"},
		{"icacls", path, "/grant:r", "*" + sid + ":F"},
	}
	if got := ownerOnlyICACLS(path, sid); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv %+v", got)
	}
	for _, argv := range want {
		joined := strings.Join(argv, " ")
		if strings.Contains(joined, "S-1-5-18") || strings.Contains(joined, "S-1-5-32-544") {
			t.Fatalf("SOCKS ACL must grant the user SID, not the service principals: %s", joined)
		}
	}

	var got [][]string
	err := applyOwnerACL(path, sid, func(name string, args ...string) ([]byte, error) {
		argv := append([]string{name}, args...)
		got = append(got, append([]string(nil), argv...))
		if len(got) == 2 {
			return []byte("denied"), fmt.Errorf("exit 5")
		}
		return []byte("ok"), nil
	})
	if err == nil || !strings.Contains(err.Error(), "/inheritance:r") {
		t.Fatalf("second command: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("commands after the failure still ran: %+v", got)
	}
	if !reflect.DeepEqual(got, want[:2]) {
		t.Fatalf("ran %+v", got)
	}
	if err := applyOwnerACL(path, "not-a-sid", func(string, ...string) ([]byte, error) {
		t.Fatal("runner called for a bad SID")
		return nil, nil
	}); err == nil {
		t.Fatal("bad SID was accepted")
	}
}

func TestR3c2SOCKSWindowsModeIgnored(t *testing.T) {
	if socksRejectsLooseModeOn(0o666, false) {
		t.Fatal("windows policy compared unix mode bits")
	}
	if socksRejectsLooseModeOn(0o644, false) {
		t.Fatal("windows policy rejected 0644")
	}
	if !socksRejectsLooseModeOn(0o644, true) || !socksRejectsLooseModeOn(0o666, true) {
		t.Fatal("unix policy accepted a loose mode")
	}
	if socksRejectsLooseModeOn(0o600, true) {
		t.Fatal("unix policy rejected 0600")
	}
	if runtime.GOOS != "windows" && !socksChecksUnixMode {
		t.Fatal("this OS must check unix mode bits")
	}
	if socksRejectsLooseMode(os.FileMode(0o644)) != socksChecksUnixMode {
		t.Fatalf("platform check unix=%v", socksChecksUnixMode)
	}
}
