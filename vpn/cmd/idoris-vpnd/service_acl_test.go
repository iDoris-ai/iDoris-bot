package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
)

func TestR2GICACLSCommandGolden(t *testing.T) {
	var cmds [][]string
	cmds = append(cmds, icaclsProtectCommands(`C:\ProgramData\idoris`, true)...)
	cmds = append(cmds, icaclsProtectCommands(`C:\ProgramData\idoris\vpn.json`, false)...)
	cmds = append(cmds, icaclsProtectCommands(`C:\ProgramData\idoris\enroll_token`, false)...)
	cmds = append(cmds, icaclsProtectCommands(`C:\ProgramData\idoris\auth_key`, false)...)
	cmds = append(cmds, icaclsProtectCommands(`C:\ProgramData\idoris\socks5.auth`, false)...)
	_, exe := systemExecutable("windows", `C:\Program Files`)
	cmds = append(cmds, icaclsProtectCommands(`C:\Program Files\iDoris`, true)...)
	cmds = append(cmds, icaclsProtectCommands(exe, false)...)
	assertGolden(t, "testdata/idoris-vpnd.icacls.txt", renderICACLSCommands(cmds))
}

func TestR5CServiceDACLUsesSIDs(t *testing.T) {
	sys := fsutil.SIDLocalSystem
	adm := fsutil.SIDAdministrators
	cases := []struct {
		name string
		view fsutil.ACLView
		ok   bool
	}{
		{
			name: "system and administrators",
			view: fsutil.ACLView{OwnerSID: sys, ACEs: []fsutil.ACE{{SID: sys}, {SID: adm}}},
			ok:   true,
		},
		{
			name: "administrators owner",
			view: fsutil.ACLView{OwnerSID: adm, ACEs: []fsutil.ACE{{SID: sys}, {SID: adm}}},
			ok:   true,
		},
		{
			name: "only system",
			view: fsutil.ACLView{OwnerSID: sys, ACEs: []fsutil.ACE{{SID: sys}}},
		},
		{
			name: "foreign ACE",
			view: fsutil.ACLView{OwnerSID: sys, ACEs: []fsutil.ACE{{SID: sys}, {SID: adm}, {SID: "S-1-1-0"}}},
		},
		{
			name: "inherited ACE",
			view: fsutil.ACLView{OwnerSID: sys, ACEs: []fsutil.ACE{{SID: sys, Inherited: true}, {SID: adm}}},
		},
		{
			name: "empty",
			view: fsutil.ACLView{OwnerSID: sys},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyServiceDACL(tc.view)
			if tc.ok && err != nil {
				t.Fatal(err)
			}
			if !tc.ok && err == nil {
				t.Fatal("DACL was accepted")
			}
		})
	}
}

func TestR2GStageWindowsCredentials(t *testing.T) {
	src := t.TempDir()
	token := filepath.Join(src, "token")
	auth := filepath.Join(src, "auth")
	socks := filepath.Join(src, "socks")
	if err := os.WriteFile(token, []byte("enroll-secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auth, []byte("hskey-secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(socks, []byte("alice:hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"control_url":"https://vpn.example","enroll_token_file":"` + token + `","auth_key_file":"` + auth + `","socks5_auth_file":"` + socks + `"}` + "\n")
	dest := t.TempDir()
	body, files, err := stageWindowsConfig(raw, dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("files %v", files)
	}
	for _, name := range []string{"enroll_token", "auth_key", "socks5.auth"} {
		path := filepath.Join(dest, name)
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", name, st.Mode().Perm())
		}
		if !strings.Contains(string(body), path) {
			t.Fatalf("rewritten config missing %s:\n%s", path, body)
		}
	}
	if strings.Contains(string(body), token) || strings.Contains(string(body), auth) {
		t.Fatalf("config still points at the source files:\n%s", body)
	}
	same, none, err := stageWindowsConfig([]byte("{\"control_url\":\"https://vpn.example\"}\n"), dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 || string(same) != "{\"control_url\":\"https://vpn.example\"}\n" {
		t.Fatalf("unchanged config was rewritten: %q files %v", same, none)
	}
	link := filepath.Join(src, "link")
	if err := os.Symlink(token, link); err != nil {
		t.Fatal(err)
	}
	linked := []byte(`{"enroll_token_file":"` + link + `"}` + "\n")
	if _, _, err := stageWindowsConfig(linked, dest); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}
}
