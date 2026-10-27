package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestR2GParseICACLS(t *testing.T) {
	ok := "" +
		`C:\ProgramData\idoris NT AUTHORITY\SYSTEM:(OI)(CI)(F)` + "\n" +
		`                       BUILTIN\Administrators:(OI)(CI)(F)` + "\n" +
		"\n" +
		"Successfully processed 1 files; Failed processing 0 files\n"
	if err := parseICACLSProtected(ok); err != nil {
		t.Fatal(err)
	}
	sid := "" +
		`C:\ProgramData\idoris\vpn.json S-1-5-18:(F)` + "\n" +
		`                               *S-1-5-32-544:(F)` + "\n"
	if err := parseICACLSProtected(sid); err != nil {
		t.Fatal(err)
	}
	users := strings.Replace(ok, "Successfully", "                       BUILTIN\\Users:(OI)(CI)(RX)\nSuccessfully", 1)
	if err := parseICACLSProtected(users); err == nil {
		t.Fatal("Users ACE was accepted")
	}
	everyone := "C:\\ProgramData\\idoris Everyone:(RX)\n                       NT AUTHORITY\\SYSTEM:(F)\n                       BUILTIN\\Administrators:(F)\n"
	if err := parseICACLSProtected(everyone); err == nil {
		t.Fatal("Everyone ACE was accepted")
	}
	onlySystem := "C:\\ProgramData\\idoris NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\nSuccessfully processed 1 files; Failed processing 0 files\n"
	if err := parseICACLSProtected(onlySystem); err == nil {
		t.Fatal("ACL without Administrators was accepted")
	}
	if err := parseICACLSProtected("Successfully processed 1 files; Failed processing 0 files\n"); err == nil {
		t.Fatal("output with no ACE was accepted")
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
