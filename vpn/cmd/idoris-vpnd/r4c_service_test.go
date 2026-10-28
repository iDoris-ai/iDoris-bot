package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR4CSharedRuntimeIsRejected(t *testing.T) {
	cases := []string{
		`{"listen":"unix:/run/user/1000/vpnd.sock"}`,
		`{"listen":"unix:/run/vpnd.sock"}`,
		`{"listen":"unix:/var/run/user/1000/vpnd.sock"}`,
		`{"socks5_listen":"unix:/var/run/vpnd.sock"}`,
		`{"state_file":"/run/user/1000/state.json"}`,
		`{"state_dir":"/run/user/1000/node"}`,
	}
	for _, cfg := range cases {
		_, err := systemReadWritePaths([]byte(cfg))
		if err == nil || (!strings.Contains(err.Error(), "shared runtime") && !strings.Contains(err.Error(), "shared directory")) {
			t.Fatalf("cfg %s err %v", cfg, err)
		}
		if _, err := renderSystemdSystemUnit("/bin/idoris-vpnd", "/etc/idoris/vpn.json", []byte(cfg)); err == nil {
			t.Fatalf("cfg %s rendered a unit", cfg)
		}
	}
	_, runtime := systemdManagedDirs([]string{"/run/user", "/run/idoris", "/run/custom"})
	if strings.Join(runtime, " ") != "idoris custom" {
		t.Fatalf("runtime directories %v", runtime)
	}

	root := t.TempDir()
	shared := filepath.Join(root, "run", "user")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	err := provisionSystemPaths(root, []byte(`{"listen":"unix:/run/user/1000/vpnd.sock"}`))
	if err == nil || !strings.Contains(err.Error(), "unix:/run/idoris/") {
		t.Fatal(err)
	}
	st, err := os.Stat(shared)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("shared runtime mode changed to %o", st.Mode().Perm())
	}
}

func TestR4CStateFileParentIsReadWrite(t *testing.T) {
	cfg := []byte(`{"state_file":"/srv/idoris/vpnd-state.json","listen":"unix:/run/idoris/vpnd.sock"}`)
	unit, err := renderSystemdSystemUnit("/usr/local/lib/idoris/idoris-vpnd", "/etc/idoris/vpn.json", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unit, "ReadWritePaths=/srv/idoris\n") {
		t.Fatalf("unit\n%s", unit)
	}
	if strings.Contains(unit, "RuntimeDirectory=user") {
		t.Fatalf("unit\n%s", unit)
	}
	root := t.TempDir()
	srv := filepath.Join(root, "srv")
	if err := os.Mkdir(srv, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(srv, 0o755); err != nil {
		t.Fatal(err)
	}
	prev := chownSystemRoot
	var owned []string
	chownSystemRoot = func(p string) error {
		owned = append(owned, p)
		return nil
	}
	t.Cleanup(func() { chownSystemRoot = prev })
	if err := provisionSystemPaths(root, cfg); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(srv, "idoris")
	st, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o750 {
		t.Fatalf("state parent mode %o", st.Mode().Perm())
	}
	srvSt, err := os.Stat(srv)
	if err != nil {
		t.Fatal(err)
	}
	if srvSt.Mode().Perm() != 0o755 {
		t.Fatalf("/srv mode changed to %o", srvSt.Mode().Perm())
	}
	if containsPath(owned, srv) {
		t.Fatalf("chowned shared ancestor /srv: %v", owned)
	}
	if !containsPath(owned, parent) {
		t.Fatalf("state parent was not chowned: %v", owned)
	}
}

func TestR4CReinstallRestartsActiveUnit(t *testing.T) {
	var cmds []string
	prev := runServiceCommand
	runServiceCommand = func(name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return []byte("ok\n"), nil
	}
	t.Cleanup(func() { runServiceCommand = prev })

	reset := func() { cmds = nil }
	check := func(want ...string) {
		t.Helper()
		if strings.Join(cmds, "\n") != strings.Join(want, "\n") {
			t.Fatalf("commands\n%s\nwant\n%s", strings.Join(cmds, "\n"), strings.Join(want, "\n"))
		}
	}

	if err := activateSystemService("linux", true); err != nil {
		t.Fatal(err)
	}
	check("systemctl daemon-reload", "systemctl restart idoris-vpnd.service")
	reset()
	if err := activateSystemService("linux", false); err != nil {
		t.Fatal(err)
	}
	check("systemctl daemon-reload", "systemctl enable --now idoris-vpnd.service")
	reset()
	if err := activateSystemService("darwin", true); err != nil {
		t.Fatal(err)
	}
	check(
		"launchctl bootout system/ai.idoris.vpnd",
		"launchctl bootstrap system /Library/LaunchDaemons/ai.idoris.vpnd.plist",
		"launchctl kickstart -k system/ai.idoris.vpnd",
	)
	reset()
	if err := activateSystemService("darwin", false); err != nil {
		t.Fatal(err)
	}
	check("launchctl bootstrap system /Library/LaunchDaemons/ai.idoris.vpnd.plist")
	reset()
	if err := activateSystemService("windows", true); err != nil {
		t.Fatal(err)
	}
	check("schtasks /End /TN idoris-vpnd", "schtasks /Run /TN idoris-vpnd")
	reset()
	if err := activateSystemService("windows", false); err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 0 {
		t.Fatalf("inactive windows task ran %v", cmds)
	}
}

func TestR4CInstallServiceAbsMissingConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	err := installService(filepath.Join("rel", "missing.json"))
	if err == nil {
		t.Fatal("missing config was accepted")
	}
	want := filepath.Join(dir, "rel", "missing.json")
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("got %v, want %s", err, want)
	}
}

func TestR4CStageWindowsConfigRollsBack(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "out")
	if err := os.Mkdir(dest, 0o750); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{
		"enroll_token_file": token,
		"auth_key_file":     filepath.Join(dir, "missing"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := stageWindowsConfig(body, dest); err == nil {
		t.Fatal("missing auth key was accepted")
	}
	if _, err := os.Stat(filepath.Join(dest, "enroll_token")); err == nil {
		t.Fatal("partial enroll_token copy was left behind")
	}
}
