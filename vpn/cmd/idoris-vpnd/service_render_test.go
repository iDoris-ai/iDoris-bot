package main

import (
	"os"
	"strings"
	"testing"
)

func TestUserServiceNotice(t *testing.T) {
	if !strings.Contains(userServiceNotice("darwin"), "does not run before this user logs in") {
		t.Fatal(userServiceNotice("darwin"))
	}
	if !strings.Contains(userServiceNotice("linux"), "loginctl enable-linger") {
		t.Fatal(userServiceNotice("linux"))
	}
}

func TestRenderServiceDefinitions(t *testing.T) {
	const userExe = "/usr/local/bin/idoris-vpnd"
	_, systemExe := systemExecutable("linux", "")
	_, winExe := systemExecutable("windows", `C:\Program Files`)
	const cfgPath = "/etc/idoris/vpn.json"
	cfg := []byte(`{
	  "state_dir": "/var/lib/idoris/node",
	  "socks5_listen": "unix:/var/lib/idoris/socks",
	  "forwards": [{"listen": "unix:/run/idoris/fwd.sock", "target": "10.0.0.1:1"}]
	}`)
	unit, err := renderSystemdSystemUnit(systemExe, cfgPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "testdata/idoris-vpnd.system.service", unit)
	assertGolden(t, "testdata/idoris-vpnd.user.service", renderSystemdUserUnit(userExe, cfgPath))
	assertGolden(t, "testdata/ai.idoris.vpnd.daemon.plist", renderSystemLaunchdPlist(systemExe, cfgPath, "/var/log/idoris"))
	if strings.Contains(renderLaunchdPlist(userExe, cfgPath, "/var/log/idoris"), "STATE_DIRECTORY") {
		t.Fatal("user LaunchAgent must not set STATE_DIRECTORY")
	}
	assertGolden(t, "testdata/idoris-vpnd.task.txt", strings.Join(renderSchtasksCreate(winExe, windowsConfigPath), "\n")+"\n")
	if systemExe != "/usr/local/lib/idoris/idoris-vpnd" || winExe != `C:\Program Files\iDoris\idoris-vpnd.exe` {
		t.Fatalf("protected paths linux %s windows %s", systemExe, winExe)
	}

	quoted, err := renderSystemdSystemUnit("/opt/iDoris VPN/idoris-vpnd", "/etc/idoris/my vpn.json", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(quoted, `ExecStart="/opt/iDoris VPN/idoris-vpnd" run --config "/etc/idoris/my vpn.json"`) {
		t.Fatalf("quoting:\n%s", quoted)
	}
	task := renderSchtasksCreate(`C:\Program Files\idoris-vpnd.exe`, `C:\ProgramData\idoris\vpn.json`)
	if task[len(task)-1] != `cmd /c set STATE_DIRECTORY=C:\ProgramData\idoris&& "C:\Program Files\idoris-vpnd.exe" run --config C:\ProgramData\idoris\vpn.json` {
		t.Fatalf("task %q", task)
	}
	del := renderSchtasksDelete()
	if strings.Join(del, " ") != "/Delete /TN idoris-vpnd /F" {
		t.Fatalf("delete %v", del)
	}
	if _, err := renderSystemdSystemUnit(systemExe, cfgPath, []byte("{")); err == nil {
		t.Fatal("broken config was accepted")
	}
	paths, err := systemReadWritePaths([]byte(`{"state_dir":"relative","socks5_listen":"127.0.0.1:1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "/var/lib/idoris" || paths[1] != "/run/idoris" {
		t.Fatalf("paths %v", paths)
	}
	if _, err := systemReadWritePaths([]byte("{\"state_dir\":\"/var/lib/idoris\\nExecStartPre=/bin/true\"}")); err == nil {
		t.Fatal("newline in state_dir was accepted")
	}
	if _, err := systemReadWritePaths([]byte(`{"state_dir":"/var/lib/idoris/../../etc"}`)); err == nil {
		t.Fatal(".. in state_dir was accepted")
	}
	if _, err := systemReadWritePaths([]byte(`{"socks5_listen":"unix:/run/idoris/../../etc/fwd.sock"}`)); err == nil {
		t.Fatal(".. in unix listen was accepted")
	}
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	want, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s\n got:\n%s\nwant:\n%s", name, got, want)
	}
}
