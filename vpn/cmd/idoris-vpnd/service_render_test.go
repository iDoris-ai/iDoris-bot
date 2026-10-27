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
	const exe = "/usr/local/bin/idoris-vpnd"
	const cfgPath = "/etc/idoris/vpn.json"
	cfg := []byte(`{
	  "state_dir": "/var/lib/idoris/node",
	  "socks5_listen": "unix:/var/lib/idoris/socks",
	  "forwards": [{"listen": "unix:/run/idoris/fwd.sock", "target": "10.0.0.1:1"}]
	}`)
	unit, err := renderSystemdSystemUnit(exe, cfgPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "testdata/idoris-vpnd.system.service", unit)
	assertGolden(t, "testdata/idoris-vpnd.user.service", renderSystemdUserUnit(exe, cfgPath))
	assertGolden(t, "testdata/ai.idoris.vpnd.daemon.plist", renderLaunchdPlist(exe, cfgPath, "/var/log/idoris"))
	assertGolden(t, "testdata/idoris-vpnd.task.txt", strings.Join(renderSchtasksCreate(exe, cfgPath), "\n")+"\n")

	quoted, err := renderSystemdSystemUnit("/opt/iDoris VPN/idoris-vpnd", "/etc/idoris/my vpn.json", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(quoted, `ExecStart="/opt/iDoris VPN/idoris-vpnd" run --config "/etc/idoris/my vpn.json"`) {
		t.Fatalf("quoting:\n%s", quoted)
	}
	task := renderSchtasksCreate(`C:\Program Files\idoris-vpnd.exe`, `C:\ProgramData\idoris\vpn.json`)
	if task[len(task)-1] != `"C:\Program Files\idoris-vpnd.exe" run --config C:\ProgramData\idoris\vpn.json` {
		t.Fatalf("task %q", task)
	}
	del := renderSchtasksDelete()
	if strings.Join(del, " ") != "/Delete /TN idoris-vpnd /F" {
		t.Fatalf("delete %v", del)
	}
	if _, err := renderSystemdSystemUnit(exe, cfgPath, []byte("{")); err == nil {
		t.Fatal("broken config was accepted")
	}
	paths, err := systemReadWritePaths([]byte(`{"state_dir":"relative","socks5_listen":"127.0.0.1:1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/var/lib/idoris" {
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
