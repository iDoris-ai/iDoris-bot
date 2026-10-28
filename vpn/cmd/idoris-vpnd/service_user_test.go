package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestR5CUserServiceRestartsWhenActive checks the user-unit command sequence.
// A first install enables or bootstraps. An already-active unit is restarted
// (Linux) or kickstarted (macOS). The runner is injected; systemctl and
// launchctl are not executed.
func TestR5CUserServiceRestartsWhenActive(t *testing.T) {
	t.Log("systemctl --user and launchctl were not executed; the runner is injected")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	var cmds []string
	active := false
	prev := runServiceCommand
	runServiceCommand = func(name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		if name == "systemctl" && len(args) >= 2 && args[1] == "is-active" {
			if active {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), errors.New("exit status 3")
		}
		if name == "launchctl" && len(args) >= 1 && args[0] == "print" {
			if active {
				return []byte("state = running\n"), nil
			}
			return []byte("Could not find service\n"), errors.New("exit status 113")
		}
		return []byte("ok\n"), nil
	}
	t.Cleanup(func() { runServiceCommand = prev })

	check := func(action userServiceAction, got error, want userServiceAction, wantCmds ...string) {
		t.Helper()
		if got != nil {
			t.Fatal(got)
		}
		if action != want {
			t.Fatalf("action %q, want %q", action, want)
		}
		if strings.Join(cmds, "\n") != strings.Join(wantCmds, "\n") {
			t.Fatalf("commands\n%s\nwant\n%s", strings.Join(cmds, "\n"), strings.Join(wantCmds, "\n"))
		}
	}

	const exe = "/usr/local/bin/idoris-vpnd"
	const cfg = "/tmp/idoris-vpn.json"
	unit := filepath.Join(home, ".config", "systemd", "user", "idoris-vpnd.service")
	plist := filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
	uid := os.Getuid()
	domain := fmt.Sprintf("gui/%d", uid)
	target := domain + "/" + launchdLabel

	active = false
	cmds = nil
	action, err := installSystemdUser(exe, cfg)
	check(action, err, userServiceStarted,
		"systemctl --user is-active idoris-vpnd.service",
		"systemctl --user daemon-reload",
		"systemctl --user enable --now idoris-vpnd.service",
	)
	body, err := os.ReadFile(unit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), exe) || !strings.Contains(string(body), cfg) {
		t.Fatalf("unit\n%s", body)
	}

	active = true
	cmds = nil
	action, err = installSystemdUser(exe, cfg)
	check(action, err, userServiceRestarted,
		"systemctl --user is-active idoris-vpnd.service",
		"systemctl --user daemon-reload",
		"systemctl --user restart idoris-vpnd.service",
	)

	active = false
	cmds = nil
	action, err = installLaunchd(exe, cfg)
	check(action, err, userServiceStarted,
		"launchctl print "+target,
		"launchctl bootstrap "+domain+" "+plist,
	)
	plistBody, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plistBody), exe) || !strings.Contains(string(plistBody), cfg) {
		t.Fatalf("plist\n%s", plistBody)
	}

	active = true
	cmds = nil
	action, err = installLaunchd(exe, cfg)
	check(action, err, userServiceRestarted,
		"launchctl print "+target,
		"launchctl bootout "+target,
		"launchctl bootstrap "+domain+" "+plist,
		"launchctl kickstart -k "+target,
	)
}
