package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestR5CFailedSystemReinstallKeepsPrevious checks that a missing credential
// and a listener under /run/user are rejected before the live token or config
// is replaced. chown is stubbed. Nothing is installed on the host.
func TestR5CFailedSystemReinstallKeepsPrevious(t *testing.T) {
	prev := chownSystemRoot
	chownSystemRoot = func(string) error { return nil }
	t.Cleanup(func() { chownSystemRoot = prev })

	root := t.TempDir()
	liveDir := filepath.Join(root, "var", "lib", "idoris")
	if err := os.MkdirAll(liveDir, 0o750); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(root, "etc", "idoris")
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatal(err)
	}
	liveConfig := filepath.Join(configDir, "vpn.json")
	oldToken := []byte("old-token")
	oldEnroll := []byte("old-enroll")
	oldState := []byte("node-state")
	oldConfig := []byte("{\"auth_key_file\":\"previous\"}\n")
	if err := os.WriteFile(filepath.Join(liveDir, "auth_key"), oldToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(liveDir, "enroll_token"), oldEnroll, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(liveDir, "vpnd-state.json"), oldState, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(liveConfig, oldConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	newToken := filepath.Join(root, "new-token")
	if err := os.WriteFile(newToken, []byte("new-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	newEnroll := filepath.Join(root, "new-enroll")
	if err := os.WriteFile(newEnroll, []byte("new-enroll"), 0o600); err != nil {
		t.Fatal(err)
	}

	runUser := "/run/user"
	beforeRun, beforeErr := os.Stat(runUser)

	missing := filepath.Join(root, "missing-auth-key")
	missingCfg, err := json.Marshal(map[string]string{
		"enroll_token_file": newEnroll,
		"auth_key_file":     missing,
	})
	if err != nil {
		t.Fatal(err)
	}
	exe := "/usr/local/lib/idoris/idoris-vpnd"
	if _, _, _, err := prepareSystemInstall(exe, liveConfig, liveDir, missingCfg); err == nil || !strings.Contains(err.Error(), "auth_key_file") {
		t.Fatalf("missing credential: %v", err)
	}
	assertPreviousInstall(t, liveDir, liveConfig, oldToken, oldEnroll, oldState, oldConfig)
	assertNoStageLeft(t, filepath.Dir(liveDir))

	rejected, err := json.Marshal(map[string]string{
		"auth_key_file": newToken,
		"listen":        "unix:/run/user/1000/vpnd.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := prepareSystemInstall(exe, liveConfig, liveDir, rejected); err == nil || !strings.Contains(err.Error(), "/run/user") {
		t.Fatalf("rejected listener: %v", err)
	}
	assertPreviousInstall(t, liveDir, liveConfig, oldToken, oldEnroll, oldState, oldConfig)
	assertNoStageLeft(t, filepath.Dir(liveDir))
	afterRun, afterErr := os.Stat(runUser)
	if errors.Is(beforeErr, os.ErrNotExist) {
		if !errors.Is(afterErr, os.ErrNotExist) {
			t.Fatalf("/run/user was created: %v", afterErr)
		}
	} else if beforeErr != nil {
		t.Fatal(beforeErr)
	} else if afterErr != nil || afterRun.Mode() != beforeRun.Mode() {
		t.Fatalf("/run/user mode changed: before %v %v after %v %v", beforeRun, beforeErr, afterRun, afterErr)
	}

	okCfg, err := json.Marshal(map[string]string{
		"auth_key_file": newToken,
		"listen":        "unix:/run/idoris/vpnd.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	unit, stage, body, err := prepareSystemInstall(exe, liveConfig, liveDir, okCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stage) })
	if err := finishSystemInstall(stage, liveDir, liveConfig, body); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(stage); err != nil {
		t.Fatal(err)
	}
	gotToken, err := os.ReadFile(filepath.Join(liveDir, "auth_key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotToken) != "new-token" {
		t.Fatalf("committed token %q", gotToken)
	}
	gotCfg, err := os.ReadFile(liveConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(gotCfg, []byte(filepath.Join(liveDir, "auth_key"))) {
		t.Fatalf("config was not retargeted: %s", gotCfg)
	}
	if bytes.Contains(gotCfg, []byte(newToken)) {
		t.Fatalf("config still names the operator token path: %s", gotCfg)
	}
	gotState, err := os.ReadFile(filepath.Join(liveDir, "vpnd-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotState, oldState) {
		t.Fatalf("node state changed: %q", gotState)
	}
	if !strings.Contains(unit, exe) || strings.Contains(unit, "/run/user") {
		t.Fatalf("unit %s", unit)
	}
	assertNoStageLeft(t, filepath.Dir(liveDir))
}

func assertPreviousInstall(t *testing.T, liveDir, liveConfig string, token, enroll, state, config []byte) {
	t.Helper()
	check := func(path string, want []byte) {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s changed: %q", path, got)
		}
	}
	check(filepath.Join(liveDir, "auth_key"), token)
	check(filepath.Join(liveDir, "enroll_token"), enroll)
	check(filepath.Join(liveDir, "vpnd-state.json"), state)
	check(liveConfig, config)
}

func assertNoStageLeft(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".idoris-stage-") {
			t.Fatalf("staging directory left behind: %s", e.Name())
		}
	}
}

// TestR5CFailedWindowsReinstallKeepsPrevious checks that a missing credential
// does not stop the task or change the previous ProgramData tree. schtasks
// was not executed. Windows was not run.
func TestR5CFailedWindowsReinstallKeepsPrevious(t *testing.T) {
	t.Log("schtasks was not executed; Windows was not run")
	prevChown := chownSystemRoot
	chownSystemRoot = func(string) error { return nil }
	prevRun := runServiceCommand
	runServiceCommand = func(name string, args ...string) ([]byte, error) {
		t.Errorf("command during failed install: %s %s", name, strings.Join(args, " "))
		return nil, errors.New("unexpected command")
	}
	t.Cleanup(func() {
		chownSystemRoot = prevChown
		runServiceCommand = prevRun
	})

	root := t.TempDir()
	liveDir := filepath.Join(root, "ProgramData", "idoris")
	if err := os.MkdirAll(liveDir, 0o750); err != nil {
		t.Fatal(err)
	}
	exeDir := filepath.Join(root, "Program Files", "iDoris")
	if err := os.MkdirAll(exeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	liveExe := filepath.Join(exeDir, "idoris-vpnd.exe")
	oldExe := []byte("old-exe")
	oldConfig := []byte("old-config\n")
	oldToken := []byte("old-token")
	oldEnroll := []byte("old-enroll")
	oldState := []byte("node-state")
	for name, body := range map[string][]byte{
		"vpn.json":        oldConfig,
		"auth_key":        oldToken,
		"enroll_token":    oldEnroll,
		"vpnd-state.json": oldState,
	} {
		if err := os.WriteFile(filepath.Join(liveDir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(liveExe, oldExe, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "new-vpnd.exe")
	if err := os.WriteFile(src, []byte("new-exe"), 0o755); err != nil {
		t.Fatal(err)
	}
	newEnroll := filepath.Join(root, "new-enroll")
	if err := os.WriteFile(newEnroll, []byte("new-enroll"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "cfg.json")
	raw, err := json.Marshal(map[string]string{
		"enroll_token_file": newEnroll,
		"auth_key_file":     filepath.Join(root, "missing-auth-key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "ProgramData", "idoris-install-test")
	err = replaceWindowsTask(windowsReplaceSpec{
		SrcExe:     src,
		LiveExe:    liveExe,
		ExeDir:     exeDir,
		ConfigSrc:  cfgPath,
		LiveDir:    liveDir,
		LiveConfig: filepath.Join(liveDir, "vpn.json"),
		StagingDir: staging,
		Active:     true,
	})
	if err == nil || !strings.Contains(err.Error(), "auth_key_file") {
		t.Fatalf("missing credential: %v", err)
	}
	if _, err := os.Stat(staging); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging directory still present: %v", err)
	}
	check := func(path string, want []byte) {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s changed: %q", path, got)
		}
	}
	check(liveExe, oldExe)
	check(filepath.Join(liveDir, "vpn.json"), oldConfig)
	check(filepath.Join(liveDir, "auth_key"), oldToken)
	check(filepath.Join(liveDir, "enroll_token"), oldEnroll)
	check(filepath.Join(liveDir, "vpnd-state.json"), oldState)
}
