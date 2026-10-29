package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestR5CWindowsReinstallStopsBeforeReplace checks the active-task order:
// stage, schtasks /End, poll until the image is gone, then replace and /Run.
// An install that is itself the running image does not overwrite that path.
// tasklist and schtasks are not executed.
func TestR5CWindowsReinstallStopsBeforeReplace(t *testing.T) {
	t.Log("schtasks and tasklist were not executed; the runner is injected. Windows was not run")
	prevChown := chownSystemRoot
	chownSystemRoot = func(string) error { return nil }
	prevSleep := windowsSleep
	prevWait := windowsExitWait
	windowsSleep = func(time.Duration) {}
	t.Cleanup(func() {
		chownSystemRoot = prevChown
		windowsSleep = prevSleep
		windowsExitWait = prevWait
	})

	var cmds []string
	polls := 0
	running := `"idoris-vpnd.exe","999","Console","1","1 K"` + "\r\n"
	prevRun := runServiceCommand
	runServiceCommand = func(name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		cmds = append(cmds, line)
		if name == "tasklist" {
			polls++
			if polls == 1 {
				return []byte(running), nil
			}
			return []byte("INFO: No tasks are running which match the specified criteria.\r\n"), nil
		}
		return []byte("ok\n"), nil
	}
	t.Cleanup(func() { runServiceCommand = prevRun })

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
	if err := os.WriteFile(liveExe, []byte("old-exe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(liveDir, "vpn.json"), []byte("old-config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(liveDir, "auth_key"), []byte("old-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(liveDir, "vpnd-state.json"), []byte("node-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "new-vpnd.exe")
	if err := os.WriteFile(src, []byte("new-exe"), 0o755); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(root, "new-token")
	if err := os.WriteFile(token, []byte("new-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "cfg.json")
	cfgBody := []byte(`{"auth_key_file":"` + token + `"}` + "\n")
	if err := os.WriteFile(cfgPath, cfgBody, 0o600); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "ProgramData", "idoris-install-test")
	if strings.HasPrefix(filepath.Clean(staging), filepath.Clean(liveDir)+string(filepath.Separator)) {
		t.Fatal("staging is inside the live tree")
	}

	replaced := false
	runServiceCommand = func(name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		cmds = append(cmds, line)
		if name == "schtasks" && len(args) > 0 && args[0] == "/End" {
			got, err := os.ReadFile(liveExe)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "old-exe" {
				t.Fatalf("executable replaced before /End: %q", got)
			}
		}
		if name == "tasklist" {
			polls++
			if polls == 1 {
				return []byte(running), nil
			}
			return []byte("INFO: No tasks are running which match the specified criteria.\r\n"), nil
		}
		if name == "schtasks" && len(args) > 0 && args[0] == "/Run" {
			got, err := os.ReadFile(liveExe)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "new-exe" {
				t.Fatalf("executable at /Run: %q", got)
			}
			replaced = true
		}
		return []byte("ok\n"), nil
	}

	spec := windowsReplaceSpec{
		SrcExe:     src,
		LiveExe:    liveExe,
		ExeDir:     exeDir,
		ConfigSrc:  cfgPath,
		LiveDir:    liveDir,
		LiveConfig: filepath.Join(liveDir, "vpn.json"),
		StagingDir: staging,
		Active:     true,
	}
	if err := replaceWindowsTask(spec); err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Fatal("/Run did not observe the new executable")
	}
	want := []string{
		"schtasks /End /TN idoris-vpnd",
		"tasklist /FI IMAGENAME eq idoris-vpnd.exe /FO CSV /NH",
		"tasklist /FI IMAGENAME eq idoris-vpnd.exe /FO CSV /NH",
	}
	joined := strings.Join(cmds, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Fatalf("missing %s\n%s", w, joined)
		}
	}
	endAt := strings.Index(joined, "schtasks /End")
	listAt := strings.Index(joined, "tasklist")
	createAt := strings.Index(joined, "schtasks /Create")
	runAt := strings.Index(joined, "schtasks /Run")
	if endAt < 0 || listAt < endAt || createAt < listAt || runAt < createAt {
		t.Fatalf("order\n%s", joined)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatalf("staging left behind: %v", err)
	}
	state, err := os.ReadFile(filepath.Join(liveDir, "vpnd-state.json"))
	if err != nil || string(state) != "node-state" {
		t.Fatalf("node state %q %v", state, err)
	}
	tokenGot, err := os.ReadFile(filepath.Join(liveDir, "auth_key"))
	if err != nil || string(tokenGot) != "new-token" {
		t.Fatalf("token %q %v", tokenGot, err)
	}
	cfgGot, err := os.ReadFile(filepath.Join(liveDir, "vpn.json"))
	if err != nil || strings.Contains(string(cfgGot), token) || !strings.Contains(string(cfgGot), filepath.Join(liveDir, "auth_key")) {
		t.Fatalf("config\n%s", cfgGot)
	}

	// First install does not stop or poll.
	cmds = nil
	polls = 0
	src2 := filepath.Join(root, "first.exe")
	if err := os.WriteFile(src2, []byte("first-exe"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec.SrcExe = src2
	spec.Active = false
	spec.StagingDir = filepath.Join(root, "ProgramData", "idoris-install-first")
	if err := replaceWindowsTask(spec); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(cmds, "\n"), "/End") || strings.Contains(strings.Join(cmds, "\n"), "tasklist") || strings.Contains(strings.Join(cmds, "\n"), "/Run") {
		t.Fatalf("inactive install ran %s", strings.Join(cmds, "\n"))
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "schtasks /Create") {
		t.Fatalf("inactive install\n%s", strings.Join(cmds, "\n"))
	}

	// Running as the installed image: do not overwrite that file.
	cmds = nil
	polls = 0
	selfPoll := 0
	runServiceCommand = func(name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		if name == "tasklist" {
			selfPoll++
			if selfPoll == 1 {
				return []byte("\"idoris-vpnd.exe\",\"42\",\"Console\",\"1\",\"1 K\"\r\n\"idoris-vpnd.exe\",\"7\",\"Services\",\"0\",\"1 K\"\r\n"), nil
			}
			return []byte("\"idoris-vpnd.exe\",\"42\",\"Console\",\"1\",\"1 K\"\r\n"), nil
		}
		return []byte("ok\n"), nil
	}
	if err := os.WriteFile(liveExe, []byte("mapped-exe"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec.SrcExe = liveExe
	spec.Active = true
	spec.SelfPID = 42
	spec.ConfigSrc = cfgPath
	spec.StagingDir = filepath.Join(root, "ProgramData", "idoris-install-self")
	if err := replaceWindowsTask(spec); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(liveExe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "mapped-exe" {
		t.Fatalf("running image was replaced: %q", got)
	}
	var versioned string
	entries, err := os.ReadDir(exeDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "idoris-vpnd-") && strings.HasSuffix(name, ".exe") {
			versioned = filepath.Join(exeDir, name)
		}
	}
	if versioned == "" {
		t.Fatal("versioned executable was not installed")
	}
	if !strings.Contains(strings.Join(cmds, "\n"), versioned) {
		t.Fatalf("task action does not use %s\n%s", versioned, strings.Join(cmds, "\n"))
	}
	body, err := os.ReadFile(versioned)
	if err != nil || string(body) != "mapped-exe" {
		t.Fatalf("versioned payload %q %v", body, err)
	}

	// The wait is bounded. A process that never exits does not replace the image.
	cmds = nil
	windowsExitWait = 0
	runServiceCommand = func(name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		if name == "tasklist" {
			return []byte(running), nil
		}
		return []byte("ok\n"), nil
	}
	if err := os.WriteFile(liveExe, []byte("still-old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("should-not-land"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec.SrcExe = src
	spec.SelfPID = 0
	spec.Active = true
	spec.StagingDir = filepath.Join(root, "ProgramData", "idoris-install-timeout")
	err = replaceWindowsTask(spec)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatal(err)
	}
	got, err = os.ReadFile(liveExe)
	if err != nil || string(got) != "still-old" {
		t.Fatalf("timeout replaced the executable: %q %v", got, err)
	}
	if strings.Contains(strings.Join(cmds, "\n"), "schtasks /Create") {
		t.Fatalf("timeout updated the task\n%s", strings.Join(cmds, "\n"))
	}
}
