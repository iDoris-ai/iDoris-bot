package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestR6CReplaceProtectsEmptyStageBeforeSecrets drives replaceWindowsTask.
// The staging directory must be protected while it is still empty. A file
// created before that call is the credential window: Windows ignores the
// 0750 mode, and the inherited ProgramData ACL can be read by another
// local user. icacls is not executed.
func TestR6CReplaceProtectsEmptyStageBeforeSecrets(t *testing.T) {
	t.Log("icacls was not executed; protectWindowsInstallFn is injected. Windows was not run")
	prevChown := chownSystemRoot
	prevRun := runServiceCommand
	prevProtect := protectWindowsInstallFn
	chownSystemRoot = func(string) error { return nil }
	runServiceCommand = func(string, ...string) ([]byte, error) {
		return []byte("ok\n"), nil
	}
	t.Cleanup(func() {
		chownSystemRoot = prevChown
		runServiceCommand = prevRun
		protectWindowsInstallFn = prevProtect
	})

	root := t.TempDir()
	liveDir := filepath.Join(root, "ProgramData", "idoris")
	exeDir := filepath.Join(root, "Program Files", "iDoris")
	if err := os.MkdirAll(liveDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(exeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	liveExe := filepath.Join(exeDir, "idoris-vpnd.exe")
	if err := os.WriteFile(liveExe, []byte("old-exe"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "Downloads", "idoris-vpnd.exe")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("new-exe"), 0o755); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(root, "enroll.token")
	if err := os.WriteFile(token, []byte("enroll-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "cfg.json")
	cfgBody := []byte(`{"enroll_token_file":"` + token + `"}` + "\n")
	if err := os.WriteFile(cfgPath, cfgBody, 0o600); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "ProgramData", "idoris-install-r6c")

	var dirProtected, filesProtected bool
	protectWindowsInstallFn = func(dir, config, exeDir, exe string, creds []string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("protect read %s: %v", dir, err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		dirOnly := config == "" && exeDir == "" && exe == "" && len(creds) == 0
		if dirOnly {
			if len(names) != 0 {
				t.Fatalf("staging directory has files before directory protection: %s", strings.Join(names, ","))
			}
			if dir != staging {
				t.Fatalf("empty-directory protect path %s", dir)
			}
			dirProtected = true
			return nil
		}
		if !dirProtected {
			t.Fatalf("file protection ran before the empty staging directory was protected; entries=%s config=%s exe=%s creds=%v", strings.Join(names, ","), config, exe, creds)
		}
		filesProtected = true
		return nil
	}

	spec := windowsReplaceSpec{
		SrcExe:     src,
		LiveExe:    liveExe,
		ExeDir:     exeDir,
		ConfigSrc:  cfgPath,
		LiveDir:    liveDir,
		LiveConfig: filepath.Join(liveDir, "vpn.json"),
		StagingDir: staging,
		Active:     false,
	}
	if err := replaceWindowsTask(spec); err != nil {
		t.Fatal(err)
	}
	if !dirProtected {
		t.Fatal("replaceWindowsTask never protected the empty staging directory")
	}
	if !filesProtected {
		t.Fatal("replaceWindowsTask did not protect the staged files after writing them")
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatalf("staging left behind: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(liveDir, "enroll_token"))
	if err != nil || string(got) != "enroll-secret\n" {
		t.Fatalf("live token %q %v", got, err)
	}
}

// TestR6CRetargetDecodesWindowsJSONPaths uses the JSON json.Marshal writes
// for a Windows path. The staging directory appears there with doubled
// backslashes, so a search of the raw text for the Go path string misses
// it and leaves vpn.json pointing at the directory that install then deletes.
func TestR6CRetargetDecodesWindowsJSONPaths(t *testing.T) {
	staging := `C:\ProgramData\idoris-install-123`
	live := `C:\ProgramData\idoris`
	raw, err := json.Marshal(map[string]string{
		"control_url":       "https://vpn.example",
		"enroll_token_file": staging + `\enroll_token`,
		"auth_key_file":     staging + `\auth_key`,
		"socks5_auth_file":  staging + `\socks5.auth`,
		"state_file":        `D:\keep\state.json`,
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, staging) {
		t.Fatalf("fixture contains the unescaped staging path:\n%s", text)
	}
	if !strings.Contains(text, `C:\\ProgramData\\idoris-install-123`) {
		t.Fatalf("marshal did not escape the staging path:\n%s", text)
	}
	out, err := retargetStagedConfig(raw, staging, live)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("retarget output: %v\n%s", err, out)
	}
	want := map[string]string{
		"enroll_token_file": live + `\enroll_token`,
		"auth_key_file":     live + `\auth_key`,
		"socks5_auth_file":  live + `\socks5.auth`,
		"state_file":        `D:\keep\state.json`,
		"control_url":       "https://vpn.example",
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s=%q, want %q\n%s", k, got[k], v, out)
		}
	}

	// A credential that was never staged must come back as the original bytes.
	outside, err := json.Marshal(map[string]string{
		"enroll_token_file": `C:\Users\ada\enroll_token`,
		"auth_key_file":     `C:\Users\ada\auth_key`,
	})
	if err != nil {
		t.Fatal(err)
	}
	same, err := retargetStagedConfig(outside, staging, live)
	if err != nil {
		t.Fatal(err)
	}
	if string(same) != string(outside) {
		t.Fatalf("unrelated paths were rewritten:\n%s", same)
	}

	// Forward slashes are still a Windows path after JSON decoding.
	slashed, err := json.Marshal(map[string]string{
		"enroll_token_file": `C:/ProgramData/idoris-install-123/enroll_token`,
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err = retargetStagedConfig(slashed, staging, live)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["enroll_token_file"] != live+`\enroll_token` {
		t.Fatalf("forward-slash staging path: %q\n%s", got["enroll_token_file"], out)
	}

	// Host-native paths still move, including when this test runs on Windows.
	nativeStage := filepath.Join(string(filepath.Separator)+"var", "lib", "idoris", ".stage")
	nativeLive := filepath.Join(string(filepath.Separator)+"var", "lib", "idoris")
	native, err := json.Marshal(map[string]string{
		"auth_key_file": filepath.Join(nativeStage, "auth_key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err = retargetStagedConfig(native, nativeStage, nativeLive)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["auth_key_file"] != filepath.Join(nativeLive, "auth_key") {
		t.Fatalf("native path %q", got["auth_key_file"])
	}
}
