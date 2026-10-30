package main

import (
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
