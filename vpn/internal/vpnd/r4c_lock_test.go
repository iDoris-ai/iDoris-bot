package vpnd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// r4cWantLockDir is the directory systemLockDir uses. Root ignores the
// per-user path the older tests compute from STATE_DIRECTORY or the cache.
func r4cWantLockDir(t *testing.T, perUser string) string {
	t.Helper()
	if !currentIsMachineController() {
		return perUser
	}
	dir, err := machineLockDir()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestR4CNonRootLockDirStaysPerUser(t *testing.T) {
	if currentIsMachineController() {
		t.Skip("this process is the machine controller")
	}
	r3c2IsolateCache(t)
	state := t.TempDir()
	home := t.TempDir()
	t.Setenv("STATE_DIRECTORY", state)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	got, err := systemLockDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(state, "locks") {
		t.Fatalf("lock dir %s", got)
	}
	machine, err := machineLockDir()
	if err != nil || machine != "" {
		t.Fatalf("non-root machine dir %q err %v", machine, err)
	}
	t.Setenv("STATE_DIRECTORY", "")
	got, err = systemLockDir()
	if err != nil {
		t.Fatal(err)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(cache, "idoris", "locks") {
		t.Fatalf("cache lock dir %s", got)
	}
}

// TestR4CRootLockProcesses re-executes with a different STATE_DIRECTORY and
// XDG/HOME. Both processes are root, so they share /var/lib/idoris/locks
// (or ProgramData on Windows) and the second one is excluded.
func TestR4CRootLockProcesses(t *testing.T) {
	if os.Getenv("R4C_LOCK_CHILD") == "1" {
		r4cRootLockChild()
		return
	}
	if !currentIsMachineController() {
		if os.Getenv("R4C_REQUIRE_ROOT") == "1" {
			t.Fatal("root required to prove the machine lock directory")
		}
		t.Skip("root lock exclusion is run in docker")
	}
	sock := filepath.Join(t.TempDir(), "tailscaled.sock")
	hold, err := LockSystem(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Release() }()
	dir, err := systemLockDir()
	if err != nil {
		t.Fatal(err)
	}
	machine, err := machineLockDir()
	if err != nil || dir != machine || machine == "" {
		t.Fatalf("lock dir %s machine %q err %v", dir, machine, err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestR4CRootLockProcesses$", "-test.count=1")
	cmd.Env = r3c2ReplaceEnv(os.Environ(), map[string]string{
		"R4C_LOCK_CHILD":  "1",
		"R4C_LOCK_SOCK":   sock,
		"STATE_DIRECTORY": filepath.Join(t.TempDir(), "other-state"),
		"HOME":            filepath.Join(t.TempDir(), "other-home"),
		"XDG_CACHE_HOME":  filepath.Join(t.TempDir(), "other-cache"),
		"XDG_STATE_HOME":  filepath.Join(t.TempDir(), "other-xdg"),
		"XDG_RUNTIME_DIR": filepath.Join(t.TempDir(), "other-run"),
	})
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("second root process acquired the lock\n%s", out)
	}
	if !strings.Contains(string(out), "another idoris-vpnd") {
		t.Fatalf("second process: %v\n%s", err, out)
	}
}

func r4cRootLockChild() {
	lk, err := LockSystem(os.Getenv("R4C_LOCK_SOCK"))
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(2)
	}
	_ = lk.Release()
	os.Exit(0)
}
