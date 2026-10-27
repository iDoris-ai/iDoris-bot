package vpnd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/paths"
)

// TestR3c2SystemLockProcesses re-executes the test binary. An in-process
// flock of two file names would not show that a second daemon, with a
// different XDG_STATE_HOME, is excluded.
func TestR3c2SystemLockProcesses(t *testing.T) {
	if os.Getenv("R3C2_LOCK_CHILD") == "1" {
		r3c2LockChildMain()
		return
	}
	r3c2IsolateCache(t)

	t.Run("different state home same socket", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "tailscaled.sock")
		stateA := filepath.Join(t.TempDir(), "state-a")
		stateB := filepath.Join(t.TempDir(), "state-b")
		t.Setenv("XDG_STATE_HOME", stateA)
		hold, err := LockSystem(sock)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = hold.Release() }()
		other, err := systemLockPath(sock)
		if err != nil {
			t.Fatal(err)
		}
		if other != hold.Path() {
			t.Fatalf("path %s, held %s", other, hold.Path())
		}
		r3c2ExpectLockDenied(t, sock, stateB)
	})

	t.Run("empty and explicit default socket", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), "state-empty"))
		hold, err := LockSystem("")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = hold.Release() }()
		explicit := paths.DefaultTailscaledSocket()
		got, err := systemLockPath(explicit)
		if err != nil {
			t.Fatal(err)
		}
		if got != hold.Path() {
			t.Fatalf("explicit default %s, empty %s", got, hold.Path())
		}
		r3c2ExpectLockDenied(t, explicit, filepath.Join(t.TempDir(), "state-explicit"))
	})
}

func r3c2ExpectLockDenied(t *testing.T, socket, stateHome string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestR3c2SystemLockProcesses$", "-test.count=1")
	cmd.Env = r3c2ReplaceEnv(os.Environ(), map[string]string{
		"R3C2_LOCK_CHILD": "1",
		"R3C2_LOCK_SOCK":  socket,
		"XDG_STATE_HOME":  stateHome,
	})
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("second process acquired the lock\n%s", out)
	}
	if !strings.Contains(string(out), "another idoris-vpnd") {
		t.Fatalf("second process: %v\n%s", err, out)
	}
}

func r3c2ReplaceEnv(base []string, replace map[string]string) []string {
	out := make([]string, 0, len(base)+len(replace))
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			if _, drop := replace[key]; drop {
				continue
			}
		}
		out = append(out, entry)
	}
	for key, val := range replace {
		out = append(out, key+"="+val)
	}
	return out
}

func r3c2LockChildMain() {
	lk, err := LockSystem(os.Getenv("R3C2_LOCK_SOCK"))
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(2)
	}
	_ = lk.Release()
	os.Exit(0)
}
