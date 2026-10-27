package vpnd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// r3svcClearStateEnv injects a closed set of directory variables. An empty
// value is unset for os.UserHomeDir and os.UserCacheDir.
func r3svcClearStateEnv(t *testing.T, extra map[string]string) {
	t.Helper()
	base := map[string]string{
		"STATE_DIRECTORY": "",
		"HOME":            "",
		"USERPROFILE":     "",
		"XDG_STATE_HOME":  "",
		"XDG_CACHE_HOME":  "",
		"XDG_CONFIG_HOME": "",
		"XDG_RUNTIME_DIR": "",
		"LocalAppData":    "",
		"APPDATA":         "",
	}
	for k, v := range extra {
		base[k] = v
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
}

func TestR3svcStateDirectoryResolution(t *testing.T) {
	state := t.TempDir()
	other := t.TempDir()
	home := t.TempDir()
	xdg := t.TempDir()

	t.Run("state directory beats home and xdg", func(t *testing.T) {
		r3svcClearStateEnv(t, map[string]string{
			"STATE_DIRECTORY": state,
			"HOME":            home,
			"XDG_STATE_HOME":  xdg,
			"XDG_CACHE_HOME":  filepath.Join(home, "cache"),
		})
		file, err := DefaultStateFile()
		if err != nil {
			t.Fatal(err)
		}
		if file != filepath.Join(state, "vpnd-state.json") {
			t.Fatalf("state file %s", file)
		}
		dir, err := DefaultStateDir()
		if err != nil {
			t.Fatal(err)
		}
		if dir != filepath.Join(state, "node") {
			t.Fatalf("state dir %s", dir)
		}
		lock, err := systemLockDir()
		if err != nil {
			t.Fatal(err)
		}
		if lock != filepath.Join(state, "locks") {
			t.Fatalf("lock dir %s", lock)
		}
		if got := DefaultListen(); got != "unix:"+filepath.Join(state, "vpnd.sock") {
			t.Fatalf("listen %s", got)
		}
	})

	t.Run("first colon entry", func(t *testing.T) {
		r3svcClearStateEnv(t, map[string]string{
			"STATE_DIRECTORY": state + ":" + other,
			"HOME":            home,
		})
		file, err := DefaultStateFile()
		if err != nil {
			t.Fatal(err)
		}
		if file != filepath.Join(state, "vpnd-state.json") {
			t.Fatalf("state file %s", file)
		}
		dir, err := DefaultStateDir()
		if err != nil {
			t.Fatal(err)
		}
		if dir != filepath.Join(state, "node") {
			t.Fatalf("state dir %s", dir)
		}
	})

	t.Run("relative state directory is an error", func(t *testing.T) {
		r3svcClearStateEnv(t, map[string]string{
			"STATE_DIRECTORY": "relative/vpnd",
			"HOME":            home,
		})
		file, err := DefaultStateFile()
		if err == nil || file != "" || !strings.Contains(err.Error(), "STATE_DIRECTORY") {
			t.Fatalf("state file %q err %v", file, err)
		}
		dir, err := DefaultStateDir()
		if err == nil || dir != "" || !strings.Contains(err.Error(), "STATE_DIRECTORY") {
			t.Fatalf("state dir %q err %v", dir, err)
		}
		lock, err := systemLockDir()
		if err == nil || lock != "" || !strings.Contains(err.Error(), "STATE_DIRECTORY") {
			t.Fatalf("lock dir %q err %v", lock, err)
		}
	})

	t.Run("empty first entry is an error", func(t *testing.T) {
		r3svcClearStateEnv(t, map[string]string{
			"STATE_DIRECTORY": ":" + state,
			"HOME":            home,
		})
		file, err := DefaultStateFile()
		if err == nil || file != "" || !strings.Contains(err.Error(), "STATE_DIRECTORY") {
			t.Fatalf("file %q err %v", file, err)
		}
	})

	t.Run("unset state directory keeps per-user defaults", func(t *testing.T) {
		r3svcClearStateEnv(t, map[string]string{
			"HOME":           home,
			"XDG_STATE_HOME": xdg,
			"XDG_CACHE_HOME": filepath.Join(home, "cache"),
		})
		file, err := DefaultStateFile()
		if err != nil {
			t.Fatal(err)
		}
		if file != filepath.Join(xdg, "idoris", "vpnd-state.json") {
			t.Fatalf("state file %s", file)
		}
		dir, err := DefaultStateDir()
		if err != nil {
			t.Fatal(err)
		}
		if dir != filepath.Join(home, ".idoris", "vpn-state") {
			t.Fatalf("state dir %s", dir)
		}
		lock, err := systemLockDir()
		if err != nil {
			t.Fatal(err)
		}
		cache, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		if lock != filepath.Join(cache, "idoris", "locks") {
			t.Fatalf("lock dir %s, cache %s", lock, cache)
		}
	})

	t.Run("unset state directory and home is a named error", func(t *testing.T) {
		r3svcClearStateEnv(t, nil)
		file, err := DefaultStateFile()
		if err == nil || file != "" || !strings.Contains(err.Error(), "STATE_DIRECTORY") {
			t.Fatalf("state file %q err %v", file, err)
		}
		dir, err := DefaultStateDir()
		if err == nil || dir != "" || !strings.Contains(err.Error(), "STATE_DIRECTORY") {
			t.Fatalf("state dir %q err %v", dir, err)
		}
		lock, err := systemLockDir()
		if err == nil || lock != "" || !strings.Contains(err.Error(), "STATE_DIRECTORY") {
			t.Fatalf("lock dir %q err %v", lock, err)
		}
	})

	t.Run("runtime dir listen does not need home", func(t *testing.T) {
		r3svcClearStateEnv(t, map[string]string{"XDG_RUNTIME_DIR": "/run/idoris"})
		if got := DefaultListen(); got != "unix:"+filepath.Join("/run/idoris", "vpnd.sock") {
			t.Fatalf("listen %s", got)
		}
	})

	t.Run("runtime dir beats state directory for the socket", func(t *testing.T) {
		r3svcClearStateEnv(t, map[string]string{
			"STATE_DIRECTORY": state,
			"XDG_RUNTIME_DIR": "/run/idoris",
		})
		if got := DefaultListen(); got != "unix:"+filepath.Join("/run/idoris", "vpnd.sock") {
			t.Fatalf("listen %s", got)
		}
	})

	t.Run("explicit path beats state directory", func(t *testing.T) {
		r3svcClearStateEnv(t, map[string]string{"STATE_DIRECTORY": state})
		file, err := ResolveStateFile("/etc/idoris/custom-state.json")
		if err != nil {
			t.Fatal(err)
		}
		if file != "/etc/idoris/custom-state.json" {
			t.Fatalf("file %s", file)
		}
		dir, err := ResolveStateDir("/var/lib/custom-node")
		if err != nil {
			t.Fatal(err)
		}
		if dir != "/var/lib/custom-node" {
			t.Fatalf("dir %s", dir)
		}
		file, err = ResolveStateFile("  ")
		if err != nil {
			t.Fatal(err)
		}
		if file != filepath.Join(state, "vpnd-state.json") {
			t.Fatalf("default file %s", file)
		}
	})
}

func TestR3svcParseStateDirectory(t *testing.T) {
	got, err := parseStateDirectory("", "linux")
	if err != nil || got != "" {
		t.Fatalf("unset %q %v", got, err)
	}
	got, err = parseStateDirectory("  ", "linux")
	if err != nil || got != "" {
		t.Fatalf("blank %q %v", got, err)
	}
	got, err = parseStateDirectory("/var/lib/idoris:/var/lib/other", "linux")
	if err != nil || got != "/var/lib/idoris" {
		t.Fatalf("colon %q %v", got, err)
	}
	got, err = parseStateDirectory("/var/lib/idoris/", "linux")
	if err != nil || got != "/var/lib/idoris" {
		t.Fatalf("slash %q %v", got, err)
	}
	if _, err := parseStateDirectory("relative", "linux"); err == nil || !strings.Contains(err.Error(), "STATE_DIRECTORY") {
		t.Fatalf("relative %v", err)
	}
	got, err = parseStateDirectory(`C:\ProgramData\idoris`, "windows")
	if err != nil || got != `C:\ProgramData\idoris` {
		t.Fatalf("windows %q %v", got, err)
	}
	// A drive-letter colon is not systemd's list separator.
	got, err = parseStateDirectory(`C:\ProgramData\idoris\node`, "windows")
	if err != nil || got != `C:\ProgramData\idoris\node` {
		t.Fatalf("windows nested %q %v", got, err)
	}
	if _, err := parseStateDirectory("not-absolute", "windows"); err == nil || !strings.Contains(err.Error(), "STATE_DIRECTORY") {
		t.Fatalf("windows relative %v", err)
	}
}
