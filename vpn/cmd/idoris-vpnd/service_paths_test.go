package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR2GSystemdPathsProvisioned(t *testing.T) {
	cfg := []byte(`{
	  "listen": "unix:/var/lib/idoris/status/vpnd.sock",
	  "state_dir": "/var/lib/idoris/node",
	  "socks5_listen": "unix:/var/lib/idoris/socks",
	  "forwards": [{"listen": "unix:/run/idoris/nested/fwd.sock", "target": "10.0.0.1:1"}]
	}`)
	unit, err := renderSystemdSystemUnit("/usr/local/lib/idoris/idoris-vpnd", "/etc/idoris/vpn.json", cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"StateDirectory=idoris",
		"StateDirectoryMode=0750",
		"RuntimeDirectory=idoris",
		"RuntimeDirectoryMode=0750",
		"Environment=XDG_RUNTIME_DIR=/run/idoris",
		"ReadWritePaths=/var/lib/idoris",
		"ReadWritePaths=/run/idoris",
		"ReadWritePaths=/var/lib/idoris/node",
		"ReadWritePaths=/var/lib/idoris/status",
	} {
		if !strings.Contains(unit, line+"\n") {
			t.Fatalf("unit missing %s\n%s", line, unit)
		}
	}
	if strings.Contains(unit, "ReadWritePaths=/run/idoris/nested") {
		t.Fatalf("nested /run path must not be an allowlist entry\n%s", unit)
	}
	if strings.Contains(unit, "IDORIS_VPN_STATE_DIR") {
		t.Fatalf("unit overrides state_dir\n%s", unit)
	}

	root := t.TempDir()
	prev := chownSystemRoot
	var owned []string
	chownSystemRoot = func(p string) error {
		owned = append(owned, p)
		return nil
	}
	t.Cleanup(func() { chownSystemRoot = prev })

	if err := provisionSystemPaths(root, cfg); err != nil {
		t.Fatal(err)
	}
	var listed int
	for _, line := range strings.Split(unit, "\n") {
		p, ok := strings.CutPrefix(line, "ReadWritePaths=")
		if !ok {
			continue
		}
		listed++
		dest := filepath.Join(root, strings.TrimPrefix(p, "/"))
		st, err := os.Stat(dest)
		if err != nil {
			t.Fatalf("installer did not create %s: %v", p, err)
		}
		if !st.IsDir() || st.Mode().Perm() != 0o750 {
			t.Fatalf("%s mode %o", p, st.Mode().Perm())
		}
		if !containsPath(owned, dest) {
			t.Fatalf("chown missing for %s in %v", dest, owned)
		}
	}
	if listed != 4 {
		t.Fatalf("ReadWritePaths count %d\n%s", listed, unit)
	}

	custom := []byte(`{"socks5_listen":"unix:/run/custom/s.sock","listen":"unix:/run/idoris/vpnd.sock"}`)
	paths, err := systemReadWritePaths(custom)
	if err != nil {
		t.Fatal(err)
	}
	state, runtime := systemdManagedDirs(paths)
	if strings.Join(state, " ") != "idoris" || strings.Join(runtime, " ") != "idoris custom" {
		t.Fatalf("managed state %v runtime %v paths %v", state, runtime, paths)
	}
	for _, p := range paths {
		if strings.HasPrefix(p, "/run/idoris/") {
			t.Fatalf("nested runtime path listed: %v", paths)
		}
	}
}
