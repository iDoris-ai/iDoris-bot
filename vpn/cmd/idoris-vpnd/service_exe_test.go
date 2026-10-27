package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR2GProtectedExecutableCopy(t *testing.T) {
	root := t.TempDir()
	srcDir := filepath.Join(root, "Downloads")
	if err := os.MkdirAll(srcDir, 0o777); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(srcDir, "idoris-vpnd")
	payload := []byte("r2g-vpnd-binary")
	if err := os.WriteFile(src, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(srcDir, 0o777); err != nil {
		t.Fatal(err)
	}
	destDir := filepath.Join(root, "usr", "local", "lib", "idoris")
	dest := filepath.Join(destDir, "idoris-vpnd")

	prev := chownSystemRoot
	var owned []string
	chownSystemRoot = func(p string) error {
		owned = append(owned, p)
		return nil
	}
	t.Cleanup(func() { chownSystemRoot = prev })

	if err := copyProtectedExecutable(src, destDir, dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload %q", got)
	}
	st, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("binary mode %o", st.Mode().Perm())
	}
	dst, err := os.Stat(destDir)
	if err != nil {
		t.Fatal(err)
	}
	if dst.Mode().Perm() != 0o755 {
		t.Fatalf("dir mode %o", dst.Mode().Perm())
	}
	if !containsPath(owned, destDir) || !containsPath(owned, dest) {
		t.Fatalf("chown calls %v", owned)
	}
	info, err := os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("installed path is a symlink")
	}

	unit, err := renderSystemdSystemUnit(dest, "/etc/idoris/vpn.json", []byte(`{"state_dir":"/var/lib/idoris"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(unit, src) {
		t.Fatalf("unit points at the user-writable source:\n%s", unit)
	}
	if !strings.Contains(unit, "ExecStart="+dest+" run --config /etc/idoris/vpn.json") {
		t.Fatalf("unit does not run the copy:\n%s", unit)
	}
	plist := renderLaunchdPlist(systemLibExe, "/etc/idoris/vpn.json", "/var/log/idoris")
	if !strings.Contains(plist, "<string>"+systemLibExe+"</string>") || strings.Contains(plist, src) {
		t.Fatalf("plist %s", plist)
	}

	if err := removeProtectedExecutable(dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("copy still present: %v", err)
	}
	if _, err := os.Stat(destDir); err != nil {
		t.Fatal(err)
	}
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}
