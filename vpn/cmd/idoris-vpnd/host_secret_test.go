package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestR3W2OSHostReplacesLooseFileAndSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix modes")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "vpn.json")
	if err := os.WriteFile(cfg, []byte("old"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg, 0o666); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "enroll.token")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	h := osHost{}
	if err := h.WriteFile(cfg, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %o", st.Mode().Perm())
	}
	if err := h.WriteFile(link, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "keep" {
		t.Fatalf("symlink target %q %v", b, err)
	}
	lst, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		t.Fatal("token path is still a symlink")
	}
	if lst.Mode().Perm() != 0o600 {
		t.Fatalf("token mode %o", lst.Mode().Perm())
	}
	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := h.MkdirAll(loose, 0o700); err == nil {
		t.Fatal("group-writable directory was accepted")
	}
}
