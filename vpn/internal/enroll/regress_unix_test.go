//go:build unix

package enroll

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestInviteKeepsInodeThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "enroll.json")
	body := "{\n  \"control_url\": \"https://vpn.example.org\",\n  \"tenants\": [{\n    \"name\": \"acme\",\n    \"headscale_user_id\": \"1\",\n    \"token_hashes\": [\"" + HashToken("seed-token") + "\"],\n    \"role\": \"gateway\",\n    \"lan_cidrs\": [\"10.251.73.10/32\"]\n  }]\n}\n"
	if err := os.WriteFile(target, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	before := inodeOf(t, target)
	if _, err := Invite(link, "acme", "", "https://enroll.example.org", "", false); err != nil {
		t.Fatal(err)
	}
	if got := inodeOf(t, target); got != before {
		t.Fatalf("inode changed %d -> %d", before, got)
	}
	st, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("path is no longer a symlink")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	cfg, err := LoadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tenants[0].TokenHashes) != 2 {
		t.Fatalf("target was not updated through the symlink: %+v", cfg.Tenants[0].TokenHashes)
	}
	if _, err := os.Stat(link + ".bak"); err != nil {
		t.Fatal(err)
	}
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		t.Fatal("no stat")
	}
	return sys.Ino
}
