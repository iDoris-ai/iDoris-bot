//go:build unix

package enroll

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestR5ORootKeepsOwner runs as root inside a Linux container. invite and
// revoke must leave the config and the lock owned by the runtime uid.
func TestR5ORootKeepsOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := r5oOwnerDir(t, "r5o-owner-")
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	writeR5OConfig(t, path)
	if err := os.Chown(dir, 65532, 65532); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65532, 65532); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}

	if _, err := ListCredentials(path, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("list created a lock: %v", err)
	}

	if _, err := Invite(path, "acme", "", "https://enroll.example.org", "lab", false); err != nil {
		t.Fatal(err)
	}
	assertR5OOwner(t, path, 65532, 65532, 0o640)
	assertR5OOwner(t, path+".bak", 65532, 65532, 0o640)
	assertR5OOwner(t, path+".lock", 65532, 65532, 0o600)

	if _, err := Invite(path, "acme", "", "https://enroll.example.org", "lab2", false); err != nil {
		t.Fatal(err)
	}
	if _, err := RevokeLabel(path, "acme", "lab"); err != nil {
		t.Fatal(err)
	}
	assertR5OOwner(t, path, 65532, 65532, 0o640)
	assertR5OOwner(t, path+".bak", 65532, 65532, 0o640)
	assertR5OOwner(t, path+".lock", 65532, 65532, 0o600)

	out := runR5OChild(t, 65532, 65532, "^TestR5ORuntimeMutates$", path, "R5O_OWNER_LABEL=from-runtime")
	if !strings.Contains(out, "PASS: TestR5ORuntimeMutates") {
		t.Fatalf("runtime output:\n%s", out)
	}
	assertR5OOwner(t, path, 65532, 65532, 0o640)
	assertR5OOwner(t, path+".bak", 65532, 65532, 0o640)
	assertR5OOwner(t, path+".lock", 65532, 65532, 0o600)
}

// TestR5ORootForeignRefuse spawns a uid that does not own the config.
// invite must fail before it creates a lock or rewrites the file.
func TestR5ORootForeignRefuse(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := r5oOwnerDir(t, "r5o-foreign-")
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	writeR5OConfig(t, path)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65532, 65532); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}

	out := runR5OChild(t, 65531, 65531, "^TestR5OForeignRefuse$", path)
	if !strings.Contains(out, "PASS: TestR5OForeignRefuse") {
		t.Fatalf("foreign output:\n%s", out)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("foreign invite changed the config")
	}
	if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("foreign invite created a lock: %v", err)
	}
	if _, err := os.Lstat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("foreign invite created a backup: %v", err)
	}
}

func TestR5ORuntimeMutates(t *testing.T) {
	path := os.Getenv("R5O_OWNER_CONFIG")
	if path == "" || os.Geteuid() == 0 {
		t.Skip("spawned as the enrollment uid")
	}
	label := os.Getenv("R5O_OWNER_LABEL")
	if label == "" {
		label = "from-runtime"
	}
	if _, err := Invite(path, "acme", "", "https://enroll.example.org", label, false); err != nil {
		t.Fatal(err)
	}
}

func TestR5OForeignRefuse(t *testing.T) {
	path := os.Getenv("R5O_OWNER_CONFIG")
	if path == "" || os.Geteuid() == 0 {
		t.Skip("spawned as a uid that does not own the config")
	}
	_, err := Invite(path, "acme", "", "https://enroll.example.org", "nope", false)
	if err == nil {
		t.Fatal("invite succeeded for a foreign owner")
	}
	msg := err.Error()
	if !strings.Contains(msg, "sudo -u \\#65532") || !strings.Contains(msg, path) {
		t.Fatalf("error %q", msg)
	}
	if _, statErr := os.Lstat(path + ".lock"); !os.IsNotExist(statErr) {
		t.Fatalf("lock created: %v", statErr)
	}
}

func r5oOwnerDir(t *testing.T, pattern string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", pattern)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func writeR5OConfig(t *testing.T, path string) {
	t.Helper()
	raw := []byte("{\n  \"control_url\": \"https://vpn.example.org\",\n  \"tenants\": [\n    {\n      \"name\": \"acme\",\n      \"headscale_user_id\": \"1\",\n      \"token_hashes\": []\n    }\n  ]\n}\n")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
}

func assertR5OOwner(t *testing.T, path string, uid, gid int, mode os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		t.Fatalf("%s has no stat owner", path)
	}
	if int(sys.Uid) != uid || int(sys.Gid) != gid || st.Mode().Perm() != mode {
		t.Fatalf("%s uid=%d gid=%d mode=%o, want uid=%d gid=%d mode=%o", path, sys.Uid, sys.Gid, st.Mode().Perm(), uid, gid, mode)
	}
}

func runR5OChild(t *testing.T, uid, gid uint32, run, path string, extra ...string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run="+run, "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), append([]string{"R5O_OWNER_CONFIG=" + path}, extra...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child uid %d: %v\n%s", uid, err, out)
	}
	return string(out)
}
