package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFileAtomicReplacesSymlinkWithoutFollowing(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	target := filepath.Join(dir, "secret")
	if err := os.Symlink(victim, target); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := WriteFileAtomic(target, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" { //nolint:gosec // test path
		t.Fatalf("symlink target was overwritten: %q", b)
	}
	if b, _ := os.ReadFile(target); string(b) != "token" { //nolint:gosec // test path
		t.Fatalf("secret not written: %q", b)
	}
	if st, _ := os.Lstat(target); st.Mode()&os.ModeSymlink != 0 {
		t.Fatal("path is still a symlink")
	}
}

func TestWriteFileAtomicModeAndNoLeftovers(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	if err := os.WriteFile(p, []byte("old"), 0o666); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o, want 600", st.Mode().Perm())
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("leftover files: %v", ents)
	}
}

func TestWriteFileAtomicMissingDirLeavesNothing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nope", "x")
	if err := WriteFileAtomic(p, []byte("x"), 0o600); err == nil {
		t.Fatal("expected error for a missing directory")
	}
}

func TestEnsurePrivateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix modes")
	}
	base := t.TempDir()
	d := filepath.Join(base, "a", "b")
	if err := EnsurePrivateDir(d); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(d); err != nil {
		t.Fatalf("second call: %v", err)
	}
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(loose); err == nil {
		t.Fatal("a group/other-writable directory must be refused")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(d, link); err != nil {
		t.Skip(err)
	}
	if err := EnsurePrivateDir(link); err == nil {
		t.Fatal("a symlinked directory must be refused")
	}
}
