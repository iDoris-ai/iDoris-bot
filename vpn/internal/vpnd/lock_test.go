package vpnd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/paths"
)

func TestEmbeddedControllerLockExcludesASecondDaemon(t *testing.T) {
	dir := t.TempDir()
	first, err := LockEmbedded(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LockEmbedded(dir)
	if err == nil || !strings.Contains(err.Error(), "another idoris-vpnd") {
		t.Fatalf("second daemon: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	third, err := LockEmbedded(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = third.Release()

	other, err := LockEmbedded(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_ = other.Release()
}

func TestSystemControllerLockFollowsTheSocket(t *testing.T) {
	dir := t.TempDir()
	a, err := lockSystemIn(dir, "/tmp/tailscaled.sock")
	if err != nil {
		t.Fatal(err)
	}
	_, err = lockSystemIn(dir, "/tmp/tailscaled.sock")
	if err == nil || !strings.Contains(err.Error(), "another idoris-vpnd") || !strings.Contains(err.Error(), "system") {
		t.Fatalf("same socket: %v", err)
	}
	other, err := lockSystemIn(dir, "/tmp/other.sock")
	if err != nil {
		t.Fatal(err)
	}
	if other.Path() == a.Path() {
		t.Fatal("different sockets share a lock file")
	}
	_ = other.Release()
	_ = a.Release()

	def, err := lockSystemIn(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = lockSystemIn(dir, "   ")
	if err == nil || !strings.Contains(err.Error(), "another idoris-vpnd") {
		t.Fatalf("empty socket must share the default lock: %v", err)
	}
	_, err = lockSystemIn(dir, paths.DefaultTailscaledSocket())
	if err == nil || !strings.Contains(err.Error(), "another idoris-vpnd") {
		t.Fatalf("explicit default socket must share the empty-socket lock: %v", err)
	}
	_ = def.Release()
}

func TestR3c2LockCanonicalIdentity(t *testing.T) {
	r3c2IsolateCache(t)
	stateA := filepath.Join(t.TempDir(), "state-a")
	stateB := filepath.Join(t.TempDir(), "state-b")
	t.Setenv("XDG_STATE_HOME", stateA)
	sock := filepath.Join(t.TempDir(), "tailscaled.sock")
	first, err := systemLockPath(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", stateB)
	second, err := systemLockPath(sock)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("XDG_STATE_HOME changed the lock path:\n%s\n%s", first, second)
	}
	if strings.Contains(first, filepath.Base(stateA)) || strings.Contains(first, filepath.Base(stateB)) {
		t.Fatalf("lock path is under the state home: %s", first)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(cache, "idoris", "locks")
	if filepath.Dir(first) != wantDir {
		t.Fatalf("lock dir %s, want %s", filepath.Dir(first), wantDir)
	}

	empty, err := systemLockPath("")
	if err != nil {
		t.Fatal(err)
	}
	named, err := systemLockPath(paths.DefaultTailscaledSocket())
	if err != nil {
		t.Fatal(err)
	}
	if empty != named {
		t.Fatalf("empty %s\nexplicit %s", empty, named)
	}

	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	viaLink, err := LockEmbedded(link)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LockEmbedded(real)
	if err == nil || !strings.Contains(err.Error(), "another idoris-vpnd") {
		t.Fatalf("symlink and target did not share a lock: %v", err)
	}
	if !strings.HasPrefix(viaLink.Path(), real) && viaLink.Path() != filepath.Join(canonicalizePath(real), "controller.lock") {
		t.Fatalf("lock path %s is not inside %s", viaLink.Path(), real)
	}
	_ = viaLink.Release()
}

func TestR3c2LockFileDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	precious := filepath.Join(dir, "precious")
	if err := os.WriteFile(precious, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, "controller.lock")
	if err := os.Symlink(precious, planted); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLock(planted, "embedded"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink lock: %v", err)
	}
	body, err := os.ReadFile(precious)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "keep" {
		t.Fatalf("precious file changed to %q", body)
	}
	st, err := os.Lstat(planted)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("planted symlink was replaced")
	}
}

func r3c2IsolateCache(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("USERPROFILE", home)
	t.Setenv("LocalAppData", filepath.Join(home, "local"))
}
