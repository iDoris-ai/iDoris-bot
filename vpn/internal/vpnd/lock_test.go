package vpnd

import (
	"runtime"
	"strings"
	"testing"
)

func TestEmbeddedControllerLockExcludesASecondDaemon(t *testing.T) {
	dir := t.TempDir()
	first, err := LockEmbedded(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LockEmbedded(dir)
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Fatal(err)
		}
		_ = second.Release()
		_ = first.Release()
		return
	}
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
	same, err := lockSystemIn(dir, "/tmp/tailscaled.sock")
	if runtime.GOOS != "windows" {
		if err == nil || !strings.Contains(err.Error(), "another idoris-vpnd") || !strings.Contains(err.Error(), "system") {
			t.Fatalf("same socket: %v", err)
		}
	} else if same != nil {
		_ = same.Release()
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
	again, err := lockSystemIn(dir, "   ")
	if runtime.GOOS != "windows" && (err == nil || !strings.Contains(err.Error(), "another idoris-vpnd")) {
		t.Fatalf("empty socket must share the default lock: %v", err)
	}
	if again != nil {
		_ = again.Release()
	}
	_ = def.Release()
}
