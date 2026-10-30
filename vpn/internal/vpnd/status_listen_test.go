package vpnd

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestR3c2StatusRegularFileIsKept(t *testing.T) {
	r3c2IsolateCache(t)
	dir := shortSockDir(t)
	path := filepath.Join(dir, "s")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("unix:" + path)
	if err == nil {
		_ = ln.Close()
		t.Fatal("regular file was replaced")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("%v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "keep" {
		t.Fatalf("file changed to %q", b)
	}
}

func TestR3c2StatusSymlinkIsKept(t *testing.T) {
	r3c2IsolateCache(t)
	dir := shortSockDir(t)
	target := filepath.Join(dir, "keep")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "sock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("unix:" + link)
	if err == nil {
		_ = ln.Close()
		t.Fatal("symlink was replaced")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("%v", err)
	}
	st, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was removed")
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "keep" {
		t.Fatalf("target %q err %v", b, err)
	}
}

func TestR3c2StatusStaleSocketIsReplaced(t *testing.T) {
	r3c2IsolateCache(t)
	dir := shortSockDir(t)
	path := filepath.Join(dir, "s")
	r3c2StaleSocket(t, path)
	ln, err := Listen("unix:" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestR3c2StatusLiveSocketIsNotTaken(t *testing.T) {
	r3c2IsolateCache(t)
	dir := shortSockDir(t)
	path := filepath.Join(dir, "s")
	first, err := Listen("unix:" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Listen("unix:" + path)
	if err == nil {
		_ = second.Close()
		t.Fatal("second listener took the live socket")
	}
	if !strings.Contains(err.Error(), "another idoris-vpnd") {
		t.Fatalf("%v", err)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestR3c2StatusDeleteWaitsForTheLock(t *testing.T) {
	r3c2IsolateCache(t)
	dir := shortSockDir(t)
	path := filepath.Join(dir, "s")
	r3c2StaleSocket(t, path)
	lockPath, err := statusLockPath(path)
	if err != nil {
		t.Fatal(err)
	}
	held, err := acquireLock(lockPath, "status")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	ln, err := Listen("unix:" + path)
	if err == nil {
		_ = ln.Close()
		t.Fatal("listen deleted a socket without the status lock")
	}
	if !strings.Contains(err.Error(), "another idoris-vpnd") {
		t.Fatalf("%v", err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSocket == 0 {
		t.Fatal("stale socket was removed before the lock was held")
	}
}

func TestR3c2StatusRefusesUnconfirmedOwner(t *testing.T) {
	r3c2IsolateCache(t)
	prev := statusFileOwner
	t.Cleanup(func() { statusFileOwner = prev })
	dir := shortSockDir(t)

	t.Run("other uid", func(t *testing.T) {
		path := filepath.Join(dir, "other")
		r3c2StaleSocket(t, path)
		statusFileOwner = func(os.FileInfo) (int, bool) { return os.Getuid() + 1, true }
		ln, err := Listen("unix:" + path)
		if err == nil {
			_ = ln.Close()
			t.Fatal("removed another uid's socket")
		}
		if !strings.Contains(err.Error(), "owned by uid") {
			t.Fatalf("%v", err)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("windows policy", func(t *testing.T) {
		path := filepath.Join(dir, "win")
		r3c2StaleSocket(t, path)
		statusFileOwner = func(os.FileInfo) (int, bool) { return 0, false }
		ln, err := Listen("unix:" + path)
		if err == nil {
			_ = ln.Close()
			t.Fatal("removed a socket whose owner could not be confirmed")
		}
		if !strings.Contains(err.Error(), "cannot be confirmed") {
			t.Fatalf("%v", err)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatal(err)
		}
	})
}

func TestR3c2StatusTCPDoesNotLock(t *testing.T) {
	ln, err := Listen("tcp:127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, ok := ln.(*statusListener); ok {
		t.Fatal("tcp listener holds the unix status lock")
	}
}

func r3c2StaleSocket(t *testing.T, path string) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		_ = syscall.Close(fd)
		t.Fatal(err)
	}
	if err := syscall.Close(fd); err != nil {
		t.Fatal(err)
	}
}
