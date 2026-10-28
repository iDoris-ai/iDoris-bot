//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR4CExecutableAncestors(t *testing.T) {
	base := t.TempDir()
	link := filepath.Join(base, "link")
	if err := os.Symlink(base, link); err != nil {
		t.Fatal(err)
	}
	err := validateExecutableAncestors(filepath.Join(link, "idoris", "idoris-vpnd"))
	if err == nil || !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}

	if os.Geteuid() != 0 {
		owned := filepath.Join(base, "owned")
		if err := os.Mkdir(owned, 0o755); err != nil {
			t.Fatal(err)
		}
		err = validateExecutableAncestors(filepath.Join(owned, "idoris-vpnd"))
		if err == nil || !strings.Contains(err.Error(), owned) || !strings.Contains(err.Error(), "uid") {
			t.Fatalf("owner: %v", err)
		}
		if os.Getenv("R4C_REQUIRE_ROOT") == "1" {
			t.Fatal("R4C_REQUIRE_ROOT=1 but this process is not root")
		}
		return
	}

	foreign := "/var/lib/r4c-exe-foreign"
	if err := os.RemoveAll(foreign); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(foreign) })
	if err := os.Chown(foreign, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	err = validateExecutableAncestors(filepath.Join(foreign, "idoris-vpnd"))
	if err == nil || !strings.Contains(err.Error(), foreign) || !strings.Contains(err.Error(), "uid 1000") {
		t.Fatalf("foreign owner: %v", err)
	}

	loose := "/var/lib/r4c-exe-loose"
	if err := os.RemoveAll(loose); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(loose) })
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	err = validateExecutableAncestors(filepath.Join(loose, "idoris-vpnd"))
	if err == nil || !strings.Contains(err.Error(), loose) || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("mode: %v", err)
	}

	goodRoot := "/var/lib/r4c-exe-good"
	if err := os.RemoveAll(goodRoot); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(goodRoot, "chain")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(goodRoot) })
	if err := validateExecutableAncestors(filepath.Join(good, "idoris", "idoris-vpnd")); err != nil {
		t.Fatal(err)
	}
}
