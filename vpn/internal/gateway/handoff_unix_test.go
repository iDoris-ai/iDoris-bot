//go:build unix

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR4WReadPlanHandoffRealStat(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := ReadPlanHandoff(path)
	if err != nil {
		t.Fatal(err)
	}
	if h.Symlink || !h.Regular || h.Mode.Perm() != 0o600 || h.DirWritable {
		t.Fatalf("stat %+v", h)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	h, err = ReadPlanHandoff(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPlanHandoff(h); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("mode: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "missing"), path); err != nil {
		t.Fatal(err)
	}
	h, err = ReadPlanHandoff(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPlanHandoff(h); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v %+v", err, h)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	h, err = ReadPlanHandoff(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPlanHandoff(h); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("directory: %v %+v", err, h)
	}
}
