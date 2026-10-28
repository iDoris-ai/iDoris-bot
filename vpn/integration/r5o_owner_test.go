//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestR5OConfigOwner checks invite and revoke ownership inside Linux.
// Docker Desktop bind mounts do not preserve this, so the files live on the
// container filesystem and the test binary is only mounted to execute.
func TestR5OConfigOwner(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	bin := filepath.Join(t.TempDir(), "r5o-owner.test")
	build := exec.Command("go", "test", "-c", "-o", bin, "./internal/enroll/")
	build.Dir = ".."
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build owner test: %v\n%s", err, out)
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	name := "idoris-vpn-r5o-owner-" + r3svcSuffix(t)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	out, err := exec.Command("docker", "run", "--rm", "--name", name, "--user", "0",
		"-v", bin+":/owner.test:ro",
		r4cDebianBookworm,
		"/owner.test", "-test.count=1", "-test.v", "-test.run", "^TestR5ORoot",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("config owner: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "--- PASS: TestR5ORootKeepsOwner") || !strings.Contains(text, "--- PASS: TestR5ORootForeignRefuse") {
		t.Fatalf("config owner output:\n%s", text)
	}
}
