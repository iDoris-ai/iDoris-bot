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

// r4cDebianBookworm is the linux image used for root-only checks.
// Pinned on 2026-10-28 from docker pull debian:bookworm (arm64).
const r4cDebianBookworm = "debian:bookworm@sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880"

// TestR4CRootLockNamespace runs the vpnd package test as root in Debian.
// Two processes with different STATE_DIRECTORY and XDG variables must share
// /var/lib/idoris/locks and exclude each other.
func TestR4CRootLockNamespace(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	bin := filepath.Join(t.TempDir(), "r4c-lock.test")
	build := exec.Command("go", "test", "-c", "-o", bin, "./internal/vpnd/")
	build.Dir = ".."
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build lock test: %v\n%s", err, out)
	}
	name := "idoris-vpn-r4c-lock-" + r3svcSuffix(t)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	out, err := exec.Command("docker", "run", "--rm", "--name", name, "--user", "0",
		"-e", "R4C_REQUIRE_ROOT=1",
		"-v", bin+":/lock.test:ro",
		r4cDebianBookworm,
		"/lock.test", "-test.count=1", "-test.v", "-test.run", "^TestR4CRootLockProcesses$",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("root lock namespace: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: TestR4CRootLockProcesses") {
		t.Fatalf("root lock output:\n%s", out)
	}
}
