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

// TestR4CServiceRootProofs runs the machine-install checks that need a real
// root process: executable ancestor ownership and sudo secret staging.
// icacls and schtasks are not executed here.
func TestR4CServiceRootProofs(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	bin := filepath.Join(t.TempDir(), "r4c-service.test")
	build := exec.Command("go", "test", "-c", "-o", bin, "./cmd/idoris-vpnd/")
	build.Dir = ".."
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build service test: %v\n%s", err, out)
	}
	name := "idoris-vpn-r4c-svc-" + r3svcSuffix(t)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	out, err := exec.Command("docker", "run", "--rm", "--name", name, "--user", "0",
		"-e", "R4C_REQUIRE_ROOT=1",
		"-v", bin+":/service.test:ro",
		r4cDebianBookworm,
		"/service.test", "-test.count=1", "-test.v", "-test.run", "^(TestR4CExecutableAncestors|TestR4CSudoSecretStaging)$",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("service root proofs: %v\n%s", err, out)
	}
	text := string(out)
	for _, pass := range []string{"TestR4CExecutableAncestors", "TestR4CSudoSecretStaging"} {
		if !strings.Contains(text, "--- PASS: "+pass) {
			t.Fatalf("missing %s\n%s", pass, text)
		}
	}
}
