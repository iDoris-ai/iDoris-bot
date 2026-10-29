//go:build integration

package integration

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestR4WSudoApplyHonoursUserOwnedPlan runs the real binary as root inside a
// container against files created as uid 1000. A root apply must enable
// forwarding and must not reject the directory for being owned by that user.
func TestR4WSudoApplyHonoursUserOwnedPlan(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required")
	}
	mod := moduleRoot(t)
	bin := filepath.Join(t.TempDir(), "idoris-vpnd")
	build := exec.Command("go", "build", "-o", bin, "./cmd/idoris-vpnd")
	build.Dir = mod
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build linux binary: %v\n%s", err, out)
	}
	var id [4]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	name := "idoris-vpn-r4w-" + hex.EncodeToString(id[:])
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	run := exec.Command("docker", "run", "-i", "--name", name, "--user", "0",
		"--sysctl", "net.ipv4.ip_forward=1",
		"-v", bin+":/idoris-vpnd:ro",
		"alpine:3.20", "sh", "-s")
	run.Stdin = strings.NewReader(r4wHandoffScript)
	out, err := run.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "R4W_HANDOFF_OK") {
		t.Fatalf("docker apply: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ip-forward: enabled") {
		t.Fatalf("forwarding was not reached:\n%s", out)
	}
	t.Log(string(out))
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(wd) == "integration" {
		return filepath.Dir(wd)
	}
	return wd
}

const r4wHandoffScript = `
set -eu
adduser -D -u 1000 acme
adduser -D -u 1001 other
mkdir -p /home/acme/.idoris
chown 1000:1000 /home/acme /home/acme/.idoris
chmod 755 /home/acme
chmod 700 /home/acme/.idoris
PLAN=/home/acme/.idoris/gateway-plan.json
SYSCTL=/etc/sysctl.d/99-idoris-vpn.conf
write_plan() {
  printf '%s\n' '{"role":"gateway","routes":["10.1.2.0/24"],"mode":"auto","enroll_url":"https://enroll.example","token_file":"/home/acme/.idoris/enroll.token","config_path":"/home/acme/.idoris/vpn.json"}' > "$PLAN"
  chown 1000:1000 "$PLAN"
  chmod 600 "$PLAN"
}
expect_reject() {
  label=$1
  want=$2
  rm -f "$SYSCTL"
  out=$(SUDO_UID=1000 /idoris-vpnd gateway apply --plan "$PLAN" 2>&1 || true)
  printf '%s\n' "$out" | grep -q "$want" || { echo "FAIL $label: $out"; exit 1; }
  if [ -f "$SYSCTL" ]; then echo "FAIL $label wrote sysctl: $out"; exit 1; fi
  printf '%s\n' "$out" | grep -q "ip-forward: enabled" && { echo "FAIL $label enabled forward"; exit 1; }
  true
}
rm -f "$PLAN"
ln -s /etc/hostname "$PLAN"
expect_reject symlink symlink
rm -f "$PLAN"
write_plan
chmod 666 "$PLAN"
expect_reject mode 0600
write_plan
chown 1001:1001 "$PLAN"
expect_reject foreign "uid 1001"
write_plan
chmod 777 /home/acme/.idoris
expect_reject directory writable
chmod 700 /home/acme/.idoris
chown 1000:1000 /home/acme/.idoris "$PLAN"
rm -f "$SYSCTL" /home/acme/.idoris/vpn.json
before=$(cksum "$PLAN")
out=$(SUDO_UID=1000 /idoris-vpnd gateway apply --plan "$PLAN" 2>&1)
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q "ip-forward: enabled" || { echo "FAIL positive: $out"; exit 1; }
printf '%s\n' "$out" | grep -q "owned by uid" && { echo "FAIL positive rejected owner"; exit 1; }
[ -f "$SYSCTL" ] || { echo "FAIL sysctl drop-in missing"; exit 1; }
[ ! -f /home/acme/.idoris/vpn.json ] || { echo "FAIL root wrote the user config"; exit 1; }
after=$(cksum "$PLAN")
[ "$before" = "$after" ] || { echo "FAIL plan rewritten"; exit 1; }
owner=$(stat -c %u /home/acme/.idoris)
[ "$owner" = "1000" ] || { echo "FAIL dir owner $owner"; exit 1; }
echo R4W_HANDOFF_OK
`
