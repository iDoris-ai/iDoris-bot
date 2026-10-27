//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestR3svcSystemdMachineService installs the real linux binary as a systemd
// system service inside Debian bookworm and checks that it stays active
// without HOME. The unit's StateDirectory= sets STATE_DIRECTORY=/var/lib/idoris.
// macOS and Windows use the same variable in rendered units; this test does
// not boot those operating systems.
func TestR3svcSystemdMachineService(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed; cannot run systemd in Docker")
	}
	buildDaemon(t)

	suffix := r3svcSuffix(t)
	name := "idoris-vpn-r3svc-" + suffix
	image := "idoris-vpn-r3svc-systemd-" + suffix + ":bookworm"
	t.Cleanup(func() { r3svcTearDown(t, name, image) })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(r3svcDockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "build", "-t", image, dir).CombinedOutput(); err != nil {
		r3svcSkipDocker(t, "docker build", out, err)
	}
	run := exec.Command("docker", "run", "-d",
		"--name", name,
		"--privileged",
		"--cgroupns=host",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
		"--tmpfs", "/run",
		"--tmpfs", "/run/lock",
		image,
	)
	if out, err := run.CombinedOutput(); err != nil {
		r3svcSkipOrFatal(t, "docker run", out, err)
	}
	r3svcWaitSystemd(t, name)

	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "vpn.json")
	cfgBody := []byte(`{"control_url":"https://vpn.example.org","auth_key":"hskey-lab","mode":"system"}` + "\n")
	if err := os.WriteFile(cfgPath, cfgBody, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join("..", "bin", "idoris-vpnd-linux")
	if out, err := exec.Command("docker", "cp", bin, name+":/tmp/idoris-vpnd").CombinedOutput(); err != nil {
		t.Fatalf("docker cp binary: %v\n%s", err, out)
	}
	r3svcMust(t, name, "mkdir", "-p", "/etc/idoris")
	if out, err := exec.Command("docker", "cp", cfgPath, name+":/etc/idoris/vpn.json").CombinedOutput(); err != nil {
		t.Fatalf("docker cp config: %v\n%s", err, out)
	}
	r3svcMust(t, name, "chmod", "755", "/tmp/idoris-vpnd")
	// docker cp keeps the host uid. The secret check requires the file owner
	// to be the daemon user, which is root inside this container.
	r3svcMust(t, name, "chown", "0:0", "/etc/idoris/vpn.json")
	r3svcMust(t, name, "chmod", "600", "/etc/idoris/vpn.json")

	// PATH must include systemctl. Do not use env -i.
	r3svcMust(t, name, "/tmp/idoris-vpnd", "service", "install", "--system", "--config", "/etc/idoris/vpn.json")
	r3svcMust(t, name, "systemctl", "daemon-reload")
	if out, err := r3svcOutput(name, "systemctl", "start", "idoris-vpnd"); err != nil {
		t.Fatalf("systemctl start: %v\n%s", err, out)
	}
	r3svcWaitActive(t, name)

	restarts := r3svcShow(t, name, "NRestarts")
	if restarts != "0" {
		t.Fatalf("NRestarts=%s before the hold window\n%s", restarts, r3svcJournal(name))
	}
	time.Sleep(30 * time.Second)
	if got := r3svcActive(t, name); got != "active" {
		t.Fatalf("is-active %s after 30s\n%s", got, r3svcJournal(name))
	}
	if got := r3svcShow(t, name, "NRestarts"); got != "0" {
		t.Fatalf("NRestarts=%s after 30s\n%s", got, r3svcJournal(name))
	}
	journal := r3svcJournal(name)
	if strings.Contains(journal, "$HOME is not defined") || strings.Contains(journal, "hskey") {
		t.Fatalf("journal:\n%s", strings.ReplaceAll(journal, "hskey-lab", "[redacted]"))
	}

	env := r3svcEnviron(t, name)
	if !strings.Contains(env, "STATE_DIRECTORY=/var/lib/idoris") {
		t.Fatalf("service environ missing STATE_DIRECTORY=/var/lib/idoris\n%s", env)
	}
	if !strings.Contains(env, "XDG_RUNTIME_DIR=/run/idoris") {
		t.Fatalf("service environ missing XDG_RUNTIME_DIR=/run/idoris\n%s", env)
	}
	if r3svcHasEnv(env, "HOME") {
		t.Fatalf("service has HOME set:\n%s", env)
	}

	status := r3svcMustEnv(t, name, []string{"XDG_RUNTIME_DIR=/run/idoris", "HOME="}, "/usr/local/lib/idoris/idoris-vpnd", "status", "--json")
	if !strings.Contains(status, `"phase"`) {
		t.Fatalf("status API:\n%s", status)
	}

	modes := r3svcMust(t, name, "sh", "-c", "stat -c '%a %n' /var/lib/idoris /var/lib/idoris/vpnd-state.json /var/lib/idoris/locks /run/idoris /run/idoris/vpnd.sock /var/lib/idoris/locks/*")
	r3svcWantMode(t, modes, "750", "/var/lib/idoris")
	r3svcWantMode(t, modes, "600", "/var/lib/idoris/vpnd-state.json")
	r3svcWantMode(t, modes, "700", "/var/lib/idoris/locks")
	r3svcWantMode(t, modes, "750", "/run/idoris")
	r3svcWantMode(t, modes, "600", "/run/idoris/vpnd.sock")
	if !strings.Contains(modes, "/var/lib/idoris/locks/") {
		t.Fatalf("no controller lock file:\n%s", modes)
	}
	for _, line := range strings.Split(strings.TrimSpace(modes), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.HasPrefix(fields[1], "/var/lib/idoris/locks/") && fields[0] != "600" {
			t.Fatalf("lock mode %s", line)
		}
	}
	stateFile := r3svcMust(t, name, "cat", "/var/lib/idoris/vpnd-state.json")
	if !strings.Contains(stateFile, "https://vpn.example.org") || strings.Contains(stateFile, "hskey") {
		t.Fatalf("state file %s", strings.ReplaceAll(stateFile, "hskey-lab", "[redacted]"))
	}

	if out, err := r3svcOutput(name, "systemctl", "restart", "idoris-vpnd"); err != nil {
		t.Fatalf("systemctl restart: %v\n%s", err, out)
	}
	r3svcWaitActive(t, name)
	if got := r3svcShow(t, name, "NRestarts"); got != "0" {
		t.Fatalf("NRestarts=%s after restart\n%s", got, r3svcJournal(name))
	}

	// Same config and the same STATE_DIRECTORY systemd injected. A different
	// listen address so the refusal is the controller lock, not the status socket.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	second := exec.CommandContext(ctx, "docker", "exec",
		"-e", "STATE_DIRECTORY=/var/lib/idoris",
		"-e", "HOME=",
		name,
		"/usr/local/lib/idoris/idoris-vpnd", "run",
		"--config", "/etc/idoris/vpn.json",
		"--listen", "unix:/tmp/r3svc-second.sock",
	)
	out, err := second.CombinedOutput()
	text := string(out)
	if err == nil || !strings.Contains(text, "another idoris-vpnd") || !strings.Contains(text, "system backend") {
		t.Fatalf("second instance: %v\n%s", err, text)
	}
	if got := r3svcActive(t, name); got != "active" {
		t.Fatalf("service left %s after the second instance", got)
	}
}

const r3svcDockerfile = `FROM debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv procps iproute2 ca-certificates
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
`

func r3svcSuffix(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

func r3svcTearDown(t *testing.T, name, image string) {
	t.Helper()
	if t.Failed() {
		t.Logf("journal:\n%s", strings.ReplaceAll(r3svcJournal(name), "hskey-lab", "[redacted]"))
	}
	_ = exec.Command("docker", "rm", "-f", name).Run()
	_ = exec.Command("docker", "rmi", "-f", image).Run()
}

func r3svcSkipDocker(t *testing.T, what string, out []byte, err error) {
	t.Helper()
	msg := what + ": " + err.Error() + "\n" + string(out)
	s := strings.ToLower(msg)
	if strings.Contains(s, "permission denied") || strings.Contains(s, "cannot connect to the docker daemon") || strings.Contains(s, "is the docker daemon running") {
		t.Skip("this host cannot run systemd in Docker (no --privileged or cgroup support): " + msg)
	}
	t.Fatal(msg)
}

func r3svcSkipOrFatal(t *testing.T, what string, out []byte, err error) {
	t.Helper()
	msg := what + ": " + err.Error() + "\n" + string(out)
	if r3svcSystemdUnavailable(msg) {
		t.Skip("this host cannot run systemd in Docker (no --privileged or cgroup support): " + msg)
	}
	t.Fatal(msg)
}

func r3svcSystemdUnavailable(msg string) bool {
	s := strings.ToLower(msg)
	for _, n := range []string{
		"permission denied",
		"operation not permitted",
		"not permitted",
		"cgroup",
		"privileged",
		"has not been booted with systemd",
		"failed to connect to bus",
	} {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func r3svcWaitSystemd(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out, err := r3svcOutput(name, "systemctl", "is-system-running")
		last = strings.TrimSpace(out)
		if err == nil && last == "running" {
			return
		}
		state, _ := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", name).Output()
		if strings.TrimSpace(string(state)) != "running" {
			logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
			msg := last + "\n" + string(logs)
			if r3svcSystemdUnavailable(msg) {
				t.Skip("this host cannot run systemd in Docker (no --privileged or cgroup support): " + msg)
			}
			t.Fatalf("systemd container is not running: %s", msg)
		}
		if r3svcSystemdUnavailable(last) {
			t.Skip("this host cannot run systemd in Docker (no --privileged or cgroup support): " + last)
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("systemd did not reach running (last %q)", last)
}

func r3svcOutput(name string, args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"exec", name}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func r3svcMust(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := r3svcOutput(name, args...)
	if err != nil {
		t.Fatalf("docker exec %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func r3svcMustEnv(t *testing.T, name string, env []string, args ...string) string {
	t.Helper()
	argv := []string{"exec"}
	for _, e := range env {
		argv = append(argv, "-e", e)
	}
	argv = append(argv, name)
	argv = append(argv, args...)
	cmd := exec.Command("docker", argv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func r3svcWaitActive(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		last = strings.TrimSpace(r3svcActive(t, name))
		if last == "active" {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("idoris-vpnd did not stay active (last %q)\n%s", last, r3svcJournal(name))
}

func r3svcActive(t *testing.T, name string) string {
	t.Helper()
	out, _ := r3svcOutput(name, "systemctl", "is-active", "idoris-vpnd")
	return strings.TrimSpace(out)
}

func r3svcShow(t *testing.T, name, prop string) string {
	t.Helper()
	out := r3svcMust(t, name, "systemctl", "show", "-p", prop, "--value", "idoris-vpnd")
	return strings.TrimSpace(out)
}

func r3svcJournal(name string) string {
	out, err := r3svcOutput(name, "journalctl", "-u", "idoris-vpnd", "--no-pager")
	if err != nil {
		return fmt.Sprintf("journalctl: %v\n%s", err, out)
	}
	return out
}

func r3svcEnviron(t *testing.T, name string) string {
	t.Helper()
	pid := r3svcShow(t, name, "MainPID")
	if pid == "" || pid == "0" {
		t.Fatalf("MainPID %q", pid)
	}
	for _, r := range pid {
		if r < '0' || r > '9' {
			t.Fatalf("MainPID %q", pid)
		}
	}
	raw := r3svcMust(t, name, "cat", "/proc/"+pid+"/environ")
	return strings.ReplaceAll(raw, "\x00", "\n")
}

func r3svcHasEnv(env, key string) bool {
	prefix := key + "="
	for _, line := range strings.Split(env, "\n") {
		if strings.HasPrefix(line, prefix) && strings.TrimPrefix(line, prefix) != "" {
			return true
		}
	}
	return false
}

func r3svcWantMode(t *testing.T, listing, mode, path string) {
	t.Helper()
	want := mode + " " + path
	if !strings.Contains(listing, want) {
		t.Fatalf("missing %s in\n%s", want, listing)
	}
}
