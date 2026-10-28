//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestR5CSystemdUserServiceRestarts installs the per-user unit twice inside
// the same systemd container the machine-service harness uses. The second
// install must change MainPID. If this host cannot start a systemd --user
// manager, the test skips and says so; the command sequence is covered by
// TestR5CUserServiceRestartsWhenActive.
func TestR5CSystemdUserServiceRestarts(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed; cannot run systemd --user in Docker")
	}
	buildDaemon(t)

	suffix := r3svcSuffix(t)
	name := "idoris-vpn-r5c-user-" + suffix
	image := "idoris-vpn-r5c-user-" + suffix + ":bookworm"
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

	r3svcMust(t, name, "useradd", "--create-home", "--shell", "/bin/bash", "idoris")
	uid := strings.TrimSpace(r3svcMust(t, name, "id", "-u", "idoris"))
	if uid == "" || uid == "0" {
		t.Fatalf("idoris uid %q", uid)
	}
	// systemctl talks to the private socket. loginctl needs the system bus,
	// which a tmpfs /run plus this image often does not provide. Start the
	// user manager directly, and only then fall back to linger.
	_, _ = r3svcOutput(name, "systemctl", "start", "dbus.socket", "systemd-logind.service")
	startOut, startErr := r3svcOutput(name, "systemctl", "start", "user@"+uid+".service")
	if startErr != nil {
		lingerOut, lingerErr := r3svcOutput(name, "loginctl", "enable-linger", "idoris")
		if lingerErr != nil && !r5cWaitUserManager(t, name, uid) {
			bus, _ := r3svcOutput(name, "sh", "-c", "ls -ld /run /run/dbus /run/systemd 2>&1; echo ---; systemctl is-active dbus.socket systemd-logind.service user@"+uid+".service 2>&1")
			t.Skip("systemd --user is not feasible in this container\n" +
				"systemctl start user@: " + startErr.Error() + "\n" + startOut +
				"loginctl enable-linger: " + lingerErr.Error() + "\n" + lingerOut +
				bus)
		}
	}
	if !r5cWaitUserManager(t, name, uid) {
		out, _ := r3svcOutput(name, "systemctl", "status", "user@"+uid+".service", "--no-pager")
		t.Skip("systemd --user is not feasible in this container (user@" + uid + " did not become active):\n" + startOut + out)
	}

	runtimeDir := "/run/user/" + uid
	env := []string{
		"HOME=/home/idoris",
		"USER=idoris",
		"XDG_RUNTIME_DIR=" + runtimeDir,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtimeDir + "/bus",
	}
	cfgDir := t.TempDir()
	writeCfg := func(url, destName string) {
		t.Helper()
		body := []byte(`{"control_url":"` + url + `","auth_key":"hskey-lab"}` + "\n")
		hostPath := filepath.Join(cfgDir, destName)
		if err := os.WriteFile(hostPath, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("docker", "cp", hostPath, name+":/home/idoris/"+destName).CombinedOutput(); err != nil {
			t.Fatalf("docker cp %s: %v\n%s", destName, err, out)
		}
		r3svcMust(t, name, "chown", uid+":"+uid, "/home/idoris/"+destName)
		r3svcMust(t, name, "chmod", "600", "/home/idoris/"+destName)
	}
	writeCfg("https://vpn.example.org", "vpn.json")

	bin := filepath.Join("..", "bin", "idoris-vpnd-linux")
	if out, err := exec.Command("docker", "cp", bin, name+":/tmp/idoris-vpnd").CombinedOutput(); err != nil {
		t.Fatalf("docker cp binary: %v\n%s", err, out)
	}
	r3svcMust(t, name, "chmod", "755", "/tmp/idoris-vpnd")

	install := func(config string) {
		t.Helper()
		out, err := r5cUserExec(name, env, "/tmp/idoris-vpnd", "service", "install", "--config", config)
		if err != nil {
			if r5cUserManagerUnavailable(out) {
				t.Skip("systemd --user is not feasible in this container (service install): " + out)
			}
			t.Fatalf("service install %s: %v\n%s", config, err, strings.ReplaceAll(out, "hskey-lab", "[redacted]"))
		}
	}
	install("/home/idoris/vpn.json")
	pid := r5cUserMainPID(t, name, env)
	if pid == "" || pid == "0" {
		t.Fatalf("MainPID %q after first install", pid)
	}

	writeCfg("https://vpn.example.org/r5c", "vpn.json")
	install("/home/idoris/vpn.json")
	newPID := r5cUserMainPID(t, name, env)
	if newPID == "" || newPID == "0" || newPID == pid {
		unit, _ := r3svcOutput(name, "cat", "/home/idoris/.config/systemd/user/idoris-vpnd.service")
		t.Fatalf("reinstall MainPID %s, was %s\nunit:\n%s", newPID, pid, unit)
	}
	unit := r3svcMust(t, name, "cat", "/home/idoris/.config/systemd/user/idoris-vpnd.service")
	if !strings.Contains(unit, "/home/idoris/vpn.json") {
		t.Fatalf("user unit\n%s", unit)
	}
}

func r5cWaitUserManager(t *testing.T, name, uid string) bool {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		out, err := r3svcOutput(name, "systemctl", "is-active", "user@"+uid+".service")
		if err == nil && strings.TrimSpace(out) == "active" {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

func r5cUserExec(name string, env []string, args ...string) (string, error) {
	argv := []string{"exec", "-u", "idoris"}
	for _, e := range env {
		argv = append(argv, "-e", e)
	}
	argv = append(argv, name)
	argv = append(argv, args...)
	cmd := exec.Command("docker", argv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func r5cUserMainPID(t *testing.T, name string, env []string) string {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out, err := r5cUserExec(name, env, "systemctl", "--user", "show", "-p", "MainPID", "--value", "idoris-vpnd.service")
		last = strings.TrimSpace(out)
		active, aerr := r5cUserExec(name, env, "systemctl", "--user", "is-active", "idoris-vpnd.service")
		if err == nil && aerr == nil && strings.TrimSpace(active) == "active" && last != "" && last != "0" {
			return last
		}
		if err != nil && r5cUserManagerUnavailable(out) {
			t.Skip("systemd --user is not feasible in this container (show MainPID): " + out)
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("user service MainPID %q", last)
	return ""
}

func r5cUserManagerUnavailable(msg string) bool {
	s := strings.ToLower(msg)
	for _, n := range []string{
		"failed to connect to bus",
		"not been booted",
		"no medium found",
		"linger",
	} {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
