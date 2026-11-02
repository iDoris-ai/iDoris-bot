//go:build unix

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestR4CAcceptInstallSecretModes(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok")
	if err := os.WriteFile(ok, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := acceptInstallSecret(ok); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_UID", strconv.Itoa(os.Getuid()))
	err := acceptInstallSecret(loose)
	if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("loose: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(ok, link); err != nil {
		t.Fatal(err)
	}
	err = acceptInstallSecret(link)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}
}

func TestR4CStageSystemSecretsRewritesPath(t *testing.T) {
	prev := chownSystemRoot
	chownSystemRoot = func(string) error { return nil }
	t.Cleanup(func() { chownSystemRoot = prev })

	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "state")
	raw := []byte(fmt.Sprintf("{\n  \"enroll_token_file\": %q,\n  \"mode\": \"system\"\n}\n", token))
	out, err := stageSystemSecrets(raw, dest)
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal(out, &probe); err != nil {
		t.Fatal(err)
	}
	got, _ := probe["enroll_token_file"].(string)
	want := filepath.Join(dest, "enroll_token")
	if got != want {
		t.Fatalf("rewritten path %q", got)
	}
	st, err := os.Stat(want)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("staged mode %o", st.Mode().Perm())
	}
	body, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "secret-token\n" {
		t.Fatalf("staged body %q", body)
	}

	missing := filepath.Join(dir, "missing-key")
	_, err = stageSystemSecrets([]byte(fmt.Sprintf(`{"enroll_token_file":%q,"auth_key_file":%q}`, token, missing)), dest)
	if err == nil {
		t.Fatal("missing auth key was staged")
	}
	if _, statErr := os.Stat(filepath.Join(dest, "enroll_token")); statErr == nil {
		t.Fatal("partial enroll_token copy was left behind")
	}
}

func TestR4CSudoSecretStaging(t *testing.T) {
	if os.Getenv("R4C_SECRET_CHILD") == "1" {
		err := acceptInstallSecret(os.Getenv("R4C_SECRET_PATH"))
		if err == nil || !strings.Contains(err.Error(), "owned by uid") {
			t.Fatalf("non-root accepted a root-owned secret with SUDO_UID set: %v", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		if os.Getenv("R4C_REQUIRE_ROOT") == "1" {
			t.Fatal("R4C_REQUIRE_ROOT=1 but this process is not root")
		}
		t.Skip("sudo secret staging needs root")
	}

	dir := "/var/lib/r4c-secret"
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(token, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(token, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SUDO_UID", "")
	if err := acceptInstallSecret(token); err == nil || !strings.Contains(err.Error(), "SUDO_UID") {
		t.Fatalf("unset SUDO_UID: %v", err)
	}
	t.Setenv("SUDO_UID", "1001")
	if err := acceptInstallSecret(token); err == nil || !strings.Contains(err.Error(), "1001") {
		t.Fatalf("wrong SUDO_UID: %v", err)
	}
	t.Setenv("SUDO_UID", "1000")
	if err := acceptInstallSecret(token); err != nil {
		t.Fatal(err)
	}

	staged, err := stageSystemSecrets([]byte(fmt.Sprintf(`{"enroll_token_file":%q}`, token)), dir)
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal(staged, &probe); err != nil {
		t.Fatal(err)
	}
	got, _ := probe["enroll_token_file"].(string)
	if got != filepath.Join(dir, "enroll_token") {
		t.Fatalf("installed path %q", got)
	}
	info, err := os.Lstat(got)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("staged mode %o", info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		t.Fatalf("staged owner %#v", info.Sys())
	}

	rootCopy := filepath.Join(dir, "root-token")
	if err := os.WriteFile(rootCopy, []byte("root\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_UID", "")
	if err := acceptInstallSecret(rootCopy); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^TestR4CSudoSecretStaging$", "-test.count=1", "-test.v")
	cmd.Env = []string{"R4C_SECRET_CHILD=1", "R4C_SECRET_PATH=" + rootCopy, "SUDO_UID=1000", "PATH=" + os.Getenv("PATH")}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("non-root child: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: TestR4CSudoSecretStaging") {
		t.Fatalf("child output:\n%s", out)
	}
}
