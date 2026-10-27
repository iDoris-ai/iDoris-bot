//go:build unix

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMode(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func configWith(t *testing.T, dir string, fields map[string]string, mode os.FileMode) string {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vpn.json")
	writeMode(t, path, string(raw), mode)
	return path
}

func TestInstallSecretsModesAndSymlink(t *testing.T) {
	dir := t.TempDir()
	tight := filepath.Join(dir, "tight")
	loose := filepath.Join(dir, "loose")
	writeMode(t, tight, "secret\n", 0o600)
	writeMode(t, loose, "secret\n", 0o644)

	ok := configWith(t, dir, map[string]string{
		"enroll_token_file": tight,
		"auth_key_file":     tight,
		"socks5_auth_file":  tight,
	}, 0o644)
	if err := checkInstallSecrets(ok); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		fields map[string]string
		mode   os.FileMode
	}{
		{name: "token file", fields: map[string]string{"enroll_token_file": loose}, mode: 0o644},
		{name: "auth key file", fields: map[string]string{"auth_key_file": loose}, mode: 0o644},
		{name: "socks5 auth file", fields: map[string]string{"socks5_auth_file": loose}, mode: 0o644},
		{name: "inline enroll token", fields: map[string]string{"enroll_token": "idv1_inline"}, mode: 0o644},
		{name: "inline auth key", fields: map[string]string{"auth_key": "hskey"}, mode: 0o644},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub := t.TempDir()
			path := configWith(t, sub, tc.fields, tc.mode)
			err := checkInstallSecrets(path)
			if err == nil || !strings.Contains(err.Error(), "chmod 600") {
				t.Fatalf("err %v", err)
			}
			for _, args := range [][]string{
				{"install", "--config", path},
				{"install", "--system", "--config", path},
			} {
				err = serviceCmd(args)
				if err == nil || !strings.Contains(err.Error(), "chmod 600") {
					t.Fatalf("%v: %v", args, err)
				}
			}
		})
	}

	inline := configWith(t, t.TempDir(), map[string]string{"enroll_token": "idv1_inline", "auth_key": "hskey"}, 0o600)
	if err := checkInstallSecrets(inline); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "token-link")
	if err := os.Symlink(tight, link); err != nil {
		t.Fatal(err)
	}
	linked := configWith(t, t.TempDir(), map[string]string{"enroll_token_file": link}, 0o644)
	err := checkInstallSecrets(linked)
	if err == nil || !strings.Contains(err.Error(), "chmod 600") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}
	err = serviceCmd([]string{"install", "--config", linked})
	if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("install symlink: %v", err)
	}
}
