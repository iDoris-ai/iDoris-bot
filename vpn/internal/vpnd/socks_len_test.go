package vpnd

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR2GSOCKSCredLength(t *testing.T) {
	long := strings.Repeat("p", 256)
	okUser := strings.Repeat("u", 255)
	cases := []struct {
		name    string
		user    string
		pass    string
		wantErr bool
	}{
		{name: "255", user: okUser, pass: strings.Repeat("p", 255)},
		{name: "user 256", user: long, pass: "secret", wantErr: true},
		{name: "pass 256", user: "alice", pass: long, wantErr: true},
		{name: "empty user", user: "", pass: "secret", wantErr: true},
		{name: "empty pass", user: "alice", pass: "", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, pass, _, _, _, err := resolveSOCKSAuth(AccessOptions{SOCKS5User: tc.user, SOCKS5Password: tc.pass})
			if tc.wantErr {
				if err == nil {
					t.Fatal("accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if user != tc.user || pass != tc.pass {
				t.Fatalf("got %d %d", len(user), len(pass))
			}
		})
	}

	dir := t.TempDir()
	badFile := filepath.Join(dir, "bad.auth")
	if err := os.WriteFile(badFile, []byte("alice:"+long+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(badFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err := resolveSOCKSAuth(AccessOptions{SOCKS5AuthFile: badFile}); err == nil {
		t.Fatal("auth file accepted a 256-byte password")
	}
	goodFile := filepath.Join(dir, "good.auth")
	if err := os.WriteFile(goodFile, []byte("alice:"+strings.Repeat("p", 255)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(goodFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err := resolveSOCKSAuth(AccessOptions{SOCKS5AuthFile: goodFile}); err != nil {
		t.Fatal(err)
	}

	state := filepath.Join(dir, "state")
	user, pass, _, path, created, err := resolveSOCKSAuth(AccessOptions{StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	if !created || path != filepath.Join(state, "socks5.auth") || user != "idoris" || len(pass) != 64 {
		t.Fatalf("generated user %q pass %d created %v path %s", user, len(pass), created, path)
	}

	access, err := StartAccess(&net.Dialer{}, nil, "127.0.0.1:0", AccessOptions{SOCKS5User: "alice", SOCKS5Password: long}, nil)
	if err == nil || access != nil {
		if access != nil {
			_ = access.Close()
		}
		t.Fatal("StartAccess opened a listener for a 256-byte password")
	}
}
