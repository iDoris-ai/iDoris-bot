//go:build unix

package enroll

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestR2GConcurrentRevokeNotLost proves an invite that has already read the
// config cannot write that stale copy over a revoke. The invite child pauses
// inside the locked read-modify-write; the revoke child runs during the pause.
// Without the lock the invite saves the pre-revoke snapshot and the removed
// hash comes back.
func TestR2GConcurrentRevokeNotLost(t *testing.T) {
	if os.Getenv("R2G_CRED_CHILD") != "" {
		r2gCredChild(t)
		return
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	stolen := HashToken("r2g-stolen-token")
	seed := HashToken("r2g-seed-token")
	raw := []byte("{\n  \"control_url\": \"https://vpn.example.org\",\n  \"tenants\": [\n    {\n      \"name\": \"acme\",\n      \"headscale_user_id\": \"1\",\n      \"token_hashes\": [\"" + seed + "\", \"" + stolen + "\"]\n    }\n  ]\n}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	signal := filepath.Join(dir, "invite-loaded")
	invite := exec.Command(os.Args[0], "-test.run=^TestR2GConcurrentRevokeNotLost$")
	invite.Env = append(os.Environ(),
		"R2G_CRED_CHILD=invite",
		"R2G_CRED_PATH="+path,
		"R2G_CRED_SIGNAL="+signal,
	)
	var inviteBuf bytes.Buffer
	invite.Stdout = &inviteBuf
	invite.Stderr = &inviteBuf
	if err := invite.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(signal); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = invite.Process.Kill()
			_ = invite.Wait()
			t.Fatalf("invite child did not reach the locked section\n%s", inviteBuf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	revoke := exec.Command(os.Args[0], "-test.run=^TestR2GConcurrentRevokeNotLost$")
	revoke.Env = append(os.Environ(),
		"R2G_CRED_CHILD=revoke",
		"R2G_CRED_PATH="+path,
		"R2G_CRED_PREFIX="+stolen[:8],
	)
	revokeOut, err := revoke.CombinedOutput()
	if err != nil {
		_ = invite.Process.Kill()
		t.Fatalf("revoke child: %v\n%s", err, revokeOut)
	}
	if err := invite.Wait(); err != nil {
		t.Fatalf("invite child: %v\n%s", err, inviteBuf.String())
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hashes := cfg.Tenants[0].TokenHashes
	for _, h := range hashes {
		if h == stolen {
			t.Fatalf("revoked credential was resurrected: %+v", hashes)
		}
	}
	if len(hashes) != 2 || hashes[0] != seed {
		t.Fatalf("hashes %+v", hashes)
	}
	st, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode %o", st.Mode().Perm())
	}
}

func r2gCredChild(t *testing.T) {
	t.Helper()
	path := os.Getenv("R2G_CRED_PATH")
	switch os.Getenv("R2G_CRED_CHILD") {
	case "invite":
		rmwAfterLoad = func() {
			if err := os.WriteFile(os.Getenv("R2G_CRED_SIGNAL"), []byte("1"), 0o600); err != nil {
				t.Fatal(err)
			}
			time.Sleep(400 * time.Millisecond)
		}
		if _, err := Invite(path, "acme", "", "https://enroll.example.org", "r2g-fresh", false); err != nil {
			t.Fatal(err)
		}
	case "revoke":
		if _, err := Revoke(path, "acme", os.Getenv("R2G_CRED_PREFIX")); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown child %q", os.Getenv("R2G_CRED_CHILD"))
	}
}
