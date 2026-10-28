//go:build unix

package enroll

import (
	"os"
	"path/filepath"
	"testing"
)

// TestR4OListDoesNotCreateLock is the read path of O#9. A credential listing
// must not leave <config>.lock behind. A root listing used to create that
// file mode 0600, and the enrollment uid could not open it later.
func TestR4OListDoesNotCreateLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	hash := HashToken("r4o-list-token")
	raw := []byte("{\n  \"control_url\": \"https://vpn.example.org\",\n  \"tenants\": [\n    {\n      \"name\": \"acme\",\n      \"headscale_user_id\": \"1\",\n      \"token_hashes\": [\"" + hash + "\"]\n    }\n  ]\n}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := ListCredentials(path, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Fatalf("credentials: %+v", creds)
	}
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("list created %s.lock: %v", path, err)
	}
	if _, err := Revoke(path, "acme", hash[:8]); err == nil {
		t.Fatal("revoke of the only credential should refuse without allow-empty")
	}
	st, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatalf("writer did not create the lock: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode %o", st.Mode().Perm())
	}
}
