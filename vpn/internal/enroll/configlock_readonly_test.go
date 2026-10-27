//go:build unix

package enroll

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A read-only mount of the config (a backup bundle, restore-drill) must still
// list credentials, while a writer must refuse because it cannot take the lock.
func TestLeadReadOnlyConfigListsButDoesNotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	hash := HashToken("lead-readonly-token")
	raw := []byte("{\n  \"control_url\": \"https://vpn.example.org\",\n  \"tenants\": [\n    {\n      \"name\": \"acme\",\n      \"headscale_user_id\": \"1\",\n      \"token_hashes\": [\"" + hash + "\"]\n    }\n  ]\n}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // test needs a read-only directory it can still read
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restore so TempDir cleanup works

	creds, err := ListCredentials(path, "acme")
	if err != nil {
		t.Fatalf("ListCredentials on a read-only directory: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("credentials: %+v", creds)
	}
	err = updateConfig(path, func(*Config) error { return nil })
	if !errors.Is(err, errConfigLockUnavailable) {
		t.Fatalf("a writer must fail when the lock is unavailable, got %v", err)
	}
}
