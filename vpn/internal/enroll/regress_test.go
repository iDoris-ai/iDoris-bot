package enroll

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

func TestConcurrentInviteKeepsEveryHash(t *testing.T) {
	path := writeTenantFile(t, 0o600)
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	var ok int
	var first error
	start := make(chan struct{})
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			if _, err := Invite(path, "acme", "", "https://enroll.example.org", "", false); err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			ok++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	if first != nil {
		t.Fatal(first)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.Tenants[0].TokenHashes); got != ok+1 {
		t.Fatalf("stored %d hashes after %d invites", got, ok)
	}
}

func TestRevokeUnknownEntryLeavesOtherHashes(t *testing.T) {
	h0 := HashToken("seed-token")
	h1 := HashToken("second-token")
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	body := "{\n  \"control_url\": \"https://vpn.example.org\",\n  \"tenants\": [\n    {\n      \"name\": \"acme\",\n      \"headscale_user_id\": \"1\",\n      \"token_hashes\": [\"" + h0 + "\", \"" + h1 + "\"]\n    },\n    {\n      \"name\": \"other\",\n      \"headscale_user_id\": \"2\",\n      \"token_hashes\": [\"" + HashToken("other-token") + "\"]\n    }\n  ]\n}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, path)
	// This prefix matches acme's first hash. A bug that treats an unknown
	// entry as index 0 would delete that hash and return success.
	if _, err := Revoke(path, "missing", h0[:8]); err == nil || !strings.Contains(err.Error(), "unknown entry") {
		t.Fatalf("unknown entry: %v", err)
	}
	if string(mustRead(t, path)) != string(before) {
		t.Fatal("unknown entry changed the file")
	}
}

func TestRevokePrefixLengthCaseAndHex(t *testing.T) {
	h0 := HashToken("seed-token")
	h1 := HashToken("second-token")
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	body := "{\n  \"control_url\": \"https://vpn.example.org\",\n  \"tenants\": [{\n    \"name\": \"acme\",\n    \"headscale_user_id\": \"1\",\n    \"token_hashes\": [\"" + h0 + "\", \"" + h1 + "\"]\n  }]\n}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, path)
	// Three hex digits uniquely match h0, and must still be rejected.
	if _, err := Revoke(path, "acme", h0[:3]); err == nil || !strings.Contains(err.Error(), "4 to 64") {
		t.Fatalf("short unique prefix: %v", err)
	}
	if string(mustRead(t, path)) != string(before) {
		t.Fatal("short prefix changed the file")
	}
	if _, err := Revoke(path, "acme", "zzzz"); err == nil || !strings.Contains(err.Error(), "hex") {
		t.Fatalf("non-hex: %v", err)
	}
	removed, err := Revoke(path, "acme", strings.ToUpper(h1[:6]))
	if err != nil {
		t.Fatal(err)
	}
	if removed != h1 {
		t.Fatalf("removed %s", removed)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tenants[0].TokenHashes) != 1 || cfg.Tenants[0].TokenHashes[0] == h1 {
		t.Fatalf("hashes %+v", cfg.Tenants[0].TokenHashes)
	}
}

func TestInviteRoundTripStillDecodes(t *testing.T) {
	path := writeTenantFile(t, 0o600)
	code, err := Invite(path, "acme", "office-gw", "https://enroll.example.org", "", false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := join.Decode(code, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Tenant != "acme" || got.Role != join.RoleGateway {
		t.Fatalf("%+v", got)
	}
}
