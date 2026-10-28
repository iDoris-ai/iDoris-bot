//go:build unix

package enroll

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
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

// TestR4OBootstrapRevokeNotResurrected is the O#1 concurrency proof for the
// bootstrap writer. Python loads a snapshot under the shared flock, holds it,
// and appends a tenant. Revoke of a hash that was in that snapshot must run
// after the write, so the hash stays gone and the append still lands.
func TestR4OBootstrapRevokeNotResurrected(t *testing.T) {
	keep := HashToken("r4o-keep")
	stolen := HashToken("r4o-stolen")
	extra := HashToken("r4o-extra")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	r4oWriteTwoHashConfig(t, path, "office", keep, stolen)
	spec := filepath.Join(dir, "spec")
	specText := "extra|2|||10m|" + extra + "|member\n"
	if err := os.WriteFile(spec, []byte(specText), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "hold.py")
	body := "import sys\n" +
		"sys.path.insert(0, sys.argv[1])\n" +
		"from enroll_lock import locked_update, merge_bootstrap_rows\n" +
		"path, spec_path = sys.argv[2], sys.argv[3]\n" +
		"spec = open(spec_path, encoding='utf-8').read()\n" +
		"def mutate(cfg):\n" +
		"    cfg = merge_bootstrap_rows(cfg, 'https://vpn.example.org', spec)\n" +
		"    cfg['control_url'] = 'https://r4o.example'\n" +
		"    return cfg\n" +
		"locked_update(path, mutate)\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", script, r4oDeployVPN(t), path, spec)
	waited := r4oRevokeDuringPython(t, cmd, path, "office", stolen)
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControlURL != "https://r4o.example" {
		t.Fatalf("control_url %q", cfg.ControlURL)
	}
	got := r4oHashes(t, cfg, "office")
	if len(got) != 1 || got[0] != keep {
		t.Fatalf("office hashes = %v, want only keep", got)
	}
	if _, ok := r4oHashSet(r4oHashes(t, cfg, "extra"))[extra]; !ok {
		t.Fatalf("extra tenant missing %s in %+v", extra, cfg.Tenants)
	}
	if waited < 800*time.Millisecond {
		t.Fatalf("revoke did not wait for the config lock: %s", waited)
	}
}

// TestR4OPolicyReconcileRevokeNotResurrected is the same proof through
// policy.py reconcile-enroll, which is the other unlocked writer O#1 named.
func TestR4OPolicyReconcileRevokeNotResurrected(t *testing.T) {
	keep := HashToken("r4o-keep-policy")
	stolen := HashToken("r4o-stolen-policy")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	r4oWriteTwoHashConfig(t, path, "office-gateway", keep, stolen)
	state := filepath.Join(dir, "managed.json")
	raw := []byte(`{"version":1,"admins":["admin"],"orgs":[{"name":"office","lan_cidrs":["192.168.9.0/24"],"public_cidrs":[]}],"tailnet_admin":false}` + "\n")
	if err := os.WriteFile(state, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	deploy := r4oDeployVPN(t)
	cmd := exec.Command("python3", filepath.Join(deploy, "policy.py"), "reconcile-enroll",
		"--state", state, "--config", path)
	waited := r4oRevokeDuringPython(t, cmd, path, "office-gateway", stolen)
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	idx := entryIndex(cfg, "office-gateway")
	if idx < 0 {
		t.Fatal("missing office-gateway")
	}
	if len(cfg.Tenants[idx].LANCIDRs) != 1 || cfg.Tenants[idx].LANCIDRs[0] != "192.168.9.0/24" {
		t.Fatalf("lan_cidrs %+v", cfg.Tenants[idx].LANCIDRs)
	}
	got := cfg.Tenants[idx].TokenHashes
	if len(got) != 1 || got[0] != keep {
		t.Fatalf("hashes = %v, want only keep", got)
	}
	if waited < 800*time.Millisecond {
		t.Fatalf("revoke did not wait for the config lock: %s", waited)
	}
}

func r4oDeployVPN(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "deploy", "vpn"))
	if _, err := os.Stat(filepath.Join(dir, "enroll_lock.py")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func r4oWriteTwoHashConfig(t *testing.T, path, name, keep, stolen string) {
	t.Helper()
	raw := "{\n  \"control_url\": \"https://vpn.example.org\",\n  \"tenants\": [\n    {\n      \"name\": \"" + name + "\",\n      \"headscale_user_id\": \"1\",\n      \"role\": \"gateway\",\n      \"token_hashes\": [\"" + keep + "\", \"" + stolen + "\"]\n    }\n  ]\n}\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
}

func r4oHashes(t *testing.T, cfg *Config, entry string) []string {
	t.Helper()
	idx := entryIndex(cfg, entry)
	if idx < 0 {
		t.Fatalf("missing entry %s", entry)
	}
	return append([]string(nil), cfg.Tenants[idx].TokenHashes...)
}

func r4oHashSet(hashes []string) map[string]struct{} {
	out := make(map[string]struct{}, len(hashes))
	for _, h := range hashes {
		out[h] = struct{}{}
	}
	return out
}

// r4oRevokeDuringPython starts cmd, waits until it has the config lock, and
// revokes stolen. It returns how long revoke blocked. The command must sleep
// in IDORIS_ENROLL_LOCK_HOLD_SECONDS after creating IDORIS_ENROLL_LOCK_SIGNAL.
func r4oRevokeDuringPython(t *testing.T, cmd *exec.Cmd, path, entry, stolen string) time.Duration {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is required")
	}
	signal := filepath.Join(t.TempDir(), "held")
	cmd.Env = append(os.Environ(),
		"IDORIS_ENROLL_LOCK_HOLD_SECONDS=1.2",
		"IDORIS_ENROLL_LOCK_SIGNAL="+signal,
	)
	var stdout, stderr []byte
	outBuf := &r4oBuf{}
	errBuf := &r4oBuf{}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(signal); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("python exited before taking the lock: %v\n%s\n%s", err, outBuf.String(), errBuf.String())
		default:
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("timed out waiting for the lock signal\n%s\n%s", outBuf.String(), errBuf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	start := time.Now()
	if _, err := Revoke(path, entry, stolen[:8]); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("revoke: %v\n%s\n%s", err, outBuf.String(), errBuf.String())
	}
	waited := time.Since(start)
	select {
	case err := <-done:
		stdout, stderr = outBuf.Bytes(), errBuf.Bytes()
		if err != nil {
			t.Fatalf("python: %v\n%s\n%s", err, stdout, stderr)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("python did not exit")
	}
	return waited
}

// r4oBuf collects process output. exec copies stdout from another goroutine.
type r4oBuf struct {
	mu sync.Mutex
	b  []byte
}

func (b *r4oBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.b = append(b.b, p...)
	return len(p), nil
}

func (b *r4oBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.b)
}

func (b *r4oBuf) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.b...)
}
