//go:build unix

package enroll

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

func writeHashes(t *testing.T, mode os.FileMode, hashes []string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("{\n  \"control_url\": \"https://vpn.example.org\",\n  \"tenants\": [{\n    \"name\": \"acme\",\n    \"headscale_user_id\": \"1\",\n    \"token_hashes\": [")
	for i, h := range hashes {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(`"` + h + `"`)
	}
	b.WriteString("],\n    \"role\": \"gateway\",\n    \"lan_cidrs\": [\"10.251.73.10/32\"]\n  }]\n}\n")
	dir := t.TempDir()
	path := filepath.Join(dir, "enroll.json")
	if err := os.WriteFile(path, []byte(b.String()), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func configInode(t *testing.T, path string) uint64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		t.Fatal("no stat")
	}
	return sys.Ino
}

func TestInviteRoundTripKeepsInodeModeAndBak(t *testing.T) {
	path := writeHashes(t, 0o640, []string{HashToken("seed-token")})
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := configInode(t, path)
	code, err := Invite(path, "acme", "office-gw", "https://enroll.example.org", false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := join.Decode(code, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Token == "" || got.Tenant != "acme" || got.Role != join.RoleGateway || got.HostnameHint != "office-gw" {
		t.Fatalf("%+v", got)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), got.Token) {
		t.Fatal("config contains the plaintext token")
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tenants[0].TokenHashes) != 2 || cfg.Tenants[0].TokenHashes[1] != HashToken(got.Token) {
		t.Fatalf("hashes %+v", cfg.Tenants[0].TokenHashes)
	}
	if configInode(t, path) != before {
		t.Fatal("inode changed")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bak, original) {
		t.Fatal("bak is not the previous bytes")
	}
	bst, err := os.Stat(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if bst.Mode().Perm() != 0o640 {
		t.Fatalf("bak mode %o", bst.Mode().Perm())
	}
	lst, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if lst.Mode().Perm()&0o077 != 0 {
		t.Fatalf("lock mode %o", lst.Mode().Perm())
	}
}

func TestInviteThroughSymlinkSharesLock(t *testing.T) {
	path := writeHashes(t, 0o640, []string{HashToken("seed-token")})
	link := filepath.Join(filepath.Dir(path), "alias.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	before := configInode(t, path)
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	afterTruncate = func() {
		once.Do(func() { close(started) })
		<-release
	}
	t.Cleanup(func() { afterTruncate = nil })
	inviteErr := make(chan error, 1)
	go func() {
		_, err := Invite(link, "acme", "", "https://enroll.example.org", false)
		inviteErr <- err
	}()
	<-started
	raw, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(raw)) != 0 {
		t.Fatalf("truncate window not open: %q %v", raw, err)
	}
	if _, err := os.Lstat(link + ".lock"); !os.IsNotExist(err) {
		t.Fatal("alias took its own lock file")
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	linkSt, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if linkSt.Mode()&os.ModeSymlink == 0 {
		t.Fatal("alias is no longer a symlink")
	}
	second := make(chan error, 1)
	go func() {
		_, err := Invite(path, "acme", "", "https://enroll.example.org", false)
		second <- err
	}()
	readDone := make(chan error, 1)
	go func() {
		_, err := ReadFileLocked(path)
		readDone <- err
	}()
	select {
	case err := <-second:
		t.Fatalf("second invite did not wait: %v", err)
	case err := <-readDone:
		t.Fatalf("locked read observed the truncate window: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-inviteErr; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	if configInode(t, path) != before {
		t.Fatal("inode changed through the symlink")
	}
	if _, err := os.Stat(link + ".bak"); !os.IsNotExist(err) {
		t.Fatal("bak was written beside the alias")
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tenants[0].TokenHashes) != 3 {
		t.Fatalf("hashes %+v", cfg.Tenants[0].TokenHashes)
	}
}

func TestWriteFailureRestoresBytes(t *testing.T) {
	path := writeHashes(t, 0o640, []string{HashToken("seed-token")})
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := configInode(t, path)
	failDiskWrite = func() error { return errors.New("injected") }
	t.Cleanup(func() { failDiskWrite = nil })
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveFile(path, cfg); err == nil {
		t.Fatal("expected injected write error")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("restored %q", got)
	}
	if configInode(t, path) != before {
		t.Fatal("restore replaced the inode")
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bak, original) {
		t.Fatal("bak changed on a failed write")
	}
}

func TestEmptyFileRestoresBak(t *testing.T) {
	path := writeHashes(t, 0o640, []string{HashToken("seed-token")})
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", original, 0o600); err != nil {
		t.Fatal(err)
	}
	before := configInode(t, path)
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tenants[0].Name != "acme" || len(cfg.Tenants[0].TokenHashes) != 1 {
		t.Fatalf("%+v", cfg.Tenants[0])
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("empty file was not restored from bak")
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bak, original) {
		t.Fatal("restore rewrote bak")
	}
	if configInode(t, path) != before {
		t.Fatal("restore replaced the inode")
	}
	locked, err := ReadFileLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(locked, original) {
		t.Fatal("locked read did not return the restored bytes")
	}
}

func TestEmptyFileWithUnparsedBakStaysEmpty(t *testing.T) {
	path := writeHashes(t, 0o640, []string{HashToken("seed-token")})
	if err := os.WriteFile(path+".bak", []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("empty file with an unparsed bak loaded")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("unparsed bak was written onto the live file")
	}
}

func TestUnknownFieldIsNotReplacedFromBak(t *testing.T) {
	path := writeHashes(t, 0o640, []string{HashToken("seed-token")})
	if _, err := Invite(path, "acme", "", "https://enroll.example.org", false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["operator_typo"] = true
	edited, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	edited = append(edited, '\n')
	if err := os.WriteFile(path, edited, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("unknown field was accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, edited) {
		t.Fatal("reload overwrote the operator edit")
	}
	locked, err := ReadFileLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(locked, edited) {
		t.Fatal("locked read overwrote the operator edit")
	}
}

func TestRevokeThenTruncationDoesNotRestoreHash(t *testing.T) {
	h0 := HashToken("seed-token")
	h1 := HashToken("second-token")
	path := writeHashes(t, 0o640, []string{h0, h1})
	if _, err := Revoke(path, "acme", h0[:8]); err != nil {
		t.Fatal(err)
	}
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(live, []byte(h0)) {
		t.Fatal("revoke left the hash in the live file")
	}
	trunc := []byte("{")
	if err := os.WriteFile(path, trunc, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("truncated file loaded")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, trunc) {
		t.Fatal("truncation was replaced from bak")
	}
	if bytes.Contains(got, []byte(h0)) {
		t.Fatal("revoked hash returned to the live file")
	}
	locked, err := ReadFileLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(locked, trunc) {
		t.Fatal("locked read restored bak over the truncation")
	}
}

func TestTwentyInvitesKeepEveryHash(t *testing.T) {
	path := writeHashes(t, 0o600, []string{HashToken("seed-token")})
	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	var first error
	start := make(chan struct{})
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			<-start
			if _, err := Invite(path, "acme", "", "https://enroll.example.org", false); err != nil {
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

func TestConcurrentRevokeDoesNotResurrect(t *testing.T) {
	h0 := HashToken("seed-token")
	h1 := HashToken("second-token")
	for round := range 40 {
		path := writeHashes(t, 0o600, []string{h0, h1})
		var wg sync.WaitGroup
		start := make(chan struct{})
		errCh := make(chan error, 9)
		wg.Add(9)
		for range 8 {
			go func() {
				defer wg.Done()
				<-start
				if _, err := Invite(path, "acme", "", "https://enroll.example.org", false); err != nil {
					errCh <- err
				}
			}()
		}
		go func() {
			defer wg.Done()
			<-start
			if _, err := Revoke(path, "acme", h0[:8]); err != nil {
				errCh <- err
			}
		}()
		close(start)
		wg.Wait()
		close(errCh)
		for err := range errCh {
			t.Fatalf("round %d: %v", round, err)
		}
		cfg, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		hashes := cfg.Tenants[0].TokenHashes
		if len(hashes) != 9 {
			t.Fatalf("round %d: got %d hashes", round, len(hashes))
		}
		for _, h := range hashes {
			if strings.EqualFold(h, h0) {
				t.Fatalf("round %d: revoked hash resurrected", round)
			}
		}
	}
}

func TestRevokeRemovesOnlyTheMatchingHash(t *testing.T) {
	h0 := HashToken("seed-token")
	h1 := HashToken("second-token")
	path := writeHashes(t, 0o600, []string{h0, h1})
	removed, err := Revoke(path, "acme", strings.ToUpper(h0[:8]))
	if err != nil {
		t.Fatal(err)
	}
	if removed != h0 {
		t.Fatalf("removed %s", removed)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tenants[0].TokenHashes) != 1 || cfg.Tenants[0].TokenHashes[0] != h1 {
		t.Fatalf("%+v", cfg.Tenants[0].TokenHashes)
	}
}

func TestShorterRewriteDropsTrailingBytes(t *testing.T) {
	path := writeHashes(t, 0o640, []string{HashToken("seed-token")})
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Tenants[0].Role = ""
	cfg.Tenants[0].LANCIDRs = nil
	if err := SaveFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tenants[0].Role != "" || len(got.Tenants[0].LANCIDRs) != 0 {
		t.Fatalf("%+v", got.Tenants[0])
	}
}

func TestSaveFileHoldsLockAcrossTruncate(t *testing.T) {
	path := writeHashes(t, 0o600, []string{HashToken("seed-token")})
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ControlURL = "https://other.example.org"
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	afterTruncate = func() {
		once.Do(func() { close(started) })
		<-release
	}
	t.Cleanup(func() { afterTruncate = nil })
	saveErr := make(chan error, 1)
	go func() { saveErr <- SaveFile(path, cfg) }()
	<-started
	readDone := make(chan error, 1)
	go func() {
		b, err := ReadFileLocked(path)
		if err != nil {
			readDone <- err
			return
		}
		if !bytes.Contains(b, []byte("https://other.example.org")) {
			readDone <- errors.New("locked read returned the pre-truncate bytes")
			return
		}
		readDone <- nil
	}()
	select {
	case err := <-readDone:
		t.Fatalf("locked read did not wait for SaveFile: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-saveErr; err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentSaveFileStaysParseable(t *testing.T) {
	path := writeHashes(t, 0o600, []string{HashToken("seed-token")})
	base, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	alt := *base
	alt.ControlURL = "https://other.example.org"
	alt.Tenants = append([]Tenant(nil), base.Tenants...)
	for round := range 40 {
		var wg sync.WaitGroup
		wg.Add(8)
		for i := range 8 {
			cfg := base
			if i%2 == 1 {
				cfg = &alt
			}
			go func() {
				defer wg.Done()
				_ = SaveFile(path, cfg)
			}()
		}
		wg.Wait()
		got, err := LoadFile(path)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if got.ControlURL != base.ControlURL && got.ControlURL != alt.ControlURL {
			t.Fatalf("round %d: torn url %s", round, got.ControlURL)
		}
	}
}

// TestReadOnlyDirectoryStillLoads is the published compose case: the enroll
// service bind is a single config file and the process cannot create a sibling
// lock. ReadFileLocked still returns the file bytes and leaves no .lock behind.
// A writable directory keeps the exclusive lock; see TestSaveFileHoldsLockAcrossTruncate.
func TestReadOnlyDirectoryStillLoads(t *testing.T) {
	path := writeHashes(t, 0o640, []string{HashToken("seed-token")})
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	probe := filepath.Join(dir, ".probe-lock")
	pf, perr := os.OpenFile(probe, os.O_CREATE|os.O_RDWR, 0o600)
	if perr == nil {
		_ = pf.Close()
		_ = os.Remove(probe)
		if !remountDirReadOnly(t, dir) {
			t.Skip("mode 0555 did not block create, and a read-only mount is unavailable")
		}
	}

	got, err := ReadFileLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("bytes = %q", got)
	}
	if _, statErr := os.Stat(path + ".lock"); !os.IsNotExist(statErr) {
		t.Fatalf("lock file: %v", statErr)
	}
}

// remountDirReadOnly bind-mounts dir onto itself and remounts it read-only.
// Root ignores a 0555 directory mode, which is how the enroll CI job runs.
// Returns false when this host cannot build that mount.
func remountDirReadOnly(t *testing.T, dir string) bool {
	t.Helper()
	if runtime.GOOS != "linux" {
		return false
	}
	if exec.Command("mount", "--bind", dir, dir).Run() != nil {
		return false
	}
	t.Cleanup(func() { _ = exec.Command("umount", dir).Run() })
	if exec.Command("mount", "-o", "remount,bind,ro", dir).Run() != nil {
		return false
	}
	probe := filepath.Join(dir, ".probe-lock")
	pf, err := os.OpenFile(probe, os.O_CREATE|os.O_RDWR, 0o600)
	if err == nil {
		_ = pf.Close()
		_ = os.Remove(probe)
		return false
	}
	return true
}
