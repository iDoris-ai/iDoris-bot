package vpnd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestR4CStateFileLockIsProcessExclusive holds the state file in this
// process, then re-executes. The child must fail before it can replace the
// persisted backoff. A second OpenState in this process still sees it.
func TestR4CStateFileLockIsProcessExclusive(t *testing.T) {
	if os.Getenv("R4C_STATE_LOCK_CHILD") == "1" {
		r4cStateLockChild()
		return
	}
	path := filepath.Join(t.TempDir(), "vpnd-state.json")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	next := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	if err := st.SetLoginBackoff(next, 4); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestR4CStateFileLockIsProcessExclusive$", "-test.count=1")
	cmd.Env = r3c2ReplaceEnv(os.Environ(), map[string]string{
		"R4C_STATE_LOCK_CHILD": "1",
		"R4C_STATE_LOCK_PATH":  path,
	})
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("second process opened the state file\n%s", out)
	}
	if !strings.Contains(string(out), "another idoris-vpnd") {
		t.Fatalf("second process: %v\n%s", err, out)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("state file changed:\n%s", after)
	}
	again, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	got := again.Get()
	if got.LoginFailures != 4 || !got.NextLoginAt.Equal(next) {
		t.Fatalf("backoff %+v", got)
	}
}

func r4cStateLockChild() {
	_, err := OpenState(os.Getenv("R4C_STATE_LOCK_PATH"))
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(2)
	}
	os.Exit(0)
}
