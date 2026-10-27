package vpnd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedLoginModeInterruptedRegistration(t *testing.T) {
	dir := t.TempDir()
	loginNow, recover, err := EmbeddedLoginMode(dir)
	if err != nil || !loginNow || recover {
		t.Fatalf("empty dir: login=%v recover=%v err=%v", loginNow, recover, err)
	}

	state := filepath.Join(dir, stateFileName)
	if err := os.WriteFile(state, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	loginNow, recover, err = EmbeddedLoginMode(dir)
	if err != nil || loginNow || !recover {
		t.Fatalf("state without marker: login=%v recover=%v err=%v", loginNow, recover, err)
	}

	if err := MarkRegistrationComplete(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, registrationMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("marker mode %o", info.Mode().Perm())
	}
	loginNow, recover, err = EmbeddedLoginMode(dir)
	if err != nil || loginNow || recover {
		t.Fatalf("after marker: login=%v recover=%v err=%v", loginNow, recover, err)
	}
	if err := MarkRegistrationComplete(dir); err != nil {
		t.Fatal(err)
	}

	wiped := t.TempDir()
	if err := os.WriteFile(filepath.Join(wiped, stateFileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	loginNow, recover, err = EmbeddedLoginMode(wiped)
	if err != nil || !loginNow || recover {
		t.Fatalf("empty state file is a fresh login: login=%v recover=%v err=%v", loginNow, recover, err)
	}
}
