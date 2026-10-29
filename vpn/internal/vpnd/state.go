package vpnd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// DaemonState is the small binding file the daemon keeps between restarts.
// It never contains an enrollment token, a join code, or an auth key.
// TokenFingerprint is a truncated SHA-256 of the enrollment token.
type DaemonState struct {
	ControlURL       string `json:"control_url,omitempty"`
	Tenant           string `json:"tenant,omitempty"`
	Role             string `json:"role,omitempty"`
	TokenFingerprint string `json:"token_fingerprint,omitempty"`
}

// Identity is the credential the enrollment service just described.
// Known is false when discovery did not run (static auth key, or discovery
// failed and the daemon is resuming from DaemonState).
type Identity struct {
	Tenant           string
	Role             string
	TokenFingerprint string
	Known            bool
}

// TokenFingerprint is hex(SHA-256(token)[:8]). An empty token yields an empty
// fingerprint. The result is safe to log and to store; it is not the token.
func TokenFingerprint(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

// DefaultStateFile is the binding file. Windows uses %AppData%/idoris.
// Elsewhere $XDG_STATE_HOME/idoris wins, then ~/.idoris.
func DefaultStateFile() (string, error) {
	if runtime.GOOS == "windows" {
		dir, err := os.UserConfigDir()
		if err != nil || dir == "" {
			return "", fmt.Errorf("state file: config directory: %w", err)
		}
		return filepath.Join(dir, "idoris", "vpnd-state.json"), nil
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); xdg != "" {
		return filepath.Join(xdg, "idoris", "vpnd-state.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("state file: home directory: %w", err)
	}
	return filepath.Join(home, ".idoris", "vpnd-state.json"), nil
}

// StateFile loads and stores DaemonState. The file is created mode 0600.
type StateFile struct {
	path string
	mu   sync.Mutex
	st   DaemonState
}

// OpenState reads path when it exists. A missing file is an empty binding.
// An existing file must pass CheckSecretFile.
func OpenState(path string) (*StateFile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("state file path is empty")
	}
	s := &StateFile{path: path}
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	if err := CheckSecretFile(path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path) //nolint:gosec // path is the daemon state file, checked above
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return s, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s.st); err != nil {
		return nil, fmt.Errorf("state file %s: %w", path, err)
	}
	return s, nil
}

// Path returns the file location.
func (s *StateFile) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Get returns a copy of the binding.
func (s *StateFile) Get() DaemonState {
	if s == nil {
		return DaemonState{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

// RememberControl persists a trusted control URL without changing the bound
// tenant or role. Discovery calls this before the node is logged in.
func (s *StateFile) RememberControl(controlURL string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.ControlURL == controlURL {
		return nil
	}
	s.st.ControlURL = controlURL
	return s.saveLocked()
}

// SetIdentity persists the credential the running node is now bound to.
func (s *StateFile) SetIdentity(controlURL, tenant, role, fingerprint string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := DaemonState{
		ControlURL:       controlURL,
		Tenant:           tenant,
		Role:             role,
		TokenFingerprint: fingerprint,
	}
	if next == s.st {
		return nil
	}
	s.st = next
	return s.saveLocked()
}

func (s *StateFile) saveLocked() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // the directory needs the owner execute bit
		return err
	}
	body, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil { //nolint:gosec // owner-only binding file
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Chmod(s.path, 0o600) //nolint:gosec // owner-only binding file
}
