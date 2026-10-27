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
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/fsutil"
)

// DaemonState is the small binding file the daemon keeps between restarts.
// It never contains an enrollment token, a join code, or an auth key.
// TokenFingerprint is a truncated SHA-256 of the enrollment token.
// NodeID is the stable ID of the self node this binding was confirmed
// against. ProfileID is the LocalAPI profile ID in system mode, when the
// client exposes one. NextLoginAt and LoginFailures are the persisted login
// backoff: a supervisor restart must not mint a new key before NextLoginAt.
type DaemonState struct {
	ControlURL       string    `json:"control_url,omitempty"`
	Tenant           string    `json:"tenant,omitempty"`
	Role             string    `json:"role,omitempty"`
	TokenFingerprint string    `json:"token_fingerprint,omitempty"`
	NodeID           string    `json:"node_id,omitempty"`
	ProfileID        string    `json:"profile_id,omitempty"`
	NextLoginAt      time.Time `json:"next_login_at,omitzero"`
	LoginFailures    int       `json:"login_failures,omitempty"`
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

// DefaultStateFile is the binding file.
// Order: $STATE_DIRECTORY/vpnd-state.json (machine service; the first
// absolute entry of a colon-separated list), then on Windows
// %AppData%/idoris, otherwise $XDG_STATE_HOME/idoris, then ~/.idoris.
// A set but unusable STATE_DIRECTORY is an error. HOME is not consulted
// on that path.
func DefaultStateFile() (string, error) {
	if dir, err := serviceStateDir(); err != nil {
		return "", err
	} else if dir != "" {
		return filepath.Join(dir, "vpnd-state.json"), nil
	}
	if runtime.GOOS == "windows" {
		dir, err := os.UserConfigDir()
		if err != nil || dir == "" {
			if err == nil {
				err = errors.New("config directory is not set")
			}
			return "", fmt.Errorf("state file: set STATE_DIRECTORY: %w", err)
		}
		return filepath.Join(dir, "idoris", "vpnd-state.json"), nil
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); xdg != "" {
		return filepath.Join(xdg, "idoris", "vpnd-state.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		if err == nil {
			err = errors.New("HOME is not defined")
		}
		return "", fmt.Errorf("state file: set STATE_DIRECTORY or HOME: %w", err)
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
// The in-memory copy changes only after the file is replaced.
func (s *StateFile) RememberControl(controlURL string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.ControlURL == controlURL {
		return nil
	}
	next := s.st
	next.ControlURL = controlURL
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.st = next
	return nil
}

// SetIdentity persists the credential the running node is now bound to.
// nodeID is the self node's stable ID. profileID is the system-mode LocalAPI
// profile ID, or empty when the backend does not expose one. Login backoff
// fields already on the file are kept. The in-memory copy changes only after
// the file is replaced, so a failed write is retried on the next pass.
func (s *StateFile) SetIdentity(controlURL, tenant, role, fingerprint, nodeID, profileID string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.st
	next.ControlURL = controlURL
	next.Tenant = tenant
	next.Role = role
	next.TokenFingerprint = fingerprint
	next.NodeID = nodeID
	next.ProfileID = profileID
	if next == s.st {
		return nil
	}
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.st = next
	return nil
}

// SetLoginBackoff persists the next time a login may mint a key, and how
// many consecutive attempts have failed to reach Running. Callers do this
// before requesting a key. A failed write leaves the previous memory intact.
func (s *StateFile) SetLoginBackoff(next time.Time, failures int) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := s.st
	if next.IsZero() {
		stored.NextLoginAt = time.Time{}
	} else {
		stored.NextLoginAt = next.UTC()
	}
	stored.LoginFailures = failures
	if stored == s.st {
		return nil
	}
	if err := s.saveLocked(stored); err != nil {
		return err
	}
	s.st = stored
	return nil
}

// ClearLoginBackoff forgets a persisted login delay after the node is up.
func (s *StateFile) ClearLoginBackoff() error {
	return s.SetLoginBackoff(time.Time{}, 0)
}

// LoginBackoff returns the persisted next-eligible time and failure count.
func (s *StateFile) LoginBackoff() (time.Time, int) {
	if s == nil {
		return time.Time{}, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.NextLoginAt, s.st.LoginFailures
}

func (s *StateFile) saveLocked(st DaemonState) error {
	dir := filepath.Dir(s.path)
	if err := fsutil.EnsurePrivateDir(dir); err != nil {
		return err
	}
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	// Unique temp name inside dir. A pre-planted path+".tmp" symlink is never
	// opened, so it cannot redirect this write onto another file.
	return fsutil.WriteFileAtomic(s.path, body, 0o600)
}
