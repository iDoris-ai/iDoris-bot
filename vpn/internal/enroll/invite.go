package enroll

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

// failDiskWrite and afterTruncate are test seams. Production leaves both nil.
// afterTruncate runs after O_TRUNC, while the caller still holds the config lock.
var (
	failDiskWrite func() error
	afterTruncate func()
)

// configPath is the path with symlinks removed, so a config and an alias share
// one lock file and one .bak beside the real inode.
func configPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("enroll: config path is empty")
	}
	return filepath.EvalSymlinks(path)
}

// LoadFile reads a config file. It does not apply environment overrides, so a
// rewrite cannot persist a value that only existed in the process environment.
// A truncated file is put back from the fsynced .bak when that backup still parses.
func LoadFile(path string) (*Config, error) {
	b, err := readConfigBytes(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(b)
}

// ReadFileLocked reads the config under the same lock Invite and Revoke hold.
// SIGHUP must use this. os.ReadFile can observe the empty inode between
// O_TRUNC and the following Write, and a rejected reload would keep a token
// that a concurrent Revoke already removed.
func ReadFileLocked(path string) ([]byte, error) {
	var b []byte
	err := withConfigLock(path, func() error {
		var err error
		b, err = readConfigBytes(path)
		return err
	})
	return b, err
}

func readConfigBytes(path string) ([]byte, error) {
	resolved, err := configPath(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(resolved) //nolint:gosec // path is the operator-chosen enroll config
	if err != nil {
		return nil, err
	}
	if decodesConfig(b) {
		return b, nil
	}
	bak, berr := os.ReadFile(resolved + ".bak") //nolint:gosec // backup beside the canonical config
	if berr != nil {
		return b, nil
	}
	if _, perr := parseConfig(bak); perr != nil {
		return b, nil
	}
	// Restore into the same inode. writeInPlace would copy the broken bytes
	// over the good backup before writing it back.
	if rerr := restoreInPlace(resolved, bak); rerr != nil {
		return nil, rerr
	}
	return bak, nil
}

func decodesConfig(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var cfg Config
	return dec.Decode(&cfg) == nil
}

func parseConfig(b []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("enroll config: %w", err)
	}
	if dec.More() {
		return nil, errors.New("enroll config: trailing data")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveFile writes cfg onto the existing inode and preserves the file mode.
// The caller must already hold the config lock. The plaintext of any
// enrollment token is not part of cfg.
func SaveFile(path string, cfg *Config) error {
	if cfg == nil {
		return errors.New("enroll: config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	return writeInPlace(path, buf.Bytes())
}

// writeInPlace truncates the existing inode. rename would leave a single-file
// bind mount serving the old file after SIGHUP. The .bak is fsynced before the
// truncate so a crash mid-write can be restored. It is the previous bytes,
// including a hash a completed revoke has already removed.
func writeInPlace(path string, data []byte) error {
	resolved, err := configPath(path)
	if err != nil {
		return err
	}
	st, err := os.Stat(resolved) //nolint:gosec // path is the operator-chosen enroll config
	if err != nil {
		return err
	}
	original, err := os.ReadFile(resolved) //nolint:gosec // path is the operator-chosen enroll config
	if err != nil {
		return err
	}
	if err := writeBak(resolved+".bak", original, st.Mode().Perm()); err != nil {
		return err
	}
	f, err := os.OpenFile(resolved, os.O_WRONLY|os.O_TRUNC, 0) //nolint:gosec // rewrite the same inode, including through a symlink
	if err != nil {
		return err
	}
	if afterTruncate != nil {
		afterTruncate()
	}
	var werr error
	if failDiskWrite != nil {
		werr = failDiskWrite()
	}
	if werr == nil {
		_, werr = f.Write(data)
	}
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr != nil {
		_ = restoreInPlace(resolved, original)
		return werr
	}
	if cerr != nil {
		_ = restoreInPlace(resolved, original)
		return cerr
	}
	return nil
}

func writeBak(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode) //nolint:gosec // backup beside the canonical config
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if werr == nil {
		// Mode on OpenFile applies only when the file is created. An existing
		// .bak would otherwise keep a looser mode forever.
		werr = f.Chmod(mode)
	}
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func restoreInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) //nolint:gosec // restore the same inode
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// Invite mints a new enrollment token for entry, appends a labeled credential,
// and returns the join code. label is stored next to the hash. An empty label
// uses hostnameHint when that hint is a valid label, otherwise cred-<hash prefix>.
// The plaintext token exists only inside the code. The caller prints the code
// once and does not log it.
func Invite(path, entry, hostnameHint, enrollURL, label string, allowInsecure bool) (string, error) {
	var code string
	err := updateConfig(path, func(cfg *Config) error {
		idx := entryIndex(cfg, entry)
		if idx < 0 {
			return fmt.Errorf("enroll: unknown entry %q", entry)
		}
		token, hash, err := distinctToken(cfg)
		if err != nil {
			return err
		}
		chosen, err := chooseLabel(label, hostnameHint, hash)
		if err != nil {
			return err
		}
		for _, c := range cfg.Tenants[idx].Credentials {
			if c.Label != "" && c.Label == chosen {
				return fmt.Errorf("enroll: label %q already exists in %q", chosen, entry)
			}
		}
		role := cfg.Tenants[idx].Role
		if role == "" {
			role = join.RoleMember
		}
		encoded, err := join.Encode(join.Payload{
			V:            join.Version,
			EnrollURL:    enrollURL,
			Token:        token,
			Role:         role,
			Tenant:       cfg.Tenants[idx].Name,
			HostnameHint: hostnameHint,
		}, join.Options{AllowInsecure: allowInsecure})
		if err != nil {
			return err
		}
		cfg.Tenants[idx].Credentials = append(cfg.Tenants[idx].Credentials, Credential{
			Hash:      hash,
			Label:     chosen,
			CreatedAt: time.Now().UTC().Truncate(time.Second),
		})
		cfg.Tenants[idx].TokenHashes = append(cfg.Tenants[idx].TokenHashes, hash)
		code = encoded
		return nil
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// CredentialMatch selects one credential. Exactly one of Label or
// HashPrefix must be set. AllowEmpty permits removing the last credential
// so the entry stays in the file and matches no token.
type CredentialMatch struct {
	Label      string
	HashPrefix string
	AllowEmpty bool
}

// RemoveCredential deletes one credential from entry and returns it.
// The plaintext token is not recoverable. Without AllowEmpty it refuses
// to remove the last credential. With AllowEmpty the entry is left with
// zero credentials and still loads.
func RemoveCredential(path, entry string, m CredentialMatch) (Credential, error) {
	byLabel := strings.TrimSpace(m.Label) != ""
	byPrefix := strings.TrimSpace(m.HashPrefix) != ""
	if byLabel == byPrefix {
		return Credential{}, errors.New("enroll: provide exactly one of label or hash prefix")
	}
	var removed Credential
	err := updateConfig(path, func(cfg *Config) error {
		idx := entryIndex(cfg, entry)
		if idx < 0 {
			return fmt.Errorf("enroll: unknown entry %q", entry)
		}
		creds := cfg.Tenants[idx].Credentials
		match := -1
		if byLabel {
			label := strings.TrimSpace(m.Label)
			if !validLabel(label) {
				return fmt.Errorf("enroll: label %q is invalid", m.Label)
			}
			for i, c := range creds {
				if c.Label == label {
					if match >= 0 {
						return fmt.Errorf("enroll: label %q matches more than one token", label)
					}
					match = i
				}
			}
			if match < 0 {
				return fmt.Errorf("enroll: label %q matches no token in %q", label, entry)
			}
		} else {
			prefix, err := normalizeHashPrefix(m.HashPrefix)
			if err != nil {
				return err
			}
			for i, c := range creds {
				if strings.HasPrefix(strings.ToLower(c.Hash), prefix) {
					if match >= 0 {
						return fmt.Errorf("enroll: hash prefix %s matches more than one token", prefix)
					}
					match = i
				}
			}
			if match < 0 {
				return fmt.Errorf("enroll: hash prefix %s matches no token in %q", prefix, entry)
			}
		}
		if len(creds) == 1 && !m.AllowEmpty {
			return errors.New("enroll: refusing to remove the last token hash")
		}
		removed = creds[match]
		cfg.Tenants[idx].Credentials = append(creds[:match], creds[match+1:]...)
		hashes := cfg.Tenants[idx].TokenHashes
		cfg.Tenants[idx].TokenHashes = append(hashes[:match], hashes[match+1:]...)
		return nil
	})
	if err != nil {
		return Credential{}, err
	}
	return removed, nil
}

// ListCredentials returns the credentials of one entry. The token plaintext
// is not in the result. Callers that print this must use HashPrefix.
func ListCredentials(path, entry string) ([]Credential, error) {
	var out []Credential
	err := withConfigLock(path, func() error {
		cfg, err := LoadFile(path)
		if err != nil {
			return err
		}
		idx := entryIndex(cfg, entry)
		if idx < 0 {
			return fmt.Errorf("enroll: unknown entry %q", entry)
		}
		out = append([]Credential(nil), cfg.Tenants[idx].Credentials...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Revoke removes the single token hash in entry that starts with prefix.
// prefix is hex, at least 4 digits. It is an error to match zero or several
// hashes, and to remove the last hash of an entry unless the caller uses
// RemoveCredential with AllowEmpty.
func Revoke(path, entry, prefix string) (string, error) {
	removed, err := RemoveCredential(path, entry, CredentialMatch{HashPrefix: prefix})
	if err != nil {
		return "", err
	}
	return strings.ToLower(removed.Hash), nil
}

// RevokeLabel removes the single credential with that label.
func RevokeLabel(path, entry, label string) (string, error) {
	removed, err := RemoveCredential(path, entry, CredentialMatch{Label: label})
	if err != nil {
		return "", err
	}
	return strings.ToLower(removed.Hash), nil
}

func normalizeHashPrefix(prefix string) (string, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len(prefix) < 4 || len(prefix) > sha256HexLen {
		return "", errors.New("enroll: hash prefix must be 4 to 64 hex digits")
	}
	for _, r := range prefix {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", errors.New("enroll: hash prefix must be hex")
		}
	}
	return prefix, nil
}

const sha256HexLen = 64

func entryIndex(cfg *Config, name string) int {
	for i := range cfg.Tenants {
		if cfg.Tenants[i].Name == name {
			return i
		}
	}
	return -1
}

func distinctToken(cfg *Config) (token, hash string, err error) {
	seen := map[string]struct{}{}
	for _, t := range cfg.Tenants {
		for _, h := range t.TokenHashes {
			seen[strings.ToLower(h)] = struct{}{}
		}
	}
	for range 5 {
		token, err = NewToken()
		if err != nil {
			return "", "", err
		}
		hash = HashToken(token)
		if _, ok := seen[hash]; !ok {
			return token, hash, nil
		}
	}
	return "", "", errors.New("enroll: could not mint a distinct token")
}
