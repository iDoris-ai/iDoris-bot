package enroll

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

// LoadFile reads a config file. It does not apply environment overrides, so a
// rewrite cannot persist a value that only existed in the process environment.
func LoadFile(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("enroll: config path is empty")
	}
	b, err := os.ReadFile(path) //nolint:gosec // path is the operator-chosen enroll config
	if err != nil {
		return nil, err
	}
	return parseConfig(b)
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

// SaveFile writes cfg atomically and preserves the existing file mode.
// The plaintext of any enrollment token is not part of cfg.
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
	return writeAtomic(path, buf.Bytes())
}

func writeAtomic(path string, data []byte) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".enroll-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(st.Mode().Perm()); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// Invite mints a new enrollment token for entry, appends only its SHA-256 to
// token_hashes, and returns the join code. The plaintext token exists only
// inside that code. The caller prints the code once and does not log it.
func Invite(path, entry, hostnameHint, enrollURL string, allowInsecure bool) (string, error) {
	cfg, err := LoadFile(path)
	if err != nil {
		return "", err
	}
	idx := entryIndex(cfg, entry)
	if idx < 0 {
		return "", fmt.Errorf("enroll: unknown entry %q", entry)
	}
	token, hash, err := distinctToken(cfg)
	if err != nil {
		return "", err
	}
	role := cfg.Tenants[idx].Role
	if role == "" {
		role = join.RoleMember
	}
	code, err := join.Encode(join.Payload{
		V:            join.Version,
		EnrollURL:    enrollURL,
		Token:        token,
		Role:         role,
		Tenant:       cfg.Tenants[idx].Name,
		HostnameHint: hostnameHint,
	}, join.Options{AllowInsecure: allowInsecure})
	if err != nil {
		return "", err
	}
	cfg.Tenants[idx].TokenHashes = append(cfg.Tenants[idx].TokenHashes, hash)
	if err := SaveFile(path, cfg); err != nil {
		return "", err
	}
	return code, nil
}

// Revoke removes the single token hash in entry that starts with prefix.
// prefix is hex, at least 4 digits. It is an error to match zero or several
// hashes, and to remove the last hash of an entry (the file must stay loadable).
func Revoke(path, entry, prefix string) (string, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len(prefix) < 4 || len(prefix) > sha256HexLen {
		return "", errors.New("enroll: hash prefix must be 4 to 64 hex digits")
	}
	for _, r := range prefix {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", errors.New("enroll: hash prefix must be hex")
		}
	}
	cfg, err := LoadFile(path)
	if err != nil {
		return "", err
	}
	idx := entryIndex(cfg, entry)
	if idx < 0 {
		return "", fmt.Errorf("enroll: unknown entry %q", entry)
	}
	hashes := cfg.Tenants[idx].TokenHashes
	match := -1
	for i, h := range hashes {
		if strings.HasPrefix(strings.ToLower(h), prefix) {
			if match >= 0 {
				return "", fmt.Errorf("enroll: hash prefix %s matches more than one token", prefix)
			}
			match = i
		}
	}
	if match < 0 {
		return "", fmt.Errorf("enroll: hash prefix %s matches no token in %q", prefix, entry)
	}
	if len(hashes) == 1 {
		return "", errors.New("enroll: refusing to remove the last token hash")
	}
	removed := strings.ToLower(hashes[match])
	cfg.Tenants[idx].TokenHashes = append(hashes[:match], hashes[match+1:]...)
	if err := SaveFile(path, cfg); err != nil {
		return "", err
	}
	return removed, nil
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
