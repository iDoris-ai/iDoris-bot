package enroll

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Credential is one enrollment token. Expiring or deleting the Headscale
// node does not revoke it; RemoveCredential does.
type Credential struct {
	Hash      string    `json:"hash"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// displayedHashPrefix is how much of a token hash operators may print.
// The rest of the hash, and the token itself, stay out of command output.
const displayedHashPrefix = 12

// HashPrefix returns the operator-visible prefix of a hex token hash.
func HashPrefix(hash string) string {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if len(hash) > displayedHashPrefix {
		return hash[:displayedHashPrefix]
	}
	return hash
}

// FormatCredentialList prints label, hash prefix and created_at. It never
// prints the token or the full hash. An empty label or timestamp is "-".
func FormatCredentialList(creds []Credential) string {
	var b strings.Builder
	for _, c := range creds {
		label := c.Label
		if label == "" {
			label = "-"
		}
		created := "-"
		if !c.CreatedAt.IsZero() {
			created = c.CreatedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\n", label, HashPrefix(c.Hash), created)
	}
	return b.String()
}

func validLabel(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '.' || r == '_' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// chooseLabel picks the credential label. An explicit label is used as
// given. Otherwise a hostname hint is used when it is a valid label, and
// otherwise a stable label is derived from the hash prefix.
func chooseLabel(explicit, hint, hash string) (string, error) {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		if !validLabel(explicit) {
			return "", fmt.Errorf("enroll: label %q is invalid", explicit)
		}
		return explicit, nil
	}
	hint = strings.TrimSpace(hint)
	if hint != "" && validLabel(hint) {
		return hint, nil
	}
	if len(hash) < 8 {
		return "", fmt.Errorf("enroll: cannot derive a label")
	}
	return "cred-" + strings.ToLower(hash[:8]), nil
}

// normalize aligns TokenHashes with Credentials and checks labels.
// Legacy configs only have hashes; those become unlabeled credentials.
func (t *Tenant) normalize() error {
	switch {
	case len(t.Credentials) == 0:
		t.Credentials = make([]Credential, len(t.TokenHashes))
		for i, h := range t.TokenHashes {
			t.Credentials[i] = Credential{Hash: strings.ToLower(h)}
		}
	case len(t.TokenHashes) == 0:
		t.TokenHashes = make([]string, len(t.Credentials))
		for i := range t.Credentials {
			t.Credentials[i].Hash = strings.ToLower(t.Credentials[i].Hash)
			t.TokenHashes[i] = t.Credentials[i].Hash
		}
	case len(t.TokenHashes) != len(t.Credentials):
		return fmt.Errorf("tenant %q: token_hashes and credentials differ in length", t.Name)
	default:
		for i := range t.Credentials {
			if t.Credentials[i].Hash == "" {
				t.Credentials[i].Hash = t.TokenHashes[i]
			}
			t.Credentials[i].Hash = strings.ToLower(t.Credentials[i].Hash)
			t.TokenHashes[i] = t.Credentials[i].Hash
		}
	}
	seen := map[string]struct{}{}
	for _, c := range t.Credentials {
		if c.Label == "" {
			continue
		}
		if !validLabel(c.Label) {
			return fmt.Errorf("tenant %q: credential label %q is invalid", t.Name, c.Label)
		}
		if _, ok := seen[c.Label]; ok {
			return fmt.Errorf("tenant %q: duplicate credential label %q", t.Name, c.Label)
		}
		seen[c.Label] = struct{}{}
	}
	return nil
}

// UnmarshalJSON accepts token_hashes entries as hex strings or objects.
func (t *Tenant) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var plain struct {
		Name            string          `json:"name"`
		HeadscaleUserID string          `json:"headscale_user_id"`
		TokenHashes     json.RawMessage `json:"token_hashes"`
		ACLTags         []string        `json:"acl_tags"`
		Role            string          `json:"role"`
		LANCIDRs        []string        `json:"lan_cidrs"`
		PreAuthTTL      Duration        `json:"preauth_ttl"`
		Ephemeral       bool            `json:"ephemeral"`
		RatePerMinute   int             `json:"rate_per_minute"`
	}
	if err := dec.Decode(&plain); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("tenant %q: trailing data", plain.Name)
	}
	creds, hashes, err := parseTokenEntries(plain.TokenHashes)
	if err != nil {
		return fmt.Errorf("tenant %q: %w", plain.Name, err)
	}
	*t = Tenant{
		Name:            plain.Name,
		HeadscaleUserID: plain.HeadscaleUserID,
		TokenHashes:     hashes,
		Credentials:     creds,
		ACLTags:         plain.ACLTags,
		Role:            plain.Role,
		LANCIDRs:        plain.LANCIDRs,
		PreAuthTTL:      plain.PreAuthTTL,
		Ephemeral:       plain.Ephemeral,
		RatePerMinute:   plain.RatePerMinute,
	}
	return nil
}

// MarshalJSON writes token_hashes as objects so a legacy string list is
// upgraded on the next save. Labels and timestamps are omitted when empty.
func (t Tenant) MarshalJSON() ([]byte, error) {
	creds := t.credentialList()
	wire := struct {
		Name            string       `json:"name"`
		HeadscaleUserID string       `json:"headscale_user_id"`
		TokenHashes     []Credential `json:"token_hashes"`
		ACLTags         []string     `json:"acl_tags,omitempty"`
		Role            string       `json:"role,omitempty"`
		LANCIDRs        []string     `json:"lan_cidrs,omitempty"`
		PreAuthTTL      Duration     `json:"preauth_ttl,omitempty"`
		Ephemeral       bool         `json:"ephemeral,omitempty"`
		RatePerMinute   int          `json:"rate_per_minute,omitempty"`
	}{
		Name:            t.Name,
		HeadscaleUserID: t.HeadscaleUserID,
		TokenHashes:     creds,
		ACLTags:         t.ACLTags,
		Role:            t.Role,
		LANCIDRs:        t.LANCIDRs,
		PreAuthTTL:      t.PreAuthTTL,
		Ephemeral:       t.Ephemeral,
		RatePerMinute:   t.RatePerMinute,
	}
	return json.Marshal(wire)
}

func (t Tenant) credentialList() []Credential {
	if len(t.Credentials) == len(t.TokenHashes) && len(t.Credentials) > 0 {
		out := make([]Credential, len(t.Credentials))
		for i, c := range t.Credentials {
			if c.Hash == "" {
				c.Hash = t.TokenHashes[i]
			}
			out[i] = c
		}
		return out
	}
	out := make([]Credential, len(t.TokenHashes))
	for i, h := range t.TokenHashes {
		out[i] = Credential{Hash: h}
	}
	return out
}

func parseTokenEntries(raw json.RawMessage) ([]Credential, []string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil, fmt.Errorf("token_hashes is required")
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, nil, fmt.Errorf("token_hashes: %w", err)
	}
	creds := make([]Credential, 0, len(elems))
	hashes := make([]string, 0, len(elems))
	for i, el := range elems {
		el = bytes.TrimSpace(el)
		if len(el) == 0 {
			return nil, nil, fmt.Errorf("token_hashes[%d]: empty", i)
		}
		if el[0] == '"' {
			var h string
			if err := json.Unmarshal(el, &h); err != nil {
				return nil, nil, fmt.Errorf("token_hashes[%d]: %w", i, err)
			}
			creds = append(creds, Credential{Hash: h})
			hashes = append(hashes, h)
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(el))
		dec.DisallowUnknownFields()
		var c Credential
		if err := dec.Decode(&c); err != nil {
			return nil, nil, fmt.Errorf("token_hashes[%d]: %w", i, err)
		}
		creds = append(creds, c)
		hashes = append(hashes, c.Hash)
	}
	return creds, hashes, nil
}
