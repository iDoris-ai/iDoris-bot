// Package join encodes and decodes an iDoris join code.
//
// A code is idoris-join-v1.<base64url(JSON)>.<crc32 hex>. The JSON carries the
// enrollment URL and token, so the code is a secret: callers must not log it,
// put it in a process argument list that is world-readable, or write it to a
// world-readable file. The checksum is CRC-32/IEEE of the base64url segment,
// eight lowercase hex digits. It rejects truncation and single-character typos
// before the JSON is trusted.
package join

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/url"
	"strings"
)

const (
	// Prefix is the literal first segment of every code.
	Prefix = "idoris-join-v1"
	// Version is the only payload version this package accepts.
	Version = 1

	// MaxCodeLen caps the whole code. A legitimate code is a few hundred
	// bytes; the cap rejects accidental pastes of a log or a file.
	MaxCodeLen = 4096
	// MaxJSONLen caps the decoded JSON object.
	MaxJSONLen = 2048

	RoleMember  = "member"
	RoleLocalAI = "local-ai"
	RoleGateway = "gateway"
	RoleAdmin   = "admin"
)

// Payload is the JSON object inside a join code.
type Payload struct {
	V            int    `json:"v"`
	EnrollURL    string `json:"enroll_url"`
	Token        string `json:"token"`
	Role         string `json:"role"`
	Tenant       string `json:"tenant"`
	HostnameHint string `json:"hostname_hint,omitempty"`
}

// Options controls URL scheme checks. AllowInsecure permits http:// for lab
// networks. The default rejects every scheme other than https.
type Options struct {
	AllowInsecure bool
}

// ValidRole reports whether role is one of the four join roles.
func ValidRole(role string) bool {
	switch role {
	case RoleMember, RoleLocalAI, RoleGateway, RoleAdmin:
		return true
	default:
		return false
	}
}

// Encode builds a join code. It does not log p.
func Encode(p Payload, opt Options) (string, error) {
	if err := validate(p, opt); err != nil {
		return "", err
	}
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	if len(body) > MaxJSONLen {
		return "", fmt.Errorf("join: payload is %d bytes, max %d", len(body), MaxJSONLen)
	}
	enc := base64.RawURLEncoding.EncodeToString(body)
	code := Prefix + "." + enc + "." + checksum(enc)
	if len(code) > MaxCodeLen {
		return "", fmt.Errorf("join: code is %d bytes, max %d", len(code), MaxCodeLen)
	}
	return code, nil
}

// Decode parses a join code. Unknown JSON fields, a bad checksum, a bad role,
// and a non-https URL (unless AllowInsecure) are errors. The returned error
// never includes the code or the token.
func Decode(code string, opt Options) (Payload, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return Payload{}, errors.New("join: code is empty")
	}
	if len(code) > MaxCodeLen {
		return Payload{}, fmt.Errorf("join: code is %d bytes, max %d", len(code), MaxCodeLen)
	}
	parts := strings.Split(code, ".")
	if len(parts) != 3 || parts[0] != Prefix || parts[1] == "" || parts[2] == "" {
		return Payload{}, errors.New("join: malformed code")
	}
	if !checksumEqual(parts[2], checksum(parts[1])) {
		return Payload{}, errors.New("join: checksum mismatch")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Payload{}, errors.New("join: payload is not base64url")
	}
	if len(raw) > MaxJSONLen {
		return Payload{}, fmt.Errorf("join: payload is %d bytes, max %d", len(raw), MaxJSONLen)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Payload
	if err := dec.Decode(&p); err != nil {
		return Payload{}, errors.New("join: payload rejected")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Payload{}, errors.New("join: payload rejected")
	}
	if err := validate(p, opt); err != nil {
		return Payload{}, err
	}
	return p, nil
}

func validate(p Payload, opt Options) error {
	if p.V != Version {
		return fmt.Errorf("join: version %d is not supported", p.V)
	}
	if err := checkURL(p.EnrollURL, opt.AllowInsecure); err != nil {
		return err
	}
	if strings.TrimSpace(p.Token) == "" || len(p.Token) > 512 {
		return errors.New("join: token is missing or too long")
	}
	if strings.ContainsAny(p.Token, " \t\r\n") {
		return errors.New("join: token contains whitespace")
	}
	if !ValidRole(p.Role) {
		return errors.New("join: role must be member, local-ai, gateway, or admin")
	}
	if err := checkTenant(p.Tenant); err != nil {
		return err
	}
	if p.HostnameHint != "" {
		if err := checkHostname(p.HostnameHint); err != nil {
			return err
		}
	}
	return nil
}

func checkURL(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("join: enroll_url is not a usable URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure {
			return nil
		}
		return errors.New("join: enroll_url must be https (allow insecure for labs)")
	default:
		return errors.New("join: enroll_url must be https")
	}
}

func checkTenant(name string) error {
	if name == "" || len(name) > 63 {
		return errors.New("join: tenant is missing or too long")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		default:
			return errors.New("join: tenant has characters outside [A-Za-z0-9-]")
		}
	}
	return nil
}

func checkHostname(name string) error {
	if len(name) > 63 {
		return errors.New("join: hostname_hint is too long")
	}
	for i, r := range name {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-'
		if !ok || (r == '-' && (i == 0 || i == len(name)-1)) {
			return errors.New("join: hostname_hint is not a hostname label")
		}
	}
	return nil
}

func checksum(payload string) string {
	return fmt.Sprintf("%08x", crc32.ChecksumIEEE([]byte(payload)))
}

func checksumEqual(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	// Constant-time compare of the short hex digest.
	var diff byte
	for i := 0; i < len(got); i++ {
		diff |= got[i] ^ want[i]
	}
	return diff == 0
}
