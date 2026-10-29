package join

import (
	"encoding/base64"
	"strings"
	"testing"
)

func sample() Payload {
	return Payload{
		V:            Version,
		EnrollURL:    "https://enroll.example.org/vpn",
		Token:        "idv1_0123456789abcdef0123456789abcdef",
		Role:         RoleGateway,
		Tenant:       "acme",
		HostnameHint: "office-gw",
	}
}

func TestRoundTrip(t *testing.T) {
	code, err := Encode(sample(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(code, Prefix+".") {
		t.Fatalf("prefix: %s", code)
	}
	parts := strings.Split(code, ".")
	if len(parts) != 3 || len(parts[2]) != 8 {
		t.Fatalf("shape %#v", parts)
	}
	got, err := Decode(code, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got != sample() {
		t.Fatalf("got %+v", got)
	}
	got, err = Decode("\n"+code+"\n", Options{})
	if err != nil || got.Token != sample().Token {
		t.Fatalf("trim: %v %+v", err, got)
	}
}

func TestRejectsHTTPUnlessAllowed(t *testing.T) {
	p := sample()
	p.EnrollURL = "http://enroll.lab/vpn"
	if _, err := Encode(p, Options{}); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("encode http: %v", err)
	}
	code, err := Encode(p, Options{AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(code, Options{}); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("decode http: %v", err)
	}
	got, err := Decode(code, Options{AllowInsecure: true})
	if err != nil || got.EnrollURL != p.EnrollURL {
		t.Fatalf("allow: %v %+v", err, got)
	}
}

func TestCorruptTruncatedOversize(t *testing.T) {
	code, err := Encode(sample(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(code, ".")
	token := sample().Token

	flipped := []byte(parts[2])
	if flipped[0] == 'a' {
		flipped[0] = 'b'
	} else {
		flipped[0] = 'a'
	}
	bad := parts[0] + "." + parts[1] + "." + string(flipped)
	err = decodeErr(bad)
	if err == nil || !strings.Contains(err.Error(), "checksum") || strings.Contains(err.Error(), token) {
		t.Fatalf("corrupt checksum: %v", err)
	}

	typo := parts[0] + "." + parts[1][:len(parts[1])-1] + "A" + "." + parts[2]
	err = decodeErr(typo)
	if err == nil || !strings.Contains(err.Error(), "checksum") || strings.Contains(err.Error(), token) {
		t.Fatalf("typo: %v", err)
	}

	if decodeErr(code[:len(code)-1]) == nil {
		t.Fatal("truncated code was accepted")
	}
	mid := parts[0] + "." + parts[1][:len(parts[1])-4] + "." + parts[2]
	if err := decodeErr(mid); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("truncated payload: %v", err)
	}

	over := Prefix + "." + strings.Repeat("A", MaxCodeLen) + ".00000000"
	if err := decodeErr(over); err == nil || !strings.Contains(err.Error(), "max") {
		t.Fatalf("oversize: %v", err)
	}
	if decodeErr("") == nil {
		t.Fatal("empty accepted")
	}
	if decodeErr(Prefix+".not-base64."+checksum("not-base64")) == nil {
		t.Fatal("non-base64 payload with a matching checksum was accepted")
	}
}

func TestRejectsUnknownFieldsAndBadRole(t *testing.T) {
	p := sample()
	p.Role = "owner"
	if _, err := Encode(p, Options{}); err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("role: %v", err)
	}
	p = sample()
	p.V = 2
	if _, err := Encode(p, Options{}); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("version: %v", err)
	}
	p = sample()
	p.HostnameHint = "-bad"
	if _, err := Encode(p, Options{}); err == nil {
		t.Fatal("bad hostname accepted")
	}

	raw := `{"v":1,"enroll_url":"https://enroll.example.org/vpn","token":"idv1_0123456789abcdef0123456789abcdef","role":"gateway","tenant":"acme","extra":true}`
	enc := base64.RawURLEncoding.EncodeToString([]byte(raw))
	code := Prefix + "." + enc + "." + checksum(enc)
	if err := decodeErr(code); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("unknown field: %v", err)
	}

	raw = `{"v":1,"enroll_url":"https://enroll.example.org/vpn","token":"idv1_0123456789abcdef0123456789abcdef","role":"member","tenant":"acme"}{}`
	enc = base64.RawURLEncoding.EncodeToString([]byte(raw))
	code = Prefix + "." + enc + "." + checksum(enc)
	if err := decodeErr(code); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("trailing junk: %v", err)
	}
}

func TestRolesAndSchemes(t *testing.T) {
	for _, role := range []string{RoleMember, RoleLocalAI, RoleGateway, RoleAdmin} {
		p := sample()
		p.Role = role
		p.HostnameHint = ""
		code, err := Encode(p, Options{})
		if err != nil {
			t.Fatal(role, err)
		}
		got, err := Decode(code, Options{})
		if err != nil || got.Role != role || got.HostnameHint != "" {
			t.Fatalf("%s: %v %+v", role, err, got)
		}
	}
	p := sample()
	p.EnrollURL = "file:///etc/passwd"
	if _, err := Encode(p, Options{AllowInsecure: true}); err == nil {
		t.Fatal("file URL accepted")
	}
	p.EnrollURL = "https://user:pass@enroll.example.org"
	if _, err := Encode(p, Options{}); err == nil {
		t.Fatal("URL userinfo accepted")
	}
}

func decodeErr(code string) error {
	_, err := Decode(code, Options{})
	return err
}
