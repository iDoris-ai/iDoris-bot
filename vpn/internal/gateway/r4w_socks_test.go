package gateway

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

func TestR4WSOCKSSkipsOccupied1080(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:1080")
	if err != nil {
		t.Fatalf("occupy 1080: %v", err)
	}
	defer func() { _ = ln.Close() }()

	want := ""
	for port := 1081; port <= 1096; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		probe, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		_ = probe.Close()
		want = addr
		break
	}
	if want == "" {
		t.Fatal("no free port in 127.0.0.1:1081-1096")
	}

	p, err := SimplePlan(join.RoleMember, "acme", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = "https://enroll.example.org"
	p.ConfigPath = "/home/acme/.idoris/member.json"
	p.TokenFile = "/home/acme/.idoris/member.json.enroll-token"
	h := newMemHost(false, "darwin")
	res, err := Apply(p, h, ApplyOptions{Token: "idv1_secretsecretsecretsecretsecretse", NoService: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg := h.files[p.ConfigPath]
	if bytes.Contains(cfg, []byte("127.0.0.1:1080")) || !bytes.Contains(cfg, []byte(`"socks5_listen": "`+want+`"`)) {
		t.Fatalf("listen %q\n%s", want, cfg)
	}
	if bytes.Contains(cfg, []byte("socks5_allow_anonymous")) {
		t.Fatalf("anonymous SOCKS was enabled:\n%s", cfg)
	}
	text := strings.Join(res.AccessInfo, "\n")
	if !strings.Contains(text, want) || strings.Contains(text, "127.0.0.1:1080") {
		t.Fatalf("access %q", text)
	}
	_, port, err := net.SplitHostPort(want)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1081 || n > 1096 {
		t.Fatalf("chosen %s", want)
	}
}
