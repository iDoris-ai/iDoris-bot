//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/headscale"
)

// TestR5LeadExpirePreAuthKeyAgainstHeadscale proves the request the enrollment
// service sends to revoke a freshly minted key is the one Headscale v0.29.6
// accepts: POST /api/v1/preauthkey/expire {"id":"<decimal>"}. The unit tests in
// internal/enroll use a fake Headscale; this one uses the real server. A client
// that presents the expired key must be refused.
func TestR5LeadExpirePreAuthKeyAgainstHeadscale(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	roots := writeTestPKI(t, embeddedPKIDir,
		[]string{"headscale", "headscale-foreign"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	e := emb{project: "idoris-vpn-r5lead-" + hex.EncodeToString(suffix[:])}
	_, _ = e.composeOK("down", "-v", "--remove-orphans")
	e.compose(t, "up", "-d", "--wait", "--wait-timeout", "180")
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := e.composeOK("logs", "--no-color", "--tail=60", "headscale")
			t.Logf("headscale logs:\n%s", logs)
		}
		_, _ = e.composeOK("down", "-v", "--remove-orphans")
	})

	ctx := context.Background()
	our := e.headscaleClient(t, roots, "headscale")
	if err := our.Health(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := our.EnsureUser(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	e.waitSock(t, "local-ai")
	key, err := our.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		UserID:     user.ID,
		Expiration: time.Now().Add(30 * time.Minute),
		ACLTags:    []string{"tag:acme-local-ai"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if key.ID == "" || key.Key == "" {
		t.Fatalf("mint returned an incomplete key: id=%q keyEmpty=%v", key.ID, key.Key == "")
	}
	if err := our.ExpirePreAuthKey(ctx, key.ID); err != nil {
		t.Fatalf("ExpirePreAuthKey against the real Headscale: %v", err)
	}
	out, err := e.composeOK("exec", "-T", "local-ai", "/usr/local/bin/tailscale", "--socket", tsSock, "up",
		"--login-server", "https://headscale", "--auth-key", key.Key,
		"--hostname", "acme-local-ai", "--accept-dns=false", "--timeout", "25s")
	if err == nil {
		t.Fatalf("a client registered with an expired pre-auth key:\n%s", out)
	}
	t.Logf("expired key refused as expected: %s", strings.TrimSpace(filepath.Base(strings.SplitN(out, "\n", 2)[0])))
}
