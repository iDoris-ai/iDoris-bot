package main

import (
	"context"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/ui"
)

func TestR3W1UIOpenArgvHasNoSecret(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	dir := t.TempDir()
	prev := uiLauncherRoot
	uiLauncherRoot = func() (string, error) { return dir, nil }
	t.Cleanup(func() { uiLauncherRoot = prev })

	srv, err := ui.New(ui.Options{
		EUID: 1, LoginUID: 1, Secret: secret, CSRF: "csrfcsrfcsrfcsrfcsrfcsrfcsrfcsrf",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	printed, err := uiPrepareOpen(srv, false, func(argv []string) error {
		got = append([]string(nil), argv...)
		return nil
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(printed, secret) || strings.Contains(printed, "#k=") || strings.Contains(printed, "?k=") || printed != srv.PageURL() {
		t.Fatalf("printed URL %q", printed)
	}
	switch runtime.GOOS {
	case "darwin", "linux":
		if len(got) != 2 {
			t.Fatalf("argv %#v", got)
		}
		want := "open"
		if runtime.GOOS == "linux" {
			want = "xdg-open"
		}
		if got[0] != want {
			t.Fatalf("argv %#v", got)
		}
	default:
		if len(got) != 0 {
			t.Fatalf("argv %#v", got)
		}
		return
	}
	for _, a := range got {
		if strings.Contains(a, secret) || strings.Contains(a, "#k=") || strings.Contains(a, "?k=") || strings.Contains(a, "http://") || strings.Contains(a, "https://") {
			t.Fatalf("secret or URL in argv %#v", got)
		}
	}
	file, err := os.ReadFile(got[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(file), secret) || !strings.Contains(string(file), "/bootstrap") {
		t.Fatal("launcher file does not post the bootstrap secret")
	}
	st, err := os.Stat(got[1])
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestR3W1UINoOpenPrintsFragment(t *testing.T) {
	const secret = "fedcba9876543210fedcba9876543210"
	srv, err := ui.New(ui.Options{
		EUID: 1, LoginUID: 1, Secret: secret, CSRF: "csrfcsrfcsrfcsrfcsrfcsrfcsrfcsrf",
	})
	if err != nil {
		t.Fatal(err)
	}
	printed, err := uiPrepareOpen(srv, true, func(argv []string) error {
		t.Fatalf("opener called with %#v", argv)
		return nil
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(printed)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("k") != "" || strings.Contains(u.RawQuery, secret) {
		t.Fatalf("secret in query: %s", printed)
	}
	if u.Fragment != "k="+secret {
		t.Fatalf("fragment %q", u.Fragment)
	}
	if !strings.HasPrefix(printed, "http://127.0.0.1:") {
		t.Fatalf("url %s", printed)
	}
}
