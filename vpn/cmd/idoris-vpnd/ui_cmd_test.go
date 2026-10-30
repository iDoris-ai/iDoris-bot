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
	var file string
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
		file = got[1]
	case "windows":
		if len(got) != 3 || got[0] != "rundll32" || got[1] != "url.dll,FileProtocolHandler" {
			t.Fatalf("argv %#v", got)
		}
		file = got[2]
	default:
		if len(got) != 0 || !strings.Contains(printed, uiLauncherHint) {
			t.Fatalf("printed %q argv %#v", printed, got)
		}
		return
	}
	for _, a := range got {
		if strings.Contains(a, secret) || strings.Contains(a, "#k=") || strings.Contains(a, "?k=") || strings.Contains(a, "http://") || strings.Contains(a, "https://") {
			t.Fatalf("secret or URL in argv %#v", got)
		}
	}
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), secret) || !strings.Contains(string(body), "/bootstrap") {
		t.Fatal("launcher file does not post the bootstrap secret")
	}
	st, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
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

func TestR4WWindowsLauncherDoesNotPutTheSecretInArgv(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	const launcher = `C:\Users\a\launch-abc.html`
	argv := uiBrowserArgv("windows", launcher)
	if len(argv) != 3 || argv[0] != "rundll32" || argv[1] != "url.dll,FileProtocolHandler" || argv[2] != launcher {
		t.Fatalf("argv %#v", argv)
	}
	joined := strings.Join(argv, "\n")
	if strings.Contains(joined, secret) || strings.Contains(joined, "http://") || strings.Contains(joined, "#k=") {
		t.Fatalf("argv %#v", argv)
	}

	prevOS := uiGOOS
	uiGOOS = "windows"
	t.Cleanup(func() { uiGOOS = prevOS })
	dir := t.TempDir()
	prevRoot := uiLauncherRoot
	uiLauncherRoot = func() (string, error) { return dir, nil }
	t.Cleanup(func() { uiLauncherRoot = prevRoot })
	srv, err := ui.New(ui.Options{
		EUID: 1, LoginUID: 1, Secret: secret, CSRF: "csrfcsrfcsrfcsrfcsrfcsrfcsrfcsrf",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	var got []string
	printed, err := uiPrepareOpen(srv, false, func(argv []string) error {
		got = append([]string(nil), argv...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if printed != srv.PageURL() || strings.Contains(printed, secret) {
		t.Fatalf("opened page printed %q", printed)
	}
	if len(got) != 3 || got[0] != "rundll32" || got[1] != "url.dll,FileProtocolHandler" {
		t.Fatalf("argv %#v", got)
	}
	if strings.Contains(strings.Join(got, "\n"), secret) || strings.Contains(got[2], "http://") {
		t.Fatalf("argv %#v", got)
	}

	failed, err := ui.New(ui.Options{
		EUID: 1, LoginUID: 1, Secret: secret, CSRF: "csrfcsrfcsrfcsrfcsrfcsrfcsrfcsrf",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = failed.Shutdown(ctx)
	})
	printed, err = uiPrepareOpen(failed, false, func([]string) error {
		return os.ErrNotExist
	})
	if err != nil {
		t.Fatal(err)
	}
	if printed == failed.PageURL() || !strings.Contains(printed, uiLauncherHint) || strings.Contains(printed, secret) {
		t.Fatalf("failed open printed %q", printed)
	}
	path := printed[strings.LastIndex(printed, "\n")+1:]
	body, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(body), secret) {
		t.Fatalf("launcher %q %v", path, err)
	}

	uiGOOS = "plan9"
	quiet, err := ui.New(ui.Options{
		EUID: 1, LoginUID: 1, Secret: secret, CSRF: "csrfcsrfcsrfcsrfcsrfcsrfcsrfcsrf",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = quiet.Shutdown(ctx)
	})
	printed, err = uiPrepareOpen(quiet, false, func(argv []string) error {
		t.Fatalf("opener called with %#v", argv)
		return nil
	})
	if err != nil || printed == quiet.PageURL() || !strings.Contains(printed, uiLauncherHint) || strings.Contains(printed, secret) {
		t.Fatalf("no opener printed %q err %v", printed, err)
	}
}
