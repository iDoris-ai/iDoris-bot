package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/ui"
)

func TestR5WBrowserOpenerObservesTheProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix shell openers")
	}
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "pid")
	t.Cleanup(func() { r5wKillPidFile(pidfile) })

	prev := uiOpenerTimeout
	uiOpenerTimeout = 300 * time.Millisecond
	t.Cleanup(func() { uiOpenerTimeout = prev })

	t.Run("exit 0", func(t *testing.T) {
		start := time.Now()
		if err := uiStartBrowser([]string{"/bin/sh", "-c", "exit 0"}); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed >= uiOpenerTimeout {
			t.Fatalf("exit 0 was left until the timeout (%s)", elapsed)
		}
	})
	t.Run("exit 1", func(t *testing.T) {
		if err := uiStartBrowser([]string{"/bin/sh", "-c", "exit 1"}); err == nil {
			t.Fatal("exit 1 was treated as success")
		}
	})
	t.Run("hang", func(t *testing.T) {
		// $1 is the pid file. $$ is this shell, so the test can stop it.
		argv := []string{"/bin/sh", "-c", "echo $$ > \"$1\"; sleep 30", "sh", pidfile}
		start := time.Now()
		if err := uiStartBrowser(argv); err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(start)
		if elapsed < 200*time.Millisecond {
			t.Fatalf("opener returned in %s, before it was observed", elapsed)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("opener waited %s for a process that was still running", elapsed)
		}
		if _, err := os.Stat(pidfile); err != nil {
			t.Fatalf("hung opener did not stay running: %v", err)
		}
	})
}

func TestR5WMissingOpenerIsNotSuccess(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-opener")
	if err := uiStartBrowser([]string{missing}); err == nil {
		t.Fatal("missing opener was treated as success")
	}
}

func TestR5WStartedBrowserNamesTheLauncherOnStderr(t *testing.T) {
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
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	stderr := r5wCaptureStderr(t)
	printed, err := uiPrepareOpen(srv, false, func([]string) error { return nil })
	text := stderr()
	if err != nil {
		t.Fatal(err)
	}
	if printed != srv.PageURL() || strings.Contains(printed, secret) || strings.Contains(printed, "open this file") {
		t.Fatalf("stdout %q", printed)
	}
	if !strings.Contains(text, uiLauncherFallback) || !strings.Contains(text, dir) || strings.Contains(text, secret) {
		t.Fatalf("stderr %q", text)
	}
}

func r5wKillPidFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = proc.Kill()
}

func r5wCaptureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = w
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	var once sync.Once
	finish := func() string {
		once.Do(func() {
			os.Stderr = prev
			_ = w.Close()
			<-done
			_ = r.Close()
		})
		return buf.String()
	}
	t.Cleanup(func() { _ = finish() })
	return finish
}
