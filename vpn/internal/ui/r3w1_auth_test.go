package ui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestR3W1BootstrapOnceThenReplayRefused(t *testing.T) {
	srv, client, _ := testServer(t, time.Minute)
	cap, csrf := r3w1Bootstrap(t, srv, client)

	req, err := http.NewRequest(http.MethodPost, srv.url()+"/api/bootstrap", strings.NewReader(`{"k":"`+srv.secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+srv.bound)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(string(raw), "already used") {
		t.Fatalf("replay %d %s", res.StatusCode, raw)
	}
	if strings.Contains(string(raw), cap) || strings.Contains(string(raw), srv.secret) {
		t.Fatalf("replay body leaked a secret: %s", raw)
	}

	// A refresh keeps working with the capability alone. The bootstrap secret
	// in the query does not.
	statusReq, _ := http.NewRequest(http.MethodGet, srv.url()+"/api/status", nil)
	statusReq.Header.Set(SessionHeader, cap)
	res, err = client.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("refresh with capability %d", res.StatusCode)
	}
	if csrf == "" {
		t.Fatal("empty csrf")
	}
	if got := client.Jar.Cookies(mustR3W1URL(t, srv.url()+"/")); len(got) != 0 {
		t.Fatalf("jar stored cookies: %+v", got)
	}
}

func TestR3W1FormBootstrapIgnoresQueryAndDeletesLauncher(t *testing.T) {
	srv, client, _ := testServer(t, time.Minute)
	dir := t.TempDir()
	path, err := srv.WriteLauncher(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("launcher mode %o", st.Mode().Perm())
	}
	dst, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dst.Mode().Perm()&0o077 != 0 {
		t.Fatalf("dir mode %o", dst.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, `value="`+srv.secret+`"`) || !strings.Contains(text, "http://"+srv.bound+"/bootstrap") {
		t.Fatalf("launcher missing the post or the secret")
	}
	if strings.Contains(text, "?k=") {
		t.Fatal("launcher uses a query secret")
	}

	// The secret in the query string must not be consumed.
	req, err := http.NewRequest(http.MethodPost, srv.url()+"/bootstrap?k="+url.QueryEscape(srv.secret), strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("query bootstrap %d %s", res.StatusCode, raw)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("launcher removed before a real bootstrap: %v", err)
	}

	form := url.Values{}
	form.Set("k", srv.secret)
	req, err = http.NewRequest(http.MethodPost, srv.url()+"/bootstrap", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", "idoris_ui=stale-from-an-earlier-launch")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("form bootstrap %d %s", res.StatusCode, page)
	}
	if res.Header.Get("Set-Cookie") != "" {
		t.Fatal(res.Header.Get("Set-Cookie"))
	}
	html := string(page)
	if strings.Contains(html, srv.secret) || !strings.Contains(html, "sessionStorage") || !strings.Contains(html, `location.replace("/")`) {
		t.Fatal("bootstrap page shape")
	}
	if !strings.Contains(res.Header.Get("Content-Security-Policy"), "script-src 'nonce-") {
		t.Fatalf("csp %s", res.Header.Get("Content-Security-Policy"))
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("launcher still present after use: %v", err)
	}

	req, err = http.NewRequest(http.MethodPost, srv.url()+"/bootstrap", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(string(raw), "already used") {
		t.Fatalf("form replay %d %s", res.StatusCode, raw)
	}
}

func TestR3W1ShutdownDeletesLauncher(t *testing.T) {
	srv, err := New(Options{EUID: 1, LoginUID: 1, Secret: "secretsecretsecretsecretsecretse", CSRF: "csrfcsrfcsrfcsrfcsrfcsrfcsrfcsrf"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	path, err := srv.WriteLauncher(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("launcher remains after shutdown: %v", err)
	}
}

func TestR3W1BootstrapExpires(t *testing.T) {
	srv, err := New(Options{
		EUID: 1, LoginUID: 1, Secret: "secretsecretsecretsecretsecretse", CSRF: "csrfcsrfcsrfcsrfcsrfcsrfcsrfcsrf",
		Idle: time.Minute, BootstrapTTL: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	time.Sleep(300 * time.Millisecond)
	req, err := http.NewRequest(http.MethodPost, srv.url()+"/api/bootstrap", strings.NewReader(`{"k":"`+srv.secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+srv.bound)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(string(raw), "expired") || res.Header.Get("Set-Cookie") != "" {
		t.Fatalf("expired %d cookie %q body %s", res.StatusCode, res.Header.Get("Set-Cookie"), raw)
	}
}

func TestR3W1SecondServerIgnoresOldSession(t *testing.T) {
	srv1, client, _ := testServer(t, time.Minute)
	cap1, _ := r3w1Bootstrap(t, srv1, client)

	u, err := url.Parse(srv1.url() + "/")
	if err != nil {
		t.Fatal(err)
	}
	client.Jar.SetCookies(u, []*http.Cookie{{Name: "idoris_ui", Value: cap1, Path: "/"}})

	srv2, err := New(Options{
		EUID: 1, LoginUID: 1, Secret: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CSRF: "cccccccccccccccccccccccccccccccc",
		Idle: time.Minute,
		Services: Services{
			Status: func(context.Context) (map[string]any, error) {
				return map[string]any{"phase": "connected"}, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv2.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv2.Shutdown(ctx)
	})

	// Same jar, stale cookie, and the previous capability header. None of
	// those may block the new bootstrap or authorize the new server.
	req, err := http.NewRequest(http.MethodPost, srv2.url()+"/api/bootstrap", strings.NewReader(`{"k":"`+srv2.secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+srv2.bound)
	req.Header.Set("Cookie", "idoris_ui="+cap1)
	req.Header.Set(SessionHeader, cap1)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Set-Cookie") != "" {
		t.Fatalf("second bootstrap %d cookie %q body %s", res.StatusCode, res.Header.Get("Set-Cookie"), raw)
	}
	var out struct {
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Capability == "" || out.Capability == cap1 {
		t.Fatalf("second capability %s err %v", raw, err)
	}

	old := mustR3W1Status(t, client, srv2.url(), cap1)
	if old != http.StatusUnauthorized {
		t.Fatalf("old capability on new server %d", old)
	}
	neu := mustR3W1Status(t, client, srv2.url(), out.Capability)
	if neu != http.StatusOK {
		t.Fatalf("new capability %d", neu)
	}
	still := mustR3W1Status(t, client, srv1.url(), cap1)
	if still != http.StatusOK {
		t.Fatalf("first server after second launch %d", still)
	}
}

func TestR3W1WrongCapabilityAndBadOriginDoNotConsume(t *testing.T) {
	srv, client, _ := testServer(t, time.Minute)

	req, err := http.NewRequest(http.MethodGet, srv.url()+"/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(SessionHeader, "not-the-capability")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong capability %d", res.StatusCode)
	}

	req, err = http.NewRequest(http.MethodPost, srv.url()+"/api/bootstrap", strings.NewReader(`{"k":"`+srv.secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://evil.example")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("evil origin bootstrap %d %s", res.StatusCode, raw)
	}

	req, err = http.NewRequest(http.MethodPost, srv.url()+"/bootstrap", strings.NewReader("k="+url.QueryEscape(srv.secret)))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "evil.example"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("evil host bootstrap %d", res.StatusCode)
	}

	// The secret was not consumed by the rejected attempts.
	cap, _ := r3w1Bootstrap(t, srv, client)
	if cap == "" {
		t.Fatal("bootstrap after rejected attempts failed")
	}
}

func TestR3W1ConcurrentBootstrapOneWinner(t *testing.T) {
	srv, client, _ := testServer(t, time.Minute)
	start := make(chan struct{})
	var wg sync.WaitGroup
	codes := make([]int, 2)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			req, err := http.NewRequest(http.MethodPost, srv.url()+"/api/bootstrap", strings.NewReader(`{"k":"`+srv.secret+`"}`))
			if err != nil {
				codes[i] = -1
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "http://"+srv.bound)
			res, err := client.Do(req)
			if err != nil {
				codes[i] = -1
				return
			}
			_ = res.Body.Close()
			codes[i] = res.StatusCode
		}(i)
	}
	close(start)
	wg.Wait()
	ok, denied := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusUnauthorized:
			denied++
		default:
			t.Fatalf("codes %v", codes)
		}
	}
	if ok != 1 || denied != 1 {
		t.Fatalf("ok %d denied %d codes %v", ok, denied, codes)
	}
}

func mustR3W1URL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustR3W1Status(t *testing.T, client *http.Client, base, capability string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	if capability != "" {
		req.Header.Set(SessionHeader, capability)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}
