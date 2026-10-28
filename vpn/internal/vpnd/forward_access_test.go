package vpnd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type scriptedListener struct {
	net.Listener
	mu   sync.Mutex
	errs []error
}

func (s *scriptedListener) Accept() (net.Conn, error) {
	s.mu.Lock()
	if len(s.errs) > 0 {
		err := s.errs[0]
		s.errs = s.errs[1:]
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
	} else {
		s.mu.Unlock()
	}
	return s.Listener.Accept()
}

func shortSockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "hardB-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSOCKS5RequiresAuthUnlessAnonymous(t *testing.T) {
	if _, err := StartAccess(&net.Dialer{}, nil, "127.0.0.1:0", AccessOptions{}, nil); err == nil {
		t.Fatal("anonymous SOCKS5 was accepted without the flag")
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	access, err := startLocalAccess(&net.Dialer{}, nil, "127.0.0.1:0", log)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = access.Close() }()
	if !bytes.Contains(logs.Bytes(), []byte(anonymousSOCKSWarning)) {
		t.Fatalf("warning missing: %s", logs.String())
	}
	echo := startEcho(t)
	conn, err := socksConnect(t, access.SOCKS5Status().Listen, echo)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestSOCKS5UsernamePassword(t *testing.T) {
	echo := startEcho(t)
	access, err := StartAccess(&net.Dialer{}, nil, "127.0.0.1:0", AccessOptions{SOCKS5User: "alice", SOCKS5Password: "s3cret"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = access.Close() }()
	addr := access.SOCKS5Status().Listen

	rejected, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rejected.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(rejected, buf); err != nil {
		t.Fatal(err)
	}
	_ = rejected.Close()
	if buf[0] != 5 || buf[1] != 0xff {
		t.Fatalf("no-auth greeting %v", buf)
	}

	bad, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientSOCKSAuth(bad, "alice", "nope"); err != nil {
		t.Fatal(err)
	}
	status := make([]byte, 2)
	if _, err := io.ReadFull(bad, status); err != nil {
		t.Fatal(err)
	}
	_ = bad.Close()
	if status[0] != 1 || status[1] != 1 {
		t.Fatalf("bad password status %v", status)
	}

	conn, err := socksConnectAuth(t, addr, echo, "alice", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("auth-ok")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "auth-ok" {
		t.Fatalf("got %q", got)
	}
}

func TestSOCKS5AuthFileModeAndStateDirReuse(t *testing.T) {
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("alice:s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, looseErr := StartAccess(&net.Dialer{}, nil, "127.0.0.1:0", AccessOptions{SOCKS5AuthFile: loose}, nil)
	if socksChecksUnixMode {
		if looseErr == nil {
			t.Fatal("mode 0644 was accepted")
		}
	} else if looseErr != nil {
		t.Fatalf("windows mode bits are not a 0600 check: %v", looseErr)
	}
	tight := filepath.Join(dir, "tight")
	if err := os.WriteFile(tight, []byte("alice:s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	access, err := StartAccess(&net.Dialer{}, nil, "127.0.0.1:0", AccessOptions{SOCKS5AuthFile: tight}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = access.Close()

	state := filepath.Join(dir, "state")
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	first, err := StartAccess(&net.Dialer{}, nil, "127.0.0.1:0", AccessOptions{StateDir: state}, log)
	if err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(state, "socks5.auth")
	st, err := os.Stat(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if socksChecksUnixMode && st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	body, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	second, err := StartAccess(&net.Dialer{}, nil, "127.0.0.1:0", AccessOptions{StateDir: state}, log)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	again, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, again) {
		t.Fatal("generated credential changed across restart")
	}
	if bytes.Contains(logs.Bytes(), body) || bytes.Contains(logs.Bytes(), []byte("s3cret")) {
		t.Fatal("log contains a SOCKS5 password")
	}
	if strings.Count(logs.String(), authPath) != 1 || !strings.Contains(logs.String(), "SOCKS5 auth file created") {
		t.Fatalf("created auth path was not logged once:\n%s", logs.String())
	}
	if first.SOCKS5Status() == nil || first.SOCKS5Status().AuthFile != authPath {
		t.Fatalf("status auth file %+v", first.SOCKS5Status())
	}
	text := FormatStatus(map[string]any{
		"socks5": map[string]any{"listen": "127.0.0.1:1", "state": "listening", "auth_file": authPath},
	})
	if !strings.Contains(text, "auth="+authPath) {
		t.Fatalf("status text missing auth path:\n%s", text)
	}
}

func TestUnixListenIsOwnerOnly(t *testing.T) {
	dir := shortSockDir(t)
	path := filepath.Join(dir, "s")
	echo := startEcho(t)
	access, err := StartAccess(&net.Dialer{}, []Forward{{Listen: "unix:" + path, Target: echo}}, "", AccessOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = access.Close() }()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("u")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "u" {
		t.Fatalf("got %q err %v", got, err)
	}

	if err := ValidateForwardListen("unix:relative"); err == nil {
		t.Fatal("relative unix path accepted")
	}
	if err := ValidateForwardListen("unix:"); err == nil {
		t.Fatal("empty unix path accepted")
	}
	file := filepath.Join(dir, "plain")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateForwardListen("unix:" + file); err == nil {
		t.Fatal("regular file accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateForwardListen("unix:" + link); err == nil {
		t.Fatal("symlink accepted")
	}
	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := ValidateForwardListen("unix:" + filepath.Join(open, "s")); err == nil {
		t.Fatal("world-writable parent accepted")
	}
}

func TestUnixStaleSocketIsReplacedAndLiveOneIsNot(t *testing.T) {
	dir := shortSockDir(t)
	stale := filepath.Join(dir, "stale")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: stale}); err != nil {
		_ = syscall.Close(fd)
		t.Fatal(err)
	}
	_ = syscall.Close(fd)
	access, err := StartAccess(&net.Dialer{}, []Forward{{Listen: "unix:" + stale, Target: "127.0.0.1:1"}}, "", AccessOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = access.Close()

	live := filepath.Join(dir, "live")
	ln, err := net.Listen("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if _, err := StartAccess(&net.Dialer{}, []Forward{{Listen: "unix:" + live, Target: "127.0.0.1:1"}}, "", AccessOptions{}, nil); err == nil {
		t.Fatal("took over a live socket")
	}
}

func TestGateRefusesNewConnections(t *testing.T) {
	echo := startEcho(t)
	var open atomic.Bool
	dialer := &fakeDialer{dest: echo}
	access, err := StartAccess(dialer, []Forward{{Listen: "127.0.0.1:0", Target: "peer:9"}}, "", AccessOptions{Gate: open.Load}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = access.Close() }()
	if !access.Suspended() || access.ForwardStatus()[0].State != "suspended" {
		t.Fatalf("state %+v suspended %v", access.ForwardStatus(), access.Suspended())
	}
	conn, err := net.Dial("tcp", access.ForwardStatus()[0].Listen)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadAll(conn)
	_ = conn.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("closed gate read: %v", err)
		}
		t.Fatal("closed gate left the client blocked")
	}
	if len(dialer.got()) != 0 {
		t.Fatalf("dialed while suspended: %v", dialer.got())
	}
	open.Store(true)
	if access.Suspended() || access.ForwardStatus()[0].State != "listening" {
		t.Fatalf("reopened %+v", access.ForwardStatus())
	}
	conn, err = net.Dial("tcp", access.ForwardStatus()[0].Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "go" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestAcceptTemporaryRetriesAndFatalFails(t *testing.T) {
	echo := startEcho(t)
	access, err := StartAccess(&net.Dialer{}, []Forward{{Listen: "127.0.0.1:0", Target: echo}}, "", AccessOptions{
		listenHook: func(ln net.Listener) net.Listener {
			return &scriptedListener{Listener: ln, errs: []error{fmt.Errorf("busy: %w", syscall.EAGAIN)}}
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := access.ForwardStatus()[0].Listen
	var conn net.Conn
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			conn = c
			break
		}
		if time.Now().After(deadline) {
			_ = access.Close()
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = conn.Close()
	if access.ForwardStatus()[0].State != "listening" {
		t.Fatalf("state %+v", access.ForwardStatus())
	}
	_ = access.Close()

	fatal, err := StartAccess(&net.Dialer{}, []Forward{{Listen: "127.0.0.1:0", Target: echo}}, "", AccessOptions{
		listenHook: func(ln net.Listener) net.Listener {
			return &scriptedListener{Listener: ln, errs: []error{errors.New("listener exploded")}}
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fatal.Close() }()
	deadline = time.Now().Add(2 * time.Second)
	for access.ForwardStatus() != nil && fatal.ForwardStatus()[0].State != "failed" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	st := fatal.ForwardStatus()[0]
	if st.State != "failed" || !bytes.Contains([]byte(st.Error), []byte("listener exploded")) {
		t.Fatalf("status %+v", st)
	}
}

func TestForwardLimitsAndAbandonedDialDoNotLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	dialer := &fakeDialer{err: errors.New("no route")}
	access, err := StartAccess(dialer, []Forward{{Listen: "127.0.0.1:0", Target: "peer:1"}}, "", AccessOptions{MaxConnections: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := access.ForwardStatus()[0].Listen
	deadline := time.Now().Add(2 * time.Second)
	for len(dialer.got()) < 2 && time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadAll(c)
		_ = c.Close()
		time.Sleep(5 * time.Millisecond)
	}
	if len(dialer.got()) != 2 {
		t.Fatalf("slot was not released: %v", dialer.got())
	}
	_ = access.Close()

	entered := make(chan struct{})
	returned := make(chan struct{})
	var once sync.Once
	blocker := &callbackDialer{fn: func(ctx context.Context, _, _ string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		close(returned)
		return nil, ctx.Err()
	}}
	held, err := StartAccess(blocker, []Forward{{Listen: "127.0.0.1:0", Target: "peer:2"}}, "", AccessOptions{MaxConnections: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := net.Dial("tcp", held.ForwardStatus()[0].Listen)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("dial did not start")
	}
	c2, err := net.Dial("tcp", held.ForwardStatus()[0].Listen)
	if err != nil {
		t.Fatal(err)
	}
	_ = c2.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadAll(c2); err != nil && !errors.Is(err, io.EOF) {
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("overflow read: %v", err)
		}
		t.Fatal("connection over the cap was not closed")
	}
	_ = c2.Close()
	start := time.Now()
	_ = c1.Close()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("client disconnect did not cancel the dial")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("client disconnect waited for the dial deadline")
	}
	_ = held.Close()
	wait := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(wait) {
		time.Sleep(20 * time.Millisecond)
		runtime.Gosched()
	}
	if got := runtime.NumGoroutine(); got > before+2 {
		t.Fatalf("goroutines before=%d after=%d", before, got)
	}
}

type callbackDialer struct {
	fn func(context.Context, string, string) (net.Conn, error)
}

func (c *callbackDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return c.fn(ctx, network, address)
}

func clientSOCKSAuth(c net.Conn, user, pass string) error {
	if _, err := c.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if buf[1] != 0x02 {
		return fmt.Errorf("method %d", buf[1])
	}
	msg := []byte{0x01, byte(len(user))}
	msg = append(msg, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)
	_, err := c.Write(msg)
	return err
}

func socksConnectAuth(t *testing.T, proxy, dest, user, pass string) (net.Conn, error) {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		return nil, err
	}
	if err := clientSOCKSAuth(c, user, pass); err != nil {
		_ = c.Close()
		return nil, err
	}
	status := make([]byte, 2)
	if _, err := io.ReadFull(c, status); err != nil {
		_ = c.Close()
		return nil, err
	}
	if status[1] != 0 {
		_ = c.Close()
		return nil, errors.New("socks5 auth rejected")
	}
	return finishSOCKSConnect(c, dest)
}

func finishSOCKSConnect(c net.Conn, dest string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		_ = c.Close()
		return nil, errors.New("test dest must be ipv4")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		_ = c.Close()
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		_ = c.Close()
		return nil, err
	}
	if hdr[1] != 0 {
		_ = c.Close()
		return nil, fmt.Errorf("socks5 rep %d", hdr[1])
	}
	if _, err := io.ReadFull(c, make([]byte, 6)); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}
