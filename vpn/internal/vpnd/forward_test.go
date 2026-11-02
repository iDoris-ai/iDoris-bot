package vpnd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

type fakeDialer struct {
	mu    sync.Mutex
	addrs []string
	err   error
	dest  string
	block bool
}

func (f *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.addrs = append(f.addrs, address)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var d net.Dialer
	return d.DialContext(ctx, network, f.dest)
}

func (f *fakeDialer) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.addrs...)
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				buf, err := io.ReadAll(c)
				if err != nil {
					return
				}
				_, _ = c.Write(buf)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestForwardHalfCloseAndLargePayload(t *testing.T) {
	echo := startEcho(t)
	dialer := &fakeDialer{dest: echo}
	access, err := startLocalAccess(dialer, []Forward{{Listen: "127.0.0.1:0", Target: "acme-local-ai:11434"}}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = access.Close() })
	st := access.ForwardStatus()
	if len(st) != 1 || st[0].State != "listening" || st[0].Target != "acme-local-ai:11434" {
		t.Fatalf("%+v", st)
	}

	payload := bytes.Repeat([]byte{7}, 1<<20+17)
	conn, err := net.Dial("tcp", st[0].Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %d bytes, want %d", len(got), len(payload))
	}
	if addrs := dialer.got(); len(addrs) != 1 || addrs[0] != "acme-local-ai:11434" {
		t.Fatalf("dialed %v", addrs)
	}
}

func TestForwardDialFailureKeepsListening(t *testing.T) {
	dialer := &fakeDialer{err: errors.New("no route")}
	access, err := startLocalAccess(dialer, []Forward{{Listen: "127.0.0.1:0", Target: "missing:9"}}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = access.Close() }()
	addr := access.ForwardStatus()[0].Listen
	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = io.ReadAll(conn)
		_ = conn.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			// The proxy closes the client when the dial fails. EOF or a
			// closed-connection error are both fine; a timeout is not.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("dial %d timed out: %v", i, err)
			}
		}
	}
	if st := access.ForwardStatus(); st[0].State != "listening" {
		t.Fatalf("state %s", st[0].State)
	}
	if len(dialer.got()) != 2 {
		t.Fatalf("dials %v", dialer.got())
	}
}

func TestForwardCloseUnblocksAndDoesNotLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	dialer := &fakeDialer{block: true}
	access, err := startLocalAccess(dialer, []Forward{{Listen: "127.0.0.1:0", Target: "peer:1"}}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", access.ForwardStatus()[0].Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	errc := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(conn)
		errc <- err
	}()
	// Let the accept loop enter DialContext, which blocks until Close.
	time.Sleep(50 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		_ = access.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked; a goroutine leaked")
	}
	select {
	case <-errc:
	case <-time.After(2 * time.Second):
		t.Fatal("client still blocked after Close")
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		runtime.Gosched()
	}
	if got := runtime.NumGoroutine(); got > before+2 {
		t.Fatalf("goroutines before=%d after=%d", before, got)
	}
}

func TestSOCKS5ReachesEcho(t *testing.T) {
	echo := startEcho(t)
	access, err := startLocalAccess(&net.Dialer{}, nil, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = access.Close() }()
	s5 := access.SOCKS5Status()
	if s5 == nil || s5.State != "listening" || s5.Listen == "" {
		t.Fatalf("%+v", s5)
	}
	conn, err := socksConnect(t, s5.Listen, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("via-socks5")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q", got)
	}
}

func socksConnect(t *testing.T, proxy, dest string) (net.Conn, error) {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = c.Close()
		return nil, err
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		_ = c.Close()
		return nil, err
	}
	if greet[0] != 5 || greet[1] != 0 {
		_ = c.Close()
		return nil, errors.New("socks5 greeting rejected")
	}
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
		return nil, errors.New("socks5 connect failed")
	}
	var rest int
	switch hdr[3] {
	case 1:
		rest = 4 + 2
	case 4:
		rest = 16 + 2
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			_ = c.Close()
			return nil, err
		}
		rest = int(n[0]) + 2
	default:
		_ = c.Close()
		return nil, errors.New("bad atyp")
	}
	if _, err := io.ReadFull(c, make([]byte, rest)); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func TestRejectNonLoopbackListen(t *testing.T) {
	if err := ValidateLoopback("0.0.0.0:1"); err == nil {
		t.Fatal("expected rejection")
	}
	if err := ValidateLoopback("127.0.0.1:1055"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLoopback("[::1]:1055"); err != nil {
		t.Fatal(err)
	}
}
